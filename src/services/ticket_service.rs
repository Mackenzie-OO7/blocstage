// everything tickets: purchase, verification, transfers

// TODO: finalize on AWS or Digital Ocean

use crate::models::{
    event::Event, ticket::Ticket, ticket_type::TicketType, transaction::Transaction, user::User,
};
use crate::services::stellar_service::StellarService;
use anyhow::{anyhow, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::{Client as S3Client};
use aws_sdk_s3::config::Region;
use base64::{engine::general_purpose, Engine as _};
use bigdecimal::BigDecimal;
use chrono::Utc;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info, warn};
#[allow(unused_imports)]
use printpdf::{Mm, PdfDocument, Point, Rgb};
use qrcode::render::svg;
use qrcode::QrCode;
use rust_decimal::prelude::{Signed, Zero};
use sqlx::{PgPool, Postgres, Transaction as SqlxTransaction};
use std::env;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub struct TicketService {
    pool: PgPool,
    stellar_service: StellarService,
    s3_client: Option<S3Client>,
}

impl TicketService {
    pub async fn new(pool: PgPool) -> Result<Self> {
        // Initialize the stellar service
        let stellar_service = StellarService::new()?;

        // If we end up using AWS, initialize S3 client with AWS credentials
        let s3_client = match Self::initialize_s3().await {
            Ok(client) => Some(client),
            Err(e) => {
                warn!("Failed to initialize S3 client: {}", e);
                None
            }
        };

        Ok(Self {
            pool,
            stellar_service,
            s3_client,
        })
    }

    // Initialize S3 client
    async fn initialize_s3() -> Result<S3Client> {
        let region_provider =
            RegionProviderChain::default_provider().or_else(Region::new("us-east-1"));
        let config = aws_config::from_env().region(region_provider).load().await;
        Ok(S3Client::new(&config))
    }

    pub async fn purchase_ticket(&self, ticket_type_id: Uuid, user_id: Uuid) -> Result<Ticket> {
        let mut tx = self.pool.begin().await?;

        // Get ticket type with locking to prevent race conditions
        let ticket_type = self
            .get_ticket_type_with_lock(&mut tx, ticket_type_id)
            .await?;

        if let Some(remaining) = ticket_type.remaining {
            if remaining <= 0 {
                return Err(anyhow!("No tickets remaining"));
            }
        }

        if !ticket_type.is_active {
            return Err(anyhow!("Ticket sales are not currently active"));
        }

        let user = User::find_by_id(&self.pool, user_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        let qr_data = format!(
            "ticket:{}:{}:{}",
            ticket_type_id,
            user_id,
            Utc::now().timestamp()
        );
        let qr_code = self.generate_qr_code(&qr_data)?;

        let ticket = self
            .create_ticket_in_transaction(&mut tx, ticket_type_id, user_id, Some(qr_code))
            .await?;

        if let Some(price) = ticket_type.price.clone() {
            if !price.is_zero() {
                let transaction = self
                    .create_transaction_in_transaction(
                        &mut tx,
                        ticket.id,
                        user_id,
                        price,
                        &ticket_type.currency,
                        "pending",
                    )
                    .await?;

                let payment_result = self
                    .process_payment(&user, &ticket_type, &transaction)
                    .await;

                match payment_result {
                    Ok(tx_hash) => {
                        // Update transaction with Stellar hash
                        self.update_transaction_hash_in_transaction(
                            &mut tx,
                            &transaction,
                            &tx_hash,
                        )
                        .await?;
                        self.update_transaction_status_in_transaction(
                            &mut tx,
                            &transaction,
                            "completed",
                        )
                        .await?;

                        self.decrease_remaining_in_transaction(&mut tx, &ticket_type)
                            .await?;
                    }
                    Err(e) => {
                        self.update_transaction_status_in_transaction(
                            &mut tx,
                            &transaction,
                            "failed",
                        )
                        .await?;

                        self.update_ticket_status_in_transaction(&mut tx, &ticket, "cancelled")
                            .await?;

                        tx.rollback().await?;
                        return Err(e);
                    }
                }
            } else {
                self.decrease_remaining_in_transaction(&mut tx, &ticket_type)
                    .await?;
            }
        } else {
            self.decrease_remaining_in_transaction(&mut tx, &ticket_type)
                .await?;
        }

        tx.commit().await?;

        let ticket_id = ticket.id;
        let pool = self.pool.clone();

        tokio::spawn(async move {
            match Ticket::find_by_id(&pool, ticket_id).await {
                Ok(Some(_)) => {
                    info!("PDF ticket generated for ticket: {}", ticket_id);
                    // TODO: implement the actual PDF generation later
                }
                Ok(None) => error!("Failed to generate PDF ticket: Ticket not found"),
                Err(e) => error!("Failed to generate PDF ticket: {}", e),
            }
        });

        Ok(ticket)
    }

    async fn get_ticket_type_with_lock<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        id: Uuid,
    ) -> Result<TicketType> {
        let row = sqlx::query!("SELECT * FROM ticket_types WHERE id = $1 FOR UPDATE", id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        let ticket_type = TicketType {
            id: row.id,
            event_id: row.event_id,
            name: row.name,
            description: row.description,
            price: row.price,
            currency: row.currency.expect("Currency should have a default value"),
            total_supply: row.total_supply,
            remaining: row.remaining,
            is_active: row.is_active,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };

        Ok(ticket_type)
    }

    async fn create_ticket_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        ticket_type_id: Uuid,
        owner_id: Uuid,
        qr_code: Option<String>,
    ) -> Result<Ticket> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let row = sqlx::query!(
            r#"
            INSERT INTO tickets (
                id, ticket_type_id, owner_id, status, qr_code, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            id,
            ticket_type_id,
            owner_id,
            "valid",
            qr_code,
            now,
            now
        )
        .fetch_one(&mut **tx)
        .await?;

        // Manually construct ticket from row
        let ticket = Ticket {
            id: row.id,
            ticket_type_id: row.ticket_type_id,
            owner_id: row.owner_id,
            status: row.status,
            qr_code: row.qr_code,
            nft_identifier: row.nft_identifier,
            created_at: row.created_at,
            updated_at: row.updated_at,
            checked_in_at: row.checked_in_at,
            checked_in_by: row.checked_in_by,
            pdf_url: row.pdf_url,
        };

        Ok(ticket)
    }

    async fn create_transaction_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        ticket_id: Uuid,
        user_id: Uuid,
        amount: BigDecimal,
        currency: &str,
        status: &str,
    ) -> Result<Transaction> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let receipt_number = format!(
            "RCT-{}-{}",
            now.format("%Y%m%d"),
            self.generate_random_receipt_suffix()
        );

        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            INSERT INTO transactions (
                id, ticket_id, user_id, amount, currency, status, created_at, updated_at, receipt_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
            id, ticket_id, user_id, amount, currency, status, now, now, receipt_number
        )
        .fetch_one(&mut **tx)
        .await?;

        Ok(transaction)
    }

    async fn update_transaction_hash_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        transaction: &Transaction,
        hash: &str,
    ) -> Result<Transaction> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET stellar_transaction_hash = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            hash,
            Utc::now(),
            transaction.id
        )
        .fetch_one(&mut **tx)
        .await?;

        Ok(transaction)
    }

    async fn update_transaction_status_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        transaction: &Transaction,
        status: &str,
    ) -> Result<Transaction> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            status,
            Utc::now(),
            transaction.id
        )
        .fetch_one(&mut **tx)
        .await?;

        Ok(transaction)
    }

    async fn decrease_remaining_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        ticket_type: &TicketType,
    ) -> Result<TicketType> {
        if let Some(remaining) = ticket_type.remaining {
            if remaining > 0 {
                let row = sqlx::query!(
                    r#"
                    UPDATE ticket_types
                    SET remaining = remaining - 1, updated_at = $1
                    WHERE id = $2
                    RETURNING *
                    "#,
                    Utc::now(),
                    ticket_type.id
                )
                .fetch_one(&mut **tx)
                .await?;

                let updated_ticket_type = TicketType {
                    id: row.id,
                    event_id: row.event_id,
                    name: row.name,
                    description: row.description,
                    price: row.price,
                    currency: row.currency.expect("Currency should have a default value"),
                    total_supply: row.total_supply,
                    remaining: row.remaining,
                    is_active: row.is_active,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                };

                return Ok(updated_ticket_type);
            }
        }

        Err(anyhow!("No tickets remaining"))
    }

    async fn update_ticket_status_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        ticket: &Ticket,
        status: &str,
    ) -> Result<Ticket> {
        let row = sqlx::query!(
            r#"
            UPDATE tickets
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            status,
            Utc::now(),
            ticket.id
        )
        .fetch_one(&mut **tx)
        .await?;

        let ticket = Ticket {
            id: row.id,
            ticket_type_id: row.ticket_type_id,
            owner_id: row.owner_id,
            status: row.status,
            qr_code: row.qr_code,
            nft_identifier: row.nft_identifier,
            created_at: row.created_at,
            updated_at: row.updated_at,
            checked_in_at: row.checked_in_at,
            checked_in_by: row.checked_in_by,
            pdf_url: row.pdf_url,
        };

        Ok(ticket)
    }

    #[allow(unused_variables)]
    async fn process_payment(
        &self,
        user: &User,
        ticket_type: &TicketType,
        transaction: &Transaction,
    ) -> Result<String> {
        let platform_wallet = env::var("PLATFORM_WALLET_PUBLIC_KEY")
            .map_err(|_| anyhow!("Platform wallet not configured"))?;

        // Get the user's secret key for payment
        // TODO: research secure ways to handle this
        let user_secret_key = user
            .stellar_secret_key
            .clone()
            .ok_or_else(|| anyhow!("User has no Stellar wallet"))?;

        let amount = transaction.amount.to_string();
        let tx_hash = self
            .stellar_service
            .send_payment(&user_secret_key, &platform_wallet, &amount)
            .await?;

        Ok(tx_hash)
    }

    fn generate_qr_code(&self, data: &str) -> Result<String> {
        let code = QrCode::new(data.as_bytes())?;

        let svg_string = code
            .render()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        let encoded = general_purpose::STANDARD.encode(svg_string);

        Ok(encoded)
    }

    fn generate_random_receipt_suffix(&self) -> String {
        use rand::distr::Alphanumeric;
        use rand::{rng, Rng};

        rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect()
    }

    pub async fn verify_ticket(&self, ticket_id: Uuid) -> Result<bool> {
        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        if ticket.status != "valid" {
            return Ok(false);
        }

        if let Some(nft_id) = &ticket.nft_identifier {
            let owner = User::find_by_id(&self.pool, ticket.owner_id)
                .await?
                .ok_or_else(|| anyhow!("Ticket owner not found"))?;

            let issuer_public_key = env::var("NFT_ISSUER_PUBLIC_KEY")
                .map_err(|_| anyhow!("NFT issuer not configured"))?;

            if let Some(public_key) = &owner.stellar_public_key {
                let is_valid = self
                    .stellar_service
                    .verify_nft_ownership(public_key, nft_id, &issuer_public_key)
                    .await?;

                if !is_valid {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        if let Some(transaction) = Transaction::find_by_ticket(&self.pool, ticket_id).await? {
            if transaction.status != "completed" {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub async fn check_in_ticket(&self, ticket_id: Uuid, staff_id: Uuid) -> Result<Ticket> {
        let is_valid = self.verify_ticket(ticket_id).await?;
        if !is_valid {
            return Err(anyhow!("Ticket is not valid"));
        }

        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        let ticket = ticket.check_in(&self.pool, staff_id).await?;

        Ok(ticket)
    }

    pub async fn generate_pdf_ticket(&self, ticket_id: Uuid) -> Result<String> {
        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        let ticket_type = TicketType::find_by_id(&self.pool, ticket.ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        let event = Event::find_by_id(&self.pool, ticket_type.event_id)
            .await?
            .ok_or_else(|| anyhow!("Event not found"))?;

        let owner = User::find_by_id(&self.pool, ticket.owner_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        let pdf_content = self.create_pdf_document(&ticket, &ticket_type, &event, &owner)?;

        let storage_path = format!("tickets/{}/{}.pdf", event.id, ticket.id);
        let pdf_url = self.upload_to_storage(&storage_path, pdf_content).await?;

        #[allow(unused_variables)]
        let updated_ticket = ticket.set_pdf_url(&self.pool, &pdf_url).await?;

        self.send_ticket_email(&owner.email, &pdf_url, &event.title)
            .await?;

        Ok(pdf_url)
    }

    fn create_pdf_document(
        &self,
        ticket: &Ticket,
        ticket_type: &TicketType,
        event: &Event,
        owner: &User,
    ) -> Result<Vec<u8>> {
        // return empty PDF until we can resolve the API issues
        let message = format!("Ticket for {} - Event: {}", owner.username, event.title);

        // return the message as bytes for now
        Ok(message.into_bytes())
    }

    async fn upload_to_storage(&self, path: &str, content: Vec<u8>) -> Result<String> {
        if let Some(client) = &self.s3_client {
            let bucket_name =
                env::var("S3_BUCKET_NAME").map_err(|_| anyhow!("S3_BUCKET_NAME not set"))?;

            client
                .put_object()
                .bucket(&bucket_name)
                .key(path)
                .body(content.into())
                .content_type("application/pdf")
                .send()
                .await?;

            let base_url = env::var("S3_BASE_URL").map_err(|_| anyhow!("S3_BASE_URL not set"))?;

            return Ok(format!("{}/{}/{}", base_url, bucket_name, path));
        } else {
            let storage_dir =
                env::var("LOCAL_STORAGE_DIR").unwrap_or_else(|_| "storage".to_string());

            let path_obj = Path::new(&storage_dir).join(path);
            if let Some(parent) = path_obj.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let mut file = File::create(&path_obj).await?;
            file.write_all(&content).await?;

            let app_url =
                env::var("APP_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

            return Ok(format!("{}/storage/{}", app_url, path));
        }
    }

    async fn send_ticket_email(&self, email: &str, pdf_url: &str, event_title: &str) -> Result<()> {
        let email_body = format!(
            "Thank you for your purchase!\n\n\
            Your ticket for {} is attached.\n\n\
            You can also download your ticket here: {}\n\n\
            Enjoy the event!",
            event_title, pdf_url
        );

        let email = Message::builder()
            .from(
                env::var("EMAIL_FROM")
                    .unwrap_or_else(|_| "tickets@example.com".to_string())
                    .parse()?,
            )
            .to(email.parse()?)
            .subject(format!("Your Ticket for {}", event_title))
            .body(email_body)?;

        // in development, log the email
        if env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
            info!("Would send email with ticket: {}", pdf_url);
            return Ok(());
        }

        // in production, send via SMTP
        let smtp_server = env::var("SMTP_SERVER")?;
        let smtp_username = env::var("SMTP_USERNAME")?;
        let smtp_password = env::var("SMTP_PASSWORD")?;

        let creds = Credentials::new(smtp_username, smtp_password);

        let mailer = SmtpTransport::relay(&smtp_server)?
            .credentials(creds)
            .build();

        mailer.send(&email)?;

        Ok(())
    }

    pub async fn convert_to_nft(&self, ticket_id: Uuid) -> Result<Ticket> {
        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        if ticket.status != "valid" {
            return Err(anyhow!("Only valid tickets can be converted to NFTs"));
        }

        if ticket.nft_identifier.is_some() {
            return Err(anyhow!("Ticket is already an NFT"));
        }

        let ticket_type = TicketType::find_by_id(&self.pool, ticket.ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        let user = User::find_by_id(&self.pool, ticket.owner_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        let issuer_secret_key =
            env::var("NFT_ISSUER_SECRET_KEY").map_err(|_| anyhow!("NFT issuer not configured"))?;

        let asset_code = format!(
            "TKT{}",
            ticket
                .id
                .to_string()
                .replace("-", "")
                .chars()
                .take(12)
                .collect::<String>()
        );

        let user_public_key = user
            .stellar_public_key
            .clone()
            .ok_or_else(|| anyhow!("User has no Stellar wallet"))?;

        let tx_hash = self
            .stellar_service
            .issue_nft_asset(&issuer_secret_key, &asset_code, &user_public_key)
            .await?;

        let updated_ticket = ticket.set_nft_identifier(&self.pool, &asset_code).await?;

        Ok(updated_ticket)
    }

    pub async fn transfer_ticket(&self, ticket_id: Uuid, from_user_id: Uuid, to_user_id: Uuid) -> Result<Ticket> {
    let ticket = Ticket::find_by_id(&self.pool, ticket_id).await?
        .ok_or_else(|| anyhow!("Ticket not found"))?;
    
    if ticket.owner_id != from_user_id {
        return Err(anyhow!("Ticket is not owned by the sender"));
    }
    
    if ticket.status != "valid" {
        return Err(anyhow!("Ticket is not valid for transfer"));
    }
    
    let to_user = User::find_by_id(&self.pool, to_user_id).await?
        .ok_or_else(|| anyhow!("Recipient user not found"))?;
    
    let mut tx = self.pool.begin().await?;
    
    // If it's an NFT ticket, handle on blockchain
    if let Some(nft_id) = &ticket.nft_identifier {
        let from_user = User::find_by_id(&self.pool, from_user_id).await?
            .ok_or_else(|| anyhow!("Sender user not found"))?;
            
        let from_secret = from_user.stellar_secret_key.clone()
            .ok_or_else(|| anyhow!("Sender has no Stellar wallet"))?;
            
        let to_public = to_user.stellar_public_key.clone()
            .ok_or_else(|| anyhow!("Recipient has no Stellar wallet"))?;
            
        let issuer_public_key = env::var("NFT_ISSUER_PUBLIC_KEY")
            .map_err(|_| anyhow!("NFT issuer not configured"))?;
            
        // Transfer the NFT on the blockchain
        self.stellar_service.transfer_nft(
            &from_secret,
            &to_public,
            nft_id,
            &issuer_public_key
        ).await?;
    }
    
    let updated_ticket = ticket.update_owner(&self.pool, to_user_id).await?;
    
    tx.commit().await?;
    
    let ticket_id = ticket_id;
    let pool = self.pool.clone();
    
    // Regenerate PDF for new owner
    tokio::spawn(async move {
        // TODO: implement PDF generation later
        info!("Regenerating PDF for transferred ticket: {}", ticket_id);
        
        // for now just log success or failure
        match Ticket::find_by_id(&pool, ticket_id).await {
            Ok(Some(_)) => info!("PDF ticket regenerated after transfer for ticket: {}", ticket_id),
            Ok(None) => error!("Failed to regenerate PDF: Ticket not found"),
            Err(e) => error!("Failed to regenerate PDF ticket after transfer: {}", e),
        }
    });
    
    Ok(updated_ticket)
    }

    pub async fn cancel_ticket(&self, ticket_id: Uuid, user_id: Uuid) -> Result<Ticket> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query!("SELECT * FROM tickets WHERE id = $1 FOR UPDATE", ticket_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        let ticket = Ticket {
            id: row.id,
            ticket_type_id: row.ticket_type_id,
            owner_id: row.owner_id,
            status: row.status,
            qr_code: row.qr_code,
            nft_identifier: row.nft_identifier,
            created_at: row.created_at,
            updated_at: row.updated_at,
            checked_in_at: row.checked_in_at,
            checked_in_by: row.checked_in_by,
            pdf_url: row.pdf_url,
        };

        if ticket.owner_id != user_id {
            return Err(anyhow!("You don't own this ticket"));
        }

        if ticket.status != "valid" {
            return Err(anyhow!(
                "Ticket cannot be cancelled (status: {})",
                ticket.status
            ));
        }

        let updated_ticket = self
            .update_ticket_status_in_transaction(&mut tx, &ticket, "cancelled")
            .await?;

        let ticket_type = TicketType::find_by_id(&self.pool, ticket.ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        if ticket_type.remaining.is_some() {
            ticket_type.increase_remaining(&self.pool, 1).await?;
        }

        let transaction = Transaction::find_by_ticket(&self.pool, ticket_id).await?;
        if let Some(tx_record) = transaction {
            if tx_record.status == "completed" && tx_record.amount.is_positive() {
                let refund_secret_key = env::var("PLATFORM_REFUND_SECRET_KEY")
                    .map_err(|_| anyhow!("Refund account not configured"))?;

                let user = User::find_by_id(&self.pool, user_id)
                    .await?
                    .ok_or_else(|| anyhow!("User not found"))?;

                let user_public_key = user
                    .stellar_public_key
                    .clone()
                    .ok_or_else(|| anyhow!("User has no Stellar wallet"))?;

                let refund_hash = self
                    .stellar_service
                    .process_refund(
                        &refund_secret_key,
                        &user_public_key,
                        &tx_record.amount.to_string(),
                    )
                    .await?;

                tx_record
                    .process_refund(&self.pool, None, Some("Ticket cancelled".to_string()))
                    .await?;
                tx_record
                    .update_refund_hash(&self.pool, &refund_hash)
                    .await?;
            }
        }

        tx.commit().await?;

        Ok(updated_ticket)
    }

    pub async fn get_user_tickets(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Ticket, TicketType, Event)>> {
        let tickets = Ticket::find_by_owner(&self.pool, user_id).await?;

        let mut result = Vec::new();

        for ticket in tickets {
            let ticket_type = TicketType::find_by_id(&self.pool, ticket.ticket_type_id)
                .await?
                .ok_or_else(|| anyhow!("Ticket type not found for ticket {}", ticket.id))?;

            let event = Event::find_by_id(&self.pool, ticket_type.event_id)
                .await?
                .ok_or_else(|| anyhow!("Event not found for ticket type {}", ticket_type.id))?;

            result.push((ticket, ticket_type, event));
        }

        Ok(result)
    }
}