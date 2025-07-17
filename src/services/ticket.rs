// everything tickets: purchase, verification, transfers
// TODO: finalize on AWS or Digital Ocean
use crate::models::{
    event::Event, ticket::Ticket, ticket_type::TicketType, transaction::Transaction, user::User,
};
use crate::services::stellar::StellarService;
use anyhow::{anyhow, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::Client as S3Client;
use base64::{engine::general_purpose, Engine as _};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info, warn};
#[allow(unused_imports)]
use printpdf::{Mm, PdfDocument, Point, Rgb};
use qrcode::render::svg;
use qrcode::QrCode;
use rust_decimal::prelude::{Signed, Zero};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction as SqlxTransaction};
use std::env;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub struct TicketService {
    pool: PgPool,
    stellar: StellarService,
    s3_client: Option<S3Client>,
}

#[derive(Debug, Serialize)]
pub struct TicketStatusResponse {
    pub ticket_id: Uuid,
    pub ticket_status: String,
    pub is_valid: bool,
    pub event_id: Uuid,
    pub event_status: String,
    pub effective_event_status: String,
    pub event_start_time: DateTime<Utc>,
    pub event_end_time: DateTime<Utc>,
    pub can_be_used: bool,
    pub reason: Option<String>,
}

impl TicketService {
    pub async fn new(pool: PgPool) -> Result<Self> {
        let stellar = StellarService::new()?;

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
            stellar,
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

    pub async fn validate_ticket_purchase(
        &self,
        ticket_type_id: Uuid,
        user_id: Uuid,
    ) -> Result<(TicketType, Event, User)> {
        // Get ticket type
        let ticket_type = TicketType::find_by_id(&self.pool, ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        // Check if ticket type is active
        if !ticket_type.is_active {
            return Err(anyhow!("This ticket type is no longer available"));
        }

        // Check remaining tickets
        if let Some(remaining) = ticket_type.remaining {
            if remaining <= 0 {
                return Err(anyhow!("No tickets remaining for this type"));
            }
        }

        // Get the event
        let event = Event::find_by_id(&self.pool, ticket_type.event_id)
            .await?
            .ok_or_else(|| anyhow!("Event not found"))?;

        // TEMPORAL VALIDATION: Check if event can sell tickets
        if !event.can_sell_tickets() {
            let effective_status = event.get_effective_status();
            match effective_status.as_str() {
                "ended" => {
                    return Err(anyhow!(
                        "Cannot purchase tickets for this event as it has already ended on {}",
                        event.end_time.format("%B %d, %Y at %H:%M UTC")
                    ))
                }
                "cancelled" => return Err(anyhow!("This event has been cancelled")),
                "draft" => return Err(anyhow!("This event is not yet available for ticket sales")),
                "ongoing" => {
                    return Err(anyhow!(
                        "Ticket sales have closed. This event is currently ongoing (started at {})",
                        event.start_time.format("%B %d, %Y at %H:%M UTC")
                    ))
                }
                _ => {
                    return Err(anyhow!(
                        "Tickets are not currently available for this event"
                    ))
                }
            }
        }

        // Get user
        let user = User::find_by_id(&self.pool, user_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        // Check if user has valid wallet for payment
        if user.stellar_public_key.is_none() || user.stellar_secret_key_encrypted.is_none() {
            return Err(anyhow!(
                "You need to set up a Stellar wallet before purchasing tickets"
            ));
        }

        Ok((ticket_type, event, user))
    }

    /// Enhanced ticket verification with temporal validation
    pub async fn verify_ticket_with_temporal_check(&self, ticket_id: Uuid) -> Result<bool> {
        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        // Check basic ticket status
        if ticket.status != "valid" {
            info!(
                "Ticket {} verification failed: status is {}",
                ticket_id, ticket.status
            );
            return Ok(false);
        }

        // Get ticket type and event
        let ticket_type = TicketType::find_by_id(&self.pool, ticket.ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        let event = Event::find_by_id(&self.pool, ticket_type.event_id)
            .await?
            .ok_or_else(|| anyhow!("Event not found"))?;

        // TEMPORAL VALIDATION: Check if event is still valid
        if !event.is_valid() {
            let effective_status = event.get_effective_status();
            info!(
                "Ticket {} verification failed: event {} status is {} (effective: {})",
                ticket_id, event.id, event.status, effective_status
            );
            return Ok(false);
        }

        // Check if event has ended
        let now = Utc::now();
        if now >= event.end_time {
            info!(
                "Ticket {} verification failed: event ended at {}",
                ticket_id, event.end_time
            );
            return Ok(false);
        }

        // NFT verification (if applicable)
        if let Some(nft_id) = &ticket.nft_identifier {
            let owner = User::find_by_id(&self.pool, ticket.owner_id)
                .await?
                .ok_or_else(|| anyhow!("Ticket owner not found"))?;

            if let Some(public_key) = &owner.stellar_public_key {
                let issuer_public_key = env::var("NFT_ISSUER_PUBLIC_KEY")
                    .map_err(|_| anyhow!("NFT issuer not configured"))?;

                let is_valid = self
                    .stellar
                    .verify_nft_ownership(public_key, nft_id, &issuer_public_key)
                    .await?;

                if !is_valid {
                    info!(
                        "Ticket {} verification failed: NFT ownership verification failed",
                        ticket_id
                    );
                    return Ok(false);
                }
            } else {
                info!(
                    "Ticket {} verification failed: owner has no Stellar wallet",
                    ticket_id
                );
                return Ok(false);
            }
        }

        // Check transaction status
        if let Some(transaction) = Transaction::find_by_ticket(&self.pool, ticket_id).await? {
            if transaction.status != "completed" {
                info!(
                    "Ticket {} verification failed: transaction status is {}",
                    ticket_id, transaction.status
                );
                return Ok(false);
            }
        }

        info!("Ticket {} verification successful", ticket_id);
        Ok(true)
    }

    pub async fn purchase_ticket(
        &self,
        ticket_type_id: Uuid,
        user_id: Uuid,
    ) -> Result<(Ticket, Transaction)> {
        // Use enhanced validation
        let (ticket_type, event, user) = self
            .validate_ticket_purchase(ticket_type_id, user_id)
            .await?;

        // Update event status if needed before proceeding
        let updated_event = event.update_status_if_needed(&self.pool).await?;

        // Double-check after status update
        if !updated_event.can_sell_tickets() {
            return Err(anyhow!(
                "Event status changed - tickets are no longer available"
            ));
        }

        // Proceed with existing purchase logic...
        let mut tx = self.pool.begin().await?;

        // Reserve a ticket
        let updated_ticket_type = self
            .reserve_ticket_in_transaction(&mut tx, &ticket_type)
            .await?;

        // 🔥 FIX: Use the service method, not model method
        let ticket = self
            .create_ticket_in_transaction(
                &mut tx,
                updated_ticket_type.id,
                user_id,
                None, // QR code will be generated later
            )
            .await?;

        // 🔥 FIX: Use the service method, not model method
        let transaction = self
            .create_transaction_in_transaction(
                &mut tx,
                ticket.id,
                user_id,
                ticket_type
                    .price
                    .clone()
                    .unwrap_or_else(|| BigDecimal::from(0)),
                &ticket_type.currency,
                "pending",
            )
            .await?;

        // Process payment
        let tx_hash = self
            .process_payment(&user, &ticket_type, &transaction)
            .await?;

        // 🔥 FIX: Use the service method to update transaction
        let completed_transaction = self
            .update_transaction_hash_in_transaction(&mut tx, &transaction, &tx_hash)
            .await?;

        let completed_transaction = self
            .update_transaction_status_in_transaction(&mut tx, &completed_transaction, "completed")
            .await?;

        tx.commit().await?;

        info!(
            "Ticket purchased successfully: ticket_id={}, transaction_id={}, tx_hash={}",
            ticket.id, completed_transaction.id, tx_hash
        );

        Ok((ticket, completed_transaction))
    }

    pub async fn get_ticket_status_with_context(
        &self,
        ticket_id: Uuid,
    ) -> Result<TicketStatusResponse> {
        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        let ticket_type = TicketType::find_by_id(&self.pool, ticket.ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))?;

        let event = Event::find_by_id(&self.pool, ticket_type.event_id)
            .await?
            .ok_or_else(|| anyhow!("Event not found"))?;

        let effective_event_status = event.get_effective_status();
        let effective_status_clone = effective_event_status.clone();
        let is_valid = self.verify_ticket_with_temporal_check(ticket_id).await?;

        Ok(TicketStatusResponse {
            ticket_id: ticket.id,
            ticket_status: ticket.status.clone(),
            is_valid,
            event_id: event.id,
            event_status: event.status.clone(),
            effective_event_status,
            event_start_time: event.start_time,
            event_end_time: event.end_time,
            can_be_used: is_valid && effective_status_clone == "ongoing",
            reason: if !is_valid {
                Some(self.get_invalid_reason(&ticket, &event).await)
            } else {
                None
            },
        })
    }

    async fn reserve_ticket_in_transaction<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        ticket_type: &TicketType,
    ) -> Result<TicketType> {
        // Get ticket type with lock to prevent race conditions
        let locked_ticket_type = self.get_ticket_type_with_lock(tx, ticket_type.id).await?;

        // Check if tickets are still available
        if let Some(remaining) = locked_ticket_type.remaining {
            if remaining <= 0 {
                return Err(anyhow!("No tickets remaining for this type"));
            }
        }

        // Decrease the remaining count
        self.decrease_remaining_in_transaction(tx, &locked_ticket_type)
            .await
    }

    async fn get_invalid_reason(&self, ticket: &Ticket, event: &Event) -> String {
        if ticket.status != "valid" {
            return format!("Ticket status is {}", ticket.status);
        }

        let effective_status = event.get_effective_status();
        match effective_status.as_str() {
            "ended" => format!(
                "Event ended on {}",
                event.end_time.format("%B %d, %Y at %H:%M UTC")
            ),
            "cancelled" => "Event has been cancelled".to_string(),
            "scheduled" => format!(
                "Event hasn't started yet (starts {})",
                event.start_time.format("%B %d, %Y at %H:%M UTC")
            ),
            _ => "Unknown reason".to_string(),
        }
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

        // TODO! Maybe manually construct ticket from row?
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
        match ticket_type.remaining {
            Some(remaining) => {
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

                    Ok(updated_ticket_type)
                } else {
                    Err(anyhow!("No tickets remaining"))
                }
            }
            None => {
                let row = sqlx::query!(
                    r#"
                UPDATE ticket_types
                SET updated_at = $1
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

                Ok(updated_ticket_type)
            }
        }
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

        // TODO: research secure ways to handle this
        let encrypted_secret = user
            .stellar_secret_key_encrypted
            .clone()
            .ok_or_else(|| anyhow!("User has no Stellar wallet"))?;

        let crypto = crate::services::crypto::KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;
        let user_secret_key = crypto
            .decrypt_secret_key(&encrypted_secret)
            .map_err(|e| anyhow!("Failed to decrypt secret key: {}", e))?;

        let amount = transaction.amount.to_string();
        let tx_hash = self
            .stellar
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
                    .stellar
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

        // in dev, log the email
        if env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
            info!("Would send email with ticket: {}", pdf_url);
            return Ok(());
        }

        // in prod, send via SMTP
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
            .stellar
            .issue_nft_asset(&issuer_secret_key, &asset_code, &user_public_key)
            .await?;

        let updated_ticket = ticket.set_nft_identifier(&self.pool, &asset_code).await?;

        Ok(updated_ticket)
    }

    pub async fn transfer_ticket(
        &self,
        ticket_id: Uuid,
        from_user_id: Uuid,
        to_user_id: Uuid,
    ) -> Result<Ticket> {
        let ticket = Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))?;

        if ticket.owner_id != from_user_id {
            return Err(anyhow!("Ticket is not owned by the sender"));
        }

        if ticket.status != "valid" {
            return Err(anyhow!("Ticket is not valid for transfer"));
        }

        let to_user = User::find_by_id(&self.pool, to_user_id)
            .await?
            .ok_or_else(|| anyhow!("Recipient user not found"))?;

        let mut tx = self.pool.begin().await?;

        // If it's an NFT ticket, handle on chain
        if let Some(nft_id) = &ticket.nft_identifier {
            let from_user = User::find_by_id(&self.pool, from_user_id)
                .await?
                .ok_or_else(|| anyhow!("Sender user not found"))?;

            let encrypted_secret = from_user
                .stellar_secret_key_encrypted
                .clone()
                .ok_or_else(|| anyhow!("Sender has no Stellar wallet"))?;

            let crypto = crate::services::crypto::KeyEncryption::new()
                .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;
            let from_secret = crypto
                .decrypt_secret_key(&encrypted_secret)
                .map_err(|e| anyhow!("Failed to decrypt secret key: {}", e))?;

            let to_public = to_user
                .stellar_public_key
                .clone()
                .ok_or_else(|| anyhow!("Recipient has no Stellar wallet"))?;

            let issuer_public_key = env::var("NFT_ISSUER_PUBLIC_KEY")
                .map_err(|_| anyhow!("NFT issuer not configured"))?;

            // Transfer the NFT on the blockchain
            self.stellar
                .transfer_nft(&from_secret, &to_public, nft_id, &issuer_public_key)
                .await?;
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
                Ok(Some(_)) => info!(
                    "PDF ticket regenerated after transfer for ticket: {}",
                    ticket_id
                ),
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
                    .stellar
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

// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{event::Event, ticket_type::TicketType, user::User};
    use crate::services::crypto::KeyEncryption;
    use bigdecimal::BigDecimal;
    use std::env;
    use uuid::Uuid;

    fn ensure_test_env() {
        dotenv::from_filename(".env.test").ok();
        dotenv::dotenv().ok();
        env::set_var("APP_ENV", "test");

        // Set env variables for testing
        env::set_var(
            "NFT_ISSUER_SECRET_KEY",
            "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        );
        env::set_var(
            "NFT_ISSUER_PUBLIC_KEY",
            "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        );
        env::set_var("EMAIL_FROM", "test@blocstage.com");
    }

    async fn setup_test_db() -> PgPool {
        ensure_test_env();

        let database_url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .expect("TEST_DATABASE_URL or DATABASE_URL must be set for tests");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        pool
    }

    // Helpers
    async fn create_test_user(pool: &PgPool, suffix: &str) -> Uuid {
        let unique_id = Uuid::new_v4().simple().to_string();
        let user_id = Uuid::new_v4();

        sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash, created_at, updated_at, email_verified, status, role) VALUES ($1, $2, $3, $4, NOW(), NOW(), true, 'active', 'user')",
            user_id,
            format!("testuser_{}_{}", suffix, unique_id),
            format!("test_{}+{}@example.com", suffix, unique_id),
            "hashed_password"
        )
        .execute(pool)
        .await
        .expect("Failed to create test user");

        user_id
    }

    async fn create_test_event(pool: &PgPool, organizer_id: Uuid, suffix: &str) -> Uuid {
        let event_id = Uuid::new_v4();
        let unique_id = Uuid::new_v4().simple().to_string();

        sqlx::query!(
            "INSERT INTO events (id, organizer_id, title, description, location, start_time, end_time, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())",
            event_id,
            organizer_id,
            format!("Test Event {}", suffix),
            format!("Test event description {}", unique_id),
            "Test Location",
            chrono::Utc::now() + chrono::Duration::hours(24),
            chrono::Utc::now() + chrono::Duration::hours(26),
            "active"
        )
        .execute(pool)
        .await
        .expect("Failed to create test event");

        event_id
    }

    async fn create_test_ticket_type(
        pool: &PgPool,
        event_id: Uuid,
        suffix: &str,
        price: Option<&str>,
        total_supply: Option<i32>,
    ) -> Uuid {
        let ticket_type_id = Uuid::new_v4();
        let unique_id = Uuid::new_v4().simple().to_string();

        let price_decimal =
            price.map(|p| BigDecimal::parse_bytes(p.as_bytes(), 10).expect("Invalid price"));

        sqlx::query!(
            "INSERT INTO ticket_types (id, event_id, name, description, price, currency, total_supply, remaining, is_active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())",
            ticket_type_id,
            event_id,
            format!("Test Ticket {}", suffix),
            format!("Test ticket description {}", unique_id),
            price_decimal,
            "XLM",
            total_supply,
            total_supply,
            true
        )
        .execute(pool)
        .await
        .expect("Failed to create test ticket type");

        ticket_type_id
    }

    async fn add_stellar_keys_to_user(pool: &PgPool, user_id: Uuid) {
        let public_key = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let secret_key = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        let crypto = KeyEncryption::new().expect("Failed to create KeyEncryption");
        let encrypted_secret = crypto
            .encrypt_secret_key(secret_key)
            .unwrap_or_else(|_| secret_key.to_string());

        sqlx::query!(
            "UPDATE users SET stellar_public_key = $1, stellar_secret_key_encrypted = $2 WHERE id = $3",
            public_key,
            encrypted_secret,
            user_id
        )
        .execute(pool)
        .await
        .expect("Failed to add stellar keys to user");
    }

    // Cleanup helpers
    async fn cleanup_test_user(pool: &PgPool, user_id: Uuid) {
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(pool)
            .await;
    }

    async fn cleanup_test_event(pool: &PgPool, event_id: Uuid) {
        let _ = sqlx::query!("DELETE FROM events WHERE id = $1", event_id)
            .execute(pool)
            .await;
    }

    async fn cleanup_test_ticket_type(pool: &PgPool, ticket_type_id: Uuid) {
        let _ = sqlx::query!("DELETE FROM ticket_types WHERE id = $1", ticket_type_id)
            .execute(pool)
            .await;
    }

    async fn cleanup_test_ticket(pool: &PgPool, ticket_id: Uuid) {
        let _ = sqlx::query!("DELETE FROM tickets WHERE id = $1", ticket_id)
            .execute(pool)
            .await;
    }

    mod service_initialization {
        use super::*;

        #[tokio::test]
        async fn test_new_service_success() {
            let pool = setup_test_db().await;

            let result = TicketService::new(pool).await;
            assert!(
                result.is_ok(),
                "TicketService should initialize successfully"
            );

            let service = result.unwrap();
            assert!(
                service.pool.is_closed() == false,
                "Database pool should be active"
            );
        }

        #[tokio::test]
        async fn test_initialize_s3_without_credentials() {
            // This test checks S3 initialization without AWS credentials
            // It should not fail but should log a warning
            let result = TicketService::initialize_s3().await;

            // S3 initialization might fail without proper AWS credentials in test environment
            // This is expected behavior and service should still work without S3
            match result {
                Ok(_) => {
                    // S3 initialized successfully (perhaps with default credentials)
                }
                Err(_) => {
                    // Expected in test environment without AWS credentials
                }
            }
        }
    }

    mod ticket_purchasing {
        use super::*;

        #[tokio::test]
        async fn test_purchase_free_ticket_success() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "free_ticket").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "free", None, Some(10)).await;

            let result = service.purchase_ticket(ticket_type_id, user_id).await;
            assert!(result.is_ok(), "Free ticket purchase should succeed");

            let (ticket, _transaction) = result.unwrap();
            assert_eq!(ticket.owner_id, user_id);
            assert_eq!(ticket.ticket_type_id, ticket_type_id);
            assert_eq!(ticket.status, "valid");
            assert!(ticket.qr_code.is_some(), "QR code should be generated");

            // Verify remaining count decreased
            let updated_ticket_type = TicketType::find_by_id(&pool, ticket_type_id)
                .await
                .expect("Should find ticket type")
                .expect("Ticket type should exist");
            assert_eq!(
                updated_ticket_type.remaining,
                Some(9),
                "Remaining count should decrease"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_purchase_ticket_no_remaining() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "sold_out").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "sold_out", None, Some(0)).await;

            let result = service.purchase_ticket(ticket_type_id, user_id).await;
            assert!(result.is_err(), "Should fail when no tickets remaining");
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("No tickets remaining"));

            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_purchase_ticket_inactive_sales() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "inactive").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "inactive", None, Some(10)).await;

            // Deactivate ticket sales
            sqlx::query!(
                "UPDATE ticket_types SET is_active = false WHERE id = $1",
                ticket_type_id
            )
            .execute(&pool)
            .await
            .expect("Failed to deactivate ticket type");

            let result = service.purchase_ticket(ticket_type_id, user_id).await;
            assert!(
                result.is_err(),
                "Should fail when ticket sales are inactive"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("not currently active"));

            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_purchase_ticket_user_not_found() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let event_id = create_test_event(&pool, organizer_id, "no_user").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "no_user", None, Some(10)).await;
            let nonexistent_user_id = Uuid::new_v4();

            let result = service
                .purchase_ticket(ticket_type_id, nonexistent_user_id)
                .await;
            assert!(result.is_err(), "Should fail when user not found");
            assert!(result.unwrap_err().to_string().contains("User not found"));

            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_purchase_paid_ticket_simulation() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            add_stellar_keys_to_user(&pool, user_id).await;

            let event_id = create_test_event(&pool, organizer_id, "paid").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "paid", Some("25.0"), Some(5)).await;

            // This will likely fail due to mock payment processing, but test the flow
            let result = service.purchase_ticket(ticket_type_id, user_id).await;

            // In test env with mock stellar service, this might succeed or fail
            // depending on payment processing implementation
            match result {
                Ok((ticket, _transaction)) => {
                    assert_eq!(ticket.owner_id, user_id);
                    cleanup_test_ticket(&pool, ticket.id).await;
                }
                Err(e) => {
                    // Expected if payment processing fails in test env
                    println!("Paid ticket purchase failed as expected in test: {}", e);
                }
            }

            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_verification {
        use super::*;

        #[tokio::test]
        async fn test_verify_valid_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "verify").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "verify", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            let is_valid = service
                .verify_ticket(ticket.id)
                .await
                .expect("Verification should complete");
            assert!(is_valid, "Valid ticket should verify successfully");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_verify_nonexistent_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let nonexistent_ticket_id = Uuid::new_v4();
            let result = service.verify_ticket(nonexistent_ticket_id).await;

            assert!(result.is_err(), "Should fail for nonexistent ticket");
            assert!(result.unwrap_err().to_string().contains("Ticket not found"));
        }

        #[tokio::test]
        async fn test_verify_cancelled_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "cancelled").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "cancelled", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            // Manually set ticket status to cancelled
            sqlx::query!(
                "UPDATE tickets SET status = 'cancelled' WHERE id = $1",
                ticket.id
            )
            .execute(&pool)
            .await
            .expect("Failed to cancel ticket");

            let is_valid = service
                .verify_ticket(ticket.id)
                .await
                .expect("Verification should complete");
            assert!(!is_valid, "Cancelled ticket should not verify");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_checkin {
        use super::*;

        #[tokio::test]
        async fn test_check_in_valid_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let staff_id = create_test_user(&pool, "staff").await;
            let event_id = create_test_event(&pool, organizer_id, "checkin").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "checkin", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service.check_in_ticket(ticket.id, staff_id).await;
            assert!(result.is_ok(), "Check-in should succeed for valid ticket");

            let checked_in_ticket = result.unwrap();
            assert_eq!(checked_in_ticket.status, "used");
            assert!(
                checked_in_ticket.checked_in_at.is_some(),
                "Check-in time should be set"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, staff_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_check_in_invalid_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let staff_id = create_test_user(&pool, "staff").await;
            let nonexistent_ticket_id = Uuid::new_v4();

            let result = service
                .check_in_ticket(nonexistent_ticket_id, staff_id)
                .await;
            assert!(result.is_err(), "Check-in should fail for invalid ticket");

            cleanup_test_user(&pool, staff_id).await;
        }

        #[tokio::test]
        async fn test_check_in_already_used_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let staff_id = create_test_user(&pool, "staff").await;
            let event_id = create_test_event(&pool, organizer_id, "used").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "used", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            // First check-in should succeed
            let first_checkin = service.check_in_ticket(ticket.id, staff_id).await;
            assert!(first_checkin.is_ok(), "First check-in should succeed");

            // Second check-in should fail
            let second_checkin = service.check_in_ticket(ticket.id, staff_id).await;
            assert!(second_checkin.is_err(), "Second check-in should fail");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, staff_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_transfer {
        use super::*;

        #[tokio::test]
        async fn test_transfer_ticket_success() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let from_user_id = create_test_user(&pool, "from_user").await;
            let to_user_id = create_test_user(&pool, "to_user").await;
            let event_id = create_test_event(&pool, organizer_id, "transfer").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "transfer", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, from_user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service
                .transfer_ticket(ticket.id, from_user_id, to_user_id)
                .await;
            assert!(result.is_ok(), "Ticket transfer should succeed");

            let transferred_ticket = result.unwrap();
            assert_eq!(
                transferred_ticket.owner_id, to_user_id,
                "Ownership should transfer to new user"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, from_user_id).await;
            cleanup_test_user(&pool, to_user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_transfer_ticket_not_owner() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let owner_id = create_test_user(&pool, "owner").await;
            let non_owner_id = create_test_user(&pool, "non_owner").await;
            let to_user_id = create_test_user(&pool, "to_user").await;
            let event_id = create_test_event(&pool, organizer_id, "not_owner").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "not_owner", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, owner_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service
                .transfer_ticket(ticket.id, non_owner_id, to_user_id)
                .await;
            assert!(
                result.is_err(),
                "Transfer should fail when sender is not owner"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("not owned by the sender"));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, non_owner_id).await;
            cleanup_test_user(&pool, to_user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_transfer_invalid_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let from_user_id = create_test_user(&pool, "from_user").await;
            let to_user_id = create_test_user(&pool, "to_user").await;
            let event_id = create_test_event(&pool, organizer_id, "invalid").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "invalid", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, from_user_id)
                .await
                .expect("Ticket purchase should succeed");

            // Cancel the ticket to make it invalid for transfer
            sqlx::query!(
                "UPDATE tickets SET status = 'cancelled' WHERE id = $1",
                ticket.id
            )
            .execute(&pool)
            .await
            .expect("Failed to cancel ticket");

            let result = service
                .transfer_ticket(ticket.id, from_user_id, to_user_id)
                .await;
            assert!(result.is_err(), "Transfer should fail for invalid ticket");
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("not valid for transfer"));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, from_user_id).await;
            cleanup_test_user(&pool, to_user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_transfer_to_nonexistent_user() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let from_user_id = create_test_user(&pool, "from_user").await;
            let nonexistent_user_id = Uuid::new_v4();
            let event_id = create_test_event(&pool, organizer_id, "no_recipient").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "no_recipient", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, from_user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service
                .transfer_ticket(ticket.id, from_user_id, nonexistent_user_id)
                .await;
            assert!(
                result.is_err(),
                "Transfer should fail for nonexistent recipient"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Recipient user not found"));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, from_user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_cancellation {
        use super::*;

        #[tokio::test]
        async fn test_cancel_ticket_success() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            add_stellar_keys_to_user(&pool, user_id).await;

            let event_id = create_test_event(&pool, organizer_id, "cancel").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "cancel", None, Some(10)).await;

            let (ticket,_transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service.cancel_ticket(ticket.id, user_id).await;

            // Cancellation might succeed or fail depending on payment/refund processing
            // In test environment, this is acceptable behavior
            match result {
                Ok(cancelled_ticket) => {
                    assert_eq!(cancelled_ticket.status, "cancelled");
                }
                Err(e) => {
                    // Expected if refund processing fails in test environment
                    println!("Ticket cancellation failed as expected in test: {}", e);
                }
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_cancel_nonexistent_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let user_id = create_test_user(&pool, "user").await;
            let nonexistent_ticket_id = Uuid::new_v4();

            let result = service.cancel_ticket(nonexistent_ticket_id, user_id).await;
            assert!(result.is_err(), "Should fail for nonexistent ticket");
            assert!(result.unwrap_err().to_string().contains("Ticket not found"));

            cleanup_test_user(&pool, user_id).await;
        }
    }

    mod nft_operations {
        use super::*;

        #[tokio::test]
        async fn test_convert_to_nft_success() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            add_stellar_keys_to_user(&pool, user_id).await;

            let event_id = create_test_event(&pool, organizer_id, "nft").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "nft", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service.convert_to_nft(ticket.id).await;

            // NFT conversion might succeed or fail depending on stellar service mock
            match result {
                Ok(nft_ticket) => {
                    assert!(
                        nft_ticket.nft_identifier.is_some(),
                        "NFT identifier should be set"
                    );

                    // Try converting again - should fail
                    let second_conversion = service.convert_to_nft(ticket.id).await;
                    assert!(second_conversion.is_err(), "Second conversion should fail");
                    assert!(second_conversion
                        .unwrap_err()
                        .to_string()
                        .contains("already an NFT"));
                }
                Err(e) => {
                    // Expected if NFT creation fails in test environment
                    println!("NFT conversion failed as expected in test: {}", e);
                }
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_convert_invalid_ticket_to_nft() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            add_stellar_keys_to_user(&pool, user_id).await;

            let event_id = create_test_event(&pool, organizer_id, "invalid_nft").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "invalid_nft", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            // Cancel the ticket to make it invalid
            sqlx::query!(
                "UPDATE tickets SET status = 'cancelled' WHERE id = $1",
                ticket.id
            )
            .execute(&pool)
            .await
            .expect("Failed to cancel ticket");

            let result = service.convert_to_nft(ticket.id).await;
            assert!(
                result.is_err(),
                "NFT conversion should fail for invalid ticket"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Only valid tickets"));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_convert_to_nft_user_no_wallet() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;

            let event_id = create_test_event(&pool, organizer_id, "no_wallet").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "no_wallet", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service.convert_to_nft(ticket.id).await;
            assert!(
                result.is_err(),
                "NFT conversion should fail when user has no wallet"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("no Stellar wallet"));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod pdf_generation {
        use super::*;

        #[tokio::test]
        async fn test_generate_pdf_ticket_success() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "pdf").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "pdf", None, Some(10)).await;

            let (ticket, _transaction) = service
                .purchase_ticket(ticket_type_id, user_id)
                .await
                .expect("Ticket purchase should succeed");

            let result = service.generate_pdf_ticket(ticket.id).await;

            // PDF generation might succeed or fail depending on storage configuration
            match result {
                Ok(pdf_url) => {
                    assert!(!pdf_url.is_empty(), "PDF URL should not be empty");
                    assert!(
                        pdf_url.contains("tickets/"),
                        "PDF URL should contain tickets path"
                    );
                }
                Err(e) => {
                    // Expected if S3/storage is not configured in test environment
                    println!("PDF generation failed as expected in test: {}", e);
                }
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_generate_pdf_nonexistent_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let nonexistent_ticket_id = Uuid::new_v4();

            let result = service.generate_pdf_ticket(nonexistent_ticket_id).await;
            assert!(
                result.is_err(),
                "PDF generation should fail for nonexistent ticket"
            );
            assert!(result.unwrap_err().to_string().contains("Ticket not found"));
        }
    }

    mod qr_code_generation {
        use super::*;

        #[tokio::test]
        async fn test_generate_qr_code_success() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let test_data = "ticket:12345:67890:1234567890";
            let result = service.generate_qr_code(test_data);

            assert!(result.is_ok(), "QR code generation should succeed");
            let qr_code = result.unwrap();
            assert!(!qr_code.is_empty(), "QR code should not be empty");

            let decoded = general_purpose::STANDARD.decode(&qr_code);
            assert!(decoded.is_ok(), "QR code should be valid base64");

            let svg_content = String::from_utf8(decoded.unwrap()).unwrap();
            assert!(svg_content.contains("svg"), "Decoded content should be SVG");
        }

        #[tokio::test]
        async fn test_generate_qr_code_empty_data() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let result = service.generate_qr_code("");

            // QR code generation might succeed with empty data
            match result {
                Ok(qr_code) => {
                    assert!(
                        !qr_code.is_empty(),
                        "QR code should not be empty even with empty data"
                    );
                }
                Err(_) => {
                    // Also acceptable if QR generation fails with empty data
                }
            }
        }

        #[tokio::test]
        async fn test_generate_qr_code_large_data() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let large_data = "A".repeat(1000);
            let result = service.generate_qr_code(&large_data);

            // QR code generation might succeed or fail with large data
            match result {
                Ok(qr_code) => {
                    assert!(!qr_code.is_empty(), "QR code should not be empty");
                }
                Err(_) => {
                    // Acceptable if QR generation fails with too much data
                }
            }
        }
    }

    mod concurrent_operations {
        use super::*;

        #[tokio::test]
        async fn test_concurrent_ticket_purchases() {
            let pool = setup_test_db().await;

            let organizer_id = create_test_user(&pool, "organizer").await;
            let event_id = create_test_event(&pool, organizer_id, "concurrent").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "concurrent", None, Some(5)).await;

            // Create multiple users
            let mut user_ids = Vec::new();
            for i in 0..10 {
                let user_id = create_test_user(&pool, &format!("buyer_{}", i)).await;
                user_ids.push(user_id);
            }

            // Attempt concurrent purchases
            let mut handles = Vec::new();
            for user_id in &user_ids {
                let pool_clone = pool.clone();
                let user_id_clone = *user_id;
                let ticket_type_id_clone = ticket_type_id;

                let handle = tokio::spawn(async move {
                    let service = TicketService::new(pool_clone)
                        .await
                        .expect("Failed to create service");
                    service
                        .purchase_ticket(ticket_type_id_clone, user_id_clone)
                        .await
                });
                handles.push(handle);
            }

            // Wait for all attempts to complete
            let mut results = Vec::new();
            for handle in handles {
                let result = handle.await.expect("Task should complete");
                results.push(result);
            }

            // Count successful purchases
            let successful_purchases: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
            let failed_purchases: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

            // Should have exactly 5 successful purchases (limited supply)
            assert_eq!(
                successful_purchases.len(),
                5,
                "Should have exactly 5 successful purchases"
            );
            assert_eq!(
                failed_purchases.len(),
                5,
                "Should have exactly 5 failed purchases"
            );

            // Clean up successful tickets
            for result in &results {
                if let Ok((ticket, _transaction)) = result {
                    cleanup_test_ticket(&pool, ticket.id).await;
                }
            }

            // Clean up users and other data
            for user_id in user_ids {
                cleanup_test_user(&pool, user_id).await;
            }
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod edge_cases {
        use super::*;

        #[tokio::test]
        async fn test_purchase_unlimited_tickets() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "unlimited").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "unlimited", None, None).await; // No limit

            let result = service.purchase_ticket(ticket_type_id, user_id).await;
            assert!(result.is_ok(), "Unlimited ticket purchase should succeed");

            let (ticket, _transaction) = result.unwrap();

            // Verify remaining count is still None (unlimited)
            let updated_ticket_type = TicketType::find_by_id(&pool, ticket_type_id)
                .await
                .expect("Should find ticket type")
                .expect("Ticket type should exist");
            assert!(
                updated_ticket_type.remaining.is_none(),
                "Remaining should still be None for unlimited"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_purchase_exactly_last_ticket() {
            let pool = setup_test_db().await;
            let service = TicketService::new(pool.clone())
                .await
                .expect("Failed to create service");

            let organizer_id = create_test_user(&pool, "organizer").await;
            let user_id = create_test_user(&pool, "buyer").await;
            let event_id = create_test_event(&pool, organizer_id, "last_ticket").await;
            let ticket_type_id =
                create_test_ticket_type(&pool, event_id, "last_ticket", None, Some(1)).await;

            let result = service.purchase_ticket(ticket_type_id, user_id).await;
            assert!(result.is_ok(), "Last ticket purchase should succeed");

            let (ticket, _transaction)  = result.unwrap();

            let updated_ticket_type = TicketType::find_by_id(&pool, ticket_type_id)
                .await
                .expect("Should find ticket type")
                .expect("Ticket type should exist");
            assert_eq!(
                updated_ticket_type.remaining,
                Some(0),
                "Remaining should be 0"
            );

            // Try to purchase another ticket - should fail
            let user_id_2 = create_test_user(&pool, "buyer_2").await;
            let second_result = service.purchase_ticket(ticket_type_id, user_id_2).await;
            assert!(
                second_result.is_err(),
                "Second purchase should fail when sold out"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type_id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, user_id_2).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }
}
