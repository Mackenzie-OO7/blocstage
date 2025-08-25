use crate::models::{
    event::Event, ticket::Ticket, ticket_type::TicketType, transaction::Transaction, user::User,
};
use crate::services::stellar::StellarService;
use crate::services::sponsor_manager::SponsorManager;
use crate::services::fee_calculator::FeeCalculator;
use crate::services::payment_orchestrator::PaymentOrchestrator;
use crate::services::storage::StorageService;
use crate::services::pdf_generator::PdfGenerator;
use crate::services::email::EmailService;
use anyhow::{anyhow, Result};
use bigdecimal::{BigDecimal};
use chrono::{DateTime, Utc};
use log::{error, info,};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction as SqlxTransaction};
use uuid::Uuid;

pub struct TicketService {
    pool: PgPool,
    _stellar: StellarService,
    sponsor_manager: SponsorManager,
    fee_calculator: FeeCalculator,
    payment_orchestrator: PaymentOrchestrator,
    storage: StorageService,
    pdf_generator: PdfGenerator,
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
    async fn get_ticket(&self, ticket_id: Uuid) -> Result<Ticket> {
        Ticket::find_by_id(&self.pool, ticket_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket not found"))
    }

    async fn get_ticket_type(&self, ticket_type_id: Uuid) -> Result<TicketType> {
        TicketType::find_by_id(&self.pool, ticket_type_id)
            .await?
            .ok_or_else(|| anyhow!("Ticket type not found"))
    }

    async fn get_event(&self, event_id: Uuid) -> Result<Event> {
        Event::find_by_id(&self.pool, event_id)
            .await?
            .ok_or_else(|| anyhow!("Event not found"))
    }

    async fn get_user(&self, user_id: Uuid) -> Result<User> {
        User::find_by_id(&self.pool, user_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))
    }
    pub async fn new(pool: PgPool) -> Result<Self> {
        let _stellar = StellarService::new()?;
        let sponsor_manager = SponsorManager::new(pool.clone())?;
        let fee_calculator = FeeCalculator::new(pool.clone())?;
        let payment_orchestrator = PaymentOrchestrator::new(
            _stellar.clone(),
            sponsor_manager.clone(),
            fee_calculator.clone(),
        )?;
        let storage = StorageService::new()?;
        let pdf_generator = PdfGenerator::new();
        
        Ok(Self {
            pool,
            _stellar,
            sponsor_manager,
            fee_calculator,
            payment_orchestrator,
            storage,
            pdf_generator,
        })
    }

    pub async fn claim_free_ticket(
        &self,
        ticket_type_id: Uuid,
        user_id: Uuid,
    ) -> Result<Ticket> {
        let (ticket_type, event, _user) = self
            .validate_free_ticket_claim(ticket_type_id, user_id)
            .await?;

        let updated_event = event.update_status_if_needed(&self.pool).await?;

        if !updated_event.can_sell_tickets() {
            return Err(anyhow!(
                "Event status changed - tickets are no longer available"
            ));
        }

        let mut tx = self.pool.begin().await?;

        let updated_ticket_type = self
            .reserve_ticket_in_transaction(&mut tx, &ticket_type)
            .await?;

        let ticket = self
            .create_ticket_in_transaction(
                &mut tx,
                updated_ticket_type.id,
                user_id,
                None,
            )
            .await?;

        let _transaction = self
            .create_free_transaction_record(
                &mut tx,
                ticket.id,
                user_id,
            )
            .await?;

        tx.commit().await?;

        info!(
            "Free ticket claimed successfully: ticket_id={}, user_id={}",
            ticket.id, user_id
        );

        let ticket_service = Self::new(self.pool.clone()).await?;
        let ticket_id = ticket.id;
        tokio::spawn(async move {
            if let Err(e) = ticket_service.generate_pdf_ticket(ticket_id).await {
                error!("Failed to generate PDF for free ticket {}: {}", ticket_id, e);
            }
        });

        Ok(ticket)
    }

    async fn validate_free_ticket_claim(
        &self,
        ticket_type_id: Uuid,
        user_id: Uuid,
    ) -> Result<(TicketType, Event, User)> {
        let ticket_type = self.get_ticket_type(ticket_type_id).await?;

        if !ticket_type.is_free {
            return Err(anyhow!("This ticket type is not free. Use the purchase endpoint instead."));
        }

        if !ticket_type.is_active {
            return Err(anyhow!("This ticket type is no longer available"));
        }

        if let Some(remaining) = ticket_type.remaining {
            if remaining <= 0 {
                return Err(anyhow!("No tickets remaining for this type"));
            }
        }

        let event = self.get_event(ticket_type.event_id).await?;

        if !event.can_sell_tickets() {
            let effective_status = event.get_effective_status();
            match effective_status.as_str() {
                "ended" => {
                    return Err(anyhow!(
                        "Cannot claim tickets for this event as it has already ended on {}",
                        event.end_time.format("%B %d, %Y at %H:%M UTC")
                    ))
                }
                "cancelled" => return Err(anyhow!("This event has been cancelled")),
                "draft" => return Err(anyhow!("This event is not yet available for ticket claims")),
                "ongoing" => {
                    return Err(anyhow!(
                        "Ticket claims have closed. This event is currently ongoing (started at {})",
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

        let user = self.get_user(user_id).await?;

        if let Some(remaining) = ticket_type.remaining {
            if remaining <= 100 {
                let existing_ticket = self.check_user_existing_free_ticket(user_id, event.id).await?;
                if existing_ticket.is_some() {
                    return Err(anyhow!("You already have a free ticket for this event"));
                }
            }
        }

        Ok((ticket_type, event, user))
    }

    async fn create_free_transaction_record<'a>(
        &self,
        tx: &mut SqlxTransaction<'a, Postgres>,
        ticket_id: Uuid,
        user_id: Uuid,
    ) -> Result<Transaction> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let receipt_number = format!(
            "FREE-{}-{}",
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
            id, 
            ticket_id, 
            user_id, 
            BigDecimal::from(0), 
            "FREE", 
            "completed",
            now, 
            now, 
            receipt_number
        )
        .fetch_one(&mut **tx)
        .await?;

        Ok(transaction)
    }

    async fn check_user_existing_free_ticket(&self, user_id: Uuid, event_id: Uuid) -> Result<Option<Uuid>> {
        let result = sqlx::query!(
            r#"
            SELECT t.id
            FROM tickets t
            JOIN ticket_types tt ON t.ticket_type_id = tt.id
            WHERE t.owner_id = $1 
            AND tt.event_id = $2 
            AND tt.is_free = true 
            AND t.status = 'valid'
            LIMIT 1
            "#,
            user_id,
            event_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|row| row.id))
    }

    pub async fn validate_ticket_purchase(
        &self,
        ticket_type_id: Uuid,
        user_id: Uuid,
    ) -> Result<(TicketType, Event, User)> {
        let ticket_type = self.get_ticket_type(ticket_type_id).await?;

        if ticket_type.is_free {
            return Err(anyhow!("This ticket type is free. Use the claim endpoint instead."));
        }

        if !ticket_type.is_purchasable() {
            return Err(anyhow!("This ticket type is not available for purchase"));
        }


        if !ticket_type.is_active {
            return Err(anyhow!("This ticket type is no longer available"));
        }

        if let Some(remaining) = ticket_type.remaining {
            if remaining <= 0 {
                return Err(anyhow!("No tickets remaining for this type"));
            }
        }

        let event = self.get_event(ticket_type.event_id).await?;

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

        let user = self.get_user(user_id).await?;

        if user.stellar_public_key.is_none() || user.stellar_secret_key_encrypted.is_none() {
            return Err(anyhow!(
                "You need to set up a Stellar wallet before purchasing paid tickets"
            ));
        }

        Ok((ticket_type, event, user))
    }

    // for real-time validation
    pub async fn verify_ticket_with_temporal_check(&self, ticket_id: Uuid) -> Result<bool> {
        let ticket = self.get_ticket(ticket_id).await?;

        if ticket.status != "valid" {
            info!(
                "Ticket {} verification failed: status is {}",
                ticket_id, ticket.status
            );
            return Ok(false);
        }

        let ticket_type = self.get_ticket_type(ticket.ticket_type_id).await?;

        let event = self.get_event(ticket_type.event_id).await?;

        if !event.is_valid() {
            let effective_status = event.get_effective_status();
            info!(
                "Ticket {} verification failed: event {} status is {} (effective: {})",
                ticket_id, event.id, event.status, effective_status
            );
            return Ok(false);
        }

        let now = Utc::now();
        if now >= event.end_time {
            info!(
                "Ticket {} verification failed: event ended at {}",
                ticket_id, event.end_time
            );
            return Ok(false);
        }

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
        info!("🎫 Starting ticket purchase with USDC for user: {}", user_id);

        let (ticket_type, event, user) = self
            .validate_ticket_purchase(ticket_type_id, user_id)
            .await?;

        let updated_event = event.update_status_if_needed(&self.pool).await?;

        if !updated_event.can_sell_tickets() {
            return Err(anyhow!(
                "Event status changed - tickets are no longer available"
            ));
        }

        // Calculate fees before starting transaction
        let ticket_price = ticket_type.price.as_ref().unwrap().to_string().parse::<f64>()?;
        let fee_calculation = self.fee_calculator.calculate_sponsorship_fee(ticket_price).await?;

        info!(
            "💰 Fee calculation: {} USDC ticket + {} USDC sponsorship fee = {} USDC total",
            fee_calculation.ticket_price,
            fee_calculation.final_sponsorship_fee,
            fee_calculation.total_user_pays
        );

        let payment_capability = self.payment_orchestrator
            .validate_payment_capability(&user, fee_calculation.total_user_pays)
            .await?;

        if !payment_capability.can_make_payment {
            let error_msg = payment_capability.errors.join("; ");
            error!("Payment validation failed for user {}: {}", user_id, error_msg);
            return Err(anyhow!("Payment validation failed: {}", error_msg));
        }

        let mut tx = self.pool.begin().await?;

        // Reserve ticket
        let updated_ticket_type = self
            .reserve_ticket_in_transaction(&mut tx, &ticket_type)
            .await?;

        // Create ticket
        let ticket = self
            .create_ticket_in_transaction(
                &mut tx,
                updated_ticket_type.id,
                user_id,
                None,
            )
            .await?;

        // Create transaction with fee breakdown
        let transaction = self
            .create_transaction_record_with_fees(
                &mut tx,
                ticket.id,
                user_id,
                BigDecimal::try_from(fee_calculation.ticket_price)
                    .map_err(|e| anyhow!("Invalid ticket price: {}", e))?,
                BigDecimal::try_from(fee_calculation.final_sponsorship_fee)
                    .map_err(|e| anyhow!("Invalid sponsorship fee: {}", e))?,
                "USDC",
                "pending",
            )
            .await?;

        self.fee_calculator.record_fee_calculation_in_tx(&mut tx, transaction.id, &fee_calculation).await?;

        let payment_result = self.payment_orchestrator
            .execute_sponsored_payment(&user, &transaction, &fee_calculation)
            .await
            .map_err(|e| {
                error!("Payment failed for user {}: {}", user_id, e);
                let user_friendly_error = self.payment_orchestrator.format_user_friendly_error(&e);
                anyhow!("{}", user_friendly_error)
            })?;

        let completed_transaction = transaction
            .update_sponsorship_details(
                &mut tx,
                &payment_result.transaction_hash,
                payment_result.gas_fee_xlm,
                &payment_result.sponsor_account_used,
            )
            .await?;

        self.sponsor_manager
            .record_sponsorship_usage(&payment_result.sponsor_account_used, payment_result.gas_fee_xlm)
            .await?;

        tx.commit().await?;

        info!(
            "✅ Ticket purchase completed: {} (tx: {})",
            ticket.id, payment_result.transaction_hash
        );

        let ticket_service = Self::new(self.pool.clone()).await?;
        let ticket_id = ticket.id;
        tokio::spawn(async move {
            if let Err(e) = ticket_service.generate_pdf_ticket(ticket_id).await {
                error!("Failed to generate PDF for purchased ticket {}: {}", ticket_id, e);
            }
        });

        Ok((ticket, completed_transaction))
    }

    async fn create_transaction_record_with_fees(
    &self,
    tx: &mut SqlxTransaction<'_, Postgres>,
    ticket_id: Uuid,
    user_id: Uuid,
    ticket_amount: BigDecimal,
    sponsorship_fee: BigDecimal,
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
                id, ticket_id, user_id, amount, currency, status, 
                transaction_sponsorship_fee, created_at, updated_at, receipt_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
            id,
            ticket_id,
            user_id,
            ticket_amount,
            currency,
            status,
            sponsorship_fee,
            now,
            now,
            receipt_number
        )
        .fetch_one(&mut **tx)
        .await?;

        Ok(transaction)
    }

    

    pub async fn get_purchase_preview(
        &self,
        ticket_type_id: Uuid,
        user_id: Uuid,
    ) -> Result<serde_json::Value> {
        info!("🎫 Getting purchase preview for user: {}", user_id);

        let (ticket_type, _event, user) = self
            .validate_ticket_purchase(ticket_type_id, user_id)
            .await?;

        if ticket_type.is_free {
            return Ok(serde_json::json!({
                "ticket_type": ticket_type.name,
                "price": "Free",
                "total": "Free",
                "currency": "N/A",
                "breakdown": "This is a free ticket - no payment required",
                "payment_capability": {
                    "can_make_payment": true,
                    "has_wallet": true,
                    "has_usdc_trustline": false,
                    "has_sufficient_balance": true
                }
            }));
        }

        let ticket_price = ticket_type.price.as_ref().unwrap().to_string().parse::<f64>()?;

        let payment_preview = self.payment_orchestrator
            .get_payment_preview(&user, ticket_price)
            .await?;

        Ok(serde_json::json!({
            "ticket_type": ticket_type.name,
            "ticket_price": payment_preview.ticket_price,
            "sponsorship_fee": payment_preview.sponsorship_fee,
            "total_amount": payment_preview.total_amount,
            "currency": payment_preview.currency,
            "breakdown": payment_preview.breakdown_text,
            "payment_capability": {
                "can_make_payment": payment_preview.payment_capability.can_make_payment,
                "has_wallet": payment_preview.payment_capability.has_wallet,
                "has_usdc_trustline": payment_preview.payment_capability.has_usdc_trustline,
                "has_sufficient_balance": payment_preview.payment_capability.has_sufficient_balance,
                "usdc_balance": payment_preview.payment_capability.usdc_balance,
                "errors": payment_preview.payment_capability.errors,
                "warnings": payment_preview.payment_capability.warnings
            }
        }))
    }

    pub async fn get_ticket_status_with_context(
        &self,
        ticket_id: Uuid,
    ) -> Result<TicketStatusResponse> {
        let ticket = self.get_ticket(ticket_id).await?;

        let ticket_type = self.get_ticket_type(ticket.ticket_type_id).await?;

        let event = self.get_event(ticket_type.event_id).await?;

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
            is_free: row.is_free,
            price: row.price,
            currency: row.currency,
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
                        is_free: row.is_free,
                        price: row.price,
                        currency: row.currency,
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
                    is_free: row.is_free,
                    price: row.price,
                    currency: row.currency,
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

    // fn generate_qr_code(&self, data: &str) -> Result<String> {
    //     let code = QrCode::new(data.as_bytes())?;

    //     let svg_string = code
    //         .render()
    //         .min_dimensions(200, 200)
    //         .dark_color(svg::Color("#000000"))
    //         .light_color(svg::Color("#ffffff"))
    //         .build();

    //     let encoded = general_purpose::STANDARD.encode(svg_string);

    //     Ok(encoded)
    // }

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
        let ticket = self.get_ticket(ticket_id).await?;

        if ticket.status != "valid" {
            return Ok(false);
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

        let ticket = self.get_ticket(ticket_id).await?;

        let ticket = ticket.check_in(&self.pool, staff_id).await?;

        Ok(ticket)
    }

    pub async fn web_check_in_ticket(&self, ticket_id: Uuid) -> Result<Ticket> {
        let ticket = self.get_ticket(ticket_id).await?;
        let ticket_type = self.get_ticket_type(ticket.ticket_type_id).await?;
        let event = self.get_event(ticket_type.event_id).await?;

        if ticket.status != "valid" {
            return Err(anyhow!("Ticket is not valid for check-in (status: {})", ticket.status));
        }

        if ticket.checked_in_at.is_some() {
            return Err(anyhow!("Ticket has already been used"));
        }

        let now = Utc::now();
        let check_in_opens = event.start_time - chrono::Duration::hours(1);
        
        if now < check_in_opens {
            let opens_in = (check_in_opens - now).num_minutes();
            return Err(anyhow!("Check-in opens {} minutes before event start (in {} minutes)", 60, opens_in));
        }

        if now > event.end_time {
            return Err(anyhow!("Event has already ended"));
        }

        if let Some(transaction) = Transaction::find_by_ticket(&self.pool, ticket_id).await? {
            if transaction.status != "completed" {
                return Err(anyhow!("Ticket payment is not completed"));
            }
        }

        let system_user_id = Uuid::nil(); // You might want to create a system user ID
        let checked_in_ticket = ticket.check_in(&self.pool, system_user_id).await?;

        info!("✅ Web check-in successful for ticket: {}", ticket_id);
        Ok(checked_in_ticket)
    }

    pub async fn generate_pdf_ticket(&self, ticket_id: Uuid) -> Result<String> {
        let ticket = self.get_ticket(ticket_id).await?;
        let ticket_type = self.get_ticket_type(ticket.ticket_type_id).await?;
        let event = self.get_event(ticket_type.event_id).await?;
        let owner = self.get_user(ticket.owner_id).await?;

        let pdf_content = self.pdf_generator.generate_ticket_pdf(
            &ticket, 
            &ticket_type, 
            &event, 
            &owner
        )?;

        let storage_path = format!("tickets/{}/{}.html", event.id, ticket.id);
        let pdf_url = self.storage.upload_pdf(&storage_path, pdf_content.clone()).await?;

        let _updated_ticket = ticket.set_pdf_url(&self.pool, &pdf_url).await?;

        self.send_ticket_email(&owner, &pdf_url, &event.title, pdf_content).await?;

        info!("✅ PDF ticket generated and sent for ticket: {}", ticket_id);
        Ok(pdf_url)
    }

    async fn send_ticket_email(&self, user: &User, _pdf_url: &str, event_title: &str, pdf_content: Vec<u8>) -> Result<()> {
        let email_service = EmailService::global().await?;
        
        let _message_id = email_service.send_ticket_email_with_attachment(
            &user.email,
            &user.first_name,
            event_title,
            pdf_content
        ).await?;
        
        info!("✅ Ticket email with PDF attachment sent using SendGrid template to: {}", user.email);
        Ok(())
    }

     pub async fn transfer_ticket(
        &self,
        ticket_id: Uuid,
        from_user_id: Uuid,
        to_user_id: Uuid,
    ) -> Result<Ticket> {
        let ticket = self.get_ticket(ticket_id).await?;

        if ticket.owner_id != from_user_id {
            return Err(anyhow!("Ticket is not owned by the sender"));
        }

        if ticket.status != "valid" {
            return Err(anyhow!("Ticket is not valid for transfer"));
        }

        let _to_user = self.get_user(to_user_id).await?;

        let tx = self.pool.begin().await?;
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

    pub async fn admin_cancel_ticket(
        &self,
        ticket_id: Uuid,
        admin_id: Uuid,
        reason: String,
    ) -> Result<Ticket> {
        let mut tx = self.pool.begin().await?;

        let ticket = sqlx::query_as!(
            Ticket,
            "SELECT * FROM tickets WHERE id = $1 FOR UPDATE",
            ticket_id
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow!("Ticket not found"))?;

        if ticket.status != "valid" {
            return Err(anyhow!("Ticket cannot be cancelled. Current status: {}", ticket.status));
        }

        let ticket_type = self.get_ticket_type(ticket.ticket_type_id).await?;

        let cancelled_ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets 
            SET status = 'cancelled', updated_at = $1 
            WHERE id = $2
            RETURNING *
            "#,
            Utc::now(),
            ticket_id
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            UPDATE transactions 
            SET status = 'cancelled', updated_at = $1 
            WHERE ticket_id = $2
            "#,
            Utc::now(),
            ticket_id
        )
        .execute(&mut *tx)
        .await?;

        if ticket_type.total_supply.is_some() {
            sqlx::query!(
                r#"
                UPDATE ticket_types 
                SET remaining = remaining + 1, updated_at = $1 
                WHERE id = $2
                "#,
                Utc::now(),
                ticket_type.id
            )
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query!(
            r#"
            INSERT INTO ticket_admin_actions (
                id, ticket_id, admin_id, action_type, reason, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::new_v4(),
            ticket_id,
            admin_id,
            "cancelled",
            reason,
            Utc::now()
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        info!(
            "Admin {} cancelled ticket {} with reason: {}",
            admin_id, ticket_id, reason
        );

        Ok(cancelled_ticket)
    }

    pub async fn get_user_tickets(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Ticket, TicketType, Event)>> {
        let tickets = Ticket::find_by_owner(&self.pool, user_id).await?;

        let mut result = Vec::new();

        for ticket in tickets {
            let ticket_type = self.get_ticket_type(ticket.ticket_type_id).await?;
            let event = self.get_event(ticket_type.event_id).await?;

            result.push((ticket, ticket_type, event));
        }

        Ok(result)
    }
}