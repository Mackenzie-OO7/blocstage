// src/services/event_service.rs
use crate::models::{Event, Ticket, Transaction, User};
use crate::services::stellar::StellarService;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use log::{error, info, warn};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

pub struct EventService {
    pool: PgPool,
    stellar_service: StellarService,
}

impl EventService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            stellar_service: StellarService::new().expect("Failed to initialize Stellar service"),
        }
    }

    pub async fn process_event_payments(&self) -> Result<Vec<(Uuid, String)>> {
        // For now, find events that:
        // 1. Have ended more than 24 hours ago
        // 2. Haven't been paid out yet
        let twenty_four_hours_ago = Utc::now() - Duration::hours(24);

        let events = sqlx::query_as!(
            Event,
            r#"
            SELECT * FROM events 
            WHERE 
                end_time < $1 
                AND status = 'active'
                AND NOT EXISTS (
                    SELECT 1 FROM event_payouts WHERE event_id = events.id
                )
            "#,
            twenty_four_hours_ago
        )
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();

        for event in events {
            match self.process_single_event_payment(&event).await {
                Ok(tx_hash) => {
                    results.push((event.id, tx_hash.clone()));
                    self.record_event_payout(&event.id, &tx_hash).await?;
                }
                Err(e) => {
                    error!("Failed to process payment for event {}: {}", event.id, e);
                }
            }
        }

        Ok(results)
    }

    // TODO: implement method to process payout in fiat
    async fn process_single_event_payment(&self, event: &Event) -> Result<String> {
        let total_revenue = self.calculate_event_revenue(event.id).await?;

        let organizer = User::find_by_id(&self.pool, event.organizer_id)
            .await?
            .ok_or_else(|| anyhow!("Organizer not found"))?;

        let organizer_wallet = organizer
            .stellar_public_key
            .ok_or_else(|| anyhow!("Organizer has no Stellar wallet"))?;

        let platform_secret_key = env::var("PLATFORM_PAYMENT_SECRET")
            .map_err(|_| anyhow!("Platform payment secret not configured"))?;

        // TODO: consider not hard-coding this? finalize revenue convo first
        let platform_fee_percentage = 5.0;

        let tx_hash = self
            .stellar_service
            .pay_event_organizer(
                &platform_secret_key,
                &organizer_wallet,
                total_revenue,
                platform_fee_percentage,
            )
            .await?;

        info!(
            "Paid organizer {} for event {}: {} XLM (tx: {})",
            organizer.username,
            event.id,
            total_revenue * 0.95,
            tx_hash
        );

        Ok(tx_hash)
    }

    async fn calculate_event_revenue(&self, event_id: Uuid) -> Result<f64> {
        let total = sqlx::query!(
            r#"
            SELECT SUM(t.amount) as total
            FROM transactions t
            JOIN tickets tk ON t.ticket_id = tk.id
            JOIN ticket_types tt ON tk.ticket_type_id = tt.id
            WHERE 
                tt.event_id = $1 
                AND t.status = 'completed'
            "#,
            event_id
        )
        .fetch_one(&self.pool)
        .await?;

        let total_amount = match total.total {
            Some(amount) => amount.to_f64().unwrap_or(0.0),
            None => 0.0,
        };

        Ok(total_amount)
    }

    async fn record_event_payout(&self, event_id: &Uuid, tx_hash: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO event_payouts (event_id, transaction_hash, amount, paid_at)
            SELECT $1, $2, 
                (SELECT SUM(t.amount) * 0.95
                FROM transactions t
                JOIN tickets tk ON t.ticket_id = tk.id
                JOIN ticket_types tt ON tk.ticket_type_id = tt.id
                WHERE tt.event_id = $1 AND t.status = 'completed'),
                NOW()
            "#,
            event_id,
            tx_hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // TODO: add the scheduler for processing events payouts
}
