// src/services/event_service.rs
use crate::models::{User, Event, Ticket, Transaction};
use crate::services::stellar_service::StellarService;
use sqlx::PgPool;
use uuid::Uuid;
use anyhow::{Result, anyhow};
use chrono::{Utc, DateTime, Duration};
use std::env;
use log::{info, warn, error};
use rust_decimal::Decimal;

pub struct EventService {
    pool: PgPool,
    stellar_service: StellarService,
}

impl EventService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            stellar_service: StellarService::new(),
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
                    results.push((event.id, tx_hash));
                    
                    self.record_event_payout(&event.id, &tx_hash).await?;
                },
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
        
        let organizer = User::find_by_id(&self.pool, event.organizer_id).await?
            .ok_or_else(|| anyhow!("Organizer not found"))?;
            
        let organizer_wallet = organizer.stellar_public_key
            .ok_or_else(|| anyhow!("Organizer has no Stellar wallet"))?;
            
        let platform_secret_key = env::var("PLATFORM_PAYMENT_SECRET")
            .map_err(|_| anyhow!("Platform payment secret not configured"))?;
            
        // TODO: consider not hard-coding this? finalize revenue convo first
        let platform_fee_percentage = 5.0;
        
        let tx_hash = self.stellar_service.pay_event_organizer(
            &platform_secret_key,
            &organizer_wallet,
            total_revenue,
            platform_fee_percentage
        ).await?;
        
        info!("Paid organizer {} for event {}: {} XLM (tx: {})", 
              organizer.username, event.id, total_revenue * 0.95, tx_hash);
              
        Ok(tx_hash)
    }
    
    async fn calculate_event_revenue(&self, event_id: Uuid) -> Result<f64> {
        let total = sqlx::query!(
            r#"
            SELECT SUM(t.amount) as total
            FROM transactions t
            JOIN tickets tk ON t.ticket_i
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
            None => 0.0
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
            event_id, tx_hash
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    // TODO: add this table to the migrations:
    // CREATE TABLE event_payouts (
    //     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    //     event_id UUID NOT NULL REFERENCES events(id),
    //     transaction_hash VARCHAR(255) NOT NULL,
    //     amount DECIMAL(19, 8) NOT NULL,
    //     paid_at TIMESTAMP WITH TIME ZONE NOT NULL,
    //     created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    // );

    // TODO: add the scheduler for processing events payouts
}