use crate::models::{Event, Transaction, User};
use crate::services::stellar::StellarService;
use anyhow::{anyhow, Result};
use bigdecimal::{BigDecimal,};
use chrono::{DateTime, Duration, Utc};
use log::{error, info};
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
        // - Have ended more than 24 hours ago;
        // - and haven't been paid out yet
        let processing_time = Utc::now() - Duration::hours(48);

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
                AND EXISTS (
                    SELECT 1 FROM transactions t
                    JOIN tickets tk ON t.ticket_id = tk.id  
                    JOIN ticket_types tt ON tk.ticket_type_id = tt.id
                    WHERE tt.event_id = events.id AND t.status = 'completed'
                )
            "#,
            processing_time
        )
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();

        for event in events {
            match self.process_single_event_payout(&event).await {
                Ok(tx_hash) => {
                    results.push((event.id, tx_hash.clone()));
                    self.record_event_payout(&event.id, &tx_hash).await?;

                    info!(
                        "✅ Event payout completed: {} (tx: {})",
                        event.title, tx_hash
                    );
                }
                Err(e) => {
                    error!("❌ Failed to process payment for event {}: {}", event.id, e);
                }
            }
        }

        if !results.is_empty() {
            info!("📊 Processed {} event payouts", results.len());
        }

        Ok(results)
    }

    async fn process_single_event_payout(&self, event: &Event) -> Result<String> {
        info!("💰 Processing USDC payout for event: {}", event.title);

        // excluding sponsorship fees
        let total_revenue_usdc = self.calculate_event_revenue_usdc(event.id).await?;

        if total_revenue_usdc <= 0.0 {
            return Err(anyhow!("No revenue to pay out for event {}", event.id));
        }

        let organizer = User::find_by_id(&self.pool, event.organizer_id)
            .await?
            .ok_or_else(|| anyhow!("Organizer not found"))?;

        let organizer_wallet = organizer
            .stellar_public_key
            .ok_or_else(|| anyhow!("Organizer has no Stellar wallet"))?;

        // Verify organizer has USDC trustline
        if !self
            .stellar_service
            .has_usdc_trustline(&organizer_wallet)
            .await?
        {
            return Err(anyhow!(
                "Organizer {} does not have USDC trustline. Cannot process payout.",
                organizer.username
            ));
        }

        let platform_secret_key = env::var("PLATFORM_PAYMENT_SECRET")
            .map_err(|_| anyhow!("Platform payment secret not configured"))?;

        let platform_fee_percentage = env::var("PLATFORM_FEE_PERCENTAGE")
            .unwrap_or_else(|_| "5.0".to_string())
            .parse::<f64>()?;

        let payout_result = self
            .stellar_service
            .send_organizer_payment(
                &platform_secret_key,
                &organizer_wallet,
                total_revenue_usdc,
            )
            .await?;

        let organizer_receives = total_revenue_usdc * (1.0 - platform_fee_percentage / 100.0);
        let platform_keeps = total_revenue_usdc * (platform_fee_percentage / 100.0);

        info!(
            "✅ USDC payout successful: {} USDC revenue → {} USDC to organizer, {} USDC platform fee (tx: {:?})",
            total_revenue_usdc, organizer_receives, platform_keeps, payout_result.transaction_hash
        );

        Ok(payout_result.transaction_hash)
    }

    async fn calculate_event_revenue_usdc(&self, event_id: Uuid) -> Result<f64> {
        let result = sqlx::query!(
            r#"
            SELECT 
                COALESCE(SUM(
                    CASE 
                        WHEN t.transaction_sponsorship_fee IS NOT NULL 
                        THEN t.amount - t.transaction_sponsorship_fee
                        ELSE t.amount
                    END
                ), 0) as revenue
            FROM transactions t
            JOIN tickets tk ON t.ticket_id = tk.id
            JOIN ticket_types tt ON tk.ticket_type_id = tt.id
            WHERE 
                tt.event_id = $1 
                AND t.status = 'completed'
                AND t.currency = 'USDC'
            "#,
            event_id
        )
        .fetch_one(&self.pool)
        .await?;

        let revenue = result
            .revenue
            .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        info!("📊 Event {} revenue: {} USDC", event_id, revenue);
        Ok(revenue)
    }

    async fn record_event_payout(&self, event_id: &Uuid, tx_hash: &str) -> Result<()> {
        let total_revenue = self.calculate_event_revenue_usdc(*event_id).await?;
        let platform_fee_percentage = env::var("PLATFORM_FEE_PERCENTAGE")
            .unwrap_or_else(|_| "5.0".to_string())
            .parse::<f64>()?;
        let organizer_payout = total_revenue * (1.0 - platform_fee_percentage / 100.0);

        sqlx::query!(
            r#"
        INSERT INTO event_payouts (event_id, transaction_hash, amount, paid_at)
        VALUES ($1, $2, $3, NOW())
        "#,
            event_id,
            tx_hash,
            bigdecimal::BigDecimal::try_from(organizer_payout)
                .map_err(|e| anyhow!("Invalid payout amount: {}", e))?
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_event_financial_summary(&self, event_id: Uuid) -> Result<serde_json::Value> {
        // Get total revenue (ticket sales only)
        let ticket_revenue = self.calculate_event_revenue_usdc(event_id).await?;

        // Get total sponsorship fees collected
        let sponsorship_fees = sqlx::query!(
            r#"
            SELECT COALESCE(SUM(t.transaction_sponsorship_fee), 0) as fees
            FROM transactions t
            JOIN tickets tk ON t.ticket_id = tk.id
            JOIN ticket_types tt ON tk.ticket_type_id = tt.id
            WHERE 
                tt.event_id = $1 
                AND t.status = 'completed'
                AND t.transaction_sponsorship_fee IS NOT NULL
            "#,
            event_id
        )
        .fetch_one(&self.pool)
        .await?;

        let sponsorship_fees_total = sponsorship_fees
            .fees
            .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        let ticket_count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM tickets tk
            JOIN ticket_types tt ON tk.ticket_type_id = tt.id  
            JOIN transactions t ON t.ticket_id = tk.id
            WHERE tt.event_id = $1 AND t.status = 'completed'
            "#,
            event_id
        )
        .fetch_one(&self.pool)
        .await?;

        let tickets_sold = ticket_count.count.unwrap_or(0);

        let platform_fee_percentage = env::var("PLATFORM_FEE_PERCENTAGE")
            .unwrap_or_else(|_| "5.0".to_string())
            .parse::<f64>()?;
        let platform_fee = ticket_revenue * (platform_fee_percentage / 100.0);
        let organizer_payout = ticket_revenue - platform_fee;

        // Check if payout has been processed
        let payout_status = sqlx::query!(
            "SELECT transaction_hash FROM event_payouts WHERE event_id = $1",
            event_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(serde_json::json!({
            "event_id": event_id,
            "ticket_revenue": format!("{:.2}", ticket_revenue),
            "sponsorship_fees_collected": format!("{:.2}", sponsorship_fees_total),
            "total_revenue": format!("{:.2}", ticket_revenue + sponsorship_fees_total),
            "tickets_sold": tickets_sold,
            "platform_fee_percentage": platform_fee_percentage,
            "platform_fee_amount": format!("{:.2}", platform_fee),
            "organizer_payout": format!("{:.2}", organizer_payout),
            "currency": "USDC",
            "payout_processed": payout_status.is_some(),
            "payout_transaction": payout_status.map(|p| p.transaction_hash),
            "breakdown": {
                "revenue_sources": {
                    "ticket_sales": format!("{:.2} USDC", ticket_revenue),
                    "sponsorship_fees": format!("{:.2} USDC (kept by platform)", sponsorship_fees_total)
                },
                "distributions": {
                    "organizer_receives": format!("{:.2} USDC ({}% of ticket revenue)", organizer_payout, 100.0 - platform_fee_percentage),
                    "platform_keeps": format!("{:.2} USDC ({}% platform fee + sponsorship fees)", platform_fee + sponsorship_fees_total, platform_fee_percentage)
                }
            }
        }))
    }

    pub async fn get_platform_revenue_summary(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<serde_json::Value> {
        let platform_fee_percentage = env::var("PLATFORM_FEE_PERCENTAGE")
            .unwrap_or_else(|_| "5.0".to_string())
            .parse::<f64>()
            .unwrap_or(5.0);

        // from organizer payouts
        let platform_fees = sqlx::query!(
            r#"
        SELECT 
            COALESCE(SUM(
                (t.amount - COALESCE(t.transaction_sponsorship_fee, 0)) * 
                (CAST($1 AS DECIMAL) / 100.0)
            ), 0) as platform_fees
        FROM transactions t
        WHERE t.created_at BETWEEN $2 AND $3
        AND t.status = 'completed'
        AND t.currency = 'USDC'
        "#,
            BigDecimal::try_from(platform_fee_percentage)
                .map_err(|e| anyhow!("Invalid platform fee percentage: {}", e))?,
            start_date,
            end_date
        )
        .fetch_one(&self.pool)
        .await?;

        // Sponsorship fee revenue
        let sponsorship_fees =
            Transaction::calculate_sponsorship_fees_for_period(&self.pool, start_date, end_date)
                .await?;

        let platform_fee_total = platform_fees
            .platform_fees
            .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        let total_platform_revenue = platform_fee_total + sponsorship_fees;

        let transaction_count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM transactions 
            WHERE created_at BETWEEN $1 AND $2
            AND status = 'completed'
            AND currency = 'USDC'
            "#,
            start_date,
            end_date
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(serde_json::json!({
            "period": {
                "start": start_date,
                "end": end_date
            },
            "revenue_breakdown": {
                "platform_fees": format!("{:.2}", platform_fee_total),
                "sponsorship_fees": format!("{:.2}", sponsorship_fees),
                "total_revenue": format!("{:.2}", total_platform_revenue)
            },
            "metrics": {
                "transactions_processed": transaction_count.count.unwrap_or(0),
                "average_revenue_per_transaction": format!("{:.2}",
                    if transaction_count.count.unwrap_or(0) > 0 {
                        total_platform_revenue / transaction_count.count.unwrap_or(1) as f64
                    } else {
                        0.0
                    }
                )
            },
            "currency": "USDC"
        }))
    }

    pub async fn get_events_pending_payout(&self) -> Result<Vec<serde_json::Value>> {
        let twenty_four_hours_ago = Utc::now() - Duration::hours(24);

        let events = sqlx::query!(
            r#"
            SELECT 
                e.*,
                COUNT(t.id) as ticket_count,
                COALESCE(SUM(
                    CASE 
                        WHEN t.transaction_sponsorship_fee IS NOT NULL 
                        THEN t.amount - t.transaction_sponsorship_fee
                        ELSE t.amount
                    END
                ), 0) as revenue
            FROM events e
            LEFT JOIN ticket_types tt ON e.id = tt.event_id
            LEFT JOIN tickets tk ON tt.id = tk.ticket_type_id
            LEFT JOIN transactions t ON tk.id = t.ticket_id AND t.status = 'completed'
            WHERE 
                e.end_time < $1 
                AND e.status = 'active'
                AND NOT EXISTS (
                    SELECT 1 FROM event_payouts WHERE event_id = e.id
                )
            GROUP BY e.id
            HAVING COUNT(t.id) > 0
            ORDER BY e.end_time DESC
            "#,
            twenty_four_hours_ago
        )
        .fetch_all(&self.pool)
        .await?;

        let mut pending_events = Vec::new();
        for event in events {
            let revenue = event
                .revenue
                .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
                .unwrap_or(0.0);

            let days_since_ended = (Utc::now() - event.end_time).num_days();

            pending_events.push(serde_json::json!({
                "event_id": event.id,
                "title": event.title,
                "organizer_id": event.organizer_id,
                "end_time": event.end_time,
                "tickets_sold": event.ticket_count.unwrap_or(0),
                "revenue": format!("{:.2}", revenue),
                "currency": "USDC",
                "days_since_ended": days_since_ended
            }));
        }

        Ok(pending_events)
    }

    // TODO: add to the scheduler for processing events payouts
}
