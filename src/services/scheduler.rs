use crate::models::event::Event;
use anyhow::Result;
use log::{error, info};
use sqlx::PgPool;
use std::time::Duration;
use tokio::time;

pub struct SchedulerService {
    pool: PgPool,
}

impl SchedulerService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn start_scheduled_tasks(&self) {
        let pool = self.pool.clone();
        
        // Start event status update job (runs every 5 minutes)
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::update_event_statuses(&pool).await {
                    error!("Failed to update event statuses: {}", e);
                }
            }
        });

        info!("Background jobs started successfully");
    }

    /// Update event statuses based on current time
    async fn update_event_statuses(pool: &PgPool) -> Result<()> {
        let updated_count = Event::batch_update_ended_events(pool).await?;
        
        if updated_count > 0 {
            info!("Background job: Updated {} events to 'ended' status", updated_count);
        }
        
        Ok(())
    }

    /// Cleanup old cancelled items (maybe run weekly?)
    pub async fn start_cleanup_tasks(&self) {
        let pool = self.pool.clone();
        
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(604800));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::cleanup_expired_data(&pool).await {
                    error!("Failed to cleanup old cancelled items: {}", e);
                }
            }
        });
    }

    async fn cleanup_expired_data(pool: &PgPool) -> Result<()> {
        // Remove events cancelled more than 30 days ago
        let events_removed = sqlx::query!(
            r#"
            DELETE FROM events 
            WHERE status = 'cancelled' 
            AND updated_at < NOW() - INTERVAL '30 days'
            "#
        )
        .execute(pool)
        .await?
        .rows_affected();

        // Remove tickets cancelled more than 30 days ago
        let tickets_removed = sqlx::query!(
            r#"
            DELETE FROM tickets 
            WHERE status = 'cancelled' 
            AND updated_at < NOW() - INTERVAL '30 days'
            "#
        )
        .execute(pool)
        .await?
        .rows_affected();

        if events_removed > 0 || tickets_removed > 0 {
            info!(
                "Cleanup job: Removed {} old cancelled events and {} old cancelled tickets",
                events_removed, tickets_removed
            );
        }

        Ok(())
    }
}