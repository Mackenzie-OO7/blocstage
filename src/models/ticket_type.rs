use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rust_decimal::Decimal;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct TicketType {
    pub id: Uuid,
    pub event_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub price: Option<Decimal>,  // None here == free ticket
    pub currency: String,
    pub total_supply: Option<i32>,
    pub remaining: Option<i32>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTicketTypeRequest {
    pub name: String,
    pub description: Option<String>,
    pub price: Option<Decimal>,
    pub currency: Option<String>,
    pub total_supply: Option<i32>,
}

impl TicketType {
    pub async fn create(pool: &PgPool, event_id: Uuid, ticket_type: CreateTicketTypeRequest) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let currency = ticket_type.currency.unwrap_or_else(|| "XLM".to_string());
        
        let ticket_type = sqlx::query_as!(
            TicketType,
            r#"
            INSERT INTO ticket_types (
                id, event_id, name, description, price, currency, 
                total_supply, remaining, is_active, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
            id, event_id, ticket_type.name, ticket_type.description, 
            ticket_type.price, currency, ticket_type.total_supply, 
            ticket_type.total_supply, true, now, now
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket_type)
    }
    
    pub async fn find_by_event(pool: &PgPool, event_id: Uuid) -> Result<Vec<Self>> {
        let ticket_types = sqlx::query_as!(
            TicketType,
            r#"SELECT * FROM ticket_types WHERE event_id = $1"#,
            event_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(ticket_types)
    }
    
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let ticket_type = sqlx::query_as!(
            TicketType,
            r#"SELECT * FROM ticket_types WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(ticket_type)
    }
    
    pub async fn decrease_remaining(&self, pool: &PgPool) -> Result<Self> {
        if let Some(remaining) = self.remaining {
            if remaining > 0 {
                let ticket_type = sqlx::query_as!(
                    TicketType,
                    r#"
                    UPDATE ticket_types
                    SET remaining = remaining - 1, updated_at = $1
                    WHERE id = $2
                    RETURNING *
                    "#,
                    Utc::now(), self.id
                )
                .fetch_one(pool)
                .await?;
                
                return Ok(ticket_type);
            }
        }
        
        anyhow::bail!("No tickets remaining")
    }
}