use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use sqlx::types::BigDecimal;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct TicketType {
    pub id: Uuid,
    pub event_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub price: Option<BigDecimal>,  // None == free ticket
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
    pub price: Option<BigDecimal>,
    pub currency: Option<String>,
    pub total_supply: Option<i32>,
}

impl TicketType {
    pub async fn create(pool: &PgPool, event_id: Uuid, ticket_type: CreateTicketTypeRequest) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let result = sqlx::query!(
            r#"
            INSERT INTO ticket_types (
                id, event_id, name, description, price, currency, 
                total_supply, remaining, is_active, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'XLM'), $7, $8, $9, $10, $11)
            RETURNING id, event_id, name, description, price, currency, 
                      total_supply, remaining, is_active, created_at, updated_at
            "#,
            id, event_id, ticket_type.name, ticket_type.description, 
            ticket_type.price, ticket_type.currency, ticket_type.total_supply, 
            ticket_type.total_supply, true, now, now
        )
        .fetch_one(pool)
        .await?;
        
        // TODO: figure out a better way to handle this rather than nanually construct the TicketType from the query result
        Ok(TicketType {
            id: result.id,
            event_id: result.event_id,
            name: result.name,
            description: result.description,
            price: result.price,
            currency: result.currency.expect("Currency should have a default value"),
            total_supply: result.total_supply,
            remaining: result.remaining,
            is_active: result.is_active,
            created_at: result.created_at,
            updated_at: result.updated_at,
        })
    }
    
    pub async fn find_by_event(pool: &PgPool, event_id: Uuid) -> Result<Vec<Self>> {
        let results = sqlx::query!(
            r#"
            SELECT id, event_id, name, description, price, currency, 
                   total_supply, remaining, is_active, created_at, updated_at
            FROM ticket_types WHERE event_id = $1
            "#,
            event_id
        )
        .fetch_all(pool)
        .await?;
        
        // Map query results to TicketType structs
        let ticket_types = results
            .into_iter()
            .map(|r| TicketType {
                id: r.id,
                event_id: r.event_id,
                name: r.name,
                description: r.description,
                price: r.price,
                currency: r.currency.expect("Currency should have a default value"),
                total_supply: r.total_supply,
                remaining: r.remaining,
                is_active: r.is_active,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect();
        
        Ok(ticket_types)
    }
    
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let result = sqlx::query!(
            r#"
            SELECT id, event_id, name, description, price, currency, 
                   total_supply, remaining, is_active, created_at, updated_at
            FROM ticket_types WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await?;
        
        let ticket_type = match result {
            Some(r) => Some(TicketType {
                id: r.id,
                event_id: r.event_id,
                name: r.name,
                description: r.description,
                price: r.price,
                currency: r.currency.expect("Currency should have a default value"),
                total_supply: r.total_supply,
                remaining: r.remaining,
                is_active: r.is_active,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }),
            None => None,
        };
        
        Ok(ticket_type)
    }
    
    pub async fn decrease_remaining(&self, pool: &PgPool) -> Result<Self> {
        if let Some(remaining) = self.remaining {
            if remaining > 0 {
                let result = sqlx::query!(
                    r#"
                    UPDATE ticket_types
                    SET remaining = remaining - 1, updated_at = $1
                    WHERE id = $2
                    RETURNING id, event_id, name, description, price, currency, 
                             total_supply, remaining, is_active, created_at, updated_at
                    "#,
                    Utc::now(), self.id
                )
                .fetch_one(pool)
                .await?;
                
                return Ok(TicketType {
                    id: result.id,
                    event_id: result.event_id,
                    name: result.name,
                    description: result.description,
                    price: result.price,
                    currency: result.currency.expect("Currency should have a default value"),
                    total_supply: result.total_supply,
                    remaining: result.remaining,
                    is_active: result.is_active,
                    created_at: result.created_at,
                    updated_at: result.updated_at,
                });
            }
        }
        
        anyhow::bail!("No tickets remaining")
    }
    
    // for cancellations
    pub async fn increase_remaining(&self, pool: &PgPool, amount: i32) -> Result<Self> {
        // only increase if there's a limit on tickets
        if self.total_supply.is_some() {
            let result = sqlx::query!(
                r#"
                UPDATE ticket_types
                SET remaining = remaining + $1, updated_at = $2
                WHERE id = $3
                RETURNING id, event_id, name, description, price, currency, 
                         total_supply, remaining, is_active, created_at, updated_at
                "#,
                amount, Utc::now(), self.id
            )
            .fetch_one(pool)
            .await?;
            
            return Ok(TicketType {
                id: result.id,
                event_id: result.event_id,
                name: result.name,
                description: result.description,
                price: result.price,
                currency: result.currency.expect("Currency should have a default value"),
                total_supply: result.total_supply,
                remaining: result.remaining,
                is_active: result.is_active,
                created_at: result.created_at,
                updated_at: result.updated_at,
            });
        }
        
        Ok(self.clone())
    }
    
    // activate/deactivate ticket sales
    pub async fn set_active_status(&self, pool: &PgPool, is_active: bool) -> Result<Self> {
        let result = sqlx::query!(
            r#"
            UPDATE ticket_types
            SET is_active = $1, updated_at = $2
            WHERE id = $3
            RETURNING id, event_id, name, description, price, currency, 
                     total_supply, remaining, is_active, created_at, updated_at
            "#,
            is_active, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(TicketType {
            id: result.id,
            event_id: result.event_id,
            name: result.name,
            description: result.description,
            price: result.price,
            currency: result.currency.expect("Currency should have a default value"),
            total_supply: result.total_supply,
            remaining: result.remaining,
            is_active: result.is_active,
            created_at: result.created_at,
            updated_at: result.updated_at,
        })
    }
    
    pub fn is_available(&self) -> bool {
        if !self.is_active {
            return false;
        }
        
        match self.remaining {
            Some(remaining) => remaining > 0,
            None => true  // no remaining count means unlimited tickets
        }
    }
    
    // get formatted price
    pub fn formatted_price(&self) -> String {
        match &self.price {
            Some(price) => format!("{} {}", price, self.currency),
            None => "Free".to_string()
        }
    }
}