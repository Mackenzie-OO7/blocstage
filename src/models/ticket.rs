use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Ticket {
    pub id: Uuid,
    pub ticket_type_id: Uuid,
    pub owner_id: Uuid,
    pub status: String,
    pub qr_code: Option<String>,
    pub nft_identifier: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Ticket {
    pub async fn create(
        pool: &PgPool, 
        ticket_type_id: Uuid, 
        owner_id: Uuid, 
        qr_code: Option<String>
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            INSERT INTO tickets (id, ticket_type_id, owner_id, status, qr_code, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            id, ticket_type_id, owner_id, "valid", qr_code, now, now
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket)
    }
    
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"SELECT * FROM tickets WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(ticket)
    }
    
    pub async fn find_by_owner(pool: &PgPool, owner_id: Uuid) -> Result<Vec<Self>> {
        let tickets = sqlx::query_as!(
            Ticket,
            r#"SELECT * FROM tickets WHERE owner_id = $1"#,
            owner_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(tickets)
    }
    
    pub async fn update_status(&self, pool: &PgPool, status: &str) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            status, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket)
    }
    
    pub async fn update_owner(&self, pool: &PgPool, new_owner_id: Uuid) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET owner_id = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            new_owner_id, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket)
    }
    
    pub async fn set_nft_identifier(&self, pool: &PgPool, nft_identifier: &str) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET nft_identifier = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            nft_identifier, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket)
    }
}