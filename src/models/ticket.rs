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
    pub checked_in_at: Option<DateTime<Utc>>,
    pub checked_in_by: Option<Uuid>,
    // for ticket pdf
    pub pdf_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CheckInRequest {
    pub ticket_id: Uuid,
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
            INSERT INTO tickets (
                id, ticket_type_id, owner_id, status, qr_code, created_at, updated_at
            )
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
    
    // set PDF URL
    pub async fn set_pdf_url(&self, pool: &PgPool, pdf_url: &str) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET pdf_url = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            pdf_url, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket)
    }
    
    pub async fn check_in(&self, pool: &PgPool, checked_in_by: Uuid) -> Result<Self> {
        if self.status != "valid" {
            anyhow::bail!("Ticket is not valid for check-in (status: {})", self.status);
        }
        
        if self.checked_in_at.is_some() {
            anyhow::bail!("Ticket has already been checked in");
        }
        
        let now = Utc::now();
        
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET 
                status = 'used',
                checked_in_at = $1,
                checked_in_by = $2,
                updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
            now, checked_in_by, now, self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(ticket)
    }
    
    //verify ticket authenticity
    pub async fn verify_authenticity(&self, pool: &PgPool) -> Result<bool> {
        // If the ticket has an NFT identifier, verify it on the blockchain
        if let Some(nft_id) = &self.nft_identifier {
            // inthe future, this would call a service on Stellar
            // to verify the NFT ownership on the blockchain
            
            // but until then, we'll just check that it has a valid format and exists in our database
            let count = sqlx::query!(
                r#"
                SELECT COUNT(*) as count 
                FROM tickets 
                WHERE nft_identifier = $1 AND id = $2
                "#,
                nft_id, self.id
            )
            .fetch_one(pool)
            .await?
            .count
            .unwrap_or(0);
            
            return Ok(count > 0);
        }
        
        // if no NFT, verify by database record only
        let count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count 
            FROM tickets 
            WHERE id = $1 AND status = 'valid'
            "#,
            self.id
        )
        .fetch_one(pool)
        .await?
        .count
        .unwrap_or(0);
        
        Ok(count > 0)
    }
}