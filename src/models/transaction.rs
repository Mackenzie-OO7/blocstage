use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rust_decimal::Decimal;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Transaction {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub user_id: Uuid,
    pub amount: Decimal,
    pub currency: String,
    pub stellar_transaction_hash: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Transaction {
    pub async fn create(
        pool: &PgPool,
        ticket_id: Uuid,
        user_id: Uuid,
        amount: Decimal,
        currency: &str,
        status: &str
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            INSERT INTO transactions (id, ticket_id, user_id, amount, currency, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
            id, ticket_id, user_id, amount, currency, status, now, now
        )
        .fetch_one(pool)
        .await?;
        
        Ok(transaction)
    }
    
    pub async fn update_stellar_hash(&self, pool: &PgPool, hash: &str) -> Result<Self> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET stellar_transaction_hash = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            hash, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(transaction)
    }
    
    pub async fn update_status(&self, pool: &PgPool, status: &str) -> Result<Self> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            status, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(transaction)
    }
    
    pub async fn find_by_ticket(pool: &PgPool, ticket_id: Uuid) -> Result<Option<Self>> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"SELECT * FROM transactions WHERE ticket_id = $1"#,
            ticket_id
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(transaction)
    }
}