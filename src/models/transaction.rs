use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgArguments, Arguments};
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
    pub status: String,  // "pending", "completed", "failed", "refunded"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub refund_amount: Option<Decimal>,
    pub refund_transaction_hash: Option<String>,
    pub refund_reason: Option<String>,
    pub refunded_at: Option<DateTime<Utc>>,
    pub receipt_number: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefundRequest {
    pub ticket_id: Uuid,
    pub amount: Option<Decimal>,  // If None, full refund
    pub reason: Option<String>,
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
        
        // Generate a receipt number
        let receipt_number = format!("RCT-{}-{}", now.format("%Y%m%d"), generate_random_receipt_suffix());
        
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            INSERT INTO transactions (
                id, ticket_id, user_id, amount, currency, status, 
                created_at, updated_at, receipt_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
            id, ticket_id, user_id, amount, currency, status, now, now, receipt_number
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
    
    pub async fn find_by_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Self>> {
        let transactions = sqlx::query_as!(
            Transaction,
            r#"
            SELECT * FROM transactions 
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(transactions)
    }
    
    pub async fn process_refund(
        &self, 
        pool: &PgPool, 
        amount: Option<Decimal>, 
        reason: Option<String>
    ) -> Result<Self> {
        // Calculate refund amount (full amount if not specified)
        let refund_amount = amount.unwrap_or(self.amount);
        
        if refund_amount > self.amount {
            anyhow::bail!("Refund amount cannot exceed original transaction amount");
        }
        
        // Ensure transaction can be refunded
        if self.status != "completed" {
            anyhow::bail!("Only completed transactions can be refunded");
        }
        
        if self.refund_amount.is_some() {
            anyhow::bail!("Transaction has already been refunded");
        }
        
        let now = Utc::now();
        
        // Update transaction with refund details
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET 
                status = 'refunded',
                refund_amount = $1,
                refund_reason = $2,
                refunded_at = $3,
                updated_at = $4
            WHERE id = $5
            RETURNING *
            "#,
            refund_amount, reason, now, now, self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(transaction)
    }
    
    pub async fn update_refund_hash(&self, pool: &PgPool, hash: &str) -> Result<Self> {
        // Ensure transaction has been marked for refund
        if self.status != "refunded" {
            anyhow::bail!("Transaction is not marked for refund");
        }
        
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET refund_transaction_hash = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            hash, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(transaction)
    }
    
//     pub async fn search(
//         pool: &PgPool,
//         user_id: Option<Uuid>,
//         status: Option<String>,
//         start_date: Option<DateTime<Utc>>,
//         end_date: Option<DateTime<Utc>>,
//         min_amount: Option<Decimal>,
//         max_amount: Option<Decimal>,
//         limit: Option<i64>,
//         offset: Option<i64>
//     ) -> Result<Vec<Self>> {
//         // Build the dynamic query
//         let mut query = String::from("SELECT * FROM transactions WHERE 1=1");
//         let mut args = PgArguments::default();
//         let mut param_index = 1;
        
//         // Add filters based on provided parameters
//         if let Some(uid) = user_id {
//             query.push_str(&format!(" AND user_id = ${}", param_index));
//             args.add(uid);
//             param_index += 1;
//         }
        
//         if let Some(s) = &status {
//             query.push_str(&format!(" AND status = ${}", param_index));
//             args.add(s);
//             param_index += 1;
//         }
        
//         if let Some(start) = start_date {
//             query.push_str(&format!(" AND created_at >= ${}", param_index));
//             args.add(start);
//             param_index += 1;
//         }
        
//         if let Some(end) = end_date {
//             query.push_str(&format!(" AND created_at <= ${}", param_index));
//             args.add(end);
//             param_index += 1;
//         }
        
//         if let Some(min) = min_amount {
//             query.push_str(&format!(" AND amount >= ${}", param_index));
//             args.add(min);
//             param_index += 1;
//         }
        
//         if let Some(max) = max_amount {
//             query.push_str(&format!(" AND amount <= ${}", param_index));
//             args.add(max);
//             param_index += 1;
//         }
        
//         query.push_str(" ORDER BY created_at DESC");
        
//         if let Some(lim) = limit {
//             query.push_str(&format!(" LIMIT ${}", param_index));
//             args.add(lim);
//             param_index += 1;
//         } else {
//             query.push_str(" LIMIT 100"); // Default limit
//         }
        
//         if let Some(off) = offset {
//             query.push_str(&format!(" OFFSET ${}", param_index));
//             args.add(off);
//         }
        
//         let transactions = sqlx::query_as_with::<_, Transaction, _>(&query, args)
//             .fetch_all(pool)
//             .await
//             .map_err(|e| anyhow::anyhow!("Database error during transaction search: {}", e))?;
        
//         Ok(transactions)
//     }
// }

    // generate a random receipt number suffix
    fn generate_random_receipt_suffix() -> String {
        use rand::{thread_rng, Rng};
        use rand::distributions::Alphanumeric;
        
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        
        rand_string
    }
}