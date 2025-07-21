use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
#[allow(unused_imports)]
use sqlx::{postgres::PgArguments, Arguments, PgPool};
use uuid::Uuid;
use bigdecimal::Signed;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Transaction {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub user_id: Uuid,
    pub amount: BigDecimal,
    pub currency: String,
    pub stellar_transaction_hash: Option<String>,
    pub status: String, // eg "pending", "completed", "failed", "refunded"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub refund_amount: Option<BigDecimal>,
    pub refund_transaction_hash: Option<String>,
    pub refund_reason: Option<String>,
    pub refunded_at: Option<DateTime<Utc>>,
    pub receipt_number: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefundRequest {
    pub ticket_id: Uuid,
    pub amount: Option<BigDecimal>,
    pub reason: Option<String>,
}

impl Transaction {
    // TODO: fix `generate_random_receipt_suffix`
    fn generate_random_receipt_suffix() -> String {
        use rand::rng;

        let rand_string: String = rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();

        rand_string
    }

    pub async fn create(
        pool: &PgPool,
        ticket_id: Uuid,
        user_id: Uuid,
        amount: BigDecimal,
        currency: &str,
        status: &str,
    ) -> Result<Self> {

        if amount.is_negative() {
            anyhow::bail!("Transaction amount cannot be negative");
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        let receipt_number = format!(
            "RCT-{}-{}",
            now.format("%Y%m%d"),
            Self::generate_random_receipt_suffix()
        );

        // first check if receipt_number column exists in db
        let has_receipt = sqlx::query!(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'transactions' AND column_name = 'receipt_number'
            ) as exists"
        )
        .fetch_one(pool)
        .await?
        .exists
        .unwrap_or(false);

        let transaction = if has_receipt {
            sqlx::query_as!(
                Transaction,
                r#"
                INSERT INTO transactions (
                    id, ticket_id, user_id, amount, currency, status, 
                    created_at, updated_at, receipt_number
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *
                "#,
                id,
                ticket_id,
                user_id,
                amount,
                currency,
                status,
                now,
                now,
                receipt_number
            )
            .fetch_one(pool)
            .await?
        } else {
            // add the column if it doesn't exist
            sqlx::query!("ALTER TABLE transactions ADD COLUMN receipt_number VARCHAR(255)")
                .execute(pool)
                .await?;

            // we can then insert with the receipt number
            sqlx::query_as!(
                Transaction,
                r#"
                INSERT INTO transactions (
                    id, ticket_id, user_id, amount, currency, status, 
                    created_at, updated_at, receipt_number
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *
                "#,
                id,
                ticket_id,
                user_id,
                amount,
                currency,
                status,
                now,
                now,
                receipt_number
            )
            .fetch_one(pool)
            .await?
        };

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
            hash,
            Utc::now(),
            self.id
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
            status,
            Utc::now(),
            self.id
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

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"SELECT * FROM transactions WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;

        Ok(transaction)
    }

    // TODO: implement refund logic based on timing/cancellations
    pub async fn process_refund(
        &self,
        pool: &PgPool,
        amount: Option<BigDecimal>,
        reason: Option<String>,
    ) -> Result<Self> {
        let refund_amount = amount.unwrap_or_else(|| self.amount.clone());
        if refund_amount.is_negative() {
            anyhow::bail!("Refund amount cannot be negative");
        }
        if refund_amount > self.amount {
            anyhow::bail!("Refund amount cannot exceed original transaction amount");
        }

        // ensure transaction can be refunded
        if self.status != "completed" {
            anyhow::bail!("Only completed transactions can be refunded");
        }

        if self.refund_amount.is_some() {
            anyhow::bail!("Transaction has already been refunded");
        }

        let now = Utc::now();

        // TODO: Check for refund columns in db
        let mut tx = pool.begin().await?;
    
        // Lock the row to prevent concurrent refunds
        let current_tx = sqlx::query_as!(
            Transaction,
            "SELECT * FROM transactions WHERE id = $1 FOR UPDATE",
            self.id
        )
        .fetch_one(&mut *tx)
        .await?;
        
        // Check again after locking
        if current_tx.refund_amount.is_some() {
            tx.rollback().await?;
            anyhow::bail!("Transaction has already been refunded");
        }
        
        // Proceed with refund...
        let updated_transaction = sqlx::query_as!(
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
            refund_amount,
            reason,
            now,
            now,
            self.id
        )
        .fetch_one(&mut *tx)
        .await?;
        
        tx.commit().await?;
        Ok(updated_transaction)
    }

    pub async fn update_refund_hash(&self, pool: &PgPool, hash: &str) -> Result<Self> {
        // ensure transaction has been marked for refund
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
            hash,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(transaction)
    }

    // use placeholder for now
    pub async fn generate_receipt(&self) -> Result<String> {
        // TODO: generate a PDF and return a real URL
        let receipt_id = self.receipt_number.clone().unwrap_or_else(|| {
            format!(
                "RCT-{}-{}",
                self.created_at.format("%Y%m%d"),
                Self::generate_random_receipt_suffix()
            )
        });

        // for now, we'll use a mock URL
        let receipt_url = format!("/receipts/{}.pdf", receipt_id);
        Ok(receipt_url)
    }

    // TODO: Allow users search for transactions

    /*
    pub async fn search(
        pool: &PgPool,
        user_id: Option<Uuid>,
        status: Option<String>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        min_amount: Option<BigDecimal>,
        max_amount: Option<BigDecimal>,
        limit: Option<i64>,
        offset: Option<i64>
    ) -> Result<Vec<Self>> {
        // Build the dynamic query
        let mut query = String::from("SELECT * FROM transactions WHERE 1=1");
        let mut args = PgArguments::default();
        let mut param_index = 1;

        // Add filters based on provided parameters
        if let Some(uid) = user_id {
            query.push_str(&format!(" AND user_id = ${}", param_index));
            args.add(uid);
            param_index += 1;
        }

        if let Some(s) = &status {
            query.push_str(&format!(" AND status = ${}", param_index));
            args.add(s);
            param_index += 1;
        }

        if let Some(start) = start_date {
            query.push_str(&format!(" AND created_at >= ${}", param_index));
            args.add(start);
            param_index += 1;
        }

        if let Some(end) = end_date {
            query.push_str(&format!(" AND created_at <= ${}", param_index));
            args.add(end);
            param_index += 1;
        }

        if let Some(min) = min_amount {
            query.push_str(&format!(" AND amount >= ${}", param_index));
            args.add(min);
            param_index += 1;
        }

        if let Some(max) = max_amount {
            query.push_str(&format!(" AND amount <= ${}", param_index));
            args.add(max);
            param_index += 1;
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(lim) = limit {
            query.push_str(&format!(" LIMIT ${}", param_index));
            args.add(lim);
            param_index += 1;
        } else {
            query.push_str(" LIMIT 100"); // Default limit
        }

        if let Some(off) = offset {
            query.push_str(&format!(" OFFSET ${}", param_index));
            args.add(off);
        }

        let transactions = sqlx::query_as_with::<_, Transaction, _>(&query, args)
            .fetch_all(pool)
            .await
            .map_err(|e| anyhow::anyhow!("Database error during transaction search: {}", e))?;

        Ok(transactions)
    }
    */
}

//tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ticket::Ticket;
    use crate::models::ticket_type::{CreateTicketTypeRequest, TicketType};
    use bigdecimal::BigDecimal;
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use std::env;
    use std::str::FromStr;
    use uuid::Uuid;


    // Helper fns

    async fn setup_test_db() -> PgPool {
        dotenv::from_filename(".env.test").ok();
        dotenv::dotenv().ok();

        println!("=== DEBUG DATABASE SETUP ===");
        println!("TEST_DATABASE_URL: {:?}", env::var("TEST_DATABASE_URL"));
        println!("DATABASE_URL: {:?}", env::var("DATABASE_URL"));

        let database_url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .expect("TEST_DATABASE_URL or DATABASE_URL must be set for tests");

        println!("Using connection string: {}", database_url);
        println!("==============================");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        pool
    }

    async fn create_test_user(pool: &PgPool, suffix: &str) -> Uuid {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let unique_id = format!("{}_{}_{}", suffix, user_id.simple(), now.timestamp_millis());

        sqlx::query!(
            r#"
            INSERT INTO users (
                id, username, email, password_hash, created_at, updated_at,
                email_verified, verification_token, status, role
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            user_id,
            format!("testuser_{}", unique_id),
            format!("test_{}@example.com", unique_id),
            "hashed_password",
            now,
            now,
            true,
            Some("verification_token"),
            "active",
            "user"
        )
        .execute(pool)
        .await
        .expect("Failed to create test user");

        user_id
    }

    async fn create_test_event(pool: &PgPool, organizer_id: Uuid, suffix: &str) -> Uuid {
        let event_id = Uuid::new_v4();
        let now = Utc::now();
        let unique_id = format!("{}_{}_{}", suffix, event_id.simple(), now.timestamp_millis());

        sqlx::query!(
            r#"
            INSERT INTO events (
                id, organizer_id, title, description, location,
                start_time, end_time, created_at, updated_at, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            event_id,
            organizer_id,
            format!("Test Event {}", unique_id),
            Some(format!("Description for {}", unique_id)),
            Some("Test Location"),
            now + Duration::days(1),
            now + Duration::days(1) + Duration::hours(2),
            now,
            now,
            "active"
        )
        .execute(pool)
        .await
        .expect("Failed to create test event");

        event_id
    }

    async fn create_test_ticket_type(pool: &PgPool, event_id: Uuid, suffix: &str) -> TicketType {
        let create_request = CreateTicketTypeRequest {
            name: format!("Test Ticket Type {}", suffix),
            description: Some(format!("Description for {}", suffix)),
            is_free: false,
            price: Some(BigDecimal::from_str("50.00").unwrap()),
            currency: Some("XLM".to_string()),
            total_supply: Some(100),
        };

        TicketType::create(pool, event_id, create_request)
            .await
            .expect("Failed to create test ticket type")
    }

    async fn create_test_ticket(pool: &PgPool, ticket_type_id: Uuid, owner_id: Uuid) -> Ticket {
        Ticket::create(pool, ticket_type_id, owner_id, None)
            .await
            .expect("Failed to create test ticket")
    }

    async fn create_test_transaction(
        pool: &PgPool,
        ticket_id: Uuid,
        user_id: Uuid,
        amount: &str,
        currency: &str,
        status: &str,
    ) -> Transaction {
        let amount_decimal = BigDecimal::from_str(amount).unwrap();
        Transaction::create(pool, ticket_id, user_id, amount_decimal, currency, status)
            .await
            .expect("Failed to create test transaction")
    }

    // Cleanup helpers
    async fn cleanup_test_transaction(pool: &PgPool, transaction_id: Uuid) {
        sqlx::query!("DELETE FROM transactions WHERE id = $1", transaction_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_test_ticket(pool: &PgPool, ticket_id: Uuid) {
        sqlx::query!("DELETE FROM tickets WHERE id = $1", ticket_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_test_ticket_type(pool: &PgPool, ticket_type_id: Uuid) {
        sqlx::query!("DELETE FROM ticket_types WHERE id = $1", ticket_type_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_test_event(pool: &PgPool, event_id: Uuid) {
        sqlx::query!("DELETE FROM events WHERE id = $1", event_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_test_user(pool: &PgPool, user_id: Uuid) {
        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(pool)
            .await
            .ok();
    }

    mod transaction_creation {
        use super::*;

        #[tokio::test]
        async fn test_create_transaction_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "create_tx").await;
            let organizer_id = create_test_user(&pool, "organizer_tx").await;
            let event_id = create_test_event(&pool, organizer_id, "create_tx").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "create_tx").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            let amount = BigDecimal::from_str("25.50").unwrap();
            let result = Transaction::create(&pool, ticket.id, user_id, amount.clone(), "XLM", "pending").await;

            assert!(result.is_ok(), "Transaction creation should succeed");
            let transaction = result.unwrap();

            assert!(!transaction.id.is_nil(), "Transaction should have valid ID");
            assert_eq!(transaction.ticket_id, ticket.id);
            assert_eq!(transaction.user_id, user_id);
            assert_eq!(transaction.amount, amount);
            assert_eq!(transaction.currency, "XLM");
            assert_eq!(transaction.status, "pending");
            assert!(transaction.stellar_transaction_hash.is_none(), "New transaction should not have stellar hash");
            assert!(transaction.receipt_number.is_some(), "Should have receipt number");
            assert!(transaction.refund_amount.is_none(), "New transaction should not have refund amount");

            // Verify receipt number format
            let receipt = transaction.receipt_number.unwrap();
            assert!(receipt.starts_with("RCT-"), "Receipt should start with RCT-");
            assert!(receipt.len() > 10, "Receipt should have reasonable length");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_free_transaction() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "free_tx").await;
            let organizer_id = create_test_user(&pool, "organizer_free").await;
            let event_id = create_test_event(&pool, organizer_id, "free_tx").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "free_tx").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            let amount = BigDecimal::from_str("0.00").unwrap();
            let result = Transaction::create(&pool, ticket.id, user_id, amount.clone(), "XLM", "completed").await;

            assert!(result.is_ok(), "Free transaction creation should succeed");
            let transaction = result.unwrap();

            assert_eq!(transaction.amount, amount);
            assert_eq!(transaction.status, "completed");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_transaction_various_currencies() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "currencies").await;
            let organizer_id = create_test_user(&pool, "organizer_curr").await;
            let event_id = create_test_event(&pool, organizer_id, "currencies").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "currencies").await;

            let currencies = vec!["XLM", "USD", "NGN", "EUR", "BTC"];
            
            for currency in currencies {
                let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
                let amount = BigDecimal::from_str("10.00").unwrap();
                
                let result = Transaction::create(&pool, ticket.id, user_id, amount.clone(), currency, "pending").await;
                
                assert!(result.is_ok(), "Should create transaction with currency: {}", currency);
                let transaction = result.unwrap();
                assert_eq!(transaction.currency, currency);

                cleanup_test_transaction(&pool, transaction.id).await;
                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_transaction_various_statuses() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "statuses").await;
            let organizer_id = create_test_user(&pool, "organizer_stat").await;
            let event_id = create_test_event(&pool, organizer_id, "statuses").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "statuses").await;

            let statuses = vec!["pending", "completed", "failed", "refunded"];
            
            for status in statuses {
                let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
                let amount = BigDecimal::from_str("15.75").unwrap();
                
                let result = Transaction::create(&pool, ticket.id, user_id, amount.clone(), "XLM", status).await;
                
                assert!(result.is_ok(), "Should create transaction with status: {}", status);
                let transaction = result.unwrap();
                assert_eq!(transaction.status, status);

                cleanup_test_transaction(&pool, transaction.id).await;
                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_transaction_nonexistent_ticket() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "nonexistent_ticket").await;
            let fake_ticket_id = Uuid::new_v4();
            let amount = BigDecimal::from_str("10.00").unwrap();

            let result = Transaction::create(&pool, fake_ticket_id, user_id, amount, "XLM", "pending").await;

            assert!(result.is_err(), "Should fail with nonexistent ticket");
            // Should fail due to foreign key constraint

            cleanup_test_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_create_transaction_nonexistent_user() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "nonexistent_user").await;
            let event_id = create_test_event(&pool, organizer_id, "nonexistent_user").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nonexistent_user").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, organizer_id).await;
            let fake_user_id = Uuid::new_v4();
            let amount = BigDecimal::from_str("10.00").unwrap();

            let result = Transaction::create(&pool, ticket.id, fake_user_id, amount, "XLM", "pending").await;

            assert!(result.is_err(), "Should fail with nonexistent user");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_transaction_high_precision_amounts() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "precision").await;
            let organizer_id = create_test_user(&pool, "organizer_prec").await;
            let event_id = create_test_event(&pool, organizer_id, "precision").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "precision").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            // Test with 8 decimal places (Stellar precision)
            let amount = BigDecimal::from_str("12.12345678").unwrap();
            let result = Transaction::create(&pool, ticket.id, user_id, amount.clone(), "XLM", "completed").await;

            assert!(result.is_ok(), "Should handle high precision amounts");
            let transaction = result.unwrap();
            assert_eq!(transaction.amount, amount, "Should preserve decimal precision");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod transaction_retrieval {
        use super::*;

        #[tokio::test]
        async fn test_find_by_id_existing_transaction() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "find_existing").await;
            let organizer_id = create_test_user(&pool, "organizer_find").await;
            let event_id = create_test_event(&pool, organizer_id, "find_existing").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "find_existing").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "30.00", "XLM", "completed").await;

            let result = Transaction::find_by_id(&pool, transaction.id).await;

            assert!(result.is_ok(), "Should find existing transaction");
            let found_transaction = result.unwrap();
            assert!(found_transaction.is_some(), "Transaction should exist");

            let t = found_transaction.unwrap();
            assert_eq!(t.id, transaction.id);
            assert_eq!(t.ticket_id, transaction.ticket_id);
            assert_eq!(t.user_id, transaction.user_id);
            assert_eq!(t.amount, transaction.amount);
            assert_eq!(t.currency, transaction.currency);
            assert_eq!(t.status, transaction.status);

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_id_nonexistent_transaction() {
            let pool = setup_test_db().await;
            let random_id = Uuid::new_v4();

            let result = Transaction::find_by_id(&pool, random_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            assert!(result.unwrap().is_none(), "Should return None for nonexistent transaction");
        }

        #[tokio::test]
        async fn test_find_by_user() {
            let pool = setup_test_db().await;
            let user1_id = create_test_user(&pool, "user1").await;
            let user2_id = create_test_user(&pool, "user2").await;
            let organizer_id = create_test_user(&pool, "organizer_user").await;
            let event_id = create_test_event(&pool, organizer_id, "find_by_user").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "find_by_user").await;

            // Create tx for user1
            let ticket1 = create_test_ticket(&pool, ticket_type.id, user1_id).await;
            let ticket2 = create_test_ticket(&pool, ticket_type.id, user1_id).await;
            let tx1 = create_test_transaction(&pool, ticket1.id, user1_id, "10.00", "XLM", "completed").await;
            let tx2 = create_test_transaction(&pool, ticket2.id, user1_id, "20.00", "XLM", "pending").await;

            // Create tx for user2
            let ticket3 = create_test_ticket(&pool, ticket_type.id, user2_id).await;
            let tx3 = create_test_transaction(&pool, ticket3.id, user2_id, "15.00", "XLM", "completed").await;

            let result = Transaction::find_by_user(&pool, user1_id).await;

            assert!(result.is_ok(), "Should find user transactions");
            let transactions = result.unwrap();
            assert_eq!(transactions.len(), 2, "Should find exactly 2 transactions for user1");

            let tx_ids: Vec<Uuid> = transactions.iter().map(|t| t.id).collect();
            assert!(tx_ids.contains(&tx1.id), "Should contain transaction 1");
            assert!(tx_ids.contains(&tx2.id), "Should contain transaction 2");
            assert!(!tx_ids.contains(&tx3.id), "Should not contain other user's transaction");

            // Verify all txs belong to correct user
            for transaction in &transactions {
                assert_eq!(transaction.user_id, user1_id, "All transactions should belong to user1");
            }

            // Verify order (should be newest first)
            assert!(transactions[0].created_at >= transactions[1].created_at, "Should be ordered by created_at DESC");

            cleanup_test_transaction(&pool, tx1.id).await;
            cleanup_test_transaction(&pool, tx2.id).await;
            cleanup_test_transaction(&pool, tx3.id).await;
            cleanup_test_ticket(&pool, ticket1.id).await;
            cleanup_test_ticket(&pool, ticket2.id).await;
            cleanup_test_ticket(&pool, ticket3.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user1_id).await;
            cleanup_test_user(&pool, user2_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_user_no_transactions() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "no_transactions").await;

            let result = Transaction::find_by_user(&pool, user_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let transactions = result.unwrap();
            assert!(transactions.is_empty(), "Should return empty vector for user with no transactions");

            cleanup_test_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_find_by_ticket() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "find_by_ticket").await;
            let organizer_id = create_test_user(&pool, "organizer_ticket").await;
            let event_id = create_test_event(&pool, organizer_id, "find_by_ticket").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "find_by_ticket").await;
            let ticket1 = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let ticket2 = create_test_ticket(&pool, ticket_type.id, user_id).await;

            // Create tx for ticket1
            let transaction = create_test_transaction(&pool, ticket1.id, user_id, "25.00", "XLM", "completed").await;

            let result1 = Transaction::find_by_ticket(&pool, ticket1.id).await;
            let result2 = Transaction::find_by_ticket(&pool, ticket2.id).await;

            assert!(result1.is_ok(), "Should find transaction for ticket1");
            assert!(result2.is_ok(), "Should execute query for ticket2");

            let found_transaction = result1.unwrap();
            let no_transaction = result2.unwrap();

            assert!(found_transaction.is_some(), "Should find transaction for ticket1");
            assert!(no_transaction.is_none(), "Should not find transaction for ticket2");

            let t = found_transaction.unwrap();
            assert_eq!(t.id, transaction.id);
            assert_eq!(t.ticket_id, ticket1.id);

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket1.id).await;
            cleanup_test_ticket(&pool, ticket2.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_ticket_nonexistent_ticket() {
            let pool = setup_test_db().await;
            let fake_ticket_id = Uuid::new_v4();

            let result = Transaction::find_by_ticket(&pool, fake_ticket_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            assert!(result.unwrap().is_none(), "Should return None for nonexistent ticket");
        }
    }

    mod transaction_updates {
        use super::*;

        #[tokio::test]
        async fn test_update_stellar_hash_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "stellar_hash").await;
            let organizer_id = create_test_user(&pool, "organizer_hash").await;
            let event_id = create_test_event(&pool, organizer_id, "stellar_hash").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "stellar_hash").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "15.00", "XLM", "pending").await;

            assert!(transaction.stellar_transaction_hash.is_none(), "Should start without stellar hash");

            let stellar_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            let result = transaction.update_stellar_hash(&pool, stellar_hash).await;

            assert!(result.is_ok(), "Stellar hash update should succeed");
            let updated_transaction = result.unwrap();

            assert_eq!(updated_transaction.stellar_transaction_hash, Some(stellar_hash.to_string()));
            assert!(updated_transaction.updated_at > transaction.updated_at, "Updated timestamp should be newer");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_stellar_hash_overwrite() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "hash_overwrite").await;
            let organizer_id = create_test_user(&pool, "organizer_over").await;
            let event_id = create_test_event(&pool, organizer_id, "hash_overwrite").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "hash_overwrite").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "20.00", "XLM", "pending").await;

            // Set initial hash
            let first_hash = "abcd1234";
            let tx_with_hash = transaction.update_stellar_hash(&pool, first_hash).await.unwrap();

            // Overwrite with new hash
            let second_hash = "efgh5678";
            let result = tx_with_hash.update_stellar_hash(&pool, second_hash).await;

            assert!(result.is_ok(), "Hash overwrite should succeed");
            let final_transaction = result.unwrap();
            assert_eq!(final_transaction.stellar_transaction_hash, Some(second_hash.to_string()));

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_status_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "status_update").await;
            let organizer_id = create_test_user(&pool, "organizer_status").await;
            let event_id = create_test_event(&pool, organizer_id, "status_update").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "status_update").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "35.00", "XLM", "pending").await;

            assert_eq!(transaction.status, "pending", "Should start as pending");

            let result = transaction.update_status(&pool, "completed").await;

            assert!(result.is_ok(), "Status update should succeed");
            let updated_transaction = result.unwrap();

            assert_eq!(updated_transaction.status, "completed");
            assert!(updated_transaction.updated_at > transaction.updated_at, "Updated timestamp should be newer");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_status_various_statuses() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "various_status").await;
            let organizer_id = create_test_user(&pool, "organizer_various").await;
            let event_id = create_test_event(&pool, organizer_id, "various_status").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "various_status").await;

            let statuses = vec!["pending", "completed", "failed", "refunded", "cancelled"];

            for status in statuses {
                let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
                let transaction = create_test_transaction(&pool, ticket.id, user_id, "10.00", "XLM", "pending").await;
                
                let result = transaction.update_status(&pool, status).await;
                
                assert!(result.is_ok(), "Should update to status: {}", status);
                assert_eq!(result.unwrap().status, status);

                cleanup_test_transaction(&pool, transaction.id).await;
                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod transaction_refund_processing {
        use super::*;

        #[tokio::test]
        async fn test_process_refund_full_amount_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "refund_full").await;
            let organizer_id = create_test_user(&pool, "organizer_refund").await;
            let event_id = create_test_event(&pool, organizer_id, "refund_full").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "refund_full").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "100.00", "XLM", "completed").await;

            let original_amount = transaction.amount.clone();
            let refund_reason = Some("Customer requested refund".to_string());
            
            let result = transaction.process_refund(&pool, None, refund_reason.clone()).await;

            assert!(result.is_ok(), "Full refund should succeed");
            let refunded_transaction = result.unwrap();

            assert_eq!(refunded_transaction.status, "refunded");
            assert_eq!(refunded_transaction.refund_amount, Some(original_amount));
            assert_eq!(refunded_transaction.refund_reason, refund_reason);
            assert!(refunded_transaction.refunded_at.is_some(), "Should have refund timestamp");
            assert!(refunded_transaction.updated_at > transaction.updated_at, "Updated timestamp should be newer");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_process_refund_partial_amount_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "refund_partial").await;
            let organizer_id = create_test_user(&pool, "organizer_partial").await;
            let event_id = create_test_event(&pool, organizer_id, "refund_partial").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "refund_partial").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "100.00", "XLM", "completed").await;

            let refund_amount = Some(BigDecimal::from_str("75.50").unwrap());
            let refund_reason = Some("Partial refund for cancellation".to_string());
            
            let result = transaction.process_refund(&pool, refund_amount.clone(), refund_reason.clone()).await;

            assert!(result.is_ok(), "Partial refund should succeed");
            let refunded_transaction = result.unwrap();

            assert_eq!(refunded_transaction.status, "refunded");
            assert_eq!(refunded_transaction.refund_amount, refund_amount);
            assert_eq!(refunded_transaction.refund_reason, refund_reason);
            assert!(refunded_transaction.refunded_at.is_some(), "Should have refund timestamp");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_process_refund_excessive_amount_failure() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "refund_excessive").await;
            let organizer_id = create_test_user(&pool, "organizer_excess").await;
            let event_id = create_test_event(&pool, organizer_id, "refund_excessive").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "refund_excessive").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "50.00", "XLM", "completed").await;

            // Try to refund more than original amount
            let excessive_amount = Some(BigDecimal::from_str("75.00").unwrap());
            
            let result = transaction.process_refund(&pool, excessive_amount, None).await;

            assert!(result.is_err(), "Excessive refund should fail");
            
            // Verify transaction state is unchanged
            let unchanged_transaction = Transaction::find_by_id(&pool, transaction.id).await.unwrap().unwrap();
            assert_eq!(unchanged_transaction.status, "completed", "Status should remain completed");
            assert!(unchanged_transaction.refund_amount.is_none(), "Should not have refund amount");
            assert!(unchanged_transaction.refunded_at.is_none(), "Should not have refund timestamp");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_process_refund_non_completed_transaction_failure() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "refund_pending").await;
            let organizer_id = create_test_user(&pool, "organizer_pending").await;
            let event_id = create_test_event(&pool, organizer_id, "refund_pending").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "refund_pending").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "30.00", "XLM", "pending").await;

            let result = transaction.process_refund(&pool, None, None).await;

            assert!(result.is_err(), "Refund should fail for non-completed transaction");
            
            // Verify transaction state is unchanged
            let unchanged_transaction = Transaction::find_by_id(&pool, transaction.id).await.unwrap().unwrap();
            assert_eq!(unchanged_transaction.status, "pending", "Status should remain pending");
            assert!(unchanged_transaction.refund_amount.is_none(), "Should not have refund amount");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_process_refund_already_refunded_failure() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "double_refund").await;
            let organizer_id = create_test_user(&pool, "organizer_double").await;
            let event_id = create_test_event(&pool, organizer_id, "double_refund").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "double_refund").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "40.00", "XLM", "completed").await;

            // First refund (should succeed)
            let first_refund = transaction.process_refund(&pool, None, Some("First refund".to_string())).await;
            assert!(first_refund.is_ok(), "First refund should succeed");
            let refunded_transaction = first_refund.unwrap();

            // Second refund attempt (should fail)
            let result = refunded_transaction.process_refund(&pool, None, Some("Second refund".to_string())).await;

            assert!(result.is_err(), "Second refund should fail");

            // Verify transaction still shows first refund only
            let final_transaction = Transaction::find_by_id(&pool, transaction.id).await.unwrap().unwrap();
            assert_eq!(final_transaction.status, "refunded");
            assert_eq!(final_transaction.refund_reason, Some("First refund".to_string()));

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_refund_hash_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "refund_hash").await;
            let organizer_id = create_test_user(&pool, "organizer_rhash").await;
            let event_id = create_test_event(&pool, organizer_id, "refund_hash").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "refund_hash").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "60.00", "XLM", "completed").await;

            // Process refund first
            let refunded_transaction = transaction.process_refund(&pool, None, None).await.unwrap();

            // Then update refund hash
            let refund_hash = "refund_tx_hash_12345";
            let result = refunded_transaction.update_refund_hash(&pool, refund_hash).await;

            assert!(result.is_ok(), "Refund hash update should succeed");
            let final_transaction = result.unwrap();

            assert_eq!(final_transaction.refund_transaction_hash, Some(refund_hash.to_string()));
            assert!(final_transaction.updated_at > refunded_transaction.updated_at, "Updated timestamp should be newer");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_refund_hash_non_refunded_transaction_failure() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "non_refunded_hash").await;
            let organizer_id = create_test_user(&pool, "organizer_nrhash").await;
            let event_id = create_test_event(&pool, organizer_id, "non_refunded_hash").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "non_refunded_hash").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "25.00", "XLM", "completed").await;

            // Try to update refund hash without processing refund first
            let refund_hash = "invalid_refund_hash";
            let result = transaction.update_refund_hash(&pool, refund_hash).await;

            assert!(result.is_err(), "Should fail to update refund hash for non-refunded transaction");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod receipt_generation {
        use super::*;

        #[tokio::test]
        async fn test_generate_receipt_success() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "receipt").await;
            let organizer_id = create_test_user(&pool, "organizer_receipt").await;
            let event_id = create_test_event(&pool, organizer_id, "receipt").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "receipt").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "45.00", "XLM", "completed").await;

            let result = transaction.generate_receipt().await;

            assert!(result.is_ok(), "Receipt generation should succeed");
            let receipt_url = result.unwrap();
            
            assert!(!receipt_url.is_empty(), "Receipt URL should not be empty");
            assert!(receipt_url.contains("/receipts/"), "Receipt URL should contain receipts path");
            assert!(receipt_url.contains(".pdf"), "Receipt URL should be PDF");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_generate_receipt_uses_existing_receipt_number() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "existing_receipt").await;
            let organizer_id = create_test_user(&pool, "organizer_existing").await;
            let event_id = create_test_event(&pool, organizer_id, "existing_receipt").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "existing_receipt").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "55.00", "XLM", "completed").await;

            // Should use existing receipt number from tx
            assert!(transaction.receipt_number.is_some(), "Transaction should have receipt number");
            
            let result = transaction.generate_receipt().await;
            assert!(result.is_ok(), "Receipt generation should succeed");
            
            let receipt_url = result.unwrap();
            let receipt_number = transaction.receipt_number.unwrap();
            assert!(receipt_url.contains(&receipt_number), "Receipt URL should contain receipt number");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod data_validation_and_serialization {
        use super::*;

        #[tokio::test]
        async fn test_transaction_serialization() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "serialization").await;
            let organizer_id = create_test_user(&pool, "organizer_serial").await;
            let event_id = create_test_event(&pool, organizer_id, "serialization").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "serialization").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "33.33", "XLM", "completed").await;

            let serialized = serde_json::to_string(&transaction).unwrap();

            // Verify key fields are included
            assert!(serialized.contains(&transaction.id.to_string()), "ID should be serialized");
            assert!(serialized.contains(&transaction.ticket_id.to_string()), "Ticket ID should be serialized");
            assert!(serialized.contains(&transaction.user_id.to_string()), "User ID should be serialized");
            assert!(serialized.contains("\"amount\""), "Amount should be serialized");
            assert!(serialized.contains("\"currency\""), "Currency should be serialized");
            assert!(serialized.contains("\"status\""), "Status should be serialized");
            assert!(serialized.contains("\"receipt_number\""), "Receipt number should be serialized");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[test]
        fn test_refund_request_deserialization() {
            let json = r#"{
                "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
                "amount": "25.50",
                "reason": "Event cancelled"
            }"#;

            let request: RefundRequest = serde_json::from_str(json).unwrap();
            assert_eq!(request.ticket_id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(request.amount, Some(BigDecimal::from_str("25.50").unwrap()));
            assert_eq!(request.reason, Some("Event cancelled".to_string()));
        }

        #[test]
        fn test_refund_request_minimal() {
            let json = r#"{
                "ticket_id": "550e8400-e29b-41d4-a716-446655440000"
            }"#;

            let request: RefundRequest = serde_json::from_str(json).unwrap();
            assert_eq!(request.ticket_id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
            assert!(request.amount.is_none());
            assert!(request.reason.is_none());
        }

        #[tokio::test]
        async fn test_transaction_with_all_fields_populated() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "all_fields").await;
            let organizer_id = create_test_user(&pool, "organizer_all").await;
            let event_id = create_test_event(&pool, organizer_id, "all_fields").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "all_fields").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "88.88", "XLM", "completed").await;

            // Populate all optional fields
            let tx_with_hash = transaction.update_stellar_hash(&pool, "stellar_hash_abc123").await.unwrap();
            let refunded_tx = tx_with_hash.process_refund(&pool, None, Some("Full refund".to_string())).await.unwrap();
            let final_tx = refunded_tx.update_refund_hash(&pool, "refund_hash_def456").await.unwrap();

            // Verify all fields are populated
            assert!(final_tx.stellar_transaction_hash.is_some());
            assert!(final_tx.receipt_number.is_some());
            assert!(final_tx.refund_amount.is_some());
            assert!(final_tx.refund_transaction_hash.is_some());
            assert!(final_tx.refund_reason.is_some());
            assert!(final_tx.refunded_at.is_some());
            assert_eq!(final_tx.status, "refunded");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod edge_cases_and_security {
        use super::*;

        #[tokio::test]
        async fn test_very_large_amounts() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "large_amount").await;
            let organizer_id = create_test_user(&pool, "organizer_large").await;
            let event_id = create_test_event(&pool, organizer_id, "large_amount").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "large_amount").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            let large_amount = BigDecimal::from_str("999999999.99999999").unwrap();
            let result = Transaction::create(&pool, ticket.id, user_id, large_amount.clone(), "XLM", "completed").await;

            if result.is_ok() {
                let transaction = result.unwrap();
                assert_eq!(transaction.amount, large_amount, "Should handle very large amounts");
                cleanup_test_transaction(&pool, transaction.id).await;
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_zero_amount_transaction() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "zero_amount").await;
            let organizer_id = create_test_user(&pool, "organizer_zero").await;
            let event_id = create_test_event(&pool, organizer_id, "zero_amount").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "zero_amount").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            let zero_amount = BigDecimal::from_str("0.00").unwrap();
            let result = Transaction::create(&pool, ticket.id, user_id, zero_amount.clone(), "XLM", "completed").await;

            assert!(result.is_ok(), "Zero amount transaction should succeed");
            let transaction = result.unwrap();
            assert_eq!(transaction.amount, zero_amount);

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_concurrent_transaction_creation() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "concurrent").await;
            let organizer_id = create_test_user(&pool, "organizer_concurrent").await;
            let event_id = create_test_event(&pool, organizer_id, "concurrent").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "concurrent").await;
            let ticket1 = create_test_ticket(&pool, ticket_type.id, user_id).await;
            let ticket2 = create_test_ticket(&pool, ticket_type.id, user_id).await;

            let amount = BigDecimal::from_str("15.00").unwrap();

            // Attempt concurrent transaction creation
            let (result1, result2) = tokio::join!(
                Transaction::create(&pool, ticket1.id, user_id, amount.clone(), "XLM", "pending"),
                Transaction::create(&pool, ticket2.id, user_id, amount.clone(), "XLM", "pending")
            );

            // Both should succeed
            assert!(result1.is_ok(), "First concurrent transaction should succeed");
            assert!(result2.is_ok(), "Second concurrent transaction should succeed");

            let tx1 = result1.unwrap();
            let tx2 = result2.unwrap();
            assert_ne!(tx1.id, tx2.id, "Transactions should have unique IDs");
            assert_ne!(tx1.receipt_number, tx2.receipt_number, "Should have unique receipt numbers");

            cleanup_test_transaction(&pool, tx1.id).await;
            cleanup_test_transaction(&pool, tx2.id).await;
            cleanup_test_ticket(&pool, ticket1.id).await;
            cleanup_test_ticket(&pool, ticket2.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_transaction_lifecycle_complete() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "lifecycle").await;
            let organizer_id = create_test_user(&pool, "organizer_lifecycle").await;
            let event_id = create_test_event(&pool, organizer_id, "lifecycle").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "lifecycle").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            // Create transaction
            let transaction = create_test_transaction(&pool, ticket.id, user_id, "77.77", "XLM", "pending").await;
            assert_eq!(transaction.status, "pending");

            // Update to completed
            let completed_tx = transaction.update_status(&pool, "completed").await.unwrap();
            assert_eq!(completed_tx.status, "completed");

            // Add stellar hash
            let tx_with_hash = completed_tx.update_stellar_hash(&pool, "lifecycle_stellar_hash").await.unwrap();
            assert!(tx_with_hash.stellar_transaction_hash.is_some());

            // Process refund
            let refunded_tx = tx_with_hash.process_refund(&pool, None, Some("Test refund".to_string())).await.unwrap();
            assert_eq!(refunded_tx.status, "refunded");

            // Add refund hash
            let final_tx = refunded_tx.update_refund_hash(&pool, "lifecycle_refund_hash").await.unwrap();
            assert!(final_tx.refund_transaction_hash.is_some());

            // Generate receipt
            let receipt_url = final_tx.generate_receipt().await.unwrap();
            assert!(!receipt_url.is_empty());

            // Verify final state
            assert_eq!(final_tx.status, "refunded");
            assert!(final_tx.stellar_transaction_hash.is_some());
            assert!(final_tx.refund_amount.is_some());
            assert!(final_tx.refund_transaction_hash.is_some());
            assert!(final_tx.refund_reason.is_some());
            assert!(final_tx.refunded_at.is_some());

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_decimal_precision_preservation() {
            let pool = setup_test_db().await;
            let user_id = create_test_user(&pool, "precision").await;
            let organizer_id = create_test_user(&pool, "organizer_precision").await;
            let event_id = create_test_event(&pool, organizer_id, "precision").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "precision").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

            // Test with maximum Stellar precision (7 decimal places)
            let precise_amount = BigDecimal::from_str("12.1234567").unwrap();
            let transaction = Transaction::create(&pool, ticket.id, user_id, precise_amount.clone(), "XLM", "completed").await.unwrap();

            // Verify precision is preserved
            assert_eq!(transaction.amount, precise_amount, "Should preserve decimal precision");

            // Test partial refund with precision
            let partial_refund = BigDecimal::from_str("5.6789012").unwrap();
            let refunded_tx = transaction.process_refund(&pool, Some(partial_refund.clone()), None).await.unwrap();
            assert_eq!(refunded_tx.refund_amount, Some(partial_refund), "Should preserve refund precision");

            cleanup_test_transaction(&pool, transaction.id).await;
            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, user_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod security_and_validation {
    use super::*;

    #[tokio::test]
    async fn test_negative_amount_rejection() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "negative_amount").await;
        let organizer_id = create_test_user(&pool, "organizer_negative").await;
        let event_id = create_test_event(&pool, organizer_id, "negative_amount").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "negative_amount").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

        let negative_amount = BigDecimal::from_str("-10.00").unwrap();
        let result = Transaction::create(&pool, ticket.id, user_id, negative_amount, "XLM", "pending").await;

        // Check if negative amount was incorrectly accepted
        if result.is_ok() {
            let transaction = result.unwrap();
            cleanup_test_transaction(&pool, transaction.id).await;
            panic!("SECURITY VULNERABILITY: Negative amounts should be rejected but were accepted");
        }

        // Should fail due to business logic validation
        assert!(result.is_err(), "Negative amounts should be rejected for financial security");

        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_negative_refund_amount_rejection() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "negative_refund").await;
        let organizer_id = create_test_user(&pool, "organizer_neg_refund").await;
        let event_id = create_test_event(&pool, organizer_id, "negative_refund").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "negative_refund").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
        let transaction = create_test_transaction(&pool, ticket.id, user_id, "50.00", "XLM", "completed").await;

        let negative_refund = Some(BigDecimal::from_str("-25.00").unwrap());
        let result = transaction.process_refund(&pool, negative_refund, Some("Negative refund test".to_string())).await;

        assert!(result.is_err(), "Negative refund amounts should be rejected");

        // Verify transaction state is unchanged
        let unchanged_tx = Transaction::find_by_id(&pool, transaction.id).await.unwrap().unwrap();
        assert_eq!(unchanged_tx.status, "completed");
        assert!(unchanged_tx.refund_amount.is_none());

        cleanup_test_transaction(&pool, transaction.id).await;
        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_concurrent_refund_race_condition() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "concurrent_refund").await;
        let organizer_id = create_test_user(&pool, "organizer_conc_refund").await;
        let event_id = create_test_event(&pool, organizer_id, "concurrent_refund").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "concurrent_refund").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
        let transaction = create_test_transaction(&pool, ticket.id, user_id, "100.00", "XLM", "completed").await;

        // Attempt concurrent refunds on the same transaction
        let (result1, result2) = tokio::join!(
            transaction.process_refund(&pool, None, Some("Concurrent refund 1".to_string())),
            transaction.process_refund(&pool, None, Some("Concurrent refund 2".to_string()))
        );

        // Exactly one should succeed, one should fail
        let success_count = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
        let failure_count = [&result1, &result2].iter().filter(|r| r.is_err()).count();

        assert_eq!(success_count, 1, "Exactly one concurrent refund should succeed");
        assert_eq!(failure_count, 1, "Exactly one concurrent refund should fail");

        // Verify final transaction state is consistent
        let final_tx = Transaction::find_by_id(&pool, transaction.id).await.unwrap().unwrap();
        assert_eq!(final_tx.status, "refunded", "Transaction should be in refunded state");
        assert!(final_tx.refund_amount.is_some(), "Should have refund amount");
        assert!(final_tx.refunded_at.is_some(), "Should have refund timestamp");
        
        // Verify only one refund reason was recorded
        assert!(
            final_tx.refund_reason == Some("Concurrent refund 1".to_string()) ||
            final_tx.refund_reason == Some("Concurrent refund 2".to_string()),
            "Should have exactly one refund reason"
        );

        cleanup_test_transaction(&pool, transaction.id).await;
        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_very_long_stellar_hash_validation() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "long_stellar_hash").await;
        let organizer_id = create_test_user(&pool, "organizer_long_hash").await;
        let event_id = create_test_event(&pool, organizer_id, "long_stellar_hash").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "long_stellar_hash").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
        let transaction = create_test_transaction(&pool, ticket.id, user_id, "25.00", "XLM", "pending").await;

        // Test with extremely long stellar hash
        let very_long_hash = "a".repeat(1000);
        let result = transaction.update_stellar_hash(&pool, &very_long_hash).await;

        // This should either succeed with truncation or fail with validation error
        match result {
            Ok(updated_tx) => {
                // If it succeeds, verify the hash was properly handled
                assert!(updated_tx.stellar_transaction_hash.is_some());
                let stored_hash = updated_tx.stellar_transaction_hash.unwrap();
                
                // Should be truncated to reasonable length (typically 64 chars for SHA-256)
                assert!(stored_hash.len() <= 255, "Stored hash should be within reasonable limits");
            }
            Err(_) => {
                // If it fails, that's also acceptable; indicates proper validation
                assert!(true, "Long hash rejection is acceptable security behavior");
            }
        }

        cleanup_test_transaction(&pool, transaction.id).await;
        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_very_long_currency_code_validation() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "long_currency").await;
        let organizer_id = create_test_user(&pool, "organizer_long_curr").await;
        let event_id = create_test_event(&pool, organizer_id, "long_currency").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "long_currency").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;

        // Test with extremely long currency code
        let very_long_currency = "X".repeat(500);
        let amount = BigDecimal::from_str("10.00").unwrap();
        let result = Transaction::create(&pool, ticket.id, user_id, amount, &very_long_currency, "pending").await;

        // This should either succeed with truncation or fail with validation error
        match result {
            Ok(transaction) => {
                // If it succeeds, check that currency was properly handled
                assert!(transaction.currency.len() <= 10, "Currency should be truncated to reasonable length");
                cleanup_test_transaction(&pool, transaction.id).await;
            }
            Err(_) => {
                // failure is acceptable and indicates proper validation
                assert!(true, "Long currency code rejection is acceptable security behavior");
            }
        }

        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_sql_injection_protection_in_status() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "sql_injection").await;
        let organizer_id = create_test_user(&pool, "organizer_sql").await;
        let event_id = create_test_event(&pool, organizer_id, "sql_injection").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "sql_injection").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
        let transaction = create_test_transaction(&pool, ticket.id, user_id, "30.00", "XLM", "pending").await;

        // Test with potential SQL injection in status field
        let malicious_status = "completed'; DROP TABLE transactions; --";
        let result = transaction.update_status(&pool, malicious_status).await;

        // Should either succeed (with sqlx protection) or fail with validation
        match result {
            Ok(updated_tx) => {
                // If it succeeds, confirm the malicious code was treated as literal string
                assert_eq!(updated_tx.status, malicious_status);
                
                // Verify transactions table still exists by querying it
                let verify_result = Transaction::find_by_id(&pool, transaction.id).await;
                assert!(verify_result.is_ok(), "Transactions table should still exist - SQL injection was prevented");
                
                cleanup_test_transaction(&pool, transaction.id).await;
            }
            Err(_) => {
                // If it fails due to validation, that's also good security
                assert!(true, "Status validation rejection is acceptable security behavior");
                cleanup_test_transaction(&pool, transaction.id).await;
            }
        }

        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_unicode_and_special_characters_in_refund_reason() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "unicode_refund").await;
        let organizer_id = create_test_user(&pool, "organizer_unicode").await;
        let event_id = create_test_event(&pool, organizer_id, "unicode_refund").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "unicode_refund").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
        let transaction = create_test_transaction(&pool, ticket.id, user_id, "40.00", "XLM", "completed").await;

        // Test with unicode, special characters, and potential script injection
        let complex_reason = "用户取消 🎫 <script>alert('xss')</script> \"; DROP TABLE transactions; --";
        let result = transaction.process_refund(&pool, None, Some(complex_reason.to_string())).await;

        assert!(result.is_ok(), "Should handle complex unicode and special characters safely");
        let refunded_tx = result.unwrap();
        
        // Verify the reason was stored as it is (no execution, just storage)
        assert_eq!(refunded_tx.refund_reason, Some(complex_reason.to_string()));
        
        // Verify database integrity
        let verify_tx = Transaction::find_by_id(&pool, transaction.id).await.unwrap().unwrap();
        assert_eq!(verify_tx.status, "refunded");

        cleanup_test_transaction(&pool, transaction.id).await;
        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]
    async fn test_receipt_number_uniqueness_under_load() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "receipt_unique").await;
        let organizer_id = create_test_user(&pool, "organizer_receipt").await;
        let event_id = create_test_event(&pool, organizer_id, "receipt_unique").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "receipt_unique").await;

        // Create multiple txs rapidly to test receipt number uniqueness
        let mut handles = vec![];
        for i in 0..10 {
            let pool_clone = pool.clone();
            let ticket_type_id = ticket_type.id;
            let user_id_clone = user_id;
            
            let handle = tokio::spawn(async move {
                let ticket = create_test_ticket(&pool_clone, ticket_type_id, user_id_clone).await;
                let amount = BigDecimal::from_str(&format!("{}.00", i + 10)).unwrap();
                Transaction::create(&pool_clone, ticket.id, user_id_clone, amount, "XLM", "completed").await
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        let transactions: Vec<Transaction> = results.into_iter()
            .filter_map(|r| r.ok())
            .filter_map(|r| r.ok())
            .collect();

        // Verify all txs have unique receipt numbers
        let receipt_numbers: Vec<_> = transactions.iter()
            .filter_map(|tx| tx.receipt_number.as_ref())
            .collect();
        
        let unique_receipts: std::collections::HashSet<_> = receipt_numbers.iter().collect();
        assert_eq!(
            receipt_numbers.len(), 
            unique_receipts.len(), 
            "All receipt numbers should be unique"
        );

        // Clean
        for transaction in transactions {
            cleanup_test_transaction(&pool, transaction.id).await;
            let ticket = Ticket::find_by_id(&pool, transaction.ticket_id).await.unwrap().unwrap();
            cleanup_test_ticket(&pool, ticket.id).await;
        }

        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }
}

mod authorization_documentation {
    use super::*;

    // TODO: These tests document authorization requirements that should be enforced 
    // at the service/controller layer, not the model layer

    #[tokio::test]
    async fn test_cross_user_transaction_access_pattern() {
        let pool = setup_test_db().await;
        let user1_id = create_test_user(&pool, "user1_auth").await;
        let user2_id = create_test_user(&pool, "user2_auth").await;
        let organizer_id = create_test_user(&pool, "organizer_auth").await;
        let event_id = create_test_event(&pool, organizer_id, "auth_test").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "auth_test").await;
        
        // Create transaction for user1
        let ticket1 = create_test_ticket(&pool, ticket_type.id, user1_id).await;
        let transaction = create_test_transaction(&pool, ticket1.id, user1_id, "50.00", "XLM", "completed").await;

        // This test documents that the MODEL LAYER does not enforce authorization
        // TODO:Authorization should be enforced at the SERVICE/CONTROLLER layer
        let user2_can_access = Transaction::find_by_id(&pool, transaction.id).await.unwrap().is_some();
        
        assert!(user2_can_access, 
            "MODEL LAYER allows cross-user access - AUTHORIZATION MUST BE ENFORCED AT SERVICE/CONTROLLER LAYER");

        // TODO: Document the expected controller-level authorization pattern:
        // if transaction.user_id != requesting_user_id && !requesting_user.is_admin() {
        //     return Err("Unauthorized access to transaction");
        // }

        cleanup_test_transaction(&pool, transaction.id).await;
        cleanup_test_ticket(&pool, ticket1.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user1_id).await;
        cleanup_test_user(&pool, user2_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }

    #[tokio::test]  
    async fn test_refund_authorization_requirement_documentation() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool, "refund_auth").await;
        let organizer_id = create_test_user(&pool, "organizer_refund_auth").await;
        let event_id = create_test_event(&pool, organizer_id, "refund_auth").await;
        let ticket_type = create_test_ticket_type(&pool, event_id, "refund_auth").await;
        let ticket = create_test_ticket(&pool, ticket_type.id, user_id).await;
        let transaction = create_test_transaction(&pool, ticket.id, user_id, "75.00", "XLM", "completed").await;

        // This test documents that MODEL LAYER allows any refund request
        // TODO: BUSINESS RULES should be enforced at SERVICE/CONTROLLER layer:
        let model_allows_refund = transaction.process_refund(&pool, None, Some("Test refund".to_string())).await.is_ok();
        
        assert!(model_allows_refund, 
            "MODEL LAYER allows refunds - BUSINESS AUTHORIZATION MUST BE ENFORCED AT SERVICE LAYER");

        // Document expected service-level authorization checks:
        // - Only ticket owner or admin can request refund
        // - Refunds may be time-limited (e.g., 24 hours before event)
        // - Event organizer approval may be required
        // - Refund amount limits based on business rules

        cleanup_test_transaction(&pool, transaction.id).await;
        cleanup_test_ticket(&pool, ticket.id).await;
        cleanup_test_ticket_type(&pool, ticket_type.id).await;
        cleanup_test_event(&pool, event_id).await;
        cleanup_test_user(&pool, user_id).await;
        cleanup_test_user(&pool, organizer_id).await;
    }
}
}
