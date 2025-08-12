use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use bigdecimal::{BigDecimal, FromPrimitive};
use sqlx::{Postgres, PgPool, Transaction as SqlxTransaction};
use uuid::Uuid;
use bigdecimal::Signed;

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
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
    pub transaction_sponsorship_fee: Option<BigDecimal>,
    pub gas_fee_xlm: Option<BigDecimal>,
    pub sponsor_account_used: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefundRequest {
    pub ticket_id: Uuid,
    pub amount: Option<BigDecimal>,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransactionWithFeeBreakdown {
    pub transaction: Transaction,
    pub fee_breakdown: FeeBreakdown,
}

#[derive(Debug, Serialize)]
pub struct FeeBreakdown {
    pub ticket_price: String,
    pub sponsorship_fee: String,
    pub total_paid: String,
    pub currency: String,
    pub gas_covered_by_platform: bool,
}

impl Transaction {
    pub async fn create(
        pool: &PgPool,
        ticket_id: Uuid,
        user_id: Uuid,
        amount: BigDecimal,
        sponsorship_fee: BigDecimal,
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
                created_at, updated_at, receipt_number, transaction_sponsorship_fee
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
            receipt_number,
            sponsorship_fee
        )
        .fetch_one(pool)
        .await?
        } else {
            // add the column if it doesn't exist
            sqlx::query!("ALTER TABLE transactions ADD COLUMN transaction_sponsorship_fee DECIMAL(19, 8)")
            .execute(pool)
            .await?;
            sqlx::query!("ALTER TABLE transactions ADD COLUMN receipt_number VARCHAR(255)")
                .execute(pool)
                .await?;

            // then insert with the receipt number
            sqlx::query_as!(
            Transaction,
            r#"
            INSERT INTO transactions (
                id, ticket_id, user_id, amount, currency, status, 
                created_at, updated_at, receipt_number, transaction_sponsorship_fee
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
            receipt_number,
            sponsorship_fee
        )
        .fetch_one(pool)
        .await?
    };

        Ok(transaction)
    }

    pub async fn update_sponsorship_details(
        &self,
        tx: &mut SqlxTransaction<'_, Postgres>,
        stellar_hash: &str,
        gas_fee_xlm: f64,
        sponsor_account: &str,
    ) -> Result<Self> {
        let transaction = sqlx::query_as!(
            Transaction,
            r#"
            UPDATE transactions
            SET stellar_transaction_hash = $1, 
                gas_fee_xlm = $2,
                sponsor_account_used = $3,
                status = 'completed',
                updated_at = $4
            WHERE id = $5
            RETURNING *
            "#,
            stellar_hash,
            BigDecimal::from_f64(gas_fee_xlm)
            .ok_or_else(|| anyhow::anyhow!("Invalid gas fee value"))?,
            sponsor_account,
            Utc::now(),
            self.id
        )
        .fetch_one(&mut **tx)
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

    pub async fn find_by_status(pool: &PgPool, status: &str) -> Result<Vec<Self>> {
        let transactions = sqlx::query_as!(
            Transaction,
            "SELECT * FROM transactions WHERE status = $1 ORDER BY created_at DESC",
            status
        )
        .fetch_all(pool)
        .await?;

        Ok(transactions)
    }

    pub async fn get_with_fee_breakdown(&self, _pool: &PgPool) -> Result<TransactionWithFeeBreakdown> {
        let ticket_price = if let Some(sponsorship_fee) = &self.transaction_sponsorship_fee {
            &self.amount - sponsorship_fee
        } else {
            self.amount.clone()
        };

        let sponsorship_fee = self.transaction_sponsorship_fee
            .as_ref()
            .cloned()
            .unwrap_or_else(|| BigDecimal::from(0));

        let fee_breakdown = FeeBreakdown {
            ticket_price: format!("{:.2}", ticket_price),
            sponsorship_fee: format!("{:.2}", sponsorship_fee),
            total_paid: format!("{:.2}", self.amount),
            currency: self.currency.clone(),
            gas_covered_by_platform: self.sponsor_account_used.is_some(),
        };

        Ok(TransactionWithFeeBreakdown {
            transaction: self.clone(),
            fee_breakdown,
        })
    }

    pub async fn calculate_revenue_for_event(pool: &PgPool, event_id: Uuid) -> Result<f64> {
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
            "#,
            event_id
        )
        .fetch_one(pool)
        .await?;

        let revenue = result.revenue
            .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        Ok(revenue)
    }

    /// Calculate total sponsorship fees collected
    pub async fn calculate_sponsorship_fees_for_period(
        pool: &PgPool,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<f64> {
        let result = sqlx::query!(
            r#"
            SELECT COALESCE(SUM(transaction_sponsorship_fee), 0) as total_fees
            FROM transactions 
            WHERE created_at BETWEEN $1 AND $2
            AND status = 'completed'
            AND transaction_sponsorship_fee IS NOT NULL
            "#,
            start_date,
            end_date
        )
        .fetch_one(pool)
        .await?;

        let total_fees = result.total_fees
            .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        Ok(total_fees)
    }

    /// Get ticket price excluding sponsorship fee
    pub fn get_ticket_price(&self) -> BigDecimal {
        if let Some(sponsorship_fee) = &self.transaction_sponsorship_fee {
            &self.amount - sponsorship_fee
        } else {
            self.amount.clone()
        }
    }

    pub fn get_sponsorship_fee(&self) -> BigDecimal {
        self.transaction_sponsorship_fee
            .as_ref()
            .cloned()
            .unwrap_or_else(|| BigDecimal::from(0))
    }

    /// Check if transaction was sponsored
    pub fn is_sponsored(&self) -> bool {
        self.sponsor_account_used.is_some()
    }

    /// Format transaction for user display
    pub fn format_for_display(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "receipt_number": self.receipt_number,
            "ticket_price": format!("{:.2}", self.get_ticket_price()),
            "sponsorship_fee": format!("{:.2}", self.get_sponsorship_fee()),
            "total_amount": format!("{:.2}", self.amount),
            "currency": self.currency,
            "status": self.status,
            "is_sponsored": self.is_sponsored(),
            "created_at": self.created_at,
            "transaction_hash": self.stellar_transaction_hash
        })
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
}