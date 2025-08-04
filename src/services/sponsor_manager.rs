use anyhow::{anyhow, Result};
use bigdecimal::{BigDecimal, FromPrimitive};
use chrono::{DateTime, Duration, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool};
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SponsorAccount {
    pub id: Uuid,
    pub account_name: String,
    pub public_key: String,
    pub is_active: bool,
    pub minimum_balance: BigDecimal,
    pub current_balance: Option<BigDecimal>,
    pub last_balance_check: Option<DateTime<Utc>>,
    pub transactions_sponsored: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SponsorAccountInfo {
    pub secret_key: String,
    pub public_key: String,
    pub account_name: String,
    pub current_balance: f64,
}


#[derive(Debug, Clone)]
pub struct SponsorManager {
    pool: PgPool,
    stellar_service: crate::services::stellar::StellarService,
    minimum_balance: f64,
    alert_threshold: f64,
}

impl SponsorManager {
    pub fn new(pool: PgPool) -> Result<Self> {
        let stellar_service = crate::services::stellar::StellarService::new()?;

        let minimum_balance = env::var("SPONSOR_MINIMUM_BALANCE")
            .unwrap_or_else(|_| "200".to_string())
            .parse::<f64>()?;

        let alert_threshold = env::var("SPONSOR_LOW_BALANCE_ALERT_THRESHOLD")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<f64>()?;

        Ok(Self {
            pool,
            stellar_service,
            minimum_balance,
            alert_threshold,
        })
    }

    /// Initialize sponsor accounts from environment variables
    pub async fn initialize_sponsor_accounts(&self) -> Result<()> {
        info!("🔧 Initializing sponsor accounts from environment");

        let sponsor_accounts = self.load_sponsor_accounts_from_env()?;

        for (i, account) in sponsor_accounts.iter().enumerate() {
            let account_name = format!("Sponsor Account {}", i + 1);

            // Check if account already exists
            let existing = sqlx::query_as!(
                SponsorAccount,
                "SELECT * FROM sponsor_accounts WHERE public_key = $1",
                account.public_key
            )
            .fetch_optional(&self.pool)
            .await?;

            if existing.is_none() {
                // Create new sponsor account record
                sqlx::query!(
                    r#"
                    INSERT INTO sponsor_accounts (account_name, public_key, minimum_balance)
                    VALUES ($1, $2, $3)
                    "#,
                    account_name,
                    account.public_key,
                    BigDecimal::from_f64(self.minimum_balance)
                        .ok_or_else(|| anyhow!("Invalid minimum balance value"))?,
                )
                .execute(&self.pool)
                .await?;

                info!(
                    "✅ Added sponsor account: {} ({})",
                    account_name, account.public_key
                );
            }
        }

        // Update balances for all accounts
        self.update_all_balances().await?;

        Ok(())
    }

    /// Get an available sponsor account for transaction sponsorship
    pub async fn get_available_sponsor(&self) -> Result<SponsorAccountInfo> {
        // First update balances if they're stale
        self.update_stale_balances().await?;

        // Get eligible sponsor accounts
        let eligible_accounts = sqlx::query_as!(
            SponsorAccount,
            r#"
            SELECT * FROM sponsor_accounts 
            WHERE is_active = true 
            AND current_balance IS NOT NULL 
            AND current_balance >= minimum_balance
            ORDER BY transactions_sponsored ASC, current_balance DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        if eligible_accounts.is_empty() {
            error!("❌ No eligible sponsor accounts available!");
            return Err(anyhow!(
                "No sponsor accounts available for transaction sponsorship"
            ));
        }

        // Get the account with least transactions sponsored (load balancing)
        let selected_account = &eligible_accounts[0];

        // Get the secret key for this account
        let secret_key = self.get_secret_key_for_account(&selected_account.public_key)?;

        info!(
            "✅ Selected sponsor account: {} (Balance: {} XLM, Transactions: {:?})",
            selected_account.account_name,
            selected_account.current_balance.as_ref().unwrap(),
            selected_account.transactions_sponsored
        );

        Ok(SponsorAccountInfo {
            secret_key,
            public_key: selected_account.public_key.clone(),
            account_name: selected_account.account_name.clone(),
            current_balance: selected_account
                .current_balance
                .as_ref()
                .unwrap()
                .to_string()
                .parse()?,
        })
    }

    /// Record that a sponsor account was used for a transaction
    pub async fn record_sponsorship_usage(
        &self,
        sponsor_public_key: &str,
        gas_fee_xlm: f64,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE sponsor_accounts 
            SET transactions_sponsored = transactions_sponsored + 1,
                current_balance = current_balance - $1,
                updated_at = NOW()
            WHERE public_key = $2
            "#,
            BigDecimal::from_f64(gas_fee_xlm).ok_or_else(|| anyhow!("Invalid gas fee value"))?,
            sponsor_public_key
        )
        .execute(&self.pool)
        .await?;

        // Check if account needs alert after usage
        self.check_and_alert_low_balance(sponsor_public_key).await?;

        Ok(())
    }

    /// Update balances for all sponsor accounts
    pub async fn update_all_balances(&self) -> Result<()> {
        let accounts = sqlx::query_as!(
            SponsorAccount,
            "SELECT * FROM sponsor_accounts WHERE is_active = true"
        )
        .fetch_all(&self.pool)
        .await?;

        for account in accounts {
            if let Err(e) = self.update_account_balance(&account.public_key).await {
                error!(
                    "Failed to update balance for {}: {}",
                    account.account_name, e
                );
            }
        }

        Ok(())
    }

    /// Update balances only for accounts that haven't been checked recently
    async fn update_stale_balances(&self) -> Result<()> {
        let check_interval_minutes = env::var("SPONSOR_BALANCE_CHECK_INTERVAL")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<i64>()?;

        let stale_threshold = Utc::now() - Duration::minutes(check_interval_minutes);

        let stale_accounts = sqlx::query_as!(
            SponsorAccount,
            r#"
            SELECT * FROM sponsor_accounts 
            WHERE is_active = true 
            AND (last_balance_check IS NULL OR last_balance_check < $1)
            "#,
            stale_threshold
        )
        .fetch_all(&self.pool)
        .await?;

        for account in stale_accounts {
            if let Err(e) = self.update_account_balance(&account.public_key).await {
                warn!(
                    "Failed to update stale balance for {}: {}",
                    account.account_name, e
                );
            }
        }

        Ok(())
    }

    /// Update balance for a specific account
    async fn update_account_balance(&self, public_key: &str) -> Result<()> {
        match self.stellar_service.get_xlm_balance(public_key).await {
            Ok(balance) => {
                sqlx::query!(
                    r#"
                    UPDATE sponsor_accounts 
                    SET current_balance = $1, last_balance_check = NOW(), updated_at = NOW()
                    WHERE public_key = $2
                    "#,
                    BigDecimal::from_f64(balance)
                        .ok_or_else(|| anyhow!("Invalid balance value"))?,
                    public_key
                )
                .execute(&self.pool)
                .await?;

                // Check for low balance
                if balance < self.alert_threshold {
                    self.alert_low_balance(public_key, balance).await?;
                }

                // Deactivate if below minimum
                if balance < self.minimum_balance {
                    self.deactivate_account(public_key).await?;
                }
            }
            Err(e) => {
                error!(
                    "Failed to get balance for sponsor account {}: {}",
                    public_key, e
                );
                return Err(e);
            }
        }

        Ok(())
    }

    async fn check_and_alert_low_balance(&self, public_key: &str) -> Result<()> {
        let account = sqlx::query_as!(
            SponsorAccount,
            "SELECT * FROM sponsor_accounts WHERE public_key = $1",
            public_key
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(account) = account {
            if let Some(balance) = account.current_balance {
                let balance_f64: f64 = balance.to_string().parse()?;

                if balance_f64 < self.alert_threshold {
                    self.alert_low_balance(public_key, balance_f64).await?;
                }

                if balance_f64 < self.minimum_balance {
                    self.deactivate_account(public_key).await?;
                }
            }
        }

        Ok(())
    }

    async fn alert_low_balance(&self, public_key: &str, balance: f64) -> Result<()> {
        warn!(
            "🚨 LOW BALANCE ALERT: Sponsor account {} has {} XLM (threshold: {} XLM)",
            public_key, balance, self.alert_threshold
        );

        // TODO: Implement actual alerting (email, Slack, etc.)
        // For now, just log the alert

        Ok(())
    }

    async fn deactivate_account(&self, public_key: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE sponsor_accounts SET is_active = false WHERE public_key = $1",
            public_key
        )
        .execute(&self.pool)
        .await?;

        error!(
            "❌ DEACTIVATED sponsor account {} (balance below minimum {} XLM)",
            public_key, self.minimum_balance
        );

        Ok(())
    }

    /// Load sponsor account configurations from environment variables
    fn load_sponsor_accounts_from_env(&self) -> Result<Vec<SponsorAccountInfo>> {
        let mut accounts = Vec::new();
        let mut counter = 1;

        loop {
            let secret_key_var = format!("SPONSOR_ACCOUNT_{}_SECRET", counter);

            match env::var(&secret_key_var) {
                Ok(secret_key) => {
                    // Derive public key from secret key
                    let public_key = self
                        .stellar_service
                        .get_public_key_from_secret(&secret_key)?;

                    accounts.push(SponsorAccountInfo {
                        secret_key,
                        public_key,
                        account_name: format!("Sponsor Account {}", counter),
                        current_balance: 0.0, // Will be updated by balance check
                    });

                    counter += 1;
                }
                Err(_) => break, // No more sponsor accounts
            }
        }

        if accounts.is_empty() {
            return Err(anyhow!(
                "No sponsor accounts configured. Please set SPONSOR_ACCOUNT_1_SECRET, etc."
            ));
        }

        info!(
            "📋 Loaded {} sponsor accounts from environment",
            accounts.len()
        );
        Ok(accounts)
    }

    /// Get secret key for a sponsor account by public key
    fn get_secret_key_for_account(&self, public_key: &str) -> Result<String> {
        let accounts = self.load_sponsor_accounts_from_env()?;

        for account in accounts {
            if account.public_key == public_key {
                return Ok(account.secret_key);
            }
        }

        Err(anyhow!(
            "Secret key not found for sponsor account: {}",
            public_key
        ))
    }

    /// Get sponsor account statistics
    pub async fn get_sponsor_statistics(&self) -> Result<Vec<SponsorAccount>> {
        let accounts = sqlx::query_as!(
            SponsorAccount,
            "SELECT * FROM sponsor_accounts ORDER BY account_name"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(accounts)
    }

    /// Manual balance refresh for all accounts
    pub async fn refresh_all_balances(&self) -> Result<()> {
        info!("🔄 Manually refreshing all sponsor account balances");
        self.update_all_balances().await
    }
}
