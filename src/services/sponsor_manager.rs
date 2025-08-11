use anyhow::{anyhow, Result};
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
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
    pub encrypted_secret_key: Option<String>,
    pub is_active: bool,
    pub minimum_balance: BigDecimal,
    pub current_balance: Option<BigDecimal>,
    pub last_balance_check: Option<DateTime<Utc>>,
    pub transactions_sponsored: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

#[derive(Debug)]
pub struct SponsorAccountInfo {
    pub secret_key: String,
    pub public_key: String,
    pub account_name: String,
    pub current_balance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSponsorRequest {
    pub account_name: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSponsorRequest {
    pub sponsor_id: Uuid,
    pub new_secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorStatusResponse {
    pub id: Uuid,
    pub account_name: String,
    pub public_key: String,
    pub is_active: bool,
    pub current_balance: Option<BigDecimal>,
    pub transactions_sponsored: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
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
                // Encrypt the secret key before storing
                let crypto = crate::services::crypto::KeyEncryption::new()
                    .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;
                
                let encrypted_secret = crypto.encrypt_secret_key(&account.secret_key)
                    .map_err(|e| anyhow!("Failed to encrypt sponsor secret key: {}", e))?;

                // Create new sponsor account record with encrypted secret key
                sqlx::query!(
                    r#"
                    INSERT INTO sponsor_accounts (account_name, public_key, encrypted_secret_key, minimum_balance)
                    VALUES ($1, $2, $3, $4)
                    "#,
                    account_name,
                    account.public_key,
                    encrypted_secret,
                    BigDecimal::from_f64(self.minimum_balance)
                        .ok_or_else(|| anyhow!("Invalid minimum balance value"))?,
                )
                .execute(&self.pool)
                .await?;

                info!("✅ Initialized sponsor account: {} ({})", account_name, account.public_key);
            } else {
                info!("ℹ️ Sponsor account already exists: {} ({})", account_name, account.public_key);
            }
        }

        // Update balances for all accounts
        self.update_all_balances().await?;

        Ok(())
    }

    /// Get an available sponsor account (reading encrypted key from database)
    pub async fn get_available_sponsor(&self) -> Result<SponsorAccountInfo> {
        // Get active sponsors with sufficient balance
        let sponsors = sqlx::query_as!(
            SponsorAccount,
            r#"
            SELECT * FROM sponsor_accounts 
            WHERE is_active = true 
              AND encrypted_secret_key IS NOT NULL
              AND (current_balance IS NULL OR current_balance >= minimum_balance)
            ORDER BY 
              CASE WHEN current_balance IS NULL THEN 1 ELSE 0 END,
              current_balance DESC NULLS LAST,
              transactions_sponsored ASC NULLS FIRST
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        if sponsors.is_empty() {
            return Err(anyhow!("No active sponsor accounts available with sufficient balance"));
        }

        // Select the sponsor with the highest balance (or unknown balance)
        let selected_sponsor = &sponsors[0];

        // Decrypt the secret key
        let crypto = crate::services::crypto::KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;

        let encrypted_secret = selected_sponsor.encrypted_secret_key
            .as_ref()
            .ok_or_else(|| anyhow!("Sponsor account {} has no encrypted secret key", selected_sponsor.public_key))?;

        let decrypted_secret = crypto.decrypt_secret_key(encrypted_secret)
            .map_err(|e| anyhow!("Failed to decrypt sponsor secret key: {}", e))?;

        let current_balance = selected_sponsor.current_balance
            .as_ref()
            .and_then(|b| b.to_f64())
            .unwrap_or(0.0);

        Ok(SponsorAccountInfo {
            secret_key: decrypted_secret,
            public_key: selected_sponsor.public_key.clone(),
            account_name: selected_sponsor.account_name.clone(),
            current_balance,
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
        let accounts = sqlx::query!("SELECT public_key FROM sponsor_accounts WHERE is_active = true")
            .fetch_all(&self.pool)
            .await?;

        for account in accounts {
            if let Err(e) = self.update_account_balance(&account.public_key).await {
                warn!("Failed to update balance for {}: {}", account.public_key, e);
            }
        }

        Ok(())
    }

    /// Update balance for a specific account
    pub async fn update_account_balance(&self, public_key: &str) -> Result<()> {
        let balance_xlm = self.stellar_service.get_xlm_balance(public_key).await?;

        sqlx::query!(
            r#"
            UPDATE sponsor_accounts 
            SET current_balance = $1, 
                last_balance_check = NOW(),
                updated_at = NOW()
            WHERE public_key = $2
            "#,
            BigDecimal::from_f64(balance_xlm),
            public_key
        )
        .execute(&self.pool)
        .await?;

        // Check if balance is below minimum and deactivate if necessary
        if balance_xlm < self.minimum_balance {
            self.deactivate_account(public_key).await?;
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
            r#"
            UPDATE sponsor_accounts 
            SET is_active = false, updated_at = NOW()
            WHERE public_key = $1
            "#,
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

    /// Add a new sponsor account (max 3 sponsors)
    pub async fn add_sponsor_account(&self, request: CreateSponsorRequest) -> Result<SponsorAccount> {
        // Check current count of sponsor accounts
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM sponsor_accounts"
        )
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(0);

        if count >= 3 {
            return Err(anyhow!("Maximum of 3 sponsor accounts allowed. Please replace an existing one."));
        }

        // Validate the secret key format
        if !self.stellar_service.is_valid_secret_key(&request.secret_key) {
            return Err(anyhow!("Invalid secret key format"));
        }

        // Derive public key from secret key
        let public_key = self.stellar_service.get_public_key_from_secret(&request.secret_key)?;

        // Check if account already exists
        let existing = sqlx::query!(
            "SELECT id FROM sponsor_accounts WHERE public_key = $1",
            public_key
        )
        .fetch_optional(&self.pool)
        .await?;

        if existing.is_some() {
            return Err(anyhow!("Sponsor account with this public key already exists"));
        }

        // Encrypt the secret key
        let crypto = crate::services::crypto::KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;
        
        let encrypted_secret = crypto.encrypt_secret_key(&request.secret_key)
            .map_err(|e| anyhow!("Failed to encrypt secret key: {}", e))?;

        // Insert new sponsor account
        let sponsor = sqlx::query_as!(
            SponsorAccount,
            r#"
            INSERT INTO sponsor_accounts (account_name, public_key, encrypted_secret_key, minimum_balance, is_active)
            VALUES ($1, $2, $3, $4, true)
            RETURNING *
            "#,
            request.account_name,
            public_key,
            encrypted_secret,
            BigDecimal::from_f64(self.minimum_balance).unwrap()
        )
        .fetch_one(&self.pool)
        .await?;

        // Update the balance for the new account
        self.update_account_balance(&public_key).await?;

        info!("✅ Added new sponsor account: {} ({})", sponsor.account_name, sponsor.public_key);
        Ok(sponsor)
    }

    /// Update/replace an existing sponsor account
    pub async fn update_sponsor_account(&self, request: UpdateSponsorRequest) -> Result<SponsorAccount> {
        // Validate the new secret key format
        if !self.stellar_service.is_valid_secret_key(&request.new_secret_key) {
            return Err(anyhow!("Invalid secret key format"));
        }

        // Check if the sponsor exists
        let existing = sqlx::query_as!(
            SponsorAccount,
            "SELECT * FROM sponsor_accounts WHERE id = $1",
            request.sponsor_id
        )
        .fetch_optional(&self.pool)
        .await?;

        let existing = existing.ok_or_else(|| anyhow!("Sponsor account not found"))?;

        // Derive new public key from new secret key
        let new_public_key = self.stellar_service.get_public_key_from_secret(&request.new_secret_key)?;

        // Check if the new public key conflicts with another account
        let conflict = sqlx::query!(
            "SELECT id FROM sponsor_accounts WHERE public_key = $1 AND id != $2",
            new_public_key,
            request.sponsor_id
        )
        .fetch_optional(&self.pool)
        .await?;

        if conflict.is_some() {
            return Err(anyhow!("Another sponsor account with this public key already exists"));
        }

        // Encrypt the new secret key
        let crypto = crate::services::crypto::KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;
        
        let encrypted_secret = crypto.encrypt_secret_key(&request.new_secret_key)
            .map_err(|e| anyhow!("Failed to encrypt secret key: {}", e))?;

        // Update the sponsor account
        let updated_sponsor = sqlx::query_as!(
            SponsorAccount,
            r#"
            UPDATE sponsor_accounts 
            SET public_key = $1, 
                encrypted_secret_key = $2, 
                current_balance = NULL,
                last_balance_check = NULL,
                updated_at = NOW()
            WHERE id = $3
            RETURNING *
            "#,
            new_public_key,
            encrypted_secret,
            request.sponsor_id
        )
        .fetch_one(&self.pool)
        .await?;

        // Update the balance for the updated account
        self.update_account_balance(&new_public_key).await?;

        info!("✅ Updated sponsor account: {} ({})", updated_sponsor.account_name, updated_sponsor.public_key);
        Ok(updated_sponsor)
    }

    /// Deactivate a sponsor account by ID
    pub async fn deactivate_sponsor_by_id(&self, sponsor_id: Uuid) -> Result<SponsorAccount> {
        let sponsor = sqlx::query_as!(
            SponsorAccount,
            r#"
            UPDATE sponsor_accounts 
            SET is_active = false, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
            sponsor_id
        )
        .fetch_optional(&self.pool)
        .await?;

        let sponsor = sponsor.ok_or_else(|| anyhow!("Sponsor account not found"))?;

        info!("❌ Deactivated sponsor account: {} ({})", sponsor.account_name, sponsor.public_key);
        Ok(sponsor)
    }

    /// Reactivate a sponsor account by ID
    pub async fn reactivate_sponsor_by_id(&self, sponsor_id: Uuid) -> Result<SponsorAccount> {
        let sponsor = sqlx::query_as!(
            SponsorAccount,
            r#"
            UPDATE sponsor_accounts 
            SET is_active = true, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
            sponsor_id
        )
        .fetch_optional(&self.pool)
        .await?;

        let sponsor = sponsor.ok_or_else(|| anyhow!("Sponsor account not found"))?;

        // Update balance after reactivation
        self.update_account_balance(&sponsor.public_key).await?;

        info!("✅ Reactivated sponsor account: {} ({})", sponsor.account_name, sponsor.public_key);
        Ok(sponsor)
    }

    /// List all sponsors with their status (for admin)
    pub async fn list_all_sponsors(&self) -> Result<Vec<SponsorStatusResponse>> {
        let sponsors = sqlx::query_as!(
            SponsorAccount,
            "SELECT * FROM sponsor_accounts ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let response: Vec<SponsorStatusResponse> = sponsors
            .into_iter()
            .map(|s| SponsorStatusResponse {
                id: s.id,
                account_name: s.account_name,
                public_key: s.public_key,
                is_active: s.is_active,
                current_balance: s.current_balance,
                transactions_sponsored: s.transactions_sponsored,
                created_at: s.created_at,
                created_by: s.created_by,
            })
            .collect();

        Ok(response)
    }

    /// Get sponsor by ID (for admin)
    pub async fn get_sponsor_by_id(&self, sponsor_id: Uuid) -> Result<SponsorStatusResponse> {
        let sponsor = sqlx::query_as!(
            SponsorAccount,
            "SELECT * FROM sponsor_accounts WHERE id = $1",
            sponsor_id
        )
        .fetch_optional(&self.pool)
        .await?;

        let sponsor = sponsor.ok_or_else(|| anyhow!("Sponsor account not found"))?;

        Ok(SponsorStatusResponse {
            id: sponsor.id,
            account_name: sponsor.account_name,
            public_key: sponsor.public_key,
            is_active: sponsor.is_active,
            current_balance: sponsor.current_balance,
            transactions_sponsored: sponsor.transactions_sponsored,
            created_at: sponsor.created_at,
            created_by: sponsor.created_by,
        })
    }
}
