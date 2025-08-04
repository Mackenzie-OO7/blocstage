use crate::models::{Transaction, User};
use crate::services::crypto::KeyEncryption;
use crate::services::fee_calculator::{FeeCalculator, FeeCalculation};
use crate::services::sponsor_manager::SponsorManager;
use crate::services::stellar::{StellarService, SponsoredPaymentResult};
use anyhow::{anyhow, Result};
use log::{error, info, warn};
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PaymentCapability {
    pub has_wallet: bool,
    pub has_usdc_trustline: bool,
    pub has_sufficient_balance: bool,
    pub usdc_balance: Option<f64>,
    pub can_make_payment: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct PaymentPreview {
    pub ticket_price: f64,
    pub sponsorship_fee: f64,
    pub total_amount: f64,
    pub currency: String,
    pub breakdown_text: String,
    pub payment_capability: PaymentCapability,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentErrorCategory {
    InsufficientFunds,
    MissingTrustline,
    WalletNotConfigured,
    SponsorUnavailable,
    NetworkError,
    ValidationFailed,
    Unknown,
}

pub struct PaymentOrchestrator {
    stellar: StellarService,
    sponsor_manager: SponsorManager,
    fee_calculator: FeeCalculator,
    crypto_service: KeyEncryption,
}

impl PaymentOrchestrator {
    /// Create new PaymentOrchestrator with dependency injection
    pub fn new(
        stellar: StellarService,
        sponsor_manager: SponsorManager,
        fee_calculator: FeeCalculator,
    ) -> Result<Self> {
        let crypto_service = KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to initialize crypto service: {}", e))?;

        Ok(Self {
            stellar,
            sponsor_manager,
            fee_calculator,
            crypto_service,
        })
    }

    /// Comprehensive payment capability validation
    pub async fn validate_payment_capability(
        &self,
        user: &User,
        required_amount: f64,
    ) -> Result<PaymentCapability> {
        info!("🔍 Validating payment capability for user {} (amount: {} USDC)", user.id, required_amount);

        let mut capability = PaymentCapability {
            has_wallet: false,
            has_usdc_trustline: false,
            has_sufficient_balance: false,
            usdc_balance: None,
            can_make_payment: false,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Check wallet configuration
        if user.stellar_public_key.is_none() || user.stellar_secret_key_encrypted.is_none() {
            capability.errors.push("User has no Stellar wallet configured".to_string());
            return Ok(capability);
        }

        capability.has_wallet = true;
        let public_key = user.stellar_public_key.as_ref().unwrap();

        // Validate public key format
        if !self.stellar.is_valid_public_key(public_key) {
            capability.errors.push("Invalid Stellar public key format".to_string());
            return Ok(capability);
        }

        // Check USDC trustline
        match self.stellar.has_usdc_trustline(public_key).await {
            Ok(has_trustline) => {
                capability.has_usdc_trustline = has_trustline;
                if !has_trustline {
                    capability.errors.push("USDC trustline not established".to_string());
                }
            }
            Err(e) => {
                warn!("Failed to check USDC trustline for user {}: {}", user.id, e);
                capability.errors.push("Unable to verify USDC trustline".to_string());
                return Ok(capability);
            }
        }

        // Check USDC balance if trustline exists
        if capability.has_usdc_trustline {
            match self.stellar.get_usdc_balance(public_key).await {
                Ok(balance) => {
                    capability.usdc_balance = Some(balance);
                    capability.has_sufficient_balance = balance >= required_amount;
                    
                    if !capability.has_sufficient_balance {
                        capability.errors.push(format!(
                            "Insufficient USDC balance. Required: {:.2}, Available: {:.2}",
                            required_amount, balance
                        ));
                    }

                    // Add warning for low balance (less than 2x required)
                    if balance < (required_amount * 2.0) && balance >= required_amount {
                        capability.warnings.push(format!(
                            "Low USDC balance: {:.2} USDC remaining after purchase",
                            balance - required_amount
                        ));
                    }
                }
                Err(e) => {
                    warn!("Failed to get USDC balance for user {}: {}", user.id, e);
                    capability.errors.push("Unable to verify USDC balance".to_string());
                }
            }
        }

        // Overall payment capability
        capability.can_make_payment = capability.has_wallet 
            && capability.has_usdc_trustline 
            && capability.has_sufficient_balance 
            && capability.errors.is_empty();

        info!(
            "💳 Payment validation for user {}: can_pay={}, wallet={}, trustline={}, balance={}",
            user.id, capability.can_make_payment, capability.has_wallet, 
            capability.has_usdc_trustline, capability.has_sufficient_balance
        );

        Ok(capability)
    }

    /// Generate comprehensive payment preview
    pub async fn get_payment_preview(
        &self,
        user: &User,
        ticket_price: f64,
    ) -> Result<PaymentPreview> {
        info!("📋 Generating payment preview for user {} (ticket: {} USDC)", user.id, ticket_price);

        // Input validation
        if ticket_price <= 0.0 {
            return Err(anyhow!("Ticket price must be greater than zero"));
        }

        if ticket_price > 100_000.0 {
            return Err(anyhow!("Ticket price exceeds maximum limit"));
        }

        // Calculate fee breakdown
        let fee_calculation = self.fee_calculator.calculate_sponsorship_fee(ticket_price).await?;
        
        // Validate payment capability
        let payment_capability = self.validate_payment_capability(user, fee_calculation.total_user_pays).await?;

        // Generate breakdown text
        let breakdown_text = format!(
            "Ticket: ${:.2} + Sponsorship Fee: ${:.2} = Total: ${:.2}",
            fee_calculation.ticket_price,
            fee_calculation.final_sponsorship_fee,
            fee_calculation.total_user_pays
        );

        Ok(PaymentPreview {
            ticket_price: fee_calculation.ticket_price,
            sponsorship_fee: fee_calculation.final_sponsorship_fee,
            total_amount: fee_calculation.total_user_pays,
            currency: "USDC".to_string(),
            breakdown_text,
            payment_capability,
        })
    }

    /// Execute sponsored payment with full orchestration
    pub async fn execute_sponsored_payment(
        &self,
        user: &User,
        transaction: &Transaction,
        fee_calculation: &FeeCalculation,
    ) -> Result<SponsoredPaymentResult> {
        info!("💳 Orchestrating sponsored payment: {} USDC for user {} (transaction: {})", 
               fee_calculation.total_user_pays, user.id, transaction.id);

        // Step 1: Pre-payment validation
        self.pre_payment_validation(user, fee_calculation).await?;

        // Step 2: Validate payment capability
        let capability = self.validate_payment_capability(user, fee_calculation.total_user_pays).await?;
        if !capability.can_make_payment {
            let error_msg = capability.errors.join("; ");
            error!("Payment validation failed for user {}: {}", user.id, error_msg);
            return Err(anyhow!("Payment validation failed: {}", error_msg));
        }

        // Step 3: Get platform wallet and sponsor
        let platform_wallet = self.get_platform_wallet()?;
        let sponsor_info = self.sponsor_manager.get_available_sponsor().await
            .map_err(|e| anyhow!("No sponsor accounts available: {}", e))?;

        info!("Using sponsor account: {}", sponsor_info.account_name);

        // Step 4: Decrypt user's secret key securely
        let user_secret_key = self.decrypt_user_secret_key(user)?;

        // Step 5: Execute payment through Stellar service
        let payment_result = self.stellar.send_payment(
            &user_secret_key,
            &platform_wallet,
            &fee_calculation.total_user_pays.to_string(),
            &sponsor_info.secret_key,
        ).await.map_err(|e| {
            error!("Payment execution failed for user {}: {}", user.id, e);
            anyhow!("Payment execution failed: {}", self.format_user_friendly_error(&e))
        })?;

        // Step 6: Record sponsor usage
        self.sponsor_manager
            .record_sponsorship_usage(&sponsor_info.public_key, payment_result.gas_fee_xlm)
            .await
            .map_err(|e| {
                warn!("Failed to record sponsor usage: {}", e);
                e
            })
            .ok();

        info!(
            "✅ Sponsored payment successful: {} USDC sent, {} XLM gas paid by sponsor {} (transaction: {})",
            payment_result.usdc_amount_sent,
            payment_result.gas_fee_xlm,
            sponsor_info.account_name,
            transaction.id
        );

        Ok(payment_result)
    }

    /// Get platform payment wallet from environment
    pub fn get_platform_wallet(&self) -> Result<String> {
        env::var("PLATFORM_PAYMENT_PUBLIC_KEY")
            .map_err(|_| anyhow!("Platform payment wallet not configured. Please set PLATFORM_PAYMENT_PUBLIC_KEY"))
    }

    /// Format user-friendly error messages
    pub fn format_user_friendly_error(&self, error: &anyhow::Error) -> String {
        let error_str = error.to_string().to_lowercase();

        if error_str.contains("trustline") {
            "Please create a USDC trustline first using the wallet setup".to_string()
        } else if error_str.contains("insufficient") && error_str.contains("balance") {
            "Insufficient USDC balance. Please fund your wallet".to_string()
        } else if error_str.contains("sponsor") {
            "Payment service temporarily unavailable. Please try again later".to_string()
        } else if error_str.contains("network") || error_str.contains("horizon") {
            "Network connectivity issue. Please try again".to_string()
        } else if error_str.contains("invalid") && error_str.contains("key") {
            "Wallet configuration issue. Please contact support".to_string()
        } else if error_str.contains("sequence") {
            "Transaction timing issue. Please try again".to_string()
        } else if error_str.contains("fee") {
            "Transaction fee issue. Please try again".to_string()
        } else {
            "Payment failed. Please try again or contact support".to_string()
        }
    }

    /// Categorize payment errors for better handling
    pub fn categorize_payment_error(&self, error: &anyhow::Error) -> PaymentErrorCategory {
        let error_msg = error.to_string().to_lowercase();
        
        if error_msg.contains("insufficient") || error_msg.contains("balance") {
            PaymentErrorCategory::InsufficientFunds
        } else if error_msg.contains("trustline") || error_msg.contains("trust") {
            PaymentErrorCategory::MissingTrustline
        } else if error_msg.contains("wallet") || error_msg.contains("key") {
            PaymentErrorCategory::WalletNotConfigured
        } else if error_msg.contains("sponsor") {
            PaymentErrorCategory::SponsorUnavailable
        } else if error_msg.contains("network") || error_msg.contains("timeout") {
            PaymentErrorCategory::NetworkError
        } else if error_msg.contains("validat") {
            PaymentErrorCategory::ValidationFailed
        } else {
            PaymentErrorCategory::Unknown
        }
    }

    /// Auto-create USDC trustline if needed
    pub async fn ensure_usdc_trustline(&self, user: &User) -> Result<Option<String>> {
        self.validate_user_wallet_config(user)?;
        
        let public_key = user.stellar_public_key.as_ref().unwrap();
        
        // Check if trustline already exists
        if self.stellar.has_usdc_trustline(public_key).await? {
            info!("User {} already has USDC trustline", user.id);
            return Ok(None);
        }

        info!("🤝 Auto-creating USDC trustline for user {}", user.id);

        // Decrypt user's secret key
        let encrypted_secret = user.stellar_secret_key_encrypted.as_ref().unwrap();
        
        // Create trustline (self-funded for now)
        let tx_hash = self.stellar.create_usdc_trustline(encrypted_secret).await?;
        
        info!("✅ USDC trustline created for user {}: {}", user.id, tx_hash);
        Ok(Some(tx_hash))
    }

    // Private helper methods

    /// Pre-payment validation to catch issues early
    async fn pre_payment_validation(
        &self,
        user: &User,
        fee_calculation: &FeeCalculation,
    ) -> Result<()> {
        // Validate user wallet configuration
        self.validate_user_wallet_config(user)?;

        // Validate amount
        if fee_calculation.total_user_pays <= 0.0 {
            return Err(anyhow!("Payment amount must be greater than zero"));
        }

        if fee_calculation.total_user_pays > 100_000.0 {
            return Err(anyhow!("Payment amount exceeds maximum limit"));
        }

        // Validate platform wallet exists
        let platform_wallet = self.get_platform_wallet()?;
        if !self.stellar.is_valid_public_key(&platform_wallet) {
            return Err(anyhow!("Invalid platform wallet configuration"));
        }

        Ok(())
    }

    /// Validate user has a properly configured Stellar wallet
    fn validate_user_wallet_config(&self, user: &User) -> Result<()> {
        if user.stellar_public_key.is_none() {
            return Err(anyhow!("User has no Stellar public key"));
        }

        if user.stellar_secret_key_encrypted.is_none() {
            return Err(anyhow!("User has no encrypted secret key"));
        }

        let public_key = user.stellar_public_key.as_ref().unwrap();
        if !self.stellar.is_valid_public_key(public_key) {
            return Err(anyhow!("Invalid Stellar public key format"));
        }

        Ok(())
    }

    /// Securely decrypt user's secret key
    fn decrypt_user_secret_key(&self, user: &User) -> Result<String> {
        let encrypted_secret = user
            .stellar_secret_key_encrypted
            .as_ref()
            .ok_or_else(|| anyhow!("User has no encrypted secret key"))?;

        self.crypto_service
            .decrypt_secret_key(encrypted_secret)
            .map_err(|e| {
                error!("Failed to decrypt secret key for user {}: {}", user.id, e);
                anyhow!("Failed to decrypt wallet credentials")
            })
    }
}