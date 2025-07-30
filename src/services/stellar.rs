use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use log::{error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::env;
use std::rc::Rc;

use soroban_client::{
    account::{Account, AccountBehavior},
    asset::{Asset, AssetBehavior},
    keypair::{Keypair, KeypairBehavior},
    network::{NetworkPassphrase, Networks},
    operation::Operation,
    transaction::{Transaction, TransactionBehavior},
    transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
    xdr::{Limits, WriteXdr},
};

#[derive(Debug, Clone, Deserialize)]
pub struct Balance {
    pub asset_type: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    pub balance: String,
}

#[derive(Debug, Deserialize)]
struct HorizonAccountResponse {
    sequence: String,
    account_id: String,
    balances: Vec<Balance>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionRecord {
    pub id: String,
    pub hash: String,
    pub successful: bool,
    pub source_account: String,
    pub fee_charged: String,
    pub created_at: String,
    pub operation_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct TransactionOperationRecord {
    #[serde(rename = "type")]
    pub operation_type: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub amount: Option<String>,
    pub asset_type: Option<String>,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionDetails {
    pub id: String,
    pub hash: String,
    pub successful: bool,
    pub source_account: String,
    pub fee_charged: String,
    pub created_at: String,
    pub memo: Option<String>,
    pub memo_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitTransactionResponse {
    pub hash: String,
    pub successful: bool,
    pub result_xdr: Option<String>,
    pub envelope_xdr: Option<String>,
}

#[derive(Debug)]
pub struct SponsoredPaymentResult {
    pub transaction_hash: String,
    pub gas_fee_xlm: f64,
    pub sponsor_account_used: String,
    pub usdc_amount_sent: f64,
}

#[derive(Debug, Clone)]
pub struct OrganizerPaymentResult {
    pub transaction_hash: String,
    pub usdc_amount_sent: f64,
    pub gas_fee_xlm: f64,
}

pub struct StellarService {
    horizon_url: String,
    is_testnet: bool,
    client: Client,
    network_passphrase: String,
    base_fee: u32,
    usdc_issuer: String,
}

impl StellarService {
    pub fn new() -> Result<Self> {
        let network_str = env::var("STELLAR_NETWORK").unwrap_or_else(|_| "testnet".to_string());
        let is_testnet = network_str != "mainnet";

        let horizon_url = if is_testnet {
            "https://horizon-testnet.stellar.org".to_string()
        } else {
            "https://horizon.stellar.org".to_string()
        };

        let network_passphrase = if is_testnet {
            Networks::testnet().to_string()
        } else {
            Networks::public().to_string()
        };

        let usdc_issuer = env::var("TESTNET_USDC_ISSUER")
            .expect("TESTNET_USDC_ISSUER must be set in environment");

        info!(
            "Connected to Stellar {} network ({})",
            if is_testnet { "testnet" } else { "mainnet" },
            horizon_url
        );

        Ok(Self {
            horizon_url,
            is_testnet,
            client: Client::new(),
            network_passphrase,
            base_fee: 100_000,
            usdc_issuer,
        })
    }

    pub async fn create_asset_trustline(
        &self,
        account_secret: &str,
        asset_code: &str,
        issuer_public_key: &str,
    ) -> Result<String> {
        info!(
            "🤝 Creating trustline for asset {} from issuer {}",
            asset_code, issuer_public_key
        );

        // Validate inputs
        if asset_code.is_empty() {
            return Err(anyhow!("Asset code cannot be empty"));
        }

        if !self.is_valid_public_key(issuer_public_key) {
            return Err(anyhow!(
                "Invalid issuer public key format: {}",
                issuer_public_key
            ));
        }

        let account_keypair = Keypair::from_secret(account_secret)
            .map_err(|e| anyhow!("Invalid account secret key: {:?}", e))?;

        let sequence = self
            .get_account_sequence(&account_keypair.public_key())
            .await
            .map_err(|e| anyhow!("Failed to get account sequence: {}", e))?;

        let account = Account::new(&account_keypair.public_key(), &sequence)
            .map_err(|e| anyhow!("Failed to create account object: {:?}", e))?;

        // Create asset
        let asset = Asset::new(asset_code, Some(issuer_public_key))
            .map_err(|e| anyhow!("Failed to create asset {}: {:?}", asset_code, e))?;

        // Create change trust operation
        let operation = Operation::new()
            .change_trust(asset, None)
            .map_err(|e| anyhow!("Failed to create change trust operation: {:?}", e))?;

        // Build transaction (without fee sponsorship for trustlines)
        let mut transaction = TransactionBuilder::new(
            Rc::new(RefCell::new(account)),
            &self.network_passphrase,
            None, // No time bounds for trustline creation
        )
        .add_operation(operation)
        .fee(self.base_fee)
        .add_memo(&format!("Trustline for {} asset", asset_code))
        .build();

        transaction.sign(&[account_keypair]);
        let tx_hash = self
            .submit_transaction(&transaction)
            .await
            .map_err(|e| anyhow!("Failed to submit trustline transaction: {}", e))?;

        info!(
            "✅ Trustline created successfully for {}: {}",
            asset_code, tx_hash
        );
        Ok(tx_hash)
    }

    /// Create USDC trustline
    pub async fn create_usdc_trustline(&self, account_secret: &str) -> Result<String> {
        info!("🤝 Creating USDC trustline using generic method");
        self.create_asset_trustline(account_secret, "USDC", &self.usdc_issuer)
            .await
    }

    // ===== USDC ASSET METHODS =====

    pub fn get_usdc_asset(&self) -> Result<Asset> {
        Asset::new("USDC", Some(&self.usdc_issuer))
            .map_err(|e| anyhow!("Failed to create USDC asset: {:?}", e))
    }

    /// Get USDC balance for an account
    pub async fn get_usdc_balance(&self, public_key: &str) -> Result<f64> {
        let balances = self.get_account_balances(public_key).await?;

        for balance in balances {
            if balance.asset_type == "credit_alphanum4"
                && balance.asset_code.as_deref() == Some("USDC")
                && balance.asset_issuer.as_deref() == Some(&self.usdc_issuer)
            {
                return Ok(balance.balance.parse::<f64>()?);
            }
        }

        Err(anyhow!(
            "No USDC balance found - account may need USDC trustline"
        ))
    }

    /// Create USDC trustline for an account
    // pub async fn create_usdc_trustline(&self, account_secret: &str) -> Result<String> {
    //     info!("🤝 Creating USDC trustline for account");

    //     let keypair = Keypair::from_secret(account_secret)
    //         .map_err(|e| anyhow!("Invalid secret key: {:?}", e))?;

    //     let sequence = self.get_account_sequence(&keypair.public_key()).await?;
    //     let account = Account::new(&keypair.public_key(), &sequence)
    //         .map_err(|e| anyhow!("Failed to create account object: {:?}", e))?;

    //     let usdc_asset = self.get_usdc_asset()?;

    //     let operation = Operation::new()
    //         .change_trust(usdc_asset, None)
    //         .map_err(|e| anyhow!("Failed to create change trust operation: {:?}", e))?;

    //     let mut transaction = TransactionBuilder::new(
    //         Rc::new(RefCell::new(account)),
    //         &self.network_passphrase,
    //         None,
    //     )
    //     .add_operation(operation)
    //     .fee(self.base_fee)
    //     .add_memo("USDC Trustline Creation")
    //     .build();

    //     transaction.sign(&[keypair]);
    //     let tx_hash = self.submit_transaction(&transaction).await?;

    //     info!("✅ USDC trustline created successfully: {}", tx_hash);
    //     Ok(tx_hash)
    // }

    // pub fn create_new_account(&self) -> Result<(String, String)> {
    //     info!("🆕 Creating new Stellar account (generating keypair)");

    //     let (public_key, secret_key) = self.generate_keypair()?;

    //     info!("✅ New account created: {}", public_key);
    //     info!("💡 Account is not active until funded. Use fund_testnet_account() for testnet.");

    //     Ok((public_key, secret_key))
    // }

    pub fn generate_keypair(&self) -> Result<(String, String)> {
        let keypair = Keypair::random()
            .map_err(|e| anyhow!("Failed to generate Stellar keypair: {:?}", e))?;

        let public_key = keypair.public_key();
        let secret_key = keypair
            .secret_key()
            .map_err(|e| anyhow!("Failed to get secret key: {:?}", e))?;

        info!("Generated new Stellar keypair: {}", public_key);
        Ok((public_key, secret_key))
    }

    pub async fn get_account_sequence(&self, public_key: &str) -> Result<String> {
        let url = format!("{}/accounts/{}", self.horizon_url, public_key);

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to get account sequence for {}: HTTP {}: {}",
                public_key,
                status,
                error_text
            ));
        }

        let account_data: HorizonAccountResponse = response.json().await?;
        Ok(account_data.sequence)
    }

    pub async fn get_account_balances(&self, public_key: &str) -> Result<Vec<Balance>> {
        let url = format!("{}/accounts/{}", self.horizon_url, public_key);

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to get account: HTTP {}: {}",
                status,
                error_text
            ));
        }

        let account_data: HorizonAccountResponse = response.json().await?;
        Ok(account_data.balances)
    }

    pub async fn get_xlm_balance(&self, public_key: &str) -> Result<f64> {
        let balances = self.get_account_balances(public_key).await?;

        for balance in balances {
            if balance.asset_type == "native" {
                return Ok(balance.balance.parse::<f64>()?);
            }
        }

        Err(anyhow!("No native XLM balance found"))
    }

    pub async fn send_payment(
        &self,
        user_secret: &str,
        recipient_public: &str,
        usdc_amount: &str,
        sponsor_secret: &str,
    ) -> Result<SponsoredPaymentResult> {
        info!(
            "💳 Sending sponsored USDC payment: {} USDC from user to {}",
            usdc_amount, recipient_public
        );

        let amount_f64: f64 = usdc_amount
            .parse()
            .map_err(|e| anyhow!("Invalid USDC amount '{}': {}", usdc_amount, e))?;
        let stroops = (amount_f64 * 10_000_000.0) as i64;

        if stroops <= 0 {
            return Err(anyhow!("Payment amount must be greater than 0"));
        }

        let user_keypair = Keypair::from_secret(user_secret)
            .map_err(|e| anyhow!("Invalid user secret key: {:?}", e))?;
        let sponsor_keypair = Keypair::from_secret(sponsor_secret)
            .map_err(|e| anyhow!("Invalid sponsor secret key: {:?}", e))?;
        let sponsor_public_key = sponsor_keypair.public_key();

        if !self.is_valid_public_key(recipient_public) {
            return Err(anyhow!(
                "Invalid recipient public key: {}",
                recipient_public
            ));
        }

        // Get sequence for user account
        let user_sequence = self
            .get_account_sequence(&user_keypair.public_key())
            .await
            .map_err(|e| anyhow!("Failed to get user account sequence: {}", e))?;
        let user_account = Account::new(&user_keypair.public_key(), &user_sequence)
            .map_err(|e| anyhow!("Failed to create user account object: {:?}", e))?;

        let usdc_asset = self.get_usdc_asset()?;

        // Create USDC payment operation
        let payment_operation = Operation::new()
            .payment(recipient_public, &usdc_asset, stroops)
            .map_err(|e| anyhow!("Failed to create payment operation: {:?}", e))?;

        // Build transaction with fee sponsorship
        let mut transaction = TransactionBuilder::new(
            Rc::new(RefCell::new(user_account)),
            &self.network_passphrase,
            None,
        )
        .add_operation(payment_operation)
        .fee(self.base_fee * 2) // Higher fee for sponsored transactions
        .add_memo(&format!("USDC Payment: {}", usdc_amount))
        .build();

        // Sign with both user and sponsor
        transaction.sign(&[user_keypair, sponsor_keypair]);

        // Submit transaction
        let tx_hash = self
            .submit_transaction(&transaction)
            .await
            .map_err(|e| anyhow!("Failed to submit sponsored payment: {}", e))?;

        // Calculate gas fee paid by sponsor
        let gas_fee_xlm = (self.base_fee * 2) as f64 / 10_000_000.0;

        let result = SponsoredPaymentResult {
            transaction_hash: tx_hash.clone(),
            gas_fee_xlm,
            sponsor_account_used: sponsor_public_key,
            usdc_amount_sent: amount_f64,
        };

        info!("✅ Sponsored USDC payment successful: {}", tx_hash);
        Ok(result)
    }

    /// Send USDC payment with encrypted user key (backward compatibility)
    pub async fn send_payment_with_encrypted_key(
        &self,
        user_secret_key_encrypted: &str,
        receiver_public_key: &str,
        usdc_amount: &str,
        sponsor_secret: &str,
    ) -> Result<SponsoredPaymentResult> {
        let crypto = crate::services::crypto::KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to create crypto service: {}", e))?;
        let decrypted_secret = crypto
            .decrypt_secret_key(user_secret_key_encrypted)
            .map_err(|e| anyhow!("Failed to decrypt secret key: {}", e))?;

        self.send_payment(
            &decrypted_secret,
            receiver_public_key,
            usdc_amount,
            sponsor_secret,
        )
        .await
    }

    pub async fn send_organizer_payment(
        &self,
        platform_secret: &str,
        recipient_public: &str,
        usdc_amount: &str,
    ) -> Result<OrganizerPaymentResult> {
        info!(
            "💰 Sending platform USDC payment: {} USDC to {}",
            usdc_amount, recipient_public
        );

        let amount_f64: f64 = usdc_amount
            .parse()
            .map_err(|e| anyhow!("Invalid USDC amount '{}': {}", usdc_amount, e))?;
        let stroops = (amount_f64 * 10_000_000.0) as i64;

        if stroops <= 0 {
            return Err(anyhow!("Payment amount must be greater than 0"));
        }

        let platform_keypair = Keypair::from_secret(platform_secret)
            .map_err(|e| anyhow!("Invalid platform secret key: {:?}", e))?;

        if !self.is_valid_public_key(recipient_public) {
            return Err(anyhow!(
                "Invalid recipient public key: {}",
                recipient_public
            ));
        }

        // Get sequence for platform account
        let platform_sequence = self
            .get_account_sequence(&platform_keypair.public_key())
            .await?;
        let platform_account = Account::new(&platform_keypair.public_key(), &platform_sequence)
            .map_err(|e| anyhow!("Failed to create platform account object: {:?}", e))?;

        let usdc_asset = self.get_usdc_asset()?;

        // Create USDC payment operation
        let payment_operation = Operation::new()
            .payment(recipient_public, &usdc_asset, stroops)
            .map_err(|e| anyhow!("Failed to create payment operation: {:?}", e))?;

        // Build transaction
        let mut transaction = TransactionBuilder::new(
            Rc::new(RefCell::new(platform_account)),
            &self.network_passphrase,
            None,
        )
        .add_operation(payment_operation)
        .fee(self.base_fee)
        .add_memo(&format!("Event Payout: {} USDC", usdc_amount))
        .build();

        // Sign with platform key
        transaction.sign(&[platform_keypair]);

        // Submit transaction
        let tx_hash = self.submit_transaction(&transaction).await?;

        // Calculate gas fee paid by platform
        let gas_fee_xlm = self.base_fee as f64 / 10_000_000.0;

        let result = OrganizerPaymentResult {
            transaction_hash: tx_hash.clone(),
            usdc_amount_sent: amount_f64,
            gas_fee_xlm,
        };

        info!("✅ Platform payment successful: {}", tx_hash);
        Ok(result)
    }

    async fn submit_transaction(&self, transaction: &Transaction) -> Result<String> {
        // Convert tx to XDR envelope
        let transaction_envelope = transaction
            .to_envelope()
            .map_err(|e| anyhow!("Failed to create transaction envelope: {:?}", e))?;

        // Get tx hash for tracking
        let transaction_hash = hex::encode(transaction.hash());

        info!(
            "Submitting transaction to Stellar network: {}",
            transaction_hash
        );

        // Serialize tx envelope to XDR base64
        let xdr_bytes = transaction_envelope
            .to_xdr(Limits::none())
            .map_err(|e| anyhow!("Failed to serialize transaction to XDR: {:?}", e))?;

        let xdr_string = base64::engine::general_purpose::STANDARD.encode(xdr_bytes);

        info!("📦 XDR encoded, length: {} bytes", xdr_string.len());

        let submit_url = format!("{}/transactions", self.horizon_url);

        let params = [("tx", xdr_string.as_str())];

        let response = self
            .client
            .post(&submit_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            let result: SubmitTransactionResponse = response.json().await?;

            if result.successful {
                info!(
                    "✅ REAL transaction submitted successfully to Stellar network: {}",
                    result.hash
                );
                Ok(result.hash)
            } else {
                error!("❌ Transaction failed on Stellar network: {}", result.hash);
                Err(anyhow!("Transaction submission failed: {}", result.hash))
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Horizon API error ({}): {}", status, error_text);
            Err(anyhow!(
                "Failed to submit transaction to Horizon: {}",
                error_text
            ))
        }
    }

    pub async fn verify_transaction(&self, tx_hash: &str) -> Result<bool> {
        info!("Verifying transaction: {}", tx_hash);

        let transaction_url = format!("{}/transactions/{}", self.horizon_url, tx_hash);

        match self.client.get(&transaction_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let transaction: TransactionDetails = response.json().await?;

                    info!(
                        "Transaction verification result: successful={}, hash={}",
                        transaction.successful, transaction.hash
                    );

                    Ok(transaction.successful)
                } else if response.status() == 404 {
                    warn!("Transaction not found: {}", tx_hash);
                    Ok(false)
                } else {
                    warn!(
                        "Transaction verification failed with status {}: {}",
                        response.status(),
                        tx_hash
                    );
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to verify transaction {}: {}", tx_hash, e);
                Ok(false)
            }
        }
    }

    pub async fn verify_payment(
        &self,
        tx_hash: &str,
        expected_from: &str,
        expected_to: &str,
        expected_amount: &str,
    ) -> Result<bool> {
        info!(
            "Verifying payment: {} from {} to {} amount {}",
            tx_hash, expected_from, expected_to, expected_amount
        );

        if !self.verify_transaction(tx_hash).await? {
            return Ok(false);
        }

        let operations_url = format!("{}/transactions/{}/operations", self.horizon_url, tx_hash);

        match self.client.get(&operations_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let operations_data: Value = response.json().await?;

                    if let Some(records) = operations_data["_embedded"]["records"].as_array() {
                        for record in records {
                            if let Ok(operation) =
                                serde_json::from_value::<TransactionOperationRecord>(record.clone())
                            {
                                if operation.operation_type == "payment" {
                                    let from_matches =
                                        operation.from.as_deref() == Some(expected_from);
                                    let to_matches = operation.to.as_deref() == Some(expected_to);
                                    let amount_matches =
                                        operation.amount.as_deref() == Some(expected_amount);

                                    if from_matches && to_matches && amount_matches {
                                        info!("Payment verification successful: all details match");
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }

                    warn!("Payment verification failed: details don't match expected values");
                    Ok(false)
                } else {
                    error!("Failed to fetch transaction operations for {}", tx_hash);
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to verify payment details for {}: {}", tx_hash, e);
                Ok(false)
            }
        }
    }

    pub async fn get_transaction_details(
        &self,
        tx_hash: &str,
    ) -> Result<Option<TransactionDetails>> {
        let transaction_url = format!("{}/transactions/{}", self.horizon_url, tx_hash);

        match self.client.get(&transaction_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let transaction: TransactionDetails = response.json().await?;
                    Ok(Some(transaction))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                error!("Failed to get transaction details for {}: {}", tx_hash, e);
                Err(anyhow!("Network error: {}", e))
            }
        }
    }

    pub async fn get_transaction_history(
        &self,
        public_key: &str,
        limit: Option<u32>,
    ) -> Result<Vec<TransactionRecord>> {
        let limit = limit.unwrap_or(10);
        let url = format!(
            "{}/accounts/{}/transactions?order=desc&limit={}",
            self.horizon_url, public_key, limit
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let data: Value = response.json().await?;

            if let Some(records) = data["_embedded"]["records"].as_array() {
                let mut transactions = Vec::new();
                for record in records {
                    if let Ok(tx) = serde_json::from_value::<TransactionRecord>(record.clone()) {
                        transactions.push(tx);
                    }
                }
                Ok(transactions)
            } else {
                Ok(Vec::new())
            }
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to get transaction history: {}", error_text))
        }
    }

    // This allows the receiver to hold the custom asset (NFT).
    // pub async fn create_trustline(
    //     &self,
    //     receiver_secret: &str,
    //     asset_code: &str,
    //     issuer_public: &str,
    // ) -> Result<String> {
    //     info!(
    //         "🤝 Creating trustline for asset {} from issuer {}",
    //         asset_code, issuer_public
    //     );

    //     let receiver_keypair = Keypair::from_secret(receiver_secret)
    //         .map_err(|e| anyhow!("Invalid receiver secret key: {:?}", e))?;

    //     let sequence = self
    //         .get_account_sequence(&receiver_keypair.public_key())
    //         .await?;
    //     let receiver_account = Account::new(&receiver_keypair.public_key(), &sequence)
    //         .map_err(|e| anyhow!("Failed to create account object: {:?}", e))?;

    //     // Create custom asset
    //     let custom_asset = Asset::new(asset_code, Some(issuer_public))
    //         .map_err(|e| anyhow!("Failed to create custom asset: {:?}", e))?;

    //     // Create change trust operation
    //     let operation = Operation::new()
    //         .change_trust(custom_asset, None)
    //         .map_err(|e| anyhow!("Failed to create change trust operation: {:?}", e))?;

    //     let mut transaction = TransactionBuilder::new(
    //         Rc::new(RefCell::new(receiver_account)),
    //         &self.network_passphrase,
    //         None,
    //     )
    //     .add_operation(operation)
    //     .fee(self.base_fee)
    //     .add_memo(&format!("Trustline for {}", asset_code))
    //     .build();

    //     transaction.sign(&[receiver_keypair]);
    //     let tx_hash = self.submit_transaction(&transaction).await?;

    //     info!("✅ Trustline created successfully: {}", tx_hash);
    //     Ok(tx_hash)
    // }

    // The receiver must have a trustline for this asset first.
    pub async fn issue_custom_asset(
        &self,
        issuer_secret: &str,
        receiver_public: &str,
        asset_code: &str,
        amount: &str,
    ) -> Result<String> {
        info!(
            "🪙 Issuing {} units of {} from issuer to {}",
            amount, asset_code, receiver_public
        );

        let asset_amount: f64 = amount.parse()?;
        let stroops = (asset_amount * 10_000_000.0) as i64;

        let issuer_keypair = Keypair::from_secret(issuer_secret)
            .map_err(|e| anyhow!("Invalid issuer secret key: {:?}", e))?;

        let sequence = self
            .get_account_sequence(&issuer_keypair.public_key())
            .await?;
        let issuer_account = Account::new(&issuer_keypair.public_key(), &sequence)
            .map_err(|e| anyhow!("Failed to create account object: {:?}", e))?;

        // Create custom asset
        let custom_asset = Asset::new(asset_code, Some(&issuer_keypair.public_key()))
            .map_err(|e| anyhow!("Failed to create custom asset: {:?}", e))?;

        // Create payment op to issues the asset
        let operation = Operation::new()
            .payment(receiver_public, &custom_asset, stroops)
            .map_err(|e| anyhow!("Failed to create payment operation: {:?}", e))?;

        let mut transaction = TransactionBuilder::new(
            Rc::new(RefCell::new(issuer_account)),
            &self.network_passphrase,
            None,
        )
        .add_operation(operation)
        .fee(self.base_fee)
        .add_memo(&format!("Issue {} {}", amount, asset_code))
        .build();

        transaction.sign(&[issuer_keypair]);
        let tx_hash = self.submit_transaction(&transaction).await?;

        info!("✅ Asset issued successfully: {}", tx_hash);
        Ok(tx_hash)
    }

    // process for creating an NFT on Stellar.
    pub async fn create_nft(
        &self,
        issuer_secret: &str,
        receiver_secret: &str,
        nft_code: &str,
    ) -> Result<(String, String)> {
        info!("🎨 Creating NFT {} - complete process", nft_code);

        let issuer_keypair = Keypair::from_secret(issuer_secret)
            .map_err(|e| anyhow!("Invalid issuer secret key: {:?}", e))?;
        let receiver_keypair = Keypair::from_secret(receiver_secret)
            .map_err(|e| anyhow!("Invalid receiver secret key: {:?}", e))?;

        info!("📝 Step 1: Creating trustline...");
        let trustline_tx = self
            .create_asset_trustline(receiver_secret, nft_code, &issuer_keypair.public_key())
            .await?;

        info!("💰 Step 2: Issuing NFT...");
        let issue_tx = self
            .issue_custom_asset(
                issuer_secret,
                &receiver_keypair.public_key(),
                nft_code,
                "1.0",
            )
            .await?;

        info!("✅ NFT {} created successfully!", nft_code);
        info!("   Trustline TX: {}", trustline_tx);
        info!("   Issue TX: {}", issue_tx);

        Ok((trustline_tx, issue_tx))
    }

    // new owner must have a trustline for this asset.
    pub async fn transfer_nft_with_amount(
        &self,
        sender_secret: &str,
        receiver_public: &str,
        nft_code: &str,
        issuer_public: &str,
        amount: &str,
    ) -> Result<String> {
        info!(
            "🔄 Transferring {} units of NFT {} from current owner to {}",
            amount, nft_code, receiver_public
        );

        let asset_amount: f64 = amount.parse()?;
        let stroops = (asset_amount * 10_000_000.0) as i64;

        let sender_keypair = Keypair::from_secret(sender_secret)
            .map_err(|e| anyhow!("Invalid sender secret key: {:?}", e))?;

        let sequence = self
            .get_account_sequence(&sender_keypair.public_key())
            .await?;
        let sender_account = Account::new(&sender_keypair.public_key(), &sequence)
            .map_err(|e| anyhow!("Failed to create account object: {:?}", e))?;

        // Create custom asset ref
        let nft_asset = Asset::new(nft_code, Some(issuer_public))
            .map_err(|e| anyhow!("Failed to create NFT asset: {:?}", e))?;

        // Create payment op for the NFT transfer
        let operation = Operation::new()
            .payment(receiver_public, &nft_asset, stroops)
            .map_err(|e| anyhow!("Failed to create NFT transfer operation: {:?}", e))?;

        let mut transaction = TransactionBuilder::new(
            Rc::new(RefCell::new(sender_account)),
            &self.network_passphrase,
            None,
        )
        .add_operation(operation)
        .fee(self.base_fee)
        .add_memo(&format!("Transfer NFT {}", nft_code))
        .build();

        transaction.sign(&[sender_keypair]);
        let tx_hash = self.submit_transaction(&transaction).await?;

        info!("✅ NFT transferred successfully: {}", tx_hash);
        Ok(tx_hash)
    }

    pub async fn transfer_nft(
        &self,
        sender_secret: &str,
        receiver_public: &str,
        nft_code: &str,
        issuer_public: &str,
    ) -> Result<String> {
        self.transfer_nft_with_amount(
            sender_secret,
            receiver_public,
            nft_code,
            issuer_public,
            "1.0",
        )
        .await
    }

    /// Creates trustline for NFT and then transfers it (for new NFT owners).
    pub async fn transfer_nft_with_trustline(
        &self,
        sender_secret: &str,
        receiver_secret: &str,
        nft_code: &str,
        issuer_public: &str,
        amount: &str,
    ) -> Result<(String, String)> {
        info!(
            "🎯 Complete NFT transfer with trustline creation for {}",
            nft_code
        );

        let receiver_keypair = Keypair::from_secret(receiver_secret)
            .map_err(|e| anyhow!("Invalid receiver secret key: {:?}", e))?;

        info!("📝 Step 1: Creating trustline for receiver...");
        let trustline_tx = self
            .create_asset_trustline(receiver_secret, nft_code, issuer_public)
            .await?;

        info!("🔄 Step 2: Transferring NFT...");
        let transfer_tx = self
            .transfer_nft_with_amount(
                sender_secret,
                &receiver_keypair.public_key(),
                nft_code,
                issuer_public,
                amount,
            )
            .await?;

        info!("✅ NFT transfer completed!");
        info!("   Trustline TX: {}", trustline_tx);
        info!("   Transfer TX: {}", transfer_tx);

        Ok((trustline_tx, transfer_tx))
    }

    pub fn get_network_info(&self) -> (String, bool) {
        (self.horizon_url.clone(), self.is_testnet)
    }

    pub async fn get_account_id(&self, public_key: &str) -> Result<String> {
        let url = format!("{}/accounts/{}", self.horizon_url, public_key);

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to get account: HTTP {}: {}",
                status,
                error_text
            ));
        }

        let account_data: HorizonAccountResponse = response.json().await?;
        Ok(account_data.account_id)
    }

    pub fn is_valid_public_key(&self, public_key: &str) -> bool {
        if !public_key.starts_with('G') || public_key.len() != 56 {
            return false;
        }

        self.is_valid_base32(&public_key[1..])
    }

    pub fn is_valid_secret_key(&self, secret_key: &str) -> bool {
        if !secret_key.starts_with('S') || secret_key.len() != 56 {
            return false;
        }

        self.is_valid_base32(&secret_key[1..])
    }

    fn is_valid_base32(&self, s: &str) -> bool {
        s.chars()
            .all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c))
    }

    pub async fn fund_testnet_account(&self, public_key: &str) -> Result<String> {
        if !self.is_testnet {
            return Err(anyhow!("Friendbot funding is only available on testnet"));
        }

        if !self.is_valid_public_key(public_key) {
            return Err(anyhow!("Invalid public key format"));
        }

        info!("🤖 Funding testnet account {} using friendbot", public_key);

        let friendbot_url = format!("https://friendbot.stellar.org/?addr={}", public_key);

        let response = self.client.get(&friendbot_url).send().await?;

        if response.status().is_success() {
            let response_text = response.text().await?;

            if let Ok(json_response) = serde_json::from_str::<serde_json::Value>(&response_text) {
                if let Some(hash) = json_response.get("hash").and_then(|h| h.as_str()) {
                    info!("✅ Account funded successfully! Transaction: {}", hash);
                    return Ok(hash.to_string());
                }
            }

            info!("✅ Account funded successfully!");
            Ok("FRIENDBOT_SUCCESS".to_string())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Friendbot funding failed: {}", error_text))
        }
    }

    pub async fn issue_nft_asset(
        &self,
        issuer_secret: &str,
        asset_code: &str,
        receiver_secret: &str,
    ) -> Result<(String, String)> {
        info!("🎨 Issuing NFT asset {} (using create_nft)", asset_code);
        self.create_nft(issuer_secret, receiver_secret, asset_code)
            .await
    }

    pub async fn verify_nft_ownership(
        &self,
        account_public: &str,
        nft_code: &str,
        issuer_public: &str,
    ) -> Result<bool> {
        info!(
            "🔍 Verifying NFT ownership: {} owns {} from {}",
            account_public, nft_code, issuer_public
        );

        let balances = self.get_account_balances(account_public).await?;

        for balance in balances {
            if balance.asset_type != "native" {
                if let (Some(code), Some(issuer)) = (&balance.asset_code, &balance.asset_issuer) {
                    if code == nft_code && issuer == issuer_public {
                        let amount: f64 = balance.balance.parse().unwrap_or(0.0);
                        info!(
                            "✅ NFT ownership verified: {} owns {} units",
                            account_public, amount
                        );
                        return Ok(amount > 0.0);
                    }
                }
            }
        }

        info!("❌ NFT ownership not found");
        Ok(false)
    }

    pub async fn transfer_nft_simple(
        &self,
        sender_secret: &str,
        receiver_public: &str,
        nft_code: &str,
        issuer_public: &str,
    ) -> Result<String> {
        self.transfer_nft(sender_secret, receiver_public, nft_code, issuer_public)
            .await
    }

    // This delegates to the event service for proper business logic separation
    // pub async fn process_refund(
    //     &self,
    //     refund_secret_key: &str,
    //     user_public_key: &str,
    //     refund_amount: &str,
    // ) -> Result<String> {
    //     info!("💸 Processing refund via StellarService (delegating to payment logic)");

    //     // For now, just use direct payment - in the future this could delegate to EventService
    //     self.send_payment(refund_secret_key, user_public_key, refund_amount)
    //         .await
    // }

    pub async fn has_stellar_wallet(&self, public_key: Option<&str>) -> Result<bool> {
        match public_key {
            Some(key) if !key.is_empty() => {
                if self.is_valid_public_key(key) {
                    // Try to fetch account from Stellar network to verify it exists
                    match self.get_account_balances(key).await {
                        Ok(_) => {
                            info!("✅ Valid Stellar wallet found: {}", key);
                            Ok(true)
                        }
                        Err(_) => {
                            // Account doesn't exist on network yet, but key format is valid
                            info!("⚠️ Valid Stellar key but account not funded: {}", key);
                            Ok(true) // Still consider this as "has wallet" since they can receive funds
                        }
                    }
                } else {
                    info!("❌ Invalid Stellar public key format: {}", key);
                    Ok(false)
                }
            }
            _ => {
                info!("❌ No Stellar public key provided");
                Ok(false)
            }
        }
    }

    pub fn validate_user_wallet(
        &self,
        stellar_public_key: Option<&str>,
        stellar_secret_key_encrypted: Option<&str>,
    ) -> Result<bool> {
        let has_public = stellar_public_key
            .map(|key| !key.is_empty() && self.is_valid_public_key(key))
            .unwrap_or(false);

        let has_encrypted_secret = stellar_secret_key_encrypted
            .map(|key| !key.is_empty())
            .unwrap_or(false);

        if !has_public {
            info!("❌ User validation failed: Missing or invalid public key");
            return Ok(false);
        }

        if !has_encrypted_secret {
            info!("❌ User validation failed: Missing encrypted secret key");
            return Ok(false);
        }

        info!("✅ User wallet validation passed");
        Ok(true)
    }

    // this is what ticket purchase should use instead of direct field checks
    pub fn can_make_purchases(
        &self,
        stellar_public_key: Option<&str>,
        stellar_secret_key_encrypted: Option<&str>,
    ) -> bool {
        self.validate_user_wallet(stellar_public_key, stellar_secret_key_encrypted)
            .unwrap_or(false)
    }

    //validate wallet and get balance in one call
    pub async fn get_wallet_info(&self, public_key: Option<&str>) -> Result<Option<(String, f64)>> {
        match public_key {
            Some(key) if !key.is_empty() && self.is_valid_public_key(key) => {
                match self.get_xlm_balance(key).await {
                    Ok(balance) => Ok(Some((key.to_string(), balance))),
                    Err(_) => {
                        // Account exists but not funded? return 0 balance
                        Ok(Some((key.to_string(), 0.0)))
                    }
                }
            }
            _ => Ok(None),
        }
    }

    pub async fn pay_event_organizer(
        &self,
        platform_secret_key: &str,
        organizer_wallet: &str,
        total_revenue_usdc: f64,
        platform_fee_percentage: f64,
    ) -> Result<String> {
        info!(
            "💰 Paying organizer: {} USDC total revenue, {}% platform fee",
            total_revenue_usdc, platform_fee_percentage
        );

        // Calculate organizer payout (revenue minus platform fee)
        let platform_fee = total_revenue_usdc * (platform_fee_percentage / 100.0);
        let organizer_payout = total_revenue_usdc - platform_fee;

        if organizer_payout <= 0.0 {
            return Err(anyhow!("Invalid payout amount: {}", organizer_payout));
        }

        // Convert to stroops
        let payout_stroops = (organizer_payout * 10_000_000.0) as i64;

        let platform_keypair = Keypair::from_secret(platform_secret_key)
            .map_err(|e| anyhow!("Invalid platform secret key: {:?}", e))?;

        let sequence = self
            .get_account_sequence(&platform_keypair.public_key())
            .await?;
        let platform_account = Account::new(&platform_keypair.public_key(), &sequence)
            .map_err(|e| anyhow!("Failed to create platform account object: {:?}", e))?;

        let usdc_asset = self.get_usdc_asset()?;

        let operation = Operation::new()
            .payment(organizer_wallet, &usdc_asset, payout_stroops)
            .map_err(|e| anyhow!("Failed to create payout operation: {:?}", e))?;

        let mut transaction = TransactionBuilder::new(
            Rc::new(RefCell::new(platform_account)),
            &self.network_passphrase,
            None,
        )
        .add_operation(operation)
        .fee(self.base_fee)
        .add_memo(&format!("Organizer Payout: {} USDC", organizer_payout))
        .build();

        transaction.sign(&[platform_keypair]);
        let tx_hash = self.submit_transaction(&transaction).await?;

        info!(
            "✅ Organizer payout successful: {} USDC sent (tx: {})",
            organizer_payout, tx_hash
        );

        Ok(tx_hash)
    }

    // ===== UTILITY METHODS =====

    /// Get current base fee from Stellar network
    pub async fn get_current_base_fee(&self) -> Result<u32> {
        let url = format!("{}/ledgers?order=desc&limit=1", self.horizon_url);

        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let data: Value = response.json().await?;

                    if let Some(records) = data["_embedded"]["records"].as_array() {
                        if let Some(latest_ledger) = records.first() {
                            if let Some(base_fee) = latest_ledger["base_fee_in_stroops"].as_u64() {
                                return Ok(base_fee as u32);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to fetch current base fee: {}", e);
            }
        }

        // Fallback to configured base fee
        Ok(self.base_fee)
    }

    /// Get public key from secret key
    pub fn get_public_key_from_secret(&self, secret_key: &str) -> Result<String> {
        let keypair =
            Keypair::from_secret(secret_key).map_err(|e| anyhow!("Invalid secret key: {:?}", e))?;
        Ok(keypair.public_key())
    }

    /// Check if user has USDC trustline
    pub async fn has_usdc_trustline(&self, public_key: &str) -> Result<bool> {
        match self.get_usdc_balance(public_key).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // No trustline or balance
        }
    }

    /// Validate that user has sufficient USDC balance for payment
    pub async fn validate_usdc_payment(
        &self,
        public_key: &str,
        required_amount: f64,
    ) -> Result<bool> {
        let balance = self.get_usdc_balance(public_key).await?;
        Ok(balance >= required_amount)
    }
}
