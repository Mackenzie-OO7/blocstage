// for onchain interactions
use anyhow::{anyhow, Result};
use log::{error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use stellar_sdk::{types::Asset, CallBuilder, Server};
use stellar_base::crypto::{KeyPair, PublicKey};

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

pub struct StellarService {
    server: Server,
    horizon_url: String,
    is_testnet: bool,
    client: Client,
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

        let server = Server::new(horizon_url.clone(), None)
            .map_err(|e| anyhow!("Failed to create Stellar server: {}", e))?;

        info!(
            "Connected to Stellar {} network",
            if is_testnet { "testnet" } else { "mainnet" }
        );

        Ok(Self {
            server,
            horizon_url,
            is_testnet,
            client: Client::new(),
        })
    }

     pub fn generate_keypair(&self) -> Result<(String, String)> {
        let keypair = KeyPair::random()
            .map_err(|e| anyhow!("Failed to generate Stellar keypair: {:?}", e))?;
        
        let public_key = keypair.public_key().account_id();
        let secret_key = keypair.secret_key().secret_seed();
        
        info!("Generated valid Stellar keypair: {}", public_key);
        
        Ok((public_key, secret_key))
    }

    pub fn is_valid_public_key(&self, public_key: &str) -> bool {
        PublicKey::from_account_id(public_key).is_ok()
    }

    pub fn is_valid_secret_key(&self, secret_key: &str) -> bool {
        KeyPair::from_secret_seed(secret_key).is_ok()
    }
    
    fn is_valid_base32(&self, s: &str) -> bool {
        s.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c))
    }

    pub async fn send_payment(
        &self,
        sender_secret_key: &str,
        receiver_public_key: &str,
        amount: &str,
    ) -> Result<String> {
        info!(
            "Initiating payment of {} XLM from {} to {}",
            amount,
            sender_secret_key.chars().take(5).collect::<String>(),
            receiver_public_key
        );

        if !self.is_valid_public_key(receiver_public_key) {
            return Err(anyhow!("Invalid receiver public key format"));
        }

        if !self.is_valid_secret_key(sender_secret_key) {
            return Err(anyhow!("Invalid sender secret key format"));
        }

        let _amount_f64: f64 = amount
            .parse()
            .map_err(|_| anyhow!("Invalid amount format"))?;

        if self.is_testnet {
            // for testnet/development simulate transaction and return mock hash
            let mock_hash =
                self.generate_mock_transaction_hash(sender_secret_key, receiver_public_key, amount);
            info!(
                "Payment simulation successful for testnet, mock hash: {}",
                mock_hash
            );
            Ok(mock_hash)
        } else {
            // mainnet: implement actual transaction building and submission
            // for now, return an error to prevent accidental mainnet usage during dev-ing
            Err(anyhow!(
                "Mainnet payments not implemented yet - use testnet for development"
            ))
        }
    }

    pub async fn send_payment_with_encrypted_key(
        &self,
        user_secret_key: &str,
        receiver_public_key: &str,
        amount: &str,
    ) -> Result<String> {
        let crypto = crate::services::crypto::KeyEncryption::new();
        let decrypted_secret = crypto.decrypt_secret_key(user_secret_key)
            .map_err(|e| anyhow!("Failed to decrypt secret key: {}", e))?;
        
        self.send_payment(&decrypted_secret, receiver_public_key, amount).await
    }

    fn generate_mock_transaction_hash(&self, sender: &str, receiver: &str, amount: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        sender.hash(&mut hasher);
        receiver.hash(&mut hasher);
        amount.hash(&mut hasher);
        chrono::Utc::now().timestamp().hash(&mut hasher);

        format!("{:016x}", hasher.finish())
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
                    // Transaction not found - check if it's a mock transaction for testing
                    if self.is_testnet && tx_hash.len() == 16 {
                        warn!(
                            "Transaction not found in Horizon (likely a mock transaction): {}",
                            tx_hash
                        );
                        // For dev-ing, assume mock transactions are valid
                        Ok(true)
                    } else {
                        warn!("Transaction not found: {}", tx_hash);
                        Ok(false)
                    }
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
                if self.is_testnet {
                    warn!(
                        "Assuming mock transaction is valid due to network error: {}",
                        tx_hash
                    );
                    Ok(true)
                } else {
                    Ok(false)
                }
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

        // For mock transactions in testnet, do a simple validation
        if self.is_testnet && tx_hash.len() == 16 {
            // Mock verification - check if the hash could have been generated from these inputs
            let expected_hash = self.generate_mock_transaction_hash(
                &format!("S{}", expected_from.trim_start_matches('G')),
                expected_to,
                expected_amount,
            );

            let matches = tx_hash == expected_hash;
            info!("Mock payment verification result: {}", matches);
            return Ok(matches);
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

    // get tx deets for debugging
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
                Err(anyhow!("Failed to fetch transaction details: {}", e))
            }
        }
    }

    pub async fn process_refund(
        &self,
        issuer_secret_key: &str,
        receiver_public_key: &str,
        amount: &str,
    ) -> Result<String> {
        info!("Processing refund of {} to {}", amount, receiver_public_key);
        let tx_hash = self
            .send_payment(issuer_secret_key, receiver_public_key, amount)
            .await?;
        info!("Refund processed successfully: {}", tx_hash);
        Ok(tx_hash)
    }

    pub async fn pay_event_organizer(
        &self,
        platform_secret_key: &str,
        organizer_public_key: &str,
        total_amount: f64,
        platform_fee_percentage: f64,
    ) -> Result<String> {
        let platform_fee = total_amount * (platform_fee_percentage / 100.0);
        let organizer_amount = total_amount - platform_fee;

        let amount_str = format!("{:.7}", organizer_amount);

        info!(
            "Paying organizer {} XLM ({}% fee: {} XLM)",
            organizer_amount, platform_fee_percentage, platform_fee
        );

        let tx_hash = self
            .send_payment(platform_secret_key, organizer_public_key, &amount_str)
            .await?;

        info!("Organizer payment successful: {}", tx_hash);
        Ok(tx_hash)
    }

    pub async fn get_account_balances(&self, public_key: &str) -> Result<Vec<Balance>> {
        match self.server.load_account(public_key) {
            Ok(account) => {
                self.get_account_balances_http(public_key).await
            }
            Err(e) => {
                warn!(
                    "Failed to load account via SDK: {}, falling back to HTTP",
                    e
                );
                self.get_account_balances_http(public_key).await
            }
        }
    }

    async fn get_account_balances_http(&self, public_key: &str) -> Result<Vec<Balance>> {
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

    // placeholder for NFT issuance
    pub async fn issue_nft_asset(
        &self,
        issuer_secret_key: &str,
        asset_code: &str,
        receiver_public_key: &str,
    ) -> Result<String> {
        info!(
            "Issuing NFT asset {} from {} to {}",
            asset_code,
            issuer_secret_key.chars().take(5).collect::<String>(),
            receiver_public_key
        );

        // for now simulate NFT creation with a special payment of 1 unit
        let amount = "1.0000000";
        let tx_hash = self
            .send_payment(issuer_secret_key, receiver_public_key, amount)
            .await?;

        info!("NFT asset {} issued successfully: {}", asset_code, tx_hash);
        Ok(tx_hash)
    }

    pub async fn transfer_nft(
        &self,
        sender_secret_key: &str,
        receiver_public_key: &str,
        asset_code: &str,
        _issuer_public_key: &str,
    ) -> Result<String> {
        info!(
            "Transferring NFT {} from {} to {}",
            asset_code,
            sender_secret_key.chars().take(5).collect::<String>(),
            receiver_public_key
        );

        // same here
        let amount = "1.0000000";
        let tx_hash = self
            .send_payment(sender_secret_key, receiver_public_key, amount)
            .await?;

        info!(
            "NFT asset {} transferred successfully: {}",
            asset_code, tx_hash
        );
        Ok(tx_hash)
    }

    pub async fn verify_nft_ownership(
        &self,
        public_key: &str,
        asset_code: &str,
        issuer_public_key: &str,
    ) -> Result<bool> {
        info!(
            "Verifying NFT ownership of {} by {} (issuer: {})",
            asset_code, public_key, issuer_public_key
        );

        match self.get_account_balances(public_key).await {
            Ok(balances) => {
                for balance in balances {
                    if balance.asset_type != "native"
                        && balance.asset_code.as_deref() == Some(asset_code)
                        && balance.asset_issuer.as_deref() == Some(issuer_public_key)
                        && balance.balance == "1.0000000"
                    {
                        info!("NFT ownership verified");
                        return Ok(true);
                    }
                }

                info!("NFT ownership not found");
                Ok(false)
            }
            Err(e) => {
                warn!("Failed to verify NFT ownership: {}", e);
                if self.is_testnet {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }
}