// for interactions with Stellar

use anyhow::{Result, anyhow};
use reqwest::Client;
use std::env;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[allow(unused_imports)]
use log::{info, error};
use base64::{engine::general_purpose, Engine};

use stellar_sdk::{Keypair, Server};
use stellar_sdk::types::{Asset, Account};

#[derive(Debug, Clone, Deserialize)]
struct Balance {
    asset_type: String,
    asset_code: Option<String>,
    asset_issuer: Option<String>,
    balance: String,
}

#[derive(Debug, Deserialize)]
struct HorizonAccountResponse {
    sequence: String,
    account_id: String,
    balances: Vec<Balance>,
}

#[derive(Debug, Deserialize)]
struct HorizonTransactionResponse {
    hash: String,
    successful: bool,
}

#[derive(Debug, Serialize)]
struct HorizonTransactionRequest {
    tx: String,
}

// For building Stellar txs
#[derive(Debug, Serialize, Deserialize)]
struct TransactionEnvelope {
    tx: Transaction,
    signatures: Vec<Signature>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Transaction {
    source_account: String,
    fee: u32,
    seq_num: String,
    time_bounds: Option<TimeBounds>,
    memo: Memo,
    operations: Vec<Operation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TimeBounds {
    min_time: u64,
    max_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Memo {
    memo_type: String,
    memo_text: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Operation {
    source_account: Option<String>,
    type_: String,
    destination: String,
    asset: AssetInfo,
    amount: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AssetInfo {
    code: String,
    issuer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Signature {
    hint: Vec<u8>,
    signature: Vec<u8>,
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
        
        let server = Server::new(horizon_url.clone(), None)?;
        
        Ok(Self { 
            server,
            horizon_url,
            is_testnet,
            client: Client::new(),
        })
    }
    
    pub fn generate_keypair(&self) -> Result<(String, String)> {
        let keypair = Keypair::random()?;
        let public_key = keypair.public_key();
        
        let mut keypair_mut = keypair.clone();
        let secret_key = keypair_mut.secret_key()?;
        
        Ok((public_key, secret_key))
    }
    
    pub async fn send_payment(&self, sender_secret_key: &str, receiver_public_key: &str, amount: &str) -> Result<String> {
        let sender_keypair = Keypair::from_secret_key(sender_secret_key)?;
        let sender_public_key = sender_keypair.public_key();
        
        // fetch account details and sequence number
        let account_url = format!("{}/accounts/{}", self.horizon_url, sender_public_key);
        let account_resp = self.client.get(&account_url).send().await?;
        
        if !account_resp.status().is_success() {
            let error_text = account_resp.text().await?;
            return Err(anyhow!("Failed to fetch account: {}", error_text));
        }
        
        let account_data: Value = account_resp.json().await?;
        let sequence = account_data["sequence"].as_str()
            .ok_or_else(|| anyhow!("Invalid account data: missing sequence"))?;
        
        let seq_num = (sequence.parse::<u64>()? + 1).to_string();
        
        let operation = Operation {
            source_account: None,
            type_: "payment".to_string(),
            destination: receiver_public_key.to_string(),
            asset: AssetInfo {
                code: "XLM".to_string(),
                issuer: None,  // remember native asset doesn't have an issuer
            },
            amount: amount.to_string(),
        };

        //TODO: implement issuer param for non-native assets
        
        let transaction = Transaction {
            source_account: sender_public_key.clone(),
            fee: 100,  // 100 stroops = 0.00001 XLM
            seq_num,
            time_bounds: Some(TimeBounds {
                min_time: 0,
                max_time: 0,  // 0 means no max time
            }),
            memo: Memo {
                memo_type: "none".to_string(),
                memo_text: None,
            },
            operations: vec![operation],
        };
        
        let tx_envelope = TransactionEnvelope {
            tx: transaction,
            signatures: vec![],
        };
        
        let tx_xdr = serde_json::to_string(&tx_envelope)?;

        // TODO: 
        // 1. Convert the transaction to XDR format
        // 2. Sign it with the sender's keypair
        // 3. Add the signature to the envelope
        
        // hash the tx (placeholder - later, use proper hashing)
        let tx_hash = format!("HASH_{}", tx_xdr);
        
        let signature = sender_keypair.sign(tx_hash.as_bytes())?;
        
        let tx_envelope_signed = json!({
            "tx": tx_envelope.tx,
            "signatures": [{
                "hint": vec![0, 1, 2, 3],  // Last 4 bytes of public key
                "signature": signature
            }]
        });
        
        // convert to base64-encoded XDR string (placeholder)
        let tx_xdr_base64 = general_purpose::STANDARD.encode(tx_envelope_signed.to_string());
        
        // submit the transaction
        let submit_url = format!("{}/transactions", self.horizon_url);
        let submit_data = json!({
            "tx": tx_xdr_base64
        });
        
        let submit_resp = self.client.post(&submit_url)
            .json(&submit_data)
            .send()
            .await?;
        
        if !submit_resp.status().is_success() {
            let error_text = submit_resp.text().await?;
            return Err(anyhow!("Transaction submission failed: {}", error_text));
        }
        
        let response: Value = submit_resp.json().await?;
        let hash = response["hash"].as_str()
            .ok_or_else(|| anyhow!("No transaction hash in response"))?
            .to_string();
        
        Ok(hash)
    }
    
    pub async fn process_refund(&self, issuer_secret_key: &str, receiver_public_key: &str, amount: &str) -> Result<String> {
        info!("Processing refund of {} to {}", amount, receiver_public_key);
        let tx_hash = self.send_payment(issuer_secret_key, receiver_public_key, amount).await?;
        info!("Refund processed successfully: {}", tx_hash);
        Ok(tx_hash)
    }
    
    pub async fn pay_event_organizer(
        &self, 
        platform_secret_key: &str, 
        organizer_public_key: &str, 
        total_amount: f64,
        platform_fee_percentage: f64
    ) -> Result<String> {
        let platform_fee = total_amount * (platform_fee_percentage / 100.0);
        let organizer_amount = total_amount - platform_fee;
        
    let amount_str = format!("{:.7}", organizer_amount);
        
        info!("Paying organizer {} XLM ({}% fee: {} XLM)", 
              organizer_amount, platform_fee_percentage, platform_fee);
        
        let tx_hash = self.send_payment(platform_secret_key, organizer_public_key, &amount_str).await?;
        
        info!("Organizer payment successful: {}", tx_hash);
        Ok(tx_hash)
    }
    
    pub async fn get_account_details(&self, public_key: &str) -> Result<Account> {
        Ok(self.server.load_account(public_key)?)
    }
    
    pub async fn get_account_balances(&self, public_key: &str) -> Result<Vec<Balance>> {
        let url = format!("{}/accounts/{}", self.horizon_url, public_key);
        
        let response = self.client.get(&url).send().await?;
        
        let status = response.status();
        
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to get account: HTTP {}: {}", 
                     status, error_text));
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
            return Err(anyhow!("Failed to get account: HTTP {}: {}", 
                     status, error_text));
        }
        
        let account_data: HorizonAccountResponse = response.json().await?;
        
        Ok(account_data.account_id)
    }
    
    async fn submit_transaction(&self, tx_envelope_xdr: String) -> Result<String> {
        let url = format!("{}/transactions", self.horizon_url);
        
        let request_body = HorizonTransactionRequest {
            tx: tx_envelope_xdr,
        };
        
        let response = self.client.post(&url)
            .json(&request_body)
            .send()
            .await?;
        
        let status = response.status();
        
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Transaction submission failed: HTTP {}: {}", 
                     status, error_text));
        }
        
        let tx_response: HorizonTransactionResponse = response.json().await?;
        
        if !tx_response.successful {
            return Err(anyhow!("Transaction failed on the network"));
        }
        
        Ok(tx_response.hash)
    }
    
    // TODO: 
    pub async fn issue_nft_asset(&self, issuer_secret_key: &str, asset_code: &str, receiver_public_key: &str) -> Result<String> {
        // Create issuer keypair
        let issuer_keypair = Keypair::from_secret_key(issuer_secret_key)?;
        let issuer_public_key = issuer_keypair.public_key();
        
        // Step 1: Create custom asset (using Asset class from the SDK)
        let asset = Asset::new(
            asset_code.to_string(),
            issuer_public_key.clone(),
        )?;
        
        // Step 2: Create trustline - this requires the receiver to submit a change trust operation
        // For NFTs, typically the receiver would need to create a trustline first
        // We'll assume this is done client-side or in a separate call
        
        // Step 3: Send exactly 1 token as payment to signify NFT
        // Get account details and sequence number
        let account_url = format!("{}/accounts/{}", self.horizon_url, issuer_public_key);
        let account_resp = self.client.get(&account_url).send().await?;
        
        if !account_resp.status().is_success() {
            let error_text = account_resp.text().await?;
            return Err(anyhow!("Failed to fetch account: {}", error_text));
        }
        
        let account_data: Value = account_resp.json().await?;
        let sequence = account_data["sequence"].as_str()
            .ok_or_else(|| anyhow!("Invalid account data: missing sequence"))?;
        
        let seq_num = (sequence.parse::<u64>()? + 1).to_string();
        
        let operation = Operation {
            source_account: None,
            type_: "payment".to_string(),
            destination: receiver_public_key.to_string(),
            asset: AssetInfo {
                code: asset_code.to_string(),
                issuer: Some(issuer_public_key.clone()),
            },
            amount: "1.0000000".to_string(), // Exactly 1 unit for NFT
        };
        
        let transaction = Transaction {
            source_account: issuer_public_key,
            fee: 100,
            seq_num,
            time_bounds: Some(TimeBounds {
                min_time: 0,
                max_time: 0,
            }),
            memo: Memo {
                memo_type: "text".to_string(),
                memo_text: Some("NFT Ticket".to_string()),
            },
            operations: vec![operation],
        };
        
        let tx_envelope = TransactionEnvelope {
            tx: transaction,
            signatures: vec![],
        };
        
        let tx_xdr = serde_json::to_string(&tx_envelope)?;
        
        let tx_hash = format!("HASH_{}", tx_xdr);
        
        let signature = issuer_keypair.sign(tx_hash.as_bytes())?;
        
        let tx_envelope_signed = json!({
            "tx": tx_envelope.tx,
            "signatures": [{
                "hint": vec![0, 1, 2, 3],  // Last 4 bytes of public key
                "signature": signature
            }]
        });
        
        let tx_xdr_base64 = general_purpose::STANDARD.encode(tx_envelope_signed.to_string());

        
        let submit_url = format!("{}/transactions", self.horizon_url);
        let submit_data = json!({
            "tx": tx_xdr_base64
        });
        
        let submit_resp = self.client.post(&submit_url)
            .json(&submit_data)
            .send()
            .await?;
        
        if !submit_resp.status().is_success() {
            let error_text = submit_resp.text().await?;
            return Err(anyhow!("Transaction submission failed: {}", error_text));
        }
        
        let response: Value = submit_resp.json().await?;
        let hash = response["hash"].as_str()
            .ok_or_else(|| anyhow!("No transaction hash in response"))?
            .to_string();
        
        Ok(hash)
    }
    
    pub async fn transfer_nft(&self, 
        sender_secret_key: &str, 
        receiver_public_key: &str, 
        asset_code: &str,
        issuer_public_key: &str
    ) -> Result<String> {
        let sender_keypair = Keypair::from_secret_key(sender_secret_key)?;
        let sender_public_key = sender_keypair.public_key();
        
        let asset = Asset::new(
            asset_code.to_string(),
            issuer_public_key.to_string(),
        )?;
        
        let account_url = format!("{}/accounts/{}", self.horizon_url, sender_public_key);
        let account_resp = self.client.get(&account_url).send().await?;
        
        if !account_resp.status().is_success() {
            let error_text = account_resp.text().await?;
            return Err(anyhow!("Failed to fetch account: {}", error_text));
        }
        
        let account_data: Value = account_resp.json().await?;
        let sequence = account_data["sequence"].as_str()
            .ok_or_else(|| anyhow!("Invalid account data: missing sequence"))?;
        
        let seq_num = (sequence.parse::<u64>()? + 1).to_string();
        
        let operation = Operation {
            source_account: None,
            type_: "payment".to_string(),
            destination: receiver_public_key.to_string(),
            asset: AssetInfo {
                code: asset_code.to_string(),
                issuer: Some(issuer_public_key.to_string()),
            },
            amount: "1.0000000".to_string(),
        };
        
        let transaction = Transaction {
            source_account: sender_public_key,
            fee: 100,
            seq_num,
            time_bounds: Some(TimeBounds {
                min_time: 0,
                max_time: 0,
            }),
            memo: Memo {
                memo_type: "text".to_string(),
                memo_text: Some("NFT Ticket Transfer".to_string()),
            },
            operations: vec![operation],
        };
        
        let tx_envelope = TransactionEnvelope {
            tx: transaction,
            signatures: vec![],
        };
        
        let tx_xdr = serde_json::to_string(&tx_envelope)?;
        
        let tx_hash = format!("HASH_{}", tx_xdr);
        
        let signature = sender_keypair.sign(tx_hash.as_bytes())?;
        
        let tx_envelope_signed = json!({
            "tx": tx_envelope.tx,
            "signatures": [{
                "hint": vec![0, 1, 2, 3],
                "signature": signature
            }]
        });
        
        let tx_xdr_base64 = general_purpose::STANDARD.encode(tx_envelope_signed.to_string());

        
        let submit_url = format!("{}/transactions", self.horizon_url);
        let submit_data = json!({
            "tx": tx_xdr_base64
        });
        
        let submit_resp = self.client.post(&submit_url)
            .json(&submit_data)
            .send()
            .await?;
        
        if !submit_resp.status().is_success() {
            let error_text = submit_resp.text().await?;
            return Err(anyhow!("Transaction submission failed: {}", error_text));
        }
        
        let response: Value = submit_resp.json().await?;
        let hash = response["hash"].as_str()
            .ok_or_else(|| anyhow!("No transaction hash in response"))?
            .to_string();
        
        Ok(hash)
    }
    
    pub async fn verify_nft_ownership(&self, public_key: &str, asset_code: &str, issuer_public_key: &str) -> Result<bool> {
        let balances = self.get_account_balances(public_key).await?;
        
        for balance in balances {
            if balance.asset_type != "native" 
                && balance.asset_code.as_deref() == Some(asset_code)
                && balance.asset_issuer.as_deref() == Some(issuer_public_key)
                && balance.balance == "1.0000000" {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
}