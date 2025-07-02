use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use ring::error::Unspecified;
use std::env;
use anyhow::{Result, anyhow};
use base64::Engine;
use log::{debug, error, warn};

pub struct KeyEncryption {
    rng: SystemRandom,
}

impl KeyEncryption {
    pub fn new() -> Self {
        debug!("🔐 Initializing KeyEncryption service");
        Self {
            rng: SystemRandom::new(),
        }
    }

    fn get_master_key() -> Result<[u8; 32]> {
        let key_hex = env::var("MASTER_ENCRYPTION_KEY")
            .map_err(|_| {
                error!("❌ MASTER_ENCRYPTION_KEY not set - please set a 64-character hex string");
                anyhow!("MASTER_ENCRYPTION_KEY not set - please set a 64-character hex string")
            })?;
        
        if key_hex.len() != 64 {
            error!("❌ MASTER_ENCRYPTION_KEY must be 64 hex characters (32 bytes), got {} characters", key_hex.len());
            return Err(anyhow!("MASTER_ENCRYPTION_KEY must be 64 hex characters (32 bytes)"));
        }
        
        let mut key = [0u8; 32];
        hex::decode_to_slice(&key_hex, &mut key)
            .map_err(|e| {
                error!("❌ MASTER_ENCRYPTION_KEY must be valid hex: {}", e);
                anyhow!("MASTER_ENCRYPTION_KEY must be valid hex")
            })?;
        
        debug!("✅ Master encryption key loaded successfully");
        Ok(key)
    }

    pub fn encrypt_secret_key(&self, secret_key: &str) -> Result<String, Box<dyn std::error::Error>> {
        debug!("🔒 Encrypting secret key (length: {})", secret_key.len());
        
        let master_key = Self::get_master_key()?;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce_bytes)
            .map_err(|_: Unspecified| {
                error!("❌ Failed to generate random nonce");
                "Failed to generate random nonce"
            })?;
        
        debug!("🎲 Random nonce generated");
        
        let unbound_key = UnboundKey::new(&AES_256_GCM, &master_key)
            .map_err(|_: Unspecified| {
                error!("❌ Failed to create encryption key");
                "Failed to create encryption key"
            })?;
        let nonce_sequence = FixedNonceSequence::new(nonce_bytes);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);
        
        // Encrypt
        let mut data = secret_key.as_bytes().to_vec();
        let tag = sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut data)
            .map_err(|_: Unspecified| {
                error!("❌ Failed to encrypt data");
                "Failed to encrypt data"
            })?;
        
        // Combine nonce + encrypted_data + tag
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&data);
        result.extend_from_slice(tag.as_ref());
        
        let encoded = base64::engine::general_purpose::STANDARD.encode(result);
        debug!("✅ Secret key encrypted successfully (output length: {})", encoded.len());
        
        Ok(encoded)
    }

    pub fn decrypt_secret_key(&self, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        debug!("🔓 Decrypting secret key (input length: {})", encrypted_data.len());
        
        let master_key = Self::get_master_key()?;
        let data = base64::engine::general_purpose::STANDARD.decode(encrypted_data)
            .map_err(|e| {
                error!("❌ Failed to decode base64 encrypted data: {}", e);
                format!("Failed to decode base64 data: {}", e)
            })?;
        
        if data.len() < NONCE_LEN + 16 {
            error!("❌ Invalid encrypted data length: {} (minimum: {})", data.len(), NONCE_LEN + 16);
            return Err("Invalid encrypted data length".into());
        }
        
        // Split nonce, encrypted data, and tag
        let (nonce_bytes, rest) = data.split_at(NONCE_LEN);
        let (encrypted_data, tag_bytes) = rest.split_at(rest.len() - 16);
        
        debug!("📊 Data split: nonce={}, encrypted={}, tag={}", nonce_bytes.len(), encrypted_data.len(), tag_bytes.len());
        
        // Create nonce from the extracted bytes
        let mut nonce_array = [0u8; NONCE_LEN];
        nonce_array.copy_from_slice(nonce_bytes);
        
        // Decrypt
        let unbound_key = UnboundKey::new(&AES_256_GCM, &master_key)
            .map_err(|_: Unspecified| {
                error!("❌ Failed to create decryption key");
                "Failed to create decryption key"
            })?;
        let nonce_sequence = FixedNonceSequence::new(nonce_array);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        
        let mut data_with_tag = encrypted_data.to_vec();
        data_with_tag.extend_from_slice(tag_bytes);
        
        let decrypted = opening_key.open_in_place(Aad::empty(), &mut data_with_tag)
            .map_err(|_: Unspecified| {
                error!("❌ Failed to decrypt data - wrong key or corrupted data");
                "Failed to decrypt data - wrong key or corrupted data"
            })?;
        
        let result = String::from_utf8(decrypted.to_vec())
            .map_err(|e| {
                error!("❌ Decrypted data is not valid UTF-8: {}", e);
                format!("Decrypted data is not valid UTF-8: {}", e)
            })?;
        
        debug!("✅ Secret key decrypted successfully (length: {})", result.len());
        Ok(result)
    }
}

struct FixedNonceSequence {
    nonce: Option<[u8; NONCE_LEN]>,
}

impl FixedNonceSequence {
    fn new(nonce_bytes: [u8; NONCE_LEN]) -> Self {
        Self {
            nonce: Some(nonce_bytes),
        }
    }
}

impl NonceSequence for FixedNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        match self.nonce.take() {
            Some(nonce_bytes) => Ok(Nonce::assume_unique_for_key(nonce_bytes)),
            None => Err(Unspecified), // Can only be used once
        }
    }
}