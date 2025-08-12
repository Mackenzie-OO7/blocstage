use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use ring::error::Unspecified;
use std::env;
use base64::Engine;
use log::{debug, error};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Master encryption key not set. Please set a 64-character hex string")]
    MasterKeyNotSet,
    #[error("Master encryption key must be 64 hex characters (32 bytes), got {0} characters")]
    InvalidKeyLength(usize),
    #[error("Master encryption key must be valid hex: {0}")]
    InvalidHexKey(#[from] hex::FromHexError),
    #[error("Failed to generate random nonce")]
    NonceGenerationFailed,
    #[error("Failed to create encryption key")]
    KeyCreationFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid encrypted data format")]
    InvalidFormat,
}

impl CryptoError {
    fn log_and_return(self) -> Self {
        error!("❌ {}", self);
        self
    }
}

pub struct KeyEncryption {
    rng: SystemRandom,
    master_key: [u8; 32],
}

// custom debug impl to avoid exposing the master key
impl std::fmt::Debug for KeyEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEncryption")
            .field("rng", &"<SystemRandom>")
            .field("master_key", &"<REDACTED>")
            .finish()
    }
}

impl KeyEncryption {
    pub fn new() -> Result<Self, CryptoError> {
        debug!("🔐 Initializing KeyEncryption service");
        
        let master_key = Self::load_master_key()?;
        
        Ok(Self {
            rng: SystemRandom::new(),
            master_key,
        })
    }

    fn load_master_key() -> Result<[u8; 32], CryptoError> {
        let key_hex = env::var("MASTER_ENCRYPTION_KEY")
            .map_err(|_| CryptoError::MasterKeyNotSet.log_and_return())?;
        
        if key_hex.len() != 64 {
            return Err(CryptoError::InvalidKeyLength(key_hex.len()).log_and_return());
        }
        
        let mut key = [0u8; 32];
        hex::decode_to_slice(&key_hex, &mut key)
            .map_err(|e| CryptoError::InvalidHexKey(e).log_and_return())?;
        
        debug!("✅ Master encryption key loaded successfully");
        Ok(key)
    }

    pub fn encrypt_secret_key(&self, secret_key: &str) -> Result<String, CryptoError> {
        debug!("🔒 Encrypting secret key (length: {})", secret_key.len());
        
        let master_key = self.master_key;
        
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce_bytes)
            .map_err(|_: Unspecified| CryptoError::NonceGenerationFailed.log_and_return())?;
        
        debug!("🎲 Random nonce generated");
        
        let unbound_key = UnboundKey::new(&AES_256_GCM, &master_key)
            .map_err(|_: Unspecified| CryptoError::KeyCreationFailed.log_and_return())?;
        let nonce_sequence = FixedNonceSequence::new(nonce_bytes);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);
        
        // Encrypt
        let mut data = secret_key.as_bytes().to_vec();
        let tag = sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut data)
            .map_err(|_: Unspecified| CryptoError::EncryptionFailed.log_and_return())?;
        
        // Combine nonce + encrypted_data + tag
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&data);
        result.extend_from_slice(tag.as_ref());
        
        let encoded = base64::engine::general_purpose::STANDARD.encode(result);
        debug!("✅ Secret key encrypted successfully (output length: {})", encoded.len());
        
        Ok(encoded)
    }

    pub fn decrypt_secret_key(&self, encrypted_data: &str) -> Result<String, CryptoError> {
        debug!("🔓 Decrypting secret key (input length: {})", encrypted_data.len());
        
        let master_key = self.master_key;
        let data = base64::engine::general_purpose::STANDARD.decode(encrypted_data)
            .map_err(|_| CryptoError::InvalidFormat.log_and_return())?;
        
        if data.len() < NONCE_LEN + 16 {
            return Err(CryptoError::InvalidFormat.log_and_return());
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
            .map_err(|_: Unspecified| CryptoError::KeyCreationFailed.log_and_return())?;
        let nonce_sequence = FixedNonceSequence::new(nonce_array);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        
        let mut data_with_tag = encrypted_data.to_vec();
        data_with_tag.extend_from_slice(tag_bytes);
        
        let decrypted = opening_key.open_in_place(Aad::empty(), &mut data_with_tag)
            .map_err(|_: Unspecified| CryptoError::DecryptionFailed.log_and_return())?;
        
        let result = String::from_utf8(decrypted.to_vec())
            .map_err(|_| CryptoError::InvalidFormat.log_and_return())?;
        
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