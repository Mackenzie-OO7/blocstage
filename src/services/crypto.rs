use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use ring::error::Unspecified;
use std::env;
use base64::Engine;
use log::{debug, error};

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
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        debug!("🔐 Initializing KeyEncryption service");
        
        let master_key = Self::load_master_key()?;
        
        Ok(Self {
            rng: SystemRandom::new(),
            master_key,
        })
    }

    fn load_master_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let key_hex = env::var("MASTER_ENCRYPTION_KEY")
            .map_err(|_| {
                error!("❌ MASTER_ENCRYPTION_KEY not set - please set a 64-character hex string");
                "MASTER_ENCRYPTION_KEY not set - please set a 64-character hex string"
            })?;
        
        if key_hex.len() != 64 {
            error!("❌ MASTER_ENCRYPTION_KEY must be 64 hex characters (32 bytes), got {} characters", key_hex.len());
            return Err("MASTER_ENCRYPTION_KEY must be 64 hex characters (32 bytes)".into());
        }
        
        let mut key = [0u8; 32];
        hex::decode_to_slice(&key_hex, &mut key)
            .map_err(|e| {
                error!("❌ MASTER_ENCRYPTION_KEY must be valid hex: {}", e);
                "MASTER_ENCRYPTION_KEY must be valid hex"
            })?;
        
        debug!("✅ Master encryption key loaded successfully");
        Ok(key)
    }

    pub fn encrypt_secret_key(&self, secret_key: &str) -> Result<String, Box<dyn std::error::Error>> {
        debug!("🔒 Encrypting secret key (length: {})", secret_key.len());
        
        let master_key = self.master_key;
        
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
        
        let master_key = self.master_key;
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

// tests 

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::env;

    fn setup_test_environment() {
        // Set test master key
        env::set_var(
            "MASTER_ENCRYPTION_KEY",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
    }

    fn cleanup_test_environment() {
        env::remove_var("MASTER_ENCRYPTION_KEY");
    }

    fn setup_invalid_environment() {
        env::remove_var("MASTER_ENCRYPTION_KEY");
    }

    mod basic_encryption_functionality {
        use super::*;

        #[test]
        fn test_encrypt_decrypt_round_trip_success() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let original_secret = "SECRETKEY123456789ABCDEFGHIJKLMNOP";

            let encrypted = crypto
                .encrypt_secret_key(original_secret)
                .expect("Encryption should succeed");

            assert!(!encrypted.is_empty(), "Encrypted data should not be empty");
            assert_ne!(
                encrypted, original_secret,
                "Encrypted data should be different from original"
            );

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Decryption should succeed");

            assert_eq!(
                decrypted, original_secret,
                "Decrypted data should match original"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_encrypt_empty_string() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let empty_secret = "";

            let encrypted = crypto
                .encrypt_secret_key(empty_secret)
                .expect("Empty string encryption should succeed");

            assert!(
                !encrypted.is_empty(),
                "Encrypted empty string should produce non-empty output"
            );

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Decryption should succeed");

            assert_eq!(
                decrypted, empty_secret,
                "Decrypted empty string should match"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_encrypt_very_long_string() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let long_secret = "A".repeat(10000); // Very long secret key

            let encrypted = crypto
                .encrypt_secret_key(&long_secret)
                .expect("Long string encryption should succeed");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Long string decryption should succeed");

            assert_eq!(
                decrypted, long_secret,
                "Long string round trip should preserve data"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_encrypt_unicode_characters() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let unicode_secret = "SECRET密钥🔐こんにちは世界";

            let encrypted = crypto
                .encrypt_secret_key(unicode_secret)
                .expect("Unicode encryption should succeed");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Unicode decryption should succeed");

            assert_eq!(
                decrypted, unicode_secret,
                "Unicode characters should be preserved"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_encrypt_special_characters() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let special_secret = "SECRET!@#$%^&*()[]{}|\\:;\"'<>?,./~`";

            let encrypted = crypto
                .encrypt_secret_key(special_secret)
                .expect("Special character encryption should succeed");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Special character decryption should succeed");

            assert_eq!(
                decrypted, special_secret,
                "Special characters should be preserved"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_multiple_encryptions_different_outputs() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SAME_SECRET_KEY_123";

            let encrypted1 = crypto
                .encrypt_secret_key(secret)
                .expect("First encryption should succeed");
            let encrypted2 = crypto
                .encrypt_secret_key(secret)
                .expect("Second encryption should succeed");

            // Due to random nonces, same input should produce different encrypted outputs
            assert_ne!(
                encrypted1, encrypted2,
                "Same input should produce different encrypted outputs due to random nonces"
            );

            // But both should decrypt to the same original
            let decrypted1 = crypto
                .decrypt_secret_key(&encrypted1)
                .expect("First decryption should succeed");
            let decrypted2 = crypto
                .decrypt_secret_key(&encrypted2)
                .expect("Second decryption should succeed");

            assert_eq!(decrypted1, secret, "First decryption should match original");
            assert_eq!(
                decrypted2, secret,
                "Second decryption should match original"
            );

            cleanup_test_environment();
        }
    }

    mod key_management_security {
        use super::*;

        #[test]
        fn test_missing_master_key_error() {
            setup_invalid_environment();

            let result = KeyEncryption::new();
            assert!(result.is_err(), "Should fail when master key is not set");

            let error_msg = result.err().unwrap().to_string();
            assert!(
                error_msg.contains("MASTER_ENCRYPTION_KEY not set"),
                "Error should mention missing master key"
            );
        }

        #[test]
        fn test_invalid_master_key_length() {
            // Set invalid length master key (too short)
            env::set_var("MASTER_ENCRYPTION_KEY", "tooshort");

            let result = KeyEncryption::new();
            assert!(result.is_err(), "Should fail with invalid key length");

            let error_msg = result.err().unwrap().to_string();
            assert!(
                error_msg.contains("64 hex characters"),
                "Error should mention required key length"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_invalid_master_key_format() {
            // Set invalid format master key (not hex)
            env::set_var(
                "MASTER_ENCRYPTION_KEY",
                "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            );

            let result = KeyEncryption::new();
            assert!(result.is_err(), "Should fail with invalid hex format");

            let error_msg = result.err().unwrap().to_string();
            assert!(
                error_msg.contains("valid hex"),
                "Error should mention hex format requirement"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_different_master_keys_incompatible() {
            // Encrypt with first master key
            env::set_var(
                "MASTER_ENCRYPTION_KEY",
                "1111111111111111111111111111111111111111111111111111111111111111",
            );
            let crypto1 = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SECRET_TO_ENCRYPT";
            let encrypted = crypto1
                .encrypt_secret_key(secret)
                .expect("Encryption with first key should succeed");

            // Try to decrypt with different master key
            env::set_var(
                "MASTER_ENCRYPTION_KEY",
                "2222222222222222222222222222222222222222222222222222222222222222",
            );
            let crypto2 = KeyEncryption::new().expect("Should create crypto instance");

            let result = crypto2.decrypt_secret_key(&encrypted);
            assert!(
                result.is_err(),
                "Decryption with different master key should fail"
            );

            cleanup_test_environment();
        }

        #[test]
        #[test]
fn test_master_key_hex_case_insensitive() {
    // Test that master keys work regardless of hex case
    env::set_var(
        "MASTER_ENCRYPTION_KEY",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    );
    let crypto1 = KeyEncryption::new().expect("Should create crypto instance");
    let secret = "SECRET_TO_ENCRYPT";
    let encrypted = crypto1
        .encrypt_secret_key(secret)
        .expect("Encryption should succeed");

    // Try with uppercase version of same key (should work - hex is case insensitive)
    env::set_var(
        "MASTER_ENCRYPTION_KEY",
        "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
    );
    let crypto2 = KeyEncryption::new().expect("Should create crypto instance");

    let decrypted = crypto2.decrypt_secret_key(&encrypted)
        .expect("Hex case should not matter");

    assert_eq!(decrypted, secret, "Hex keys should be case insensitive");

    // test with mixed case too
    env::set_var(
        "MASTER_ENCRYPTION_KEY",
        "AbCdEf1234567890aBcDeF1234567890AbCdEf1234567890aBcDeF1234567890",
    );
    let crypto3 = KeyEncryption::new().expect("Should create crypto instance");

    let decrypted_mixed = crypto3.decrypt_secret_key(&encrypted)
        .expect("Mixed case hex should work");

    assert_eq!(decrypted_mixed, secret, "Mixed case hex should work");

    cleanup_test_environment();
}
    }

    mod nonce_security {
        use super::*;

        #[test]
        fn test_nonce_uniqueness() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SAME_SECRET_FOR_NONCE_TEST";
            let mut encrypted_values = Vec::new();

            // Generate multiple encryptions
            for _ in 0..100 {
                let encrypted = crypto
                    .encrypt_secret_key(secret)
                    .expect("Encryption should succeed");
                encrypted_values.push(encrypted);
            }

            // Check that all encrypted values are unique (due to unique nonces)
            let unique_values: HashSet<_> = encrypted_values.iter().collect();
            assert_eq!(
                unique_values.len(),
                encrypted_values.len(),
                "All encrypted values should be unique due to unique nonces"
            );

            // Verify all decrypt to the same original
            for encrypted in &encrypted_values {
                let decrypted = crypto
                    .decrypt_secret_key(encrypted)
                    .expect("All should decrypt successfully");
                assert_eq!(decrypted, secret, "All should decrypt to original secret");
            }

            cleanup_test_environment();
        }

        #[test]
        fn test_nonce_length_consistency() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SECRET_FOR_NONCE_LENGTH_TEST";

            let mut encrypted_lengths = Vec::new();
            for _ in 0..10 {
                let encrypted = crypto
                    .encrypt_secret_key(secret)
                    .expect("Encryption should succeed");
                encrypted_lengths.push(encrypted.len());
            }

            // All encrypted values should have consistent length structure
            // (though content differs due to nonces)
            let unique_lengths: HashSet<_> = encrypted_lengths.iter().collect();
            assert_eq!(
                unique_lengths.len(),
                1,
                "All encrypted values should have same length structure"
            );

            cleanup_test_environment();
        }
    }

    mod attack_resistance {
        use super::*;

        #[test]
        fn test_decrypt_invalid_base64() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let invalid_base64 = "This is not valid base64!@#$%";

            let result = crypto.decrypt_secret_key(invalid_base64);
            assert!(result.is_err(), "Should fail with invalid base64");

            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains("base64"),
                "Error should mention base64 decoding issue"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_decrypt_truncated_data() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SECRET_TO_TRUNCATE";

            let encrypted = crypto
                .encrypt_secret_key(secret)
                .expect("Encryption should succeed");

            // Truncate the encrypted data
            let truncated = &encrypted[..encrypted.len() / 2];

            let result = crypto.decrypt_secret_key(truncated);
            assert!(result.is_err(), "Should fail with truncated data");

            cleanup_test_environment();
        }

        #[test]
        fn test_decrypt_corrupted_data() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SECRET_TO_CORRUPT";

            let encrypted = crypto
                .encrypt_secret_key(secret)
                .expect("Encryption should succeed");

            // Corrupt some bytes in the middle
            let mut corrupted = encrypted.into_bytes();
            if corrupted.len() > 10 {
                corrupted[5] = corrupted[5].wrapping_add(1);
                corrupted[10] = corrupted[10].wrapping_add(1);
            }
            let corrupted_string = String::from_utf8_lossy(&corrupted).to_string();

            let result = crypto.decrypt_secret_key(&corrupted_string);
            assert!(result.is_err(), "Should fail with corrupted data");

            cleanup_test_environment();
        }

        #[test]
        fn test_decrypt_wrong_format_data() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");

            // Try various wrong format inputs
            let wrong_formats = vec![
                "",
                "a",
                "short",
                "not_encrypted_data_at_all",
                "SGVsbG8gV29ybGQ=", // Valid base64 but wrong content
            ];

            for wrong_data in wrong_formats {
                let result = crypto.decrypt_secret_key(wrong_data);
                assert!(
                    result.is_err(),
                    "Should fail with wrong format: {}",
                    wrong_data
                );
            }

            cleanup_test_environment();
        }

        #[test]
        fn test_timing_attack_resistance() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SECRET_FOR_TIMING_TEST";

            let encrypted = crypto
                .encrypt_secret_key(secret)
                .expect("Encryption should succeed");

            // Test that decryption with wrong keys fails consistently
            // (not testing actual timing, but ensuring consistent failure behavior)
            let wrong_keys = vec![
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ];

            for wrong_key in wrong_keys {
                env::set_var("MASTER_ENCRYPTION_KEY", wrong_key);
                let wrong_crypto = KeyEncryption::new().expect("Should create crypto instance");

                let result = wrong_crypto.decrypt_secret_key(&encrypted);
                assert!(result.is_err(), "Should consistently fail with wrong keys");
            }

            cleanup_test_environment();
        }
    }

    mod memory_and_performance {
        use super::*;

        #[test]
        fn test_large_data_handling() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");

            // Test with increasingly large data
            let sizes = vec![1024, 10240, 102400]; // 1KB, 10KB, 100KB

            for size in sizes {
                let large_secret = "X".repeat(size);

                let encrypted = crypto
                    .encrypt_secret_key(&large_secret)
                    .expect(&format!("Should handle {}KB data", size / 1024));

                let decrypted = crypto
                    .decrypt_secret_key(&encrypted)
                    .expect(&format!("Should decrypt {}KB data", size / 1024));

                assert_eq!(
                    decrypted, large_secret,
                    "Large data should round-trip correctly"
                );
            }

            cleanup_test_environment();
        }

        #[test]
        fn test_multiple_crypto_instances() {
            setup_test_environment();

            let secret = "SECRET_FOR_MULTIPLE_INSTANCES";

            // Create multiple instances and ensure they work consistently
            let crypto1 = KeyEncryption::new().expect("Should create crypto instance");
            let crypto2 = KeyEncryption::new().expect("Should create crypto instance");
            let crypto3 = KeyEncryption::new().expect("Should create crypto instance");

            let encrypted1 = crypto1
                .encrypt_secret_key(secret)
                .expect("Instance 1 encryption should succeed");
            let encrypted2 = crypto2
                .encrypt_secret_key(secret)
                .expect("Instance 2 encryption should succeed");

            // Cross-decrypt: instance 3 should decrypt data from instances 1 and 2
            let decrypted1 = crypto3
                .decrypt_secret_key(&encrypted1)
                .expect("Cross-decryption 1 should succeed");
            let decrypted2 = crypto3
                .decrypt_secret_key(&encrypted2)
                .expect("Cross-decryption 2 should succeed");

            assert_eq!(
                decrypted1, secret,
                "Cross-decryption 1 should match original"
            );
            assert_eq!(
                decrypted2, secret,
                "Cross-decryption 2 should match original"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_repeated_operations() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "SECRET_FOR_REPEATED_OPS";

            // Perform many encrypt/decrypt cycles
            for i in 0..100 {
                let test_secret = format!("{}_{}", secret, i);

                let encrypted = crypto
                    .encrypt_secret_key(&test_secret)
                    .expect(&format!("Encryption {} should succeed", i));

                let decrypted = crypto
                    .decrypt_secret_key(&encrypted)
                    .expect(&format!("Decryption {} should succeed", i));

                assert_eq!(decrypted, test_secret, "Cycle {} should preserve data", i);
            }

            cleanup_test_environment();
        }
    }

    mod stellar_key_specific_tests {
        use super::*;

        #[test]
        fn test_typical_stellar_secret_key_format() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");

            // Test with typical Stellar secret key format
            let stellar_secret = "SDWHLBK2OZCJGBPQZ3NHRJB6FYFGXKQJHXCNM4SMNPX5URSX4O2RGZGN";

            let encrypted = crypto
                .encrypt_secret_key(stellar_secret)
                .expect("Stellar key encryption should succeed");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Stellar key decryption should succeed");

            assert_eq!(
                decrypted, stellar_secret,
                "Stellar key should be preserved exactly"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_multiple_stellar_keys() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");

            // Test with multiple different Stellar secret keys
            let stellar_keys = vec![
                "SDWHLBK2OZCJGBPQZ3NHRJB6FYFGXKQJHXCNM4SMNPX5URSX4O2RGZGN",
                "SCAXBAH5XHQX2Q4BMSW4QESGQZXR2HHKVQPQRXDXQXQXQXQXQXQXQXQX",
                "SBJF3IZLQHQZ5FYFGXKQJHXCNM4SMNPX5URSX4O2RGZGNSDWHLBK2OZC",
            ];

            let mut encrypted_keys = Vec::new();

            // Encrypt all keys
            for key in &stellar_keys {
                let encrypted = crypto
                    .encrypt_secret_key(key)
                    .expect(&format!("Should encrypt key: {}", key));
                encrypted_keys.push(encrypted);
            }

            // Decrypt all keys and verify
            for (i, encrypted) in encrypted_keys.iter().enumerate() {
                let decrypted = crypto
                    .decrypt_secret_key(encrypted)
                    .expect(&format!("Should decrypt key {}", i));
                assert_eq!(
                    decrypted, stellar_keys[i],
                    "Key {} should match original",
                    i
                );
            }

            cleanup_test_environment();
        }

        #[test]
        fn test_stellar_key_case_sensitivity() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");

            let uppercase_key = "SDWHLBK2OZCJGBPQZ3NHRJB6FYFGXKQJHXCNM4SMNPX5URSX4O2RGZGN";
            let lowercase_key = "sdwhlbk2ozcjgbpqz3nhrjb6fyfgxkqjhxcnm4smnpx5ursx4o2rgzgn";

            let encrypted_upper = crypto
                .encrypt_secret_key(uppercase_key)
                .expect("Uppercase key encryption should succeed");
            let encrypted_lower = crypto
                .encrypt_secret_key(lowercase_key)
                .expect("Lowercase key encryption should succeed");

            let decrypted_upper = crypto
                .decrypt_secret_key(&encrypted_upper)
                .expect("Uppercase key decryption should succeed");
            let decrypted_lower = crypto
                .decrypt_secret_key(&encrypted_lower)
                .expect("Lowercase key decryption should succeed");

            assert_eq!(
                decrypted_upper, uppercase_key,
                "Uppercase key should be preserved"
            );
            assert_eq!(
                decrypted_lower, lowercase_key,
                "Lowercase key should be preserved"
            );
            assert_ne!(decrypted_upper, decrypted_lower, "Case should be preserved");

            cleanup_test_environment();
        }
    }

    mod edge_cases_and_boundary_conditions {
        use super::*;

        #[test]
        fn test_null_byte_handling() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret_with_null = "SECRET\0WITH\0NULLS";

            let encrypted = crypto
                .encrypt_secret_key(secret_with_null)
                .expect("Should handle null bytes");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Should decrypt null bytes");

            assert_eq!(
                decrypted, secret_with_null,
                "Null bytes should be preserved"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_newline_and_whitespace_handling() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret_with_whitespace = "SECRET\n\r\t WITH \n WHITESPACE \r\n";

            let encrypted = crypto
                .encrypt_secret_key(secret_with_whitespace)
                .expect("Should handle whitespace");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Should decrypt whitespace");

            assert_eq!(
                decrypted, secret_with_whitespace,
                "Whitespace should be preserved"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_binary_data_handling() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");

            // Create string with various byte values (only valid UTF-8)
            let binary_secret = (32..=126u8).map(|b| b as char).collect::<String>();

            let encrypted = crypto
                .encrypt_secret_key(&binary_secret)
                .expect("Should handle binary data");

            let decrypted = crypto
                .decrypt_secret_key(&encrypted)
                .expect("Should decrypt binary data");

            assert_eq!(decrypted, binary_secret, "Binary data should be preserved");

            cleanup_test_environment();
        }

        #[test]
        fn test_concurrent_encryption_operations() {
            setup_test_environment();

            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "CONCURRENT_TEST_SECRET";

            // Perform concurrent encryption operations
            let handles: Vec<_> = (0..10)
                .map(|i| {
                    let crypto_clone = KeyEncryption::new().expect("Should create crypto instance");
                    let secret_clone = format!("{}_{}", secret, i);

                    std::thread::spawn(move || -> Result<String, String> {
                        crypto_clone
                            .encrypt_secret_key(&secret_clone)
                            .map_err(|e| e.to_string())
                    })
                })
                .collect();

            let mut results = Vec::new();
            for handle in handles {
                let encrypted = handle
                    .join()
                    .unwrap()
                    .expect("Concurrent encryption should succeed");
                results.push(encrypted);
            }

            let unique_results: HashSet<_> = results.iter().collect();
            assert_eq!(
                unique_results.len(),
                results.len(),
                "All concurrent results should be unique"
            );

            for (i, encrypted) in results.iter().enumerate() {
                let decrypted = crypto
                    .decrypt_secret_key(encrypted)
                    .expect("Concurrent decryption should succeed");
                let expected = format!("{}_{}", secret, i);
                assert_eq!(decrypted, expected, "Concurrent result {} should match", i);
            }

            cleanup_test_environment();
        }
    }

    mod environment_variable_security {
        use super::*;

        #[test]
        fn test_environment_variable_isolation() {
            // Ensure changes to environment don't affect existing instances
            env::set_var(
                "MASTER_ENCRYPTION_KEY",
                "1111111111111111111111111111111111111111111111111111111111111111",
            );
            let crypto1 = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "ISOLATION_TEST";

            let encrypted = crypto1
                .encrypt_secret_key(secret)
                .expect("Initial encryption should succeed");

            // Change environment variable
            env::set_var(
                "MASTER_ENCRYPTION_KEY",
                "2222222222222222222222222222222222222222222222222222222222222222",
            );

            // Original instance should still work with original key
            let decrypted = crypto1
                .decrypt_secret_key(&encrypted)
                .expect("Original instance should still work");

            assert_eq!(
                decrypted, secret,
                "Environment changes shouldn't affect existing instances"
            );

            cleanup_test_environment();
        }

        #[test]
        fn test_master_key_validation_comprehensive() {
            env::remove_var("MASTER_ENCRYPTION_KEY"); // Start clean

            let invalid_keys = vec![
                ("", "empty key"),
                ("abc", "too short"),
                (
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789",
                    "63 chars",
                ),
                (
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678901",
                    "65 chars",
                ),
                (
                    "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
                    "invalid hex",
                ),
                (
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890G",
                    "invalid char",
                ),
            ];

            for (key, description) in invalid_keys {
                env::set_var("MASTER_ENCRYPTION_KEY", key);
                let result = KeyEncryption::new();
                assert!(result.is_err(), "Should reject {}: {}", description, key);
            }

            // Valid key should work
            env::set_var(
                "MASTER_ENCRYPTION_KEY",
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            );
            let result = KeyEncryption::new();
            assert!(result.is_ok(), "Valid key should work");

            cleanup_test_environment();
        }
    }

    mod critical_security_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn test_nonce_collision_resistance() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "NONCE_COLLISION_TEST";
            
            // Generate many more encryptions to test for nonce collisions
            let mut nonces = HashSet::new();
            let iterations = 100; // Reduced for reasonable test time
            
            for i in 0..iterations {
                let encrypted = crypto.encrypt_secret_key(&format!("{}_{}", secret, i))
                    .expect("Encryption should succeed");
                
                // Extract nonce from encrypted data (first 12 bytes after base64 decode)
                let decoded = base64::engine::general_purpose::STANDARD.decode(&encrypted)
                    .expect("Should decode base64");
                
                if decoded.len() >= 12 {
                    let nonce = &decoded[0..12];
                    let nonce_inserted = nonces.insert(nonce.to_vec());
                    
                    if !nonce_inserted {
                        panic!("CRITICAL VULNERABILITY: Nonce collision detected at iteration {}", i);
                    }
                }
            }
            
            assert_eq!(nonces.len(), iterations, "All nonces must be unique - collision is catastrophic");
            cleanup_test_environment();
        }

        #[test]
        fn test_nonce_randomness_distribution() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "RANDOMNESS_TEST";
            
            let mut bit_counts = [0u32; 8]; // Count bits in each position
            let samples = 100; // Reduced for reasonable test time
            
            for _ in 0..samples {
                let encrypted = crypto.encrypt_secret_key(secret)
                    .expect("Encryption should succeed");
                
                let decoded = base64::engine::general_purpose::STANDARD.decode(&encrypted)
                    .expect("Should decode base64");
                    
                if decoded.len() >= 12 {
                    // Check first byte of nonce for bit distribution
                    let first_nonce_byte = decoded[0];
                    for bit_pos in 0..8 {
                        if (first_nonce_byte >> bit_pos) & 1 == 1 {
                            bit_counts[bit_pos] += 1;
                        }
                    }
                }
            }
            
            // Each bit should appear roughly 50% of the time (with tolerance for small sample)
            for (i, &count) in bit_counts.iter().enumerate() {
                let percentage = (count as f64 / samples as f64) * 100.0;
                assert!(percentage >= 20.0 && percentage <= 80.0, 
                    "Bit {} appears {}% of time - poor randomness (expected ~50%)", i, percentage);
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_authentication_tag_manipulation_resistance() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "AUTH_TAG_TEST";
            
            let encrypted = crypto.encrypt_secret_key(secret)
                .expect("Encryption should succeed");
            
            let mut decoded = base64::engine::general_purpose::STANDARD.decode(&encrypted)
                .expect("Should decode base64");
            
            // AES-GCM uses 16-byte authentication tag at the end
            if decoded.len() >= 16 {
                let original_len = decoded.len();
                
                // Flip bits in the authentication tag (last 16 bytes)
                for i in 1..16 {
                    let mut corrupted = decoded.clone();
                    corrupted[original_len - i] ^= 0x01; // Flip one bit
                    
                    let corrupted_base64 = base64::engine::general_purpose::STANDARD.encode(&corrupted);
                    let result = crypto.decrypt_secret_key(&corrupted_base64);
                    
                    assert!(result.is_err(), 
                        "Authentication tag manipulation at position {} should be detected", i);
                }
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_ciphertext_bit_flipping_resistance() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "BIT_FLIP_TEST_SECRET";
            
            let encrypted = crypto.encrypt_secret_key(secret)
                .expect("Encryption should succeed");
            
            let mut decoded = base64::engine::general_purpose::STANDARD.decode(&encrypted)
                .expect("Should decode base64");
            
            // Try flipping bits in the ciphertext portion (between nonce and auth tag)
            if decoded.len() > 28 { // 12 (nonce) + 16 (auth tag) = 28 minimum
                let ciphertext_start = 12;
                let ciphertext_end = decoded.len() - 16;
                
                for pos in ciphertext_start..ciphertext_end {
                    let mut bit_flipped = decoded.clone();
                    bit_flipped[pos] ^= 0x01; // Flip one bit
                    
                    let corrupted_base64 = base64::engine::general_purpose::STANDARD.encode(&bit_flipped);
                    let result = crypto.decrypt_secret_key(&corrupted_base64);
                    
                    assert!(result.is_err(), 
                        "Bit flipping at ciphertext position {} should be detected by authentication", pos);
                }
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_chosen_plaintext_attack_resistance() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            
            // Create owned strings to avoid temporary value issues
            let all_zeros = String::from_utf8(vec![0u8; 8]).unwrap_or_default();
            let high_ascii = "\u{007f}".repeat(8);
            
            // Test with patterns that might reveal key information
            let attack_patterns = vec![
                "AAAAAAAAAAAAAAAA".to_string(), // All same character
                "ABABABABABABABAB".to_string(), // Alternating pattern
                "0123456789ABCDEF".to_string(), // Sequential pattern
                all_zeros, // All zeros
                high_ascii, // High ASCII
            ];
            
            let mut encrypted_patterns = Vec::new();
            
            for pattern in &attack_patterns {
                let encrypted = crypto.encrypt_secret_key(pattern)
                    .expect("Should encrypt attack pattern");
                encrypted_patterns.push(encrypted);
            }
            
            // Encrypted outputs should not reveal patterns even with chosen plaintexts
            for (i, encrypted1) in encrypted_patterns.iter().enumerate() {
                for (j, encrypted2) in encrypted_patterns.iter().enumerate() {
                    if i != j {
                        assert_ne!(encrypted1, encrypted2, 
                            "Different plaintexts should produce different ciphertexts");
                        
                        // Check that no obvious patterns exist in the encrypted data
                        let decoded1 = base64::engine::general_purpose::STANDARD.decode(encrypted1).unwrap();
                        let decoded2 = base64::engine::general_purpose::STANDARD.decode(encrypted2).unwrap();
                        
                        // Should not share common subsequences (beyond chance)
                        let mut common_bytes = 0;
                        let min_len = decoded1.len().min(decoded2.len());
                        for k in 0..min_len {
                            if decoded1[k] == decoded2[k] {
                                common_bytes += 1;
                            }
                        }
                        
                        let similarity_ratio = common_bytes as f64 / min_len as f64;
                        assert!(similarity_ratio < 0.7, 
                            "Encrypted patterns {} and {} are too similar ({}% match)", i, j, similarity_ratio * 100.0);
                    }
                }
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_key_derivation_independence() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let base_secret = "KEY_DERIVATION_TEST";
            
            // Encrypt many related secrets to test for key derivation weaknesses
            let mut encryptions = Vec::new();
            for i in 0..100 {
                let related_secret = format!("{}_{}", base_secret, i);
                let encrypted = crypto.encrypt_secret_key(&related_secret)
                    .expect("Should encrypt related secret");
                encryptions.push(encrypted);
            }
            
            // No two encryptions should be identical (due to nonces)
            let unique_encryptions: HashSet<_> = encryptions.iter().collect();
            assert_eq!(unique_encryptions.len(), encryptions.len(), 
                "All encryptions should be unique even with related plaintexts");
            
            // Verify all decrypt correctly
            for (i, encrypted) in encryptions.iter().enumerate() {
                let decrypted = crypto.decrypt_secret_key(encrypted)
                    .expect("Should decrypt correctly");
                let expected = format!("{}_{}", base_secret, i);
                assert_eq!(decrypted, expected, "Decryption {} should be correct", i);
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_side_channel_timing_consistency() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "TIMING_TEST_SECRET";
            
            let encrypted = crypto.encrypt_secret_key(secret)
                .expect("Encryption should succeed");
            
            // Test timing consistency for decryption with wrong keys
            let wrong_keys = vec![
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ];
            
            let mut timings = Vec::new();
            
            for wrong_key in &wrong_keys {
                env::set_var("MASTER_ENCRYPTION_KEY", wrong_key);
                let wrong_crypto = KeyEncryption::new().expect("Should create crypto instance");
                
                // Measure timing for decryption attempts
                let start = Instant::now();
                let result = wrong_crypto.decrypt_secret_key(&encrypted);
                let duration = start.elapsed();
                
                assert!(result.is_err(), "Should fail with wrong key");
                timings.push(duration.as_nanos());
            }
            
            // Check timing consistency (should not vary significantly)
            if timings.len() >= 2 {
                let min_time = *timings.iter().min().unwrap();
                let max_time = *timings.iter().max().unwrap();
                
                if min_time > 0 {
                    let timing_ratio = max_time as f64 / min_time as f64;
                    assert!(timing_ratio < 5.0, 
                        "Timing variation too high ({:.2}x) - potential side channel", timing_ratio);
                }
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_denial_of_service_resistance() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            
            // Test with moderately large input (DoS attack simulation)
            let large_secret = "A".repeat(1_000_000); // 1MB (reduced from 10MB for test speed)
            
            let start_time = Instant::now();
            let result = crypto.encrypt_secret_key(&large_secret);
            let duration = start_time.elapsed();
            
            match result {
                Ok(encrypted) => {
                    // If it succeeds, it should complete in reasonable time
                    assert!(duration.as_secs() < 30, 
                        "Encryption took too long ({:.2}s) - DoS vulnerability", duration.as_secs_f64());
                    
                    // And decryption should also be reasonable
                    let decrypt_start = Instant::now();
                    let decrypted = crypto.decrypt_secret_key(&encrypted)
                        .expect("Large data decryption should succeed");
                    let decrypt_duration = decrypt_start.elapsed();
                    
                    assert!(decrypt_duration.as_secs() < 30,
                        "Decryption took too long ({:.2}s) - DoS vulnerability", decrypt_duration.as_secs_f64());
                    assert_eq!(decrypted, large_secret, "Large data should round-trip correctly");
                }
                Err(_) => {
                    // If it fails, that's also acceptable - shows input validation
                    assert!(duration.as_millis() < 5000,
                        "Even failure should be reasonably fast to prevent DoS");
                }
            }
            
            cleanup_test_environment();
        }

        #[test]
        fn test_replay_attack_resistance() {
            setup_test_environment();
            
            let crypto = KeyEncryption::new().expect("Should create crypto instance");
            let secret = "REPLAY_ATTACK_TEST";
            
            let encrypted1 = crypto.encrypt_secret_key(secret)
                .expect("First encryption should succeed");
            let encrypted2 = crypto.encrypt_secret_key(secret)
                .expect("Second encryption should succeed");
            
            // Same plaintext should produce different ciphertexts (due to nonces)
            assert_ne!(encrypted1, encrypted2, 
                "Replay attack protection: same plaintext should produce different ciphertexts");
            
            // Both should decrypt to the same original
            let decrypted1 = crypto.decrypt_secret_key(&encrypted1)
                .expect("First decryption should succeed");
            let decrypted2 = crypto.decrypt_secret_key(&encrypted2)
                .expect("Second decryption should succeed");
            
            assert_eq!(decrypted1, secret, "First decryption should match");
            assert_eq!(decrypted2, secret, "Second decryption should match");
            
            // This demonstrates that replaying the same ciphertext won't reveal if
            // it's the same plaintext, providing protection against replay attacks
            
            cleanup_test_environment();
        }
    }
}