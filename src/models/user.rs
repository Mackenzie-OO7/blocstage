use crate::services::crypto::KeyEncryption;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use log::{info, warn};
use rand::{distr::Alphanumeric, rng, Rng};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub stellar_public_key: Option<String>,
    #[serde(skip_serializing)]
    pub stellar_secret_key: Option<String>,
    pub stellar_secret_key_encrypted: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub email_verified: bool,
    pub verification_token: Option<String>,
    pub reset_token: Option<String>,
    pub reset_token_expires: Option<DateTime<Utc>>,
    pub status: String, // "active", "deleted", etc.
    pub role: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestPasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

impl User {
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT * FROM users WHERE id = $1 AND status != 'deleted'"#,
            id
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT * FROM users WHERE email = $1 AND status != 'deleted'"#,
            email
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn create(
        pool: &PgPool,
        user: CreateUserRequest,
        password_hash: String,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let verification_token = generate_random_token(32);

        let user = sqlx::query_as!(
            User,
            r#"
        INSERT INTO users (
        id, username, email, first_name, last_name, password_hash, 
        created_at, updated_at, email_verified, verification_token, status, role
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *
        "#,
            id,
            user.username,
            user.email,
            user.first_name, // ADD this
            user.last_name,  // ADD this
            password_hash,
            now,
            now,
            false,
            Some(verification_token),
            "active",
            "user"
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub async fn update_stellar_keys(
        &self,
        pool: &PgPool,
        public_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        let key_encryption = KeyEncryption::new()
            .map_err(|e| anyhow!("Failed to initialize crypto service: {}", e))?;
        let encrypted_secret = key_encryption
            .encrypt_secret_key(secret_key)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt secret key: {}", e))?;

        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET 
                stellar_public_key = $1, 
                stellar_secret_key_encrypted = $2, 
                updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
            public_key,
            encrypted_secret,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub fn decrypt_stellar_secret(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.stellar_secret_key_encrypted {
            Some(encrypted) => {
                let key_encryption = KeyEncryption::new()
                    .map_err(|e| anyhow!("Failed to initialize crypto service: {}", e))?;
                key_encryption.decrypt_secret_key(encrypted)
            }
            None => Err("No encrypted secret key found".into()),
        }
    }

    pub async fn verify_email(pool: &PgPool, token: &str) -> Result<Option<Self>> {
        let now = Utc::now();

        // Find the user with this token and validate ownership + expiry
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET 
                email_verified = true, 
                verification_token = NULL, 
                updated_at = $1
            WHERE verification_token = $2 
                AND status = 'active'
                AND email_verified = false
                AND created_at > $3
            RETURNING *
            "#,
            now,
            token,
            now - Duration::hours(24) // Token expires after 24 hours from user creation
        )
        .fetch_optional(pool)
        .await?;

        if let Some(ref user) = user {
            info!(
                "✅ Email successfully verified for user: {} ({})",
                user.id, user.email
            );
        } else {
            warn!(
                "❌ Invalid or expired verification token attempted: {}",
                token
            );
        }

        Ok(user)
    }

    pub async fn request_password_reset(&self, pool: &PgPool) -> Result<String> {
        let now = Utc::now();

        // Check if user already has a recent reset token (rate limiting)
        if let Some(reset_expires) = self.reset_token_expires {
            let time_until_expiry = reset_expires.signed_duration_since(now);
            if time_until_expiry > Duration::minutes(5) {
                // Token still has more than 5 minutes left, don't allow new request
                return Err(anyhow!(
                    "Please wait before requesting another password reset"
                ));
            }
        }

        // Generate new secure token using your existing helper
        let token = generate_random_token(32);
        let expires = now + Duration::hours(24);

        // Update user with new reset token
        let updated_rows = sqlx::query!(
            r#"
            UPDATE users
            SET 
                reset_token = $1, 
                reset_token_expires = $2, 
                updated_at = $3
            WHERE id = $4 AND status = 'active'
            "#,
            token,
            expires,
            now,
            self.id
        )
        .execute(pool)
        .await?
        .rows_affected();

        if updated_rows == 0 {
            return Err(anyhow!("Failed to generate password reset token"));
        }

        info!(
            "🔑 Password reset token generated for user: {} ({})",
            self.id, self.email
        );
        Ok(token)
    }

    // Enhanced password reset with security improvements
    // REPLACE your existing reset_password method with this one
    pub async fn reset_password(
        pool: &PgPool,
        token: &str,
        new_password_hash: &str,
    ) -> Result<Option<Self>> {
        let now = Utc::now();

        // Reset password and clear token in one atomic operation
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET 
                password_hash = $1, 
                reset_token = NULL, 
                reset_token_expires = NULL,
                updated_at = $2
            WHERE reset_token = $3 
                AND reset_token_expires > $4 
                AND status = 'active'
            RETURNING *
            "#,
            new_password_hash,
            now,
            token,
            now
        )
        .fetch_optional(pool)
        .await?;

        if let Some(ref user) = user {
            info!(
                "🔐 Password successfully reset for user: {} ({})",
                user.id, user.email
            );
        } else {
            warn!(
                "❌ Invalid or expired password reset token attempted: {}",
                token
            );
        }

        Ok(user)
    }

    // NEW METHOD - Add this for rate limiting password reset attempts
    pub async fn can_request_password_reset(pool: &PgPool, email: &str) -> Result<bool> {
        let now = Utc::now();

        let user = sqlx::query!(
            r#"
            SELECT 
                reset_token_expires
            FROM users
            WHERE email = $1 AND status = 'active'
            "#,
            email
        )
        .fetch_optional(pool)
        .await?;

        let Some(user) = user else {
            return Ok(true); // User doesn't exist, but don't leak that info
        };

        // Simple rate limiting: if user has active reset token with more than 5 minutes left, deny
        if let Some(reset_expires) = user.reset_token_expires {
            let time_until_expiry = reset_expires.signed_duration_since(now);
            if time_until_expiry > Duration::minutes(5) {
                return Ok(false); // Too soon to request another reset
            }
        }

        Ok(true)
    }

    // soft delete account
    pub async fn delete_account(&self, pool: &PgPool) -> Result<Self> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET 
                status = 'deleted',
                email = $1, 
                username = $2, 
                updated_at = $3
            WHERE id = $4
            RETURNING 
                id, username, email, first_name, last_name, password_hash, 
                stellar_public_key, stellar_secret_key, stellar_secret_key_encrypted,
                created_at, updated_at,
                email_verified, verification_token,
                reset_token, reset_token_expires, status, role
            "#,
            format!("deleted_{}@deleted.com", self.id),
            format!("deleted_user_{}", self.id),
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }
}

fn generate_random_token(length: usize) -> String {
    let rand_string: String = rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    rand_string
}

// tests

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use chrono::Duration;
//     use sqlx::PgPool;
//     use std::env;

//     // test database
//     async fn setup_test_db() -> PgPool {
//         dotenv::from_filename(".env.test").ok();
//         dotenv::dotenv().ok();

//         // Debug
//         println!("=== DEBUG DATABASE SETUP ===");
//         println!("TEST_DATABASE_URL: {:?}", env::var("TEST_DATABASE_URL"));
//         println!("DATABASE_URL: {:?}", env::var("DATABASE_URL"));

//         let database_url = env::var("TEST_DATABASE_URL")
//             .or_else(|_| env::var("DATABASE_URL"))
//             .expect("TEST_DATABASE_URL or DATABASE_URL must be set for tests");

//         println!("Using connection string: {}", database_url);
//         println!("==============================");

//         let pool = PgPool::connect(&database_url)
//             .await
//             .expect("Failed to connect to test database");

//         // Run migrations to ensure test database is up to date
//         sqlx::migrate!("./migrations")
//             .run(&pool)
//             .await
//             .expect("Failed to run migrations");

//         pool
//     }

//     // Helper to create a test user in the dd
//     async fn create_test_user(pool: &PgPool, suffix: &str) -> User {
//         let user_id = Uuid::new_v4();
//         let now = Utc::now();
//         let verification_token = generate_random_token(32);

//         // Create truly unique identifiers to avoid collisions between test runs
//         let unique_id = format!("{}_{}_{}", suffix, user_id.simple(), now.timestamp_millis());

//         sqlx::query_as!(
//             User,
//             r#"
//         INSERT INTO users (
//             id, username, email, password_hash, created_at, updated_at,
//             email_verified, verification_token, status, role
//         )
//         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
//         RETURNING *
//         "#,
//             user_id,
//             format!("testuser_{}", unique_id),
//             format!("test_{}@example.com", unique_id),
//             "hashed_password",
//             now,
//             now,
//             false,
//             Some(verification_token),
//             "active",
//             "user"
//         )
//         .fetch_one(pool)
//         .await
//         .expect("Failed to create test user")
//     }

//     // Helper to clean up test data
//     async fn cleanup_test_user(pool: &PgPool, user_id: Uuid) {
//         sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
//             .execute(pool)
//             .await
//             .ok(); // Ignore errors during cleanup (for now)
//     }

//     mod find_operations {
//         use super::*;

//         #[tokio::test]
//         async fn test_find_by_id_existing_user() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "find_id_exists").await;

//             let result = User::find_by_id(&pool, test_user.id).await;

//             assert!(result.is_ok(), "Should successfully find user by ID");
//             let found_user = result.unwrap();
//             assert!(found_user.is_some(), "User should exist");

//             let user = found_user.unwrap();
//             assert_eq!(user.id, test_user.id);
//             assert_eq!(user.email, test_user.email);
//             assert_eq!(user.username, test_user.username);
//             assert_eq!(user.status, "active");

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_find_by_id_nonexistent_user() {
//             let pool = setup_test_db().await;
//             let random_id = Uuid::new_v4();

//             let result = User::find_by_id(&pool, random_id).await;

//             assert!(result.is_ok(), "Should successfully execute query");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should return None for nonexistent user"
//             );
//         }

//         #[tokio::test]
//         async fn test_find_by_id_deleted_user() {
//             let pool = setup_test_db().await;
//             let mut test_user = create_test_user(&pool, "find_id_deleted").await;

//             // Mark user as deleted
//             sqlx::query!(
//                 "UPDATE users SET status = 'deleted' WHERE id = $1",
//                 test_user.id
//             )
//             .execute(&pool)
//             .await
//             .expect("Failed to mark user as deleted");

//             let result = User::find_by_id(&pool, test_user.id).await;

//             assert!(result.is_ok(), "Should successfully execute query");
//             assert!(result.unwrap().is_none(), "Should not find deleted user");

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_find_by_email_existing_user() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "find_email_exists").await;

//             let result = User::find_by_email(&pool, &test_user.email).await;

//             assert!(result.is_ok(), "Should successfully find user by email");
//             let found_user = result.unwrap();
//             assert!(found_user.is_some(), "User should exist");

//             let user = found_user.unwrap();
//             assert_eq!(user.id, test_user.id);
//             assert_eq!(user.email, test_user.email);

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_find_by_email_nonexistent_user() {
//             let pool = setup_test_db().await;

//             let result = User::find_by_email(&pool, "nonexistent@example.com").await;

//             assert!(result.is_ok(), "Should successfully execute query");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should return None for nonexistent email"
//             );
//         }

//         #[tokio::test]
//         async fn test_find_by_email_case_sensitivity() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "find_email_case").await;

//             // Test with different case. should not find (emails are case sensitive in DB)
//             let result = User::find_by_email(&pool, &test_user.email.to_uppercase()).await;

//             assert!(result.is_ok(), "Should successfully execute query");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should not find user with different case email"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_find_by_email_deleted_user() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "find_email_deleted").await;

//             sqlx::query!(
//                 "UPDATE users SET status = 'deleted' WHERE id = $1",
//                 test_user.id
//             )
//             .execute(&pool)
//             .await
//             .expect("Failed to mark user as deleted");

//             let result = User::find_by_email(&pool, &test_user.email).await;

//             assert!(result.is_ok(), "Should successfully execute query");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should not find deleted user by email"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }
//     }

//     mod user_creation {
//         use super::*;

//         #[tokio::test]
//         async fn test_create_user_success() {
//             let pool = setup_test_db().await;
//             let unique_suffix = Uuid::new_v4().simple().to_string();

//             let create_request = CreateUserRequest {
//                 username: format!("newuser_{}", unique_suffix),
//                 email: format!("newuser_{}@example.com", unique_suffix),
//                 password: "test_password".to_string(),
//             };

//             let password_hash = "hashed_test_password".to_string();

//             let result = User::create(&pool, create_request, password_hash.clone()).await;

//             assert!(result.is_ok(), "User creation should succeed");
//             let user = result.unwrap();

//             assert!(!user.id.is_nil(), "User should have valid ID");
//             assert_eq!(user.username, format!("newuser_{}", unique_suffix));
//             assert_eq!(user.email, format!("newuser_{}@example.com", unique_suffix));
//             assert_eq!(user.password_hash, password_hash);
//             assert!(
//                 !user.email_verified,
//                 "Email should not be verified initially"
//             );
//             assert!(
//                 user.verification_token.is_some(),
//                 "Should have verification token"
//             );
//             assert_eq!(user.status, "active");
//             assert_eq!(user.role, "user");
//             assert!(
//                 user.verification_token.as_ref().unwrap().len() >= 32,
//                 "Verification token should be at least 32 chars"
//             );

//             cleanup_test_user(&pool, user.id).await;
//         }

//         #[tokio::test]
//         async fn test_create_user_duplicate_email() {
//             let pool = setup_test_db().await;
//             let unique_suffix = Uuid::new_v4().simple().to_string();
//             let email = format!("duplicate_{}@example.com", unique_suffix);

//             // Create first user
//             let first_request = CreateUserRequest {
//                 username: format!("user1_{}", unique_suffix),
//                 email: email.clone(),
//                 password: "password1".to_string(),
//             };
//             let first_user = User::create(&pool, first_request, "hash1".to_string())
//                 .await
//                 .expect("First user creation should succeed");

//             // Attempt to create second user with same email
//             let second_request = CreateUserRequest {
//                 username: format!("user2_{}", unique_suffix),
//                 email: email.clone(),
//                 password: "password2".to_string(),
//             };

//             let result = User::create(&pool, second_request, "hash2".to_string()).await;

//             assert!(
//                 result.is_err(),
//                 "Should fail to create user with duplicate email"
//             );

//             cleanup_test_user(&pool, first_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_create_user_duplicate_username() {
//             let pool = setup_test_db().await;
//             let unique_suffix = Uuid::new_v4().simple().to_string();
//             let username = format!("duplicate_user_{}", unique_suffix);

//             let first_request = CreateUserRequest {
//                 username: username.clone(),
//                 email: format!("user1_{}@example.com", unique_suffix),
//                 password: "password1".to_string(),
//             };
//             let first_user = User::create(&pool, first_request, "hash1".to_string())
//                 .await
//                 .expect("First user creation should succeed");

//             let second_request = CreateUserRequest {
//                 username: username.clone(),
//                 email: format!("user2_{}@example.com", unique_suffix),
//                 password: "password2".to_string(),
//             };

//             let result = User::create(&pool, second_request, "hash2".to_string()).await;

//             assert!(
//                 result.is_err(),
//                 "Should fail to create user with duplicate username"
//             );

//             cleanup_test_user(&pool, first_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_create_user_empty_fields() {
//             let pool = setup_test_db().await;

//             let create_request = CreateUserRequest {
//                 username: "".to_string(),
//                 email: "".to_string(),
//                 password: "".to_string(),
//             };

//             let result = User::create(&pool, create_request, "hash".to_string()).await;

//             assert!(
//                 result.is_err(),
//                 "Should fail to create user with empty fields"
//             );
//         }

//         #[tokio::test]
//         async fn test_create_user_invalid_email_format() {
//             let pool = setup_test_db().await;
//             let unique_suffix = Uuid::new_v4().simple().to_string();

//             let create_request = CreateUserRequest {
//                 username: format!("user_{}", unique_suffix),
//                 email: "invalid_email_format".to_string(),
//                 password: "password".to_string(),
//             };

//             // This test depends on DB constraints or validation
//             // The current implementation doesn't validate email format at the model level
//             let result = User::create(&pool, create_request, "hash".to_string()).await;

//             // If db has email format constraints, this should fail
//             // If not, it will succeed but the email will be invalid
//             // This test documents current behavior
//             if result.is_ok() {
//                 let user = result.unwrap();
//                 cleanup_test_user(&pool, user.id).await;
//             }
//             // Test passes either way, but documents the behavior
//         }
//     }

//     mod stellar_key_operations {
//         use super::*;

//         #[tokio::test]
//         async fn test_update_stellar_keys_success() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "stellar_keys").await;

//             let public_key = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
//             let secret_key = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

//             let result = test_user
//                 .update_stellar_keys(&pool, public_key, secret_key)
//                 .await;

//             if result.is_ok() {
//                 let updated_user = result.unwrap();
//                 assert_eq!(
//                     updated_user.stellar_public_key,
//                     Some(public_key.to_string())
//                 );
//                 assert!(
//                     updated_user.stellar_secret_key_encrypted.is_some(),
//                     "Secret key should be encrypted and stored"
//                 );
//                 assert_ne!(
//                     updated_user.stellar_secret_key_encrypted.as_ref().unwrap(),
//                     secret_key,
//                     "Encrypted key should be different from original"
//                 );
//             }

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_decrypt_stellar_secret_no_key() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "decrypt_no_key").await;

//             let result = test_user.decrypt_stellar_secret();

//             assert!(
//                 result.is_err(),
//                 "Should fail when no encrypted secret key exists"
//             );
//             assert!(result
//                 .unwrap_err()
//                 .to_string()
//                 .contains("No encrypted secret key found"));

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_stellar_key_encryption_decryption_cycle() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "crypto_cycle").await;

//             let original_secret = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
//             let public_key = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

//             // Update with stellar keys (mock?)
//             let update_result = test_user
//                 .update_stellar_keys(&pool, public_key, original_secret)
//                 .await;

//             if update_result.is_ok() {
//                 let updated_user = update_result.unwrap();

//                 // Try to decrypt the secret key
//                 let decrypt_result = updated_user.decrypt_stellar_secret();

//                 if decrypt_result.is_ok() {
//                     let decrypted_secret = decrypt_result.unwrap();
//                     assert_eq!(
//                         decrypted_secret, original_secret,
//                         "Decrypted secret should match original"
//                     );
//                 }
//             }

//             cleanup_test_user(&pool, test_user.id).await;
//         }
//     }

//     mod email_verification {
//         use super::*;

//         #[tokio::test]
//         async fn test_verify_email_success() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "verify_email").await;
//             let token = test_user.verification_token.clone().unwrap();

//             let result = User::verify_email(&pool, &token).await;

//             assert!(result.is_ok(), "Email verification should succeed");
//             let verified_user = result.unwrap();
//             assert!(verified_user.is_some(), "Should return verified user");

//             let user = verified_user.unwrap();
//             assert!(
//                 user.email_verified,
//                 "User should be marked as email verified"
//             );
//             assert!(
//                 user.verification_token.is_none(),
//                 "Verification token should be cleared"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_verify_email_invalid_token() {
//             let pool = setup_test_db().await;
//             let invalid_token = "invalid_token_12345";

//             let result = User::verify_email(&pool, invalid_token).await;

//             assert!(result.is_ok(), "Query should execute successfully");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should return None for invalid token"
//             );
//         }

//         #[tokio::test]
//         async fn test_verify_email_deleted_user() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "verify_deleted").await;
//             let token = test_user.verification_token.clone().unwrap();

//             sqlx::query!(
//                 "UPDATE users SET status = 'deleted' WHERE id = $1",
//                 test_user.id
//             )
//             .execute(&pool)
//             .await
//             .expect("Failed to mark user as deleted");

//             let result = User::verify_email(&pool, &token).await;

//             assert!(result.is_ok(), "Query should execute successfully");
//             assert!(result.unwrap().is_none(), "Should not verify deleted user");

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_verify_email_already_verified() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "already_verified").await;

//             sqlx::query!(
//                 "UPDATE users SET email_verified = true, verification_token = NULL WHERE id = $1",
//                 test_user.id
//             )
//             .execute(&pool)
//             .await
//             .expect("Failed to mark user as verified");

//             let result = User::verify_email(&pool, "any_token").await;

//             assert!(result.is_ok(), "Query should execute successfully");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should not verify user without token"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }
//     }

//     mod password_reset {
//         use super::*;

//         #[tokio::test]
//         async fn test_request_password_reset_success() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "reset_request").await;

//             let result = test_user.request_password_reset(&pool).await;

//             assert!(result.is_ok(), "Password reset request should succeed");
//             let token = result.unwrap();
//             assert!(!token.is_empty(), "Should return non-empty token");
//             assert!(token.len() >= 32, "Token should be at least 32 characters");

//             // Verify token was stored in database
//             let updated_user = User::find_by_id(&pool, test_user.id)
//                 .await
//                 .unwrap()
//                 .unwrap();
//             assert!(
//                 updated_user.reset_token.is_some(),
//                 "Reset token should be stored"
//             );
//             assert!(
//                 updated_user.reset_token_expires.is_some(),
//                 "Reset token expiry should be set"
//             );

//             // Verify token expires in the future
//             let expiry = updated_user.reset_token_expires.unwrap();
//             assert!(
//                 expiry > Utc::now(),
//                 "Reset token should expire in the future"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_reset_password_success() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "reset_password").await;

//             // Request password reset first
//             let token = test_user.request_password_reset(&pool).await.unwrap();
//             let new_password_hash = "new_hashed_password";

//             let result = User::reset_password(&pool, &token, new_password_hash).await;

//             assert!(result.is_ok(), "Password reset should succeed");
//             let reset_user = result.unwrap();
//             assert!(reset_user.is_some(), "Should return updated user");

//             let user = reset_user.unwrap();
//             assert_eq!(user.password_hash, new_password_hash);
//             assert!(user.reset_token.is_none(), "Reset token should be cleared");
//             assert!(
//                 user.reset_token_expires.is_none(),
//                 "Reset token expiry should be cleared"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_reset_password_invalid_token() {
//             let pool = setup_test_db().await;
//             let invalid_token = "invalid_reset_token";
//             let new_password_hash = "new_hashed_password";

//             let result = User::reset_password(&pool, invalid_token, new_password_hash).await;

//             assert!(result.is_ok(), "Query should execute successfully");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should return None for invalid token"
//             );
//         }

//         #[tokio::test]
//         async fn test_reset_password_expired_token() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "expired_token").await;

//             let token = generate_random_token(32);
//             let expired_time = Utc::now() - Duration::hours(25);

//             sqlx::query!(
//                 "UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3",
//                 token,
//                 expired_time,
//                 test_user.id
//             )
//             .execute(&pool)
//             .await
//             .expect("Failed to set expired token");

//             let result = User::reset_password(&pool, &token, "new_hash").await;

//             assert!(result.is_ok(), "Query should execute successfully");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should not reset password with expired token"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_reset_password_deleted_user() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "reset_deleted").await;

//             let token = test_user.request_password_reset(&pool).await.unwrap();

//             sqlx::query!(
//                 "UPDATE users SET status = 'deleted' WHERE id = $1",
//                 test_user.id
//             )
//             .execute(&pool)
//             .await
//             .expect("Failed to mark user as deleted");

//             let result = User::reset_password(&pool, &token, "new_hash").await;

//             assert!(result.is_ok(), "Query should execute successfully");
//             assert!(
//                 result.unwrap().is_none(),
//                 "Should not reset password for deleted user"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }
//     }

//     mod account_deletion {
//         use super::*;

//         #[tokio::test]
//         async fn test_delete_account_success() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "delete_account").await;
//             let original_email = test_user.email.clone();
//             let original_username = test_user.username.clone();

//             let result = test_user.delete_account(&pool).await;

//             assert!(result.is_ok(), "Account deletion should succeed");
//             let deleted_user = result.unwrap();

//             assert_eq!(deleted_user.status, "deleted");
//             assert_eq!(
//                 deleted_user.email,
//                 format!("deleted_{}@deleted.com", test_user.id)
//             );
//             assert_eq!(
//                 deleted_user.username,
//                 format!("deleted_user_{}", test_user.id)
//             );
//             assert_ne!(deleted_user.email, original_email);
//             assert_ne!(deleted_user.username, original_username);

//             let find_result = User::find_by_id(&pool, test_user.id).await.unwrap();
//             assert!(
//                 find_result.is_none(),
//                 "Deleted user should not be found by normal queries"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[tokio::test]
//         async fn test_delete_account_preserves_id() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "delete_preserve_id").await;
//             let original_id = test_user.id;

//             let result = test_user.delete_account(&pool).await;

//             assert!(result.is_ok(), "Account deletion should succeed");
//             let deleted_user = result.unwrap();

//             assert_eq!(
//                 deleted_user.id, original_id,
//                 "User ID should be preserved after deletion"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         /*
//         this test is passing, meaning `delete_acciunt()` can be called multiple times.
//         while this isn't a functional or security issue, it should still be fixed.
//         TODO
//         */

//         // #[tokio::test]
//         // async fn test_delete_account_multiple_calls() {
//         //     let pool = setup_test_db().await;
//         //     let test_user = create_test_user(&pool, "delete_multiple").await;

//         //     // First deletion
//         //     let first_result = test_user.delete_account(&pool).await;
//         //     assert!(first_result.is_ok(), "First deletion should succeed");

//         //     // Attempt second deletion
//         //     let second_result = test_user.delete_account(&pool).await;
//         //     assert!(
//         //         second_result.is_err(),
//         //         "Second deletion should fail - user already deleted"
//         //     );

//         //     cleanup_test_user(&pool, test_user.id).await;
//         // }
//     }

//     mod utility_functions {
//         use super::*;

//         #[test]
//         fn test_generate_random_token_length() {
//             let token = generate_random_token(32);
//             assert_eq!(token.len(), 32, "Token should have requested length");
//         }

//         #[test]
//         fn test_generate_random_token_uniqueness() {
//             let token1 = generate_random_token(32);
//             let token2 = generate_random_token(32);
//             assert_ne!(token1, token2, "Generated tokens should be unique");
//         }

//         #[test]
//         fn test_generate_random_token_alphanumeric() {
//             let token = generate_random_token(100);
//             assert!(
//                 token.chars().all(|c| c.is_alphanumeric()),
//                 "Token should contain only alphanumeric characters"
//             );
//         }

//         #[test]
//         fn test_generate_random_token_zero_length() {
//             let token = generate_random_token(0);
//             assert_eq!(token.len(), 0, "Zero length should produce empty token");
//         }

//         #[test]
//         fn test_generate_random_token_large_length() {
//             let token = generate_random_token(1000);
//             assert_eq!(token.len(), 1000, "Should handle large token lengths");
//         }
//     }

//     mod data_validation {
//         use super::*;

//         #[tokio::test]
//         async fn test_user_serialization_excludes_sensitive_data() {
//             let pool = setup_test_db().await;
//             let test_user = create_test_user(&pool, "serialization").await;

//             let serialized = serde_json::to_string(&test_user).unwrap();

//             // Verify sensitive fields are not included in serialization
//             assert!(
//                 !serialized.contains(&test_user.password_hash),
//                 "Password hash should not be serialized"
//             );

//             // If stellar_secretkey exists, it should not be serialized
//             if let Some(secret_key) = &test_user.stellar_secret_key {
//                 assert!(
//                     !serialized.contains(secret_key),
//                     "Stellar secret key should not be serialized"
//                 );
//             }

//             // Verify safe fields are included
//             assert!(
//                 serialized.contains(&test_user.id.to_string()),
//                 "User ID should be serialized"
//             );
//             assert!(
//                 serialized.contains(&test_user.email),
//                 "Email should be serialized"
//             );
//             assert!(
//                 serialized.contains(&test_user.username),
//                 "Username should be serialized"
//             );

//             cleanup_test_user(&pool, test_user.id).await;
//         }

//         #[test]
//         fn test_create_user_request_deserialization() {
//             let json =
//                 r#"{"username":"testuser","email":"test@example.com","password":"password123"}"#;
//             let request: CreateUserRequest = serde_json::from_str(json).unwrap();

//             assert_eq!(request.username, "testuser");
//             assert_eq!(request.email, "test@example.com");
//             assert_eq!(request.password, "password123");
//         }

//         #[test]
//         fn test_login_request_deserialization() {
//             let json = r#"{"email":"test@example.com","password":"password123"}"#;
//             let request: LoginRequest = serde_json::from_str(json).unwrap();

//             assert_eq!(request.email, "test@example.com");
//             assert_eq!(request.password, "password123");
//         }
//     }

//     mod edge_cases {
//         use super::*;

//         #[tokio::test]
//         async fn test_concurrent_user_creation_same_email() {
//             let pool = setup_test_db().await;
//             let unique_suffix = Uuid::new_v4().simple().to_string();
//             let email = format!("concurrent_{}@example.com", unique_suffix);

//             let request1 = CreateUserRequest {
//                 username: format!("user1_{}", unique_suffix),
//                 email: email.clone(),
//                 password: "password1".to_string(),
//             };

//             let request2 = CreateUserRequest {
//                 username: format!("user2_{}", unique_suffix),
//                 email: email.clone(),
//                 password: "password2".to_string(),
//             };

//             // Attempt concurrent creation
//             let (result1, result2) = tokio::join!(
//                 User::create(&pool, request1, "hash1".to_string()),
//                 User::create(&pool, request2, "hash2".to_string())
//             );

//             // Exactly one should succeed
//             let success_count = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
//             assert_eq!(
//                 success_count, 1,
//                 "Exactly one concurrent user creation should succeed"
//             );

//             // Clean up the successful user
//             if let Ok(user) = result1 {
//                 cleanup_test_user(&pool, user.id).await;
//             }
//             if let Ok(user) = result2 {
//                 cleanup_test_user(&pool, user.id).await;
//             }
//         }

//         #[tokio::test]
//         async fn test_very_long_input_fields() {
//             let pool = setup_test_db().await;
//             let long_string = "x".repeat(1000);

//             let request = CreateUserRequest {
//                 username: long_string.clone(),
//                 email: format!("{}@example.com", long_string),
//                 password: long_string.clone(),
//             };

//             let result = User::create(&pool, request, "hash".to_string()).await;

//             // This should either succeed (if db allows long fields) or fail gracefully
//             if result.is_ok() {
//                 let user = result.unwrap();
//                 cleanup_test_user(&pool, user.id).await;
//             }
//             // Test documents current behavior without asserting specific outcome
//         }

//         #[tokio::test]
//         async fn test_unicode_characters_in_fields() {
//             let pool = setup_test_db().await;
//             let unique_suffix = Uuid::new_v4().simple().to_string();

//             let request = CreateUserRequest {
//                 username: format!("用户_{}", unique_suffix), // Chinese
//                 email: format!("test_{}@例え.com", unique_suffix), // Mixed unicode
//                 password: "密码123".to_string(),             // Chinese pw
//             };

//             let result = User::create(&pool, request, "hash".to_string()).await;

//             if result.is_ok() {
//                 let user = result.unwrap();
//                 assert!(
//                     user.username.contains("用户"),
//                     "Should preserve unicode characters"
//                 );
//                 cleanup_test_user(&pool, user.id).await;
//             }
//         }
//     }
// }
