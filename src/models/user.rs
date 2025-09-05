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
    pub profile_picture_url: Option<String>,
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
        created_at, updated_at, email_verified, verification_token, status, role, profile_picture_url
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *
        "#,
            id,
            user.username,
            user.email,
            user.first_name,
            user.last_name,
            password_hash,
            now,
            now,
            false,
            Some(verification_token),
            "active",
            "user",
            None::<String>
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

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
            now - Duration::hours(24) // for now token expires after 24 hours from user creation
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

        // rate limiting
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

    pub async fn reset_password(
        pool: &PgPool,
        token: &str,
        new_password_hash: &str,
    ) -> Result<Option<Self>> {
        let now = Utc::now();

        // atomic op to reset password and clear token
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
                reset_token, reset_token_expires, status, role, profile_picture_url
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
