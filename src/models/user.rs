use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::{distr::Alphanumeric, rng, Rng};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub stellar_public_key: Option<String>,
    #[serde(skip_serializing)]
    pub stellar_secret_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub email_verified: bool,
    pub verification_token: Option<String>,
    pub reset_token: Option<String>,
    pub reset_token_expires: Option<DateTime<Utc>>,
    pub status: String, // "active", "deleted", etc.
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
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
            id, username, email, password_hash, created_at, updated_at,
            email_verified, verification_token, status, role
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        "#,
            id,
            user.username,
            user.email,
            password_hash,
            now,
            now,
            false,
            Some(verification_token),
            "active",
            "user" // ADD "user" HERE
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
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET 
                stellar_public_key = $1, 
                stellar_secret_key = $2, 
                updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
            public_key,
            secret_key,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub async fn verify_email(pool: &PgPool, token: &str) -> Result<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET email_verified = true, verification_token = NULL, updated_at = $1
            WHERE verification_token = $2 AND status = 'active'
            RETURNING *
            "#,
            Utc::now(),
            token
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn request_password_reset(&self, pool: &PgPool) -> Result<String> {
        let token = generate_random_token(32);
        let expires = Utc::now() + chrono::Duration::hours(24);

        sqlx::query!(
            r#"
            UPDATE users
            SET reset_token = $1, reset_token_expires = $2, updated_at = $3
            WHERE id = $4
            "#,
            token,
            expires,
            Utc::now(),
            self.id
        )
        .execute(pool)
        .await?;

        Ok(token)
    }

    // reset password with token
    pub async fn reset_password(
        pool: &PgPool,
        token: &str,
        new_password_hash: &str,
    ) -> Result<Option<Self>> {
        let now = Utc::now();

        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL, updated_at = $2
            WHERE reset_token = $3 AND reset_token_expires > $4 AND status = 'active'
            RETURNING *
            "#,
            new_password_hash,
            now,
            token,
            now
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
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
                id, username, email, password_hash, 
                stellar_public_key, stellar_secret_key,
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
