use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;

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

impl User {
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT * FROM users WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT * FROM users WHERE email = $1"#,
            email
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn create(pool: &PgPool, user: CreateUserRequest, password_hash: String) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
            id, user.username, user.email, password_hash, now, now
        )
        .fetch_one(pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn update_stellar_keys(&self, pool: &PgPool, public_key: &str, secret_key: &str) -> Result<Self> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET stellar_public_key = $1, stellar_secret_key = $2, updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
            public_key, secret_key, Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(user)
    }
}