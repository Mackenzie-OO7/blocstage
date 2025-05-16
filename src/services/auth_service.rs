// for user authentication, registrations, and managing accounts

use crate::models::user::{User, CreateUserRequest, LoginRequest};
use sqlx::PgPool;
use anyhow::{Result, anyhow};
use bcrypt::{hash, verify};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;
use std::env;
use crate::services::stellar_service::StellarService;
use log::info;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user ID
    pub exp: i64,     // Expiration
    pub role: String, // User role (admin, organizer, attendee)
    pub iat: i64,     // Issued at
}

pub struct AuthService {
    pool: PgPool,
    stellar_service: StellarService,
}

impl AuthService {
     pub fn new(pool: PgPool) -> Result<Self> {
        let stellar_service = StellarService::new()?;
        
        Ok(Self {
            pool,
            stellar_service,
        })
    }
    
    pub async fn register(&self, user_req: CreateUserRequest) -> Result<User> {
        if let Some(_) = User::find_by_email(&self.pool, &user_req.email).await? {
            return Err(anyhow!("Email already registered"));
        }
        
        let password_hash = hash(&user_req.password, 10)?;
        
        let user = User::create(&self.pool, user_req, password_hash).await?;
        
        let (public_key, secret_key) = self.stellar_service.generate_keypair()?;
        
        let user = user.update_stellar_keys(&self.pool, &public_key, &secret_key).await?;
        
        self.send_verification_email(&user).await?;
        
        // user must fund their own account
        info!("New user registered with Stellar address: {}", public_key);
        
        Ok(user)
    }
    
    pub async fn login(&self, login_req: LoginRequest) -> Result<String> {
        let user = User::find_by_email(&self.pool, &login_req.email).await?
            .ok_or_else(|| anyhow!("Invalid email or password"))?;
        
        if user.status == "deleted" {
            return Err(anyhow!("Account has been deleted"));
        }
        
        if !user.email_verified {
            return Err(anyhow!("Email not verified. Please verify your email before logging in."));
        }
        
        // verify password - use constant time comparison to prevent timing attacks
        if !verify(&login_req.password, &user.password_hash)? {
            return Err(anyhow!("Invalid email or password"));
        }
        
        let token = self.generate_token(user.id, "user".to_string())?;
        
        Ok(token)
    }
    
    pub fn verify_token(&self, token: &str) -> Result<Uuid> {
        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| anyhow!("JWT_SECRET not set"))?;
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )?;
        
        let now = Utc::now().timestamp();
        if token_data.claims.exp < now {
            return Err(anyhow!("Token expired"));
        }
        
        let user_id = Uuid::parse_str(&token_data.claims.sub)?;
        
        Ok(user_id)
    }
    
    pub async fn verify_email(&self, token: &str) -> Result<User> {
        let user = User::verify_email(&self.pool, token).await?
            .ok_or_else(|| anyhow!("Invalid or expired verification token"))?;
        
        Ok(user)
    }
    
    pub async fn request_password_reset(&self, email: &str) -> Result<()> {
        let user = User::find_by_email(&self.pool, email).await?
            .ok_or_else(|| anyhow!("Email not found"))?;
        
        let reset_token = user.request_password_reset(&self.pool).await?;
        
        self.send_password_reset_email(&user, &reset_token).await?;
        
        Ok(())
    }
    
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        if new_password.len() < 8 {
            return Err(anyhow!("Password must be at least 8 characters"));
        }
        
        let password_hash = hash(new_password, 10)?;
        
        let user = User::reset_password(&self.pool, token, &password_hash).await?
            .ok_or_else(|| anyhow!("Invalid or expired reset token"))?;
        
        self.send_password_changed_email(&user).await?;
        
        Ok(())
    }
    
    pub async fn delete_account(&self, user_id: Uuid) -> Result<()> {
        let user = User::find_by_id(&self.pool, user_id).await?
            .ok_or_else(|| anyhow!("User not found"))?;
        
        // soft delete
        user.delete_account(&self.pool).await?;
        
        self.send_account_deleted_email(&user).await?;
        
        Ok(())
    }
    
    async fn send_verification_email(&self, user: &User) -> Result<()> {
        if let Some(token) = &user.verification_token {
            let verification_url = format!(
                "{}/verify-email?token={}", 
                env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
                token
            );
            
            let email = self.create_email(
                &user.email,
                "Verify Your Email",
                &format!("Click the link to verify your email: {}", verification_url)
            )?;
            
            self.send_email(email)?;
        }
        
        Ok(())
    }
    
    async fn send_password_reset_email(&self, user: &User, token: &str) -> Result<()> {
        let reset_url = format!(
            "{}/reset-password?token={}", 
            env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
            token
        );
        
        let email = self.create_email(
            &user.email,
            "Reset Your Password",
            &format!("Click the link to reset your password: {}", reset_url)
        )?;
        
        self.send_email(email)?;
        
        Ok(())
    }
    
    async fn send_password_changed_email(&self, user: &User) -> Result<()> {
        let email = self.create_email(
            &user.email,
            "Password Changed",
            "Your password has been successfully changed."
        )?;
        
        self.send_email(email)?;
        
        Ok(())
    }
    
    async fn send_account_deleted_email(&self, user: &User) -> Result<()> {
        let email = self.create_email(
            &user.email,
            "Account Deleted",
            "Your account has been successfully deleted."
        )?;
        
        self.send_email(email)?;
        
        Ok(())
    }
    
    // to generate email
    fn create_email(&self, to: &str, subject: &str, body: &str) -> Result<Message> {
        let email = Message::builder()
            .from(env::var("EMAIL_FROM").unwrap_or_else(|_| "noreply@ticketing.com".to_string()).parse()?)
            .to(to.parse()?)
            .subject(subject)
            .body(body.to_string())?;
        
        Ok(email)
    }
    
    fn send_email(&self, email: Message) -> Result<()> {
        // if in development, just log the email
        if env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
            info!("Would send email: {:?}", email);
            return Ok(());
        }
        
        // when in production, send via SMTP
        let smtp_server = env::var("SMTP_SERVER")?;
        let smtp_username = env::var("SMTP_USERNAME")?;
        let smtp_password = env::var("SMTP_PASSWORD")?;
        
        let creds = Credentials::new(smtp_username, smtp_password);
        
        let mailer = SmtpTransport::relay(&smtp_server)?
            .credentials(creds)
            .build();
        
        mailer.send(&email)?;
        
        Ok(())
    }
    
    // JWT token
    fn generate_token(&self, user_id: Uuid, role: String) -> Result<String> {
        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| anyhow!("JWT_SECRET not set"))?;
        
        let now = Utc::now().timestamp();
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
            .ok_or_else(|| anyhow!("Invalid timestamp calculation"))?
            .timestamp();
        
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
            role,
            iat: now,
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )?;
        
        Ok(token)
    }
}