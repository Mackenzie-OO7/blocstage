// for user authentication, registrations, and managing accounts

use crate::models::user::{CreateUserRequest, LoginRequest, User};
use crate::services::stellar::StellarService;
use anyhow::{anyhow, Result};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user ID
    pub exp: i64,     // Expiration
    pub role: String, // User role (admin, organizer, attendee)
    pub iat: i64,     // Issued at
    pub jti: String,  // JWT ID for uniqueness
}

pub struct AuthService {
    pool: PgPool,
    stellar: StellarService,
}

impl AuthService {
    pub fn new(pool: PgPool) -> Result<Self> {
        let stellar = StellarService::new()?;

        Ok(Self {
            pool,
            stellar,
        })
    }

    pub async fn register(&self, user_req: CreateUserRequest) -> Result<User> {
        info!("🚀 Starting registration for email: {}", user_req.email);

        if let Some(existing_user) = User::find_by_email(&self.pool, &user_req.email).await? {
            warn!(
                "❌ Registration failed: Email {} already exists with ID {}",
                user_req.email, existing_user.id
            );
            return Err(anyhow!("Email already registered"));
        }

        let password_hash = hash(&user_req.password, 10)?;
        info!("🔐 Password hashed successfully");

        let user = User::create(&self.pool, user_req, password_hash).await?;
        info!("✅ User created with ID: {}", user.id);

        let (public_key, secret_key) = self.stellar.generate_keypair()?;
        info!("🌟 Stellar keypair generated: {}", public_key);

        let user = user
            .update_stellar_keys(&self.pool, &public_key, &secret_key)
            .await?;
        info!("💳 Stellar keys updated for user: {}", user.id);

        self.send_verification_email(&user).await?;
        info!("📧 Verification email sent to: {}", user.email);

        info!(
            "🎉 Registration completed for user: {} ({})",
            user.id, user.email
        );
        Ok(user)
    }

    pub async fn login(&self, login_req: LoginRequest) -> Result<String> {
        info!("🔑 Login attempt for email: {}", login_req.email);

        let user = User::find_by_email(&self.pool, &login_req.email)
            .await?
            .ok_or_else(|| {
                warn!(
                    "❌ Login failed: User not found for email {}",
                    login_req.email
                );
                anyhow!("Invalid email or password")
            })?;

        info!("👤 User found:");
        info!("   - ID: {}", user.id);
        info!("   - Email: {}", user.email);
        info!("   - Username: {}", user.username);
        info!("   - Role: {}", user.role);
        info!("   - Email Verified: {}", user.email_verified);
        info!("   - Status: {}", user.status);

        if user.status == "deleted" {
            warn!("❌ Login failed: Account deleted for user {}", user.id);
            return Err(anyhow!("Account has been deleted"));
        }

        if !user.email_verified {
            warn!("❌ Login failed: Email not verified for user {}", user.id);
            return Err(anyhow!(
                "Email not verified. Please verify your email before logging in."
            ));
        }

        // use constant time comparison to prevent timing attacks
        if !verify(&login_req.password, &user.password_hash)? {
            warn!("❌ Login failed: Invalid password for user {}", user.id);
            return Err(anyhow!("Invalid email or password"));
        }

        info!("🔐 Password verified for user: {}", user.id);

        let token = self.generate_token(user.id, user.role.clone())?;
        info!(
            "🎫 Token generated for user: {} (role: {})",
            user.id, user.role
        );

        debug!("Token preview: {}...", &token[0..20.min(token.len())]);

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Uuid> {
        debug!("🔍 Verifying token: {}...", &token[0..20.min(token.len())]);

        let jwt_secret = env::var("JWT_SECRET").map_err(|_| anyhow!("JWT_SECRET not set"))?;

        // TODO: Create validation with correct settings
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.leeway = 60;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &validation,
        )?;

        let now = Utc::now().timestamp();
        if token_data.claims.exp < now {
            warn!(
                "❌ Token expired for user: {} (exp: {}, now: {})",
                token_data.claims.sub, token_data.claims.exp, now
            );
            return Err(anyhow!("Token expired"));
        }

        let user_id = Uuid::parse_str(&token_data.claims.sub)?;
        debug!(
            "✅ Token verified for user: {} (jti: {})",
            user_id, token_data.claims.jti
        );

        Ok(user_id)
    }

    pub async fn verify_email(&self, token: &str) -> Result<User> {
        info!(
            "📧 Verifying email with token: {}...",
            &token[0..10.min(token.len())]
        );

        let user = User::verify_email(&self.pool, token)
            .await?
            .ok_or_else(|| {
                warn!("❌ Email verification failed: Invalid token {}", token);
                anyhow!("Invalid or expired verification token")
            })?;

        info!("✅ Email verified for user: {} ({})", user.id, user.email);
        Ok(user)
    }

    pub async fn request_password_reset(&self, email: &str) -> Result<()> {
        let user = User::find_by_email(&self.pool, email)
            .await?
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

        let user = User::reset_password(&self.pool, token, &password_hash)
            .await?
            .ok_or_else(|| anyhow!("Invalid or expired reset token"))?;

        self.send_password_changed_email(&user).await?;

        Ok(())
    }

    pub async fn delete_account(&self, user_id: Uuid) -> Result<()> {
        let user = User::find_by_id(&self.pool, user_id)
            .await?
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
                &format!("Click the link to verify your email: {}", verification_url),
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
            &format!("Click the link to reset your password: {}", reset_url),
        )?;

        self.send_email(email)?;

        Ok(())
    }

    async fn send_password_changed_email(&self, user: &User) -> Result<()> {
        let email = self.create_email(
            &user.email,
            "Password Changed",
            "Your password has been successfully changed.",
        )?;

        self.send_email(email)?;

        Ok(())
    }

    async fn send_account_deleted_email(&self, user: &User) -> Result<()> {
        let email = self.create_email(
            &user.email,
            "Account Deleted",
            "Your account has been successfully deleted.",
        )?;

        self.send_email(email)?;

        Ok(())
    }

    // to generate email
    fn create_email(&self, to: &str, subject: &str, body: &str) -> Result<Message> {
        let email = Message::builder()
            .from(
                env::var("EMAIL_FROM")
                    .unwrap_or_else(|_| "noreply@ticketing.com".to_string())
                    .parse()?,
            )
            .to(to.parse()?)
            .subject(subject)
            .body(body.to_string())?;

        Ok(email)
    }

    fn send_email(&self, email: Message) -> Result<()> {
        // if in development, just log the email
        if env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
            info!("📧 Would send email: {:?}", email);
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
        info!(
            "🎫 Generating token for user: {} with role: {}",
            user_id, role
        );

        let jwt_secret = env::var("JWT_SECRET").map_err(|_| anyhow!("JWT_SECRET not set"))?;

        info!("🔑 JWT Secret length: {} characters", jwt_secret.len());

        let now = Utc::now().timestamp();
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
            .ok_or_else(|| anyhow!("Invalid timestamp calculation"))?
            .timestamp();

        // Create a unique JWT ID (jti) for each token
        use rand::Rng;
        let mut rng = rand::rng();
        let random_bytes: [u8; 16] = rng.random();
        let jti = format!(
            "{}-{}-{}",
            user_id.simple(),
            now,
            hex::encode(random_bytes)
        );

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
            role: role.clone(),
            iat: now,
            jti: jti.clone(),
        };

        info!("🎯 Token Claims:");
        info!("   - sub (user_id): {}", claims.sub);
        info!("   - role: {}", claims.role);
        info!("   - iat (issued_at): {}", claims.iat);
        info!("   - exp (expires): {}", claims.exp);
        info!("   - jti (unique_id): {}", claims.jti);

        let header = Header::default();

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )?;

        info!("✅ Token generated successfully for user: {}", user_id);
        info!("🎫 Token length: {}", token.len());
        info!(
            "🎫 Token preview: {}...{}",
            &token[0..20.min(token.len())],
            &token[token.len().saturating_sub(20)..]
        );

        match self.verify_token(&token) {
            Ok(verified_user_id) => {
                if verified_user_id == user_id {
                    info!(
                        "✅ Token verification successful for user: {}",
                        verified_user_id
                    );
                } else {
                    error!(
                        "❌ Token verification mismatch! Expected: {}, Got: {}",
                        user_id, verified_user_id
                    );
                }
            }
            Err(e) => {
                error!("❌ Token verification failed: {}", e);
            }
        }

        Ok(token.to_owned())
    }
}
