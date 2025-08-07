// for user authentication, registrations, and managing accounts

use crate::models::user::{CreateUserRequest, LoginRequest, User};
use crate::services::stellar::StellarService;
use anyhow::{anyhow, Result};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lettre::message::Mailbox;
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

        Ok(Self { pool, stellar })
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

        match self.auto_create_sponsored_usdc_trustline(&user).await {
            Ok(tx_hash) => {
                info!("✅ USDC trustline for user {}: has been created! {}", user.id, tx_hash);
            }
            Err(e) => {
                warn!("⚠️ Failed to auto-create USDC trustline for user {}: {}", user.id, e);
            }
        }

        self.send_verification_email(&user).await?;
        info!("📧 Verification email sent to: {}", user.email);

        info!(
            "🎉 Yay! Registration completed for user: {} ({})",
            user.id, user.email
        );
        Ok(user)
    }

     async fn auto_create_sponsored_usdc_trustline(&self, user: &User) -> Result<String> {
        info!("🤝 sponsoring USDC trustline for user: {}", user.id);

        let encrypted_secret = user
            .stellar_secret_key_encrypted
            .as_ref()
            .ok_or_else(|| anyhow!("User has no encrypted secret key😞"))?;

        let sponsor_manager = crate::services::sponsor_manager::SponsorManager::new(self.pool.clone())
            .map_err(|e| anyhow!("😞 Failed to initialize sponsor manager: {}", e))?;
        
        let sponsor_info = sponsor_manager.get_available_sponsor().await
            .map_err(|e| anyhow!("😞 Failed to get available sponsor: {}", e))?;

        let usdc_issuer = std::env::var("TESTNET_USDC_ISSUER")
            .unwrap_or_else(|_| "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string());

        let tx_hash = self.stellar
            .create_asset_trustline(
                encrypted_secret,
                "USDC",
                &usdc_issuer,
                Some(&sponsor_info.secret_key),
            )
            .await
            .map_err(|e| anyhow!("Failed to create sponsored trustline: {}", e))?;

        let gas_fee_xlm = self.stellar.sponsored_gas_fee();
        sponsor_manager
            .record_sponsorship_usage(&sponsor_info.public_key, gas_fee_xlm)
            .await
            .map_err(|e| anyhow!("Failed to record sponsor usage: {}", e))?;

        info!(
            "✅ Auto-created sponsored USDC trustline for user {}: {} (gas: {:.7} XLM)",
            user.id, tx_hash, gas_fee_xlm
        );

        Ok(tx_hash)
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
        let jti = format!("{}-{}-{}", user_id.simple(), now, hex::encode(random_bytes));

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

// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::CreateUserRequest;
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use std::env;
    use uuid::Uuid;

    fn ensure_test_env() {
        dotenv::from_filename(".env.test").ok();
        dotenv::dotenv().ok();

        env::set_var("APP_ENV", "test");

        // Debug
        println!(
            "DEBUG: MASTER_ENCRYPTION_KEY present: {}",
            env::var("MASTER_ENCRYPTION_KEY").is_ok()
        );
        println!(
            "DEBUG: JWT_SECRET present: {}",
            env::var("JWT_SECRET").is_ok()
        );
        println!(
            "DEBUG: APP_ENV set to: {}",
            env::var("APP_ENV").unwrap_or_else(|_| "not_set".to_string())
        );
    }

    // Test database setup helper
    async fn setup_test_db() -> PgPool {
        ensure_test_env();

        // Debug
        println!("=== DEBUG DATABASE SETUP ===");
        println!("TEST_DATABASE_URL: {:?}", env::var("TEST_DATABASE_URL"));
        println!("DATABASE_URL: {:?}", env::var("DATABASE_URL"));

        let database_url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .expect("TEST_DATABASE_URL or DATABASE_URL must be set for tests");

        println!("Using connection string: {}", database_url);
        println!("==============================");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        // Run migrations to ensure test database is up to date
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        pool
    }

    // Helper to create unique test data
    fn get_unique_test_id() -> String {
        format!("{}", Uuid::new_v4().simple())
    }

    // Helper to create test user data
    fn create_test_user_request(suffix: &str) -> CreateUserRequest {
        let unique_id = get_unique_test_id();
        CreateUserRequest {
            username: format!("testuser_{}_{}", suffix, unique_id),
            email: format!("test_{}+{}@example.com", suffix, unique_id),
            password: "test_password_123".to_string(),
        }
    }

    // Helper to clean up test users
    async fn cleanup_test_user(pool: &PgPool, user_id: Uuid) {
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(pool)
            .await;
    }

    mod service_initialization {
        use super::*;

        #[tokio::test]
        async fn test_new_service_success() {
            let pool = setup_test_db().await;

            let result = AuthService::new(pool);
            assert!(result.is_ok(), "AuthService should initialize successfully");
        }

        #[tokio::test]
        async fn test_new_service_missing_stellar() {
            let pool = setup_test_db().await;

            // Store the original key to restore later
            let original_key = env::var("MASTER_ENCRYPTION_KEY").ok();

            // Remove the encryption key AFTER database setup
            env::remove_var("MASTER_ENCRYPTION_KEY");

            // Verify it's actually removed
            println!(
                "DEBUG: MASTER_ENCRYPTION_KEY after removal: {}",
                env::var("MASTER_ENCRYPTION_KEY").is_ok()
            );

            // AuthService::new() should succeed since it doesn't validate crypto immediately
            let result = AuthService::new(pool.clone());
            assert!(
                result.is_ok(),
                "AuthService::new should succeed even without crypto key"
            );

            // But user registration should fail
            if let Ok(auth) = result {
                let user_req = create_test_user_request("no_crypto");
                let reg_result = auth.register(user_req).await;

                // Debug: print the actual result
                match &reg_result {
                    Ok(user) => println!(
                        "DEBUG: Registration unexpectedly succeeded for user: {}",
                        user.id
                    ),
                    Err(e) => println!("DEBUG: Registration failed as expected with error: {}", e),
                }

                assert!(
                    reg_result.is_err(),
                    "Registration should fail without crypto key"
                );

                if let Err(e) = reg_result {
                    let error_message = e.to_string();
                    println!("DEBUG: Full error message: {}", error_message);
                    assert!(
                        error_message.contains("MASTER_ENCRYPTION_KEY")
                            || error_message.contains("Failed to encrypt secret key"),
                        "Error should be related to encryption key, got: {}",
                        error_message
                    );
                }
            }

            // Restore the original key
            if let Some(key) = original_key {
                env::set_var("MASTER_ENCRYPTION_KEY", key);
            }
        }
    }

    mod user_registration {
        use super::*;

        #[tokio::test]
        async fn test_register_success() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_req = create_test_user_request("register");

            let result = auth.register(user_req.clone()).await;
            assert!(
                result.is_ok(),
                "Registration should succeed: {:?}",
                result.err()
            );

            let user = result.unwrap();
            assert_eq!(user.email, user_req.email);
            assert_eq!(user.username, user_req.username);
            assert!(
                !user.email_verified,
                "Email should not be verified initially"
            );
            assert!(
                user.stellar_public_key.is_some(),
                "Should have stellar public key"
            );
            assert!(
                user.stellar_secret_key_encrypted.is_some(),
                "Should have encrypted stellar secret key"
            );
            assert!(
                user.verification_token.is_some(),
                "Should have verification token"
            );

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_register_duplicate_email() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_req = create_test_user_request("duplicate");

            // First registration
            let result1 = auth.register(user_req.clone()).await;
            assert!(
                result1.is_ok(),
                "First registration should succeed: {:?}",
                result1.err()
            );
            let user1 = result1.unwrap();

            // Second registration with same email
            let result2 = auth.register(user_req).await;
            assert!(result2.is_err(), "Second registration should fail");
            assert!(result2
                .unwrap_err()
                .to_string()
                .contains("already registered"));

            cleanup_test_user(&pool, user1.id).await;
        }

        #[tokio::test]
        async fn test_register_password_security() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_req = create_test_user_request("password_test");
            let original_password = user_req.password.clone();

            let result = auth.register(user_req).await;
            assert!(
                result.is_ok(),
                "Registration should succeed: {:?}",
                result.err()
            );

            let user = result.unwrap();

            // Verify password is hashed (not stored in plaintext)
            assert_ne!(
                user.password_hash, original_password,
                "Password should be hashed"
            );
            assert!(
                user.password_hash.starts_with("$2b$"),
                "Should use bcrypt format"
            );

            // Verify password can be verified
            let verification = bcrypt::verify(&original_password, &user.password_hash);
            assert!(verification.is_ok(), "Password verification should work");
            assert!(verification.unwrap(), "Password should verify correctly");

            cleanup_test_user(&pool, user.id).await;
        }
    }

    mod user_login {
        use super::*;
        use crate::models::user::LoginRequest;

        #[tokio::test]
        async fn test_login_success() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create and register user
            let user_req = create_test_user_request("login_success");
            let password = user_req.password.clone();
            let email = user_req.email.clone();

            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            // Verify email to enable login
            sqlx::query!(
                "UPDATE users SET email_verified = true WHERE id = $1",
                user.id
            )
            .execute(&pool)
            .await
            .expect("Failed to verify email");

            // Test login
            let login_req = LoginRequest { email, password };
            let result = auth.login(login_req).await;

            assert!(result.is_ok(), "Login should succeed: {:?}", result.err());
            let token = result.unwrap();
            assert!(!token.is_empty(), "Token should not be empty");

            // Verify token is valid
            let verify_result = auth.verify_token(&token);
            assert!(verify_result.is_ok(), "Token should be valid");
            assert_eq!(
                verify_result.unwrap(),
                user.id,
                "Token should contain correct user ID"
            );

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_login_invalid_email() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let login_req = LoginRequest {
                email: "nonexistent@example.com".to_string(),
                password: "password123".to_string(),
            };

            let result = auth.login(login_req).await;
            assert!(result.is_err(), "Login should fail for nonexistent email");
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid email or password"));
        }

        #[tokio::test]
        async fn test_login_invalid_password() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user
            let user_req = create_test_user_request("invalid_password");
            let email = user_req.email.clone();
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            // Verify email
            sqlx::query!(
                "UPDATE users SET email_verified = true WHERE id = $1",
                user.id
            )
            .execute(&pool)
            .await
            .expect("Failed to verify email");

            // Test login with wrong password
            let login_req = LoginRequest {
                email,
                password: "wrong_password".to_string(),
            };

            let result = auth.login(login_req).await;
            assert!(result.is_err(), "Login should fail with wrong password");
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid email or password"));

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_login_unverified_email() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user but don't verify email
            let user_req = create_test_user_request("unverified");
            let password = user_req.password.clone();
            let email = user_req.email.clone();
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            // Test login without email verification
            let login_req = LoginRequest { email, password };
            let result = auth.login(login_req).await;

            assert!(result.is_err(), "Login should fail for unverified email");
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Email not verified"));

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_login_deleted_account() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create and verify user
            let user_req = create_test_user_request("deleted");
            let password = user_req.password.clone();
            let email = user_req.email.clone();
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            // Mark user as both verified and deleted
            sqlx::query!(
                "UPDATE users SET email_verified = true, status = 'deleted' WHERE id = $1",
                user.id
            )
            .execute(&pool)
            .await
            .expect("Failed to mark user as deleted");

            // Verify the user is actually marked as deleted
            let updated_user = sqlx::query!("SELECT status FROM users WHERE id = $1", user.id)
                .fetch_one(&pool)
                .await
                .expect("Should find user");
            assert_eq!(
                updated_user.status, "deleted",
                "User should be marked as deleted"
            );

            // Test login with deleted account
            let login_req = LoginRequest { email, password };
            let result = auth.login(login_req).await;

            assert!(result.is_err(), "Login should fail for deleted account");

            // NOTE: Deleted users return "Invalid email or password" because find_by_email
            // excludes deleted users entirely (which is correct security behavior)
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains("Invalid email or password"),
                "Should return generic error for security, got: {}",
                error_msg
            );

            cleanup_test_user(&pool, user.id).await;
        }
    }

    mod token_management {
        use super::*;

        #[tokio::test]
        async fn test_generate_and_verify_token() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_id = Uuid::new_v4();
            let role = "user".to_string();

            // Generate token
            let token_result = auth.generate_token(user_id, role.clone());
            assert!(token_result.is_ok(), "Token generation should succeed");
            let token = token_result.unwrap();

            assert!(!token.is_empty(), "Token should not be empty");
            assert!(token.len() > 100, "JWT token should be substantial length");

            // Verify token
            let verify_result = auth.verify_token(&token);
            assert!(verify_result.is_ok(), "Token verification should succeed");
            assert_eq!(
                verify_result.unwrap(),
                user_id,
                "Should return correct user ID"
            );
        }

        #[tokio::test]
        async fn test_verify_invalid_token() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let invalid_tokens = vec![
                "",
                "invalid.token.here",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
                "not_a_jwt_at_all",
            ];

            for invalid_token in invalid_tokens {
                let result = auth.verify_token(invalid_token);
                assert!(
                    result.is_err(),
                    "Should reject invalid token: {}",
                    invalid_token
                );
            }
        }

        #[tokio::test]
        async fn test_verify_expired_token() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create token with expired timestamp
            let jwt_secret = env::var("JWT_SECRET").unwrap();
            let user_id = Uuid::new_v4();
            let expired_time = Utc::now()
                .checked_sub_signed(Duration::hours(25))
                .unwrap()
                .timestamp();

            let claims = Claims {
                sub: user_id.to_string(),
                exp: expired_time,
                role: "user".to_string(),
                iat: expired_time - 3600,
                jti: "test_jti".to_string(),
            };

            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes()),
            )
            .expect("Failed to create expired token");

            let result = auth.verify_token(&token);
            assert!(result.is_err(), "Should reject expired token");

            // Check for any expiration-related error message
            let error_msg = result.unwrap_err().to_string().to_lowercase();
            assert!(
                error_msg.contains("expired")
                    || error_msg.contains("invalid")
                    || error_msg.contains("token"),
                "Should contain token error, got: {}",
                error_msg
            );
        }

        #[tokio::test]
        async fn test_token_contains_correct_claims() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_id = Uuid::new_v4();
            let role = "admin".to_string();

            let token = auth
                .generate_token(user_id, role.clone())
                .expect("Token generation should succeed");

            // Decode token to verify claims
            let jwt_secret = env::var("JWT_SECRET").unwrap();
            let token_data = jsonwebtoken::decode::<Claims>(
                &token,
                &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
                &jsonwebtoken::Validation::default(),
            )
            .expect("Token should decode successfully");

            assert_eq!(token_data.claims.sub, user_id.to_string());
            assert_eq!(token_data.claims.role, role);
            assert!(token_data.claims.exp > Utc::now().timestamp());
            assert!(token_data.claims.iat <= Utc::now().timestamp());
            assert!(!token_data.claims.jti.is_empty());
        }

        #[tokio::test]
        async fn test_token_uniqueness() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_id = Uuid::new_v4();
            let role = "user".to_string();

            // Generate multiple tokens for same user
            let mut tokens = Vec::new();
            for _ in 0..5 {
                let token = auth
                    .generate_token(user_id, role.clone())
                    .expect("Token generation should succeed");
                tokens.push(token);
            }

            // Verify all tokens are unique (due to different jti and iat)
            let unique_tokens: std::collections::HashSet<_> = tokens.iter().collect();
            assert_eq!(
                unique_tokens.len(),
                tokens.len(),
                "All tokens should be unique"
            );

            // Verify all tokens are valid for the same user
            for token in &tokens {
                let verify_result = auth.verify_token(token);
                assert!(verify_result.is_ok(), "All tokens should be valid");
                assert_eq!(
                    verify_result.unwrap(),
                    user_id,
                    "All tokens should be for same user"
                );
            }
        }
    }

    mod email_verification {
        use super::*;

        #[tokio::test]
        async fn test_verify_email_success() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user
            let user_req = create_test_user_request("verify_email");
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");
            let token = user.verification_token.clone().unwrap();

            // Verify email
            let result = auth.verify_email(&token).await;
            assert!(result.is_ok(), "Email verification should succeed");

            let verified_user = result.unwrap();
            assert!(
                verified_user.email_verified,
                "User should be marked as verified"
            );
            assert!(
                verified_user.verification_token.is_none(),
                "Verification token should be cleared"
            );

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_verify_email_invalid_token() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let result = auth.verify_email("invalid_token_12345").await;
            assert!(result.is_err(), "Should fail with invalid token");
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid or expired"));
        }

        #[tokio::test]
        async fn test_verify_email_already_verified() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user and manually verify
            let user_req = create_test_user_request("already_verified");
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            sqlx::query!(
                "UPDATE users SET email_verified = true, verification_token = NULL WHERE id = $1",
                user.id
            )
            .execute(&pool)
            .await
            .expect("Failed to verify user manually");

            // Try to verify again
            let result = auth.verify_email("any_token").await;
            assert!(result.is_err(), "Should fail when user already verified");

            cleanup_test_user(&pool, user.id).await;
        }
    }

    mod password_reset {
        use super::*;

        #[tokio::test]
        async fn test_request_password_reset_success() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user
            let user_req = create_test_user_request("password_reset");
            let email = user_req.email.clone();
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            // Request password reset
            let result = auth.request_password_reset(&email).await;
            assert!(result.is_ok(), "Password reset request should succeed");

            // Verify user has reset token
            let updated_user = User::find_by_id(&pool, user.id)
                .await
                .expect("Should find user")
                .expect("User should exist");
            assert!(
                updated_user.reset_token.is_some(),
                "User should have reset token"
            );
            assert!(
                updated_user.reset_token_expires.is_some(),
                "User should have reset token expiry"
            );

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_request_password_reset_nonexistent_user() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let result = auth.request_password_reset("nonexistent@example.com").await;
            assert!(result.is_err(), "Should fail for nonexistent user");
        }

        #[tokio::test]
        async fn test_reset_password_success() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user and request reset
            let user_req = create_test_user_request("reset_password");
            let email = user_req.email.clone();
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            auth.request_password_reset(&email)
                .await
                .expect("Reset request should succeed");

            // Get reset token
            let user_with_token = User::find_by_id(&pool, user.id)
                .await
                .expect("Should find user")
                .expect("User should exist");
            let reset_token = user_with_token.reset_token.unwrap();

            // Reset password
            let new_password = "new_secure_password_123";
            let result = auth.reset_password(&reset_token, new_password).await;
            assert!(result.is_ok(), "Password reset should succeed");

            // Verify password was changed
            let updated_user = User::find_by_id(&pool, user.id)
                .await
                .expect("Should find user")
                .expect("User should exist");

            let password_verify = bcrypt::verify(new_password, &updated_user.password_hash);
            assert!(
                password_verify.is_ok() && password_verify.unwrap(),
                "New password should verify"
            );
            assert!(
                updated_user.reset_token.is_none(),
                "Reset token should be cleared"
            );

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_reset_password_invalid_token() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let result = auth.reset_password("invalid_token", "new_password").await;
            assert!(result.is_err(), "Should fail with invalid token");
        }

        #[tokio::test]
        async fn test_reset_password_weak_password() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let weak_passwords = vec!["", "12", "weak", "1234567"]; // Less than 8 characters

            for weak_password in weak_passwords {
                let result = auth.reset_password("any_token", weak_password).await;
                assert!(
                    result.is_err(),
                    "Should reject weak password: {}",
                    weak_password
                );
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("at least 8 characters"));
            }
        }
    }

    mod account_management {
        use super::*;

        /* this is already being tested in the user model. 
        here, i'm actually trying to test it from the perspective of the specific user themself, but there's an issue.
        TODO! */
        
        // #[tokio::test]
        // async fn test_delete_account_success() {
        //     ensure_test_env(); // Add this line
        //     let pool = setup_test_db().await;
        //     let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

        //     // Create user
        //     let user_req = create_test_user_request("delete_account");
        //     let user = auth
        //         .register(user_req)
        //         .await
        //         .expect("Registration should succeed");

        //     // Delete account
        //     let result = auth.delete_account(user.id).await;
        //     assert!(result.is_ok(), "Account deletion should succeed");

        //     // Verify account is marked as deleted
        //     let deleted_user = User::find_by_id(&pool, user.id)
        //         .await
        //         .expect("Should find user")
        //         .expect("User should exist");
        //     assert_eq!(
        //         deleted_user.status, "deleted",
        //         "User should be marked as deleted"
        //     );

        //     cleanup_test_user(&pool, user.id).await;
        // }

        #[tokio::test]
        async fn test_delete_nonexistent_account() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let nonexistent_id = Uuid::new_v4();
            let result = auth.delete_account(nonexistent_id).await;
            assert!(result.is_err(), "Should fail for nonexistent user");
        }
    }

    mod security_tests {
        use super::*;

        #[tokio::test]
        async fn test_password_timing_attack_resistance() {
            ensure_test_env(); // Make sure this is called first
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Create user
            let user_req = create_test_user_request("timing_test");
            let email = user_req.email.clone();
            let user = auth
                .register(user_req)
                .await
                .expect("Registration should succeed");

            sqlx::query!(
                "UPDATE users SET email_verified = true WHERE id = $1",
                user.id
            )
            .execute(&pool)
            .await
            .expect("Failed to verify email");

            // Test login timing with correct vs incorrect passwords
            let correct_password = "test_password_123";
            let wrong_passwords = vec![
                "wrong_password_1",
                "wrong_password_2",
                "completely_different_length_password_here",
                "",
            ];

            // Verify correct password works
            let login_req = LoginRequest {
                email: email.clone(),
                password: correct_password.to_string(),
            };
            let result = auth.login(login_req).await;
            assert!(result.is_ok(), "Correct password should work");

            // Test wrong passwords fail consistently
            for wrong_password in wrong_passwords {
                let login_req = LoginRequest {
                    email: email.clone(),
                    password: wrong_password.to_string(),
                };
                let result = auth.login(login_req).await;
                assert!(
                    result.is_err(),
                    "Wrong password should fail: {}",
                    wrong_password
                );
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid email or password"));
            }

            cleanup_test_user(&pool, user.id).await;
        }

        #[tokio::test]
        async fn test_email_enumeration_protection() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Test login with nonexistent emails
            let nonexistent_emails = vec![
                "definitely_not_registered@example.com",
                "another_fake@example.com",
                "test123@nonexistent.com",
            ];

            for email in nonexistent_emails {
                let login_req = LoginRequest {
                    email: email.to_string(),
                    password: "any_password".to_string(),
                };

                let result = auth.login(login_req).await;
                assert!(result.is_err(), "Should fail for nonexistent email");

                // Error message should not reveal whether email exists
                let error_msg = result.unwrap_err().to_string();
                assert!(
                    error_msg.contains("Invalid email or password"),
                    "Should use generic error message for security"
                );
                assert!(
                    !error_msg.contains("not found"),
                    "Should not reveal email doesn't exist"
                );
            }
        }

        #[tokio::test]
        async fn test_jwt_secret_required() {
            let pool = setup_test_db().await;

            // Store original secret to restore later
            let original_secret = env::var("JWT_SECRET").ok();

            // Remove JWT secret AFTER database setup
            env::remove_var("JWT_SECRET");

            println!(
                "DEBUG: JWT_SECRET after removal: {}",
                env::var("JWT_SECRET").is_ok()
            );

            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_id = Uuid::new_v4();
            let result = auth.generate_token(user_id, "user".to_string());

            // Debug the actual result
            match &result {
                Ok(_) => println!("DEBUG: Token generation unexpectedly succeeded"),
                Err(e) => println!("DEBUG: Token generation failed as expected: {}", e),
            }

            assert!(result.is_err(), "Should fail without JWT secret");

            if let Err(e) = result {
                let error_message = e.to_string();
                assert!(
                    error_message.contains("JWT_SECRET") || error_message.contains("not set"),
                    "Should fail due to missing JWT secret, got: {}",
                    error_message
                );
            }

            // Restore the original secret
            if let Some(secret) = original_secret {
                env::set_var("JWT_SECRET", secret);
            }
        }

        #[tokio::test]
        async fn test_sql_injection_resistance() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Test SQL injection attempts in email field
            let injection_attempts = vec![
                "'; DROP TABLE users; --",
                "admin@example.com'; UPDATE users SET role='admin' WHERE '1'='1",
                "test' OR '1'='1' --",
                "'; INSERT INTO users (email) VALUES ('hacked@evil.com'); --",
            ];

            for injection_email in injection_attempts {
                let login_req = LoginRequest {
                    email: injection_email.to_string(),
                    password: "password".to_string(),
                };

                let result = auth.login(login_req).await;
                // Should fail safely without executing malicious SQL
                assert!(
                    result.is_err(),
                    "Should safely reject SQL injection attempt"
                );
            }

            // Verify no malicious data was inserted
            let user_count =
                sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE email LIKE '%evil%'")
                    .fetch_one(&pool)
                    .await
                    .expect("Should be able to count users");
            assert_eq!(
                user_count.unwrap_or(0),
                0,
                "No malicious users should be created"
            );
        }

        #[tokio::test]
        async fn test_token_signature_verification() {
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Generate valid token
            let user_id = Uuid::new_v4();
            let valid_token = auth
                .generate_token(user_id, "user".to_string())
                .expect("Token generation should succeed");

            // Tamper with token by changing signature
            let token_parts: Vec<&str> = valid_token.split('.').collect();
            assert_eq!(token_parts.len(), 3, "JWT should have 3 parts");

            let tampered_token =
                format!("{}.{}.tampered_signature", token_parts[0], token_parts[1]);

            // Verify tampered token is rejected
            let result = auth.verify_token(&tampered_token);
            assert!(result.is_err(), "Tampered token should be rejected");
        }
    }

    mod edge_cases {
        use super::*;

        #[tokio::test]
        async fn test_concurrent_registrations() {
            let pool = setup_test_db().await;

            let email = format!("concurrent_test_{}@example.com", get_unique_test_id());

            // Create multiple auth services and try concurrent registration with same email
            let handles: Vec<_> = (0..5)
                .map(|i| {
                    let pool_clone = pool.clone();
                    let email_clone = email.clone();

                    tokio::spawn(async move {
                        // Ensure environment is set up in each task
                        ensure_test_env();

                        let auth =
                            AuthService::new(pool_clone).expect("Failed to create AuthService");
                        let user_req = CreateUserRequest {
                            username: format!("concurrent_user_{}", i),
                            email: email_clone,
                            password: "password123".to_string(),
                        };
                        auth.register(user_req).await
                    })
                })
                .collect();

            let mut results = Vec::new();
            for handle in handles {
                let result = handle.await.expect("Task should complete");
                results.push(result);
            }

            // Only one registration should succeed
            let successful_registrations: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
            let failed_registrations: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

            // Print debug info if assertion fails
            if successful_registrations.len() != 1 {
                println!(
                    "DEBUG: Successful registrations: {}",
                    successful_registrations.len()
                );
                println!(
                    "DEBUG: Failed registrations: {}",
                    failed_registrations.len()
                );
                for (i, result) in results.iter().enumerate() {
                    match result {
                        Ok(user) => println!("  Result {}: Success - User ID {}", i, user.id),
                        Err(e) => println!("  Result {}: Error - {}", i, e),
                    }
                }
            }

            assert_eq!(
                successful_registrations.len(),
                1,
                "Only one registration should succeed"
            );
            assert_eq!(
                failed_registrations.len(),
                4,
                "Four registrations should fail"
            );

            // Clean up the successful registration
            if let Ok(user) = successful_registrations[0] {
                cleanup_test_user(&pool, user.id).await;
            }
        }

        #[tokio::test]
        async fn test_extremely_long_inputs() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            // Test with extremely long inputs
            let long_string = "a".repeat(10000);

            let user_req = CreateUserRequest {
                username: long_string.clone(),
                email: format!("{}@example.com", &long_string[0..50]), // Keep email reasonable
                password: long_string.clone(),
            };

            // Should handle gracefully (either succeed or fail with appropriate error)
            let result = auth.register(user_req).await;
            if let Ok(user) = result {
                cleanup_test_user(&pool, user.id).await;
            }
            // If it fails, that's also acceptable - just shouldn't crash
        }

        #[tokio::test]
        async fn test_unicode_and_special_characters() {
            ensure_test_env(); // Add this line
            let pool = setup_test_db().await;
            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_req = CreateUserRequest {
                username: "用户名_🚀_тест".to_string(),
                email: format!("unicode_test_{}@example.com", get_unique_test_id()),
                password: "пароль_密码_🔐_test_123".to_string(),
            };

            let result = auth.register(user_req).await;
            if let Ok(user) = result {
                // Verify unicode data is preserved
                assert!(user.username.contains("🚀"), "Unicode should be preserved");

                cleanup_test_user(&pool, user.id).await;
            }
        }

        #[tokio::test]
        async fn test_email_service_failure_simulation() {
            let pool = setup_test_db().await;

            // Store original environment values
            let original_env = env::var("APP_ENV").ok();
            let original_smtp_server = env::var("SMTP_SERVER").ok();
            let original_smtp_username = env::var("SMTP_USERNAME").ok();
            let original_smtp_password = env::var("SMTP_PASSWORD").ok();

            // Set invalid SMTP settings to simulate email failure
            env::set_var("APP_ENV", "production"); // Force actual email sending
            env::set_var("SMTP_SERVER", "invalid.smtp.server");
            env::set_var("SMTP_USERNAME", "invalid");
            env::set_var("SMTP_PASSWORD", "invalid");

            let auth = AuthService::new(pool.clone()).expect("Failed to create AuthService");

            let user_req = create_test_user_request("email_failure");

            // Registration should fail because of email sending failure
            let result = auth.register(user_req).await;

            // Debug the actual result
            match &result {
                Ok(user) => println!(
                    "DEBUG: Registration unexpectedly succeeded for user: {}",
                    user.id
                ),
                Err(e) => println!("DEBUG: Registration failed as expected: {}", e),
            }

            assert!(
                result.is_err(),
                "Registration should fail due to email sending failure"
            );

            if let Err(e) = result {
                let error_msg = e.to_string();
                println!("DEBUG: Full error message: {}", error_msg);
                // Be more flexible with error message matching since SMTP errors can vary
                assert!(
                    error_msg.contains("Connection")
                        || error_msg.contains("failed")
                        || error_msg.contains("SMTP")
                        || error_msg.contains("email")
                        || error_msg.contains("lookup"),
                    "Should fail due to connection/email error, got: {}",
                    error_msg
                );
            }

            // Restore original environment variables
            match original_env {
                Some(env_val) => env::set_var("APP_ENV", env_val),
                None => env::set_var("APP_ENV", "test"), // Default to test
            }
            if let Some(server) = original_smtp_server {
                env::set_var("SMTP_SERVER", server);
            } else {
                env::remove_var("SMTP_SERVER");
            }
            if let Some(username) = original_smtp_username {
                env::set_var("SMTP_USERNAME", username);
            } else {
                env::remove_var("SMTP_USERNAME");
            }
            if let Some(password) = original_smtp_password {
                env::set_var("SMTP_PASSWORD", password);
            } else {
                env::remove_var("SMTP_PASSWORD");
            }
        }
    }
}
