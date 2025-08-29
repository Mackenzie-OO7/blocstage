use actix_cors::Cors;
use actix_web::{web, HttpResponse, Responder};
use dotenv::dotenv;
use log::{error, info, warn};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::{env, time::Duration};

use blocstage::services::{SchedulerService, SponsorManager, RedisService, StellarService};
use blocstage::services::email::EmailService;
use std::sync::Arc;

use blocstage::controllers::configure_routes;

async fn health_check(
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
) -> impl Responder {
    let mut health_status = json!({
        "status": "healthy",
        "service": "blocstage-api",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "components": {
            "database": "healthy"
        }
    });

    if let Some(redis) = redis.as_ref().map(|d| d.get_ref()) {
        match redis.health_check().await {
            Ok(redis_health) => {
                health_status["components"]["redis"] = json!({
                    "status": redis_health.status,
                    "latency_ms": redis_health.latency_ms
                });
            }
            Err(_) => {
                health_status["components"]["redis"] = json!({
                    "status": "unhealthy"
                });
                health_status["status"] = json!("degraded");
            }
        }
    } else {
        health_status["components"]["redis"] = json!({
            "status": "disabled",
            "message": "Redis not configured"
        });
    }

    if let Some(email) = email_service.as_ref().map(|d| d.get_ref()) {
        let email_health = match email.health_check().await {
            Ok(true) => "healthy",
            Ok(false) => "unhealthy",
            Err(_) => "error",
        };
        health_status["checks"]["email"] = serde_json::json!({
            "status": email_health,
            "provider": email.provider_name()
        });
    }

    HttpResponse::Ok().json(health_status)
}

// 404 handler for undefined routes
async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json(json!({
        "error": "Endpoint not found",
        "message": "The requested resource does not exist",
        "available_endpoints": "/api for API documentation"
    }))
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_runtime::Secrets] secrets: shuttle_runtime::SecretStore,
) -> shuttle_actix_web::ShuttleActixWeb<
    impl FnOnce(&mut actix_web::web::ServiceConfig) + Send + Clone + 'static,
> {
    dotenv().ok();

    for key in [
        "APP_ENV",
        "DATABASE_URL",
        "EMAIL_FROM",
        "EMAIL_FROM_SUPPORT",
        "APP_URL",
        "CORS_ALLOWED_ORIGINS",
        "JWT_SECRET",
        "MASTER_ENCRYPTION_KEY",
        "STELLAR_NETWORK",
        "PLATFORM_PAYMENT_PUBLIC_KEY",
        "SPONSORSHIP_FEE_ACCOUNT_PUBLIC",
        "TESTNET_USDC_ISSUER",
        "PLATFORM_FEE_PERCENTAGE",
        "TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE",
        "GAS_FEE_MARGIN_PERCENTAGE",
        "SPONSOR_MINIMUM_BALANCE",
        "SPONSOR_LOW_BALANCE_ALERT_THRESHOLD",
        "REDIS_URL",
        "SENDGRID_API_KEY",
        "SENDGRID_TEMPLATE_EMAIL_VERIFICATION",
        "SENDGRID_TEMPLATE_PASSWORD_RESET",
        "SENDGRID_TEMPLATE_WELCOME",
        "SENDGRID_TEMPLATE_PASSWORD_CHANGED",
        "SENDGRID_TEMPLATE_ACCOUNT_DELETED",
        "SENDGRID_TICKET_TEMPLATE_ID",
        "STORAGE_URL",
        "SUPABASE_URL",
        "STORAGE_SERVICE_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "STORAGE_BUCKET",
    ] {
        if let Some(value) = secrets.get(key) {
            std::env::set_var(key, value);
            info!("Set {} from Shuttle secrets", key);
        }
    }

    info!(
        "Starting Blocstage Ticketing Platform API v{}",
        env!("CARGO_PKG_VERSION")
    );

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    validate_environment_variables();

    info!("🔍 Current Configuration:");
    info!(
        "   APP_ENV: {}",
        env::var("APP_ENV").unwrap_or_else(|_| "not set".to_string())
    );
    info!(
        "   Using database: {}...",
        &env::var("DATABASE_URL").unwrap_or_else(|_| "not set".to_string())[..30]
    );
    info!(
        "   Email from: {}",
        env::var("EMAIL_FROM").unwrap_or_else(|_| "not set".to_string())
    );

    info!("Connecting to database...");
    let db_pool = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(&database_url)
        .await
        .expect("Failed to create database pool");

    let redis_service: Option<Arc<RedisService>> = match RedisService::new().await {
        Ok(redis) => {
            info!("✅ Redis connection established");

            // Test Redis connection
            match redis.ping().await {
                Ok(pong) => info!("🏓 Redis ping successful: {}", pong),
                Err(e) => warn!("⚠️ Redis ping failed: {}", e),
            }

            Some(Arc::new(redis))
        }
        Err(e) => {
            warn!("⚠️ Redis connection failed: {}", e);
            warn!("🚀 Application will continue without Redis caching");
            None
        }
    };

    // Initialize shared services
    let stellar_service = Arc::new(
        StellarService::new().expect("Failed to initialize Stellar service"),
    );
    let email_service: Option<Arc<EmailService>> = match EmailService::new().await {
        Ok(service) => Some(Arc::new(service)),
        Err(e) => {
            warn!("⚠️ Email service initialization failed: {}", e);
            None
        }
    };

    match sqlx::query("SELECT 1").fetch_one(&db_pool).await {
        Ok(_) => info!("Database connection successful"),
        Err(e) => {
            error!("Database connection failed: {}", e);
            std::process::exit(1);
        }
    }

    info!("🏦 Initializing sponsor accounts...");
    match initialize_sponsor_system(&db_pool).await {
        Ok(sponsor_count) => {
            info!(
                "✅ {} sponsor accounts initialized and validated",
                sponsor_count
            );
        }
        Err(e) => {
            error!("❌ Failed to initialize sponsor system: {}", e);
            error!("💡 Please check your sponsor account configuration");
            std::process::exit(1);
        }
    }

    info!("Running database migrations...");
    match sqlx::migrate!("./migrations").run(&db_pool).await {
        Ok(_) => info!("Database migrations completed successfully"),
        Err(e) => {
            error!("Database migration failed: {}", e);
            std::process::exit(1);
        }
    }

    info!("Initializing scheduled tasks...");
    let scheduler = SchedulerService::new(db_pool.clone());
    scheduler.start_scheduled_tasks().await;
    scheduler.start_cleanup_tasks().await;

    info!("✅ Blocstage API setup completed - creating service configuration");

    let cors_origins = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://blocstage.com,http://localhost:3000,http://localhost:5173".to_string());
    let origins: Vec<String> = cors_origins.split(',').map(|s| s.to_string()).collect();
    
    info!("🌍 CORS allowed origins: {:?}", origins);

    let config = move |cfg: &mut web::ServiceConfig| {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                "accept",
                "accept-encoding", 
                "authorization",
                "content-type",
                "dnt",
                "origin",
                "user-agent",
                "x-csrftoken",
                "x-requested-with",
            ])
            .supports_credentials()
            .max_age(3600);

        // Add each origin separately
        for origin in &origins {
            cors = cors.allowed_origin(origin);
        }

        // Register shared app data at the root so all scopes/handlers can access it
        cfg.app_data(web::Data::new(db_pool.clone()));
        cfg.app_data(web::Data::new(stellar_service.clone()));
        if let Some(redis) = &redis_service {
            cfg.app_data(web::Data::new(redis.clone()));
        }
        if let Some(email) = &email_service {
            cfg.app_data(web::Data::new(email.clone()));
        }

        cfg.service(
            web::scope("")
                .wrap(cors)
                .app_data(
                    web::JsonConfig::default()
                        .limit(10 * 1024 * 1024)
                        .error_handler(|err, _req| {
                            error!("JSON payload error: {}", err);
                            actix_web::error::InternalError::from_response(
                            err,
                            HttpResponse::BadRequest().json(json!({
                                "message": "Invalid JSON payload"
                            }))
                        ).into()
                        }),
                )
                .app_data(
                    web::FormConfig::default()
                        .limit(5 * 1024 * 1024)
                        .error_handler(|err, _req| {
                            error!("Form payload error: {}", err);
                            actix_web::error::InternalError::from_response(
                                err,
                                HttpResponse::BadRequest().json(json!({
                                    "error": "Invalid form data",
                                    "message": "Form data is invalid or exceeds size limit"
                                })),
                            )
                            .into()
                        }),
                )
                .route("/health", web::get().to(health_check))
                .configure(configure_routes)
                .default_service(web::route().to(not_found))
        );
    };

    info!("🚀 Service configuration ready for deployment");
    Ok(config.into())
}

async fn initialize_sponsor_system(
    pool: &sqlx::PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let sponsor_manager = SponsorManager::new(pool.clone())?;

    let existing_sponsors = sponsor_manager.get_sponsor_statistics().await?;

    if existing_sponsors.is_empty() {
        info!("📋 No sponsors found in database, attempting migration from environment variables");

        match sponsor_manager.initialize_sponsor_accounts().await {
            Ok(_) => {
                info!("✅ Successfully migrated sponsor accounts from environment to database");
            }
            Err(e) => {
                warn!("⚠️  Failed to migrate sponsors from environment: {}", e);
                warn!("💡 You may need to add sponsor accounts manually via the admin API");
                warn!("💡 System will continue but sponsored payments may not work until sponsors are added");

                // Don't exit. Allow system to start without sponsors for admin setup
                return Ok(0);
            }
        }
    } else {
        info!(
            "📋 Found {} existing sponsor accounts in database",
            existing_sponsors.len()
        );

        if let Err(e) = sponsor_manager.update_all_balances().await {
            warn!("⚠️  Failed to refresh sponsor balances: {}", e);
        }
    }

    let sponsor_stats = sponsor_manager.get_sponsor_statistics().await?;
    let active_sponsors = sponsor_stats.iter().filter(|s| s.is_active).count();

    if active_sponsors == 0 {
        warn!("⚠️  No active sponsor accounts available for fee sponsorship");
        warn!("💡 Please add or reactivate sponsor accounts via the admin API");
        warn!("💡 Sponsored payments will fail until at least one sponsor is active");
    } else {
        info!(
            "✅ {} active sponsor accounts available for fee sponsorship",
            active_sponsors
        );
    }

    info!("📊 Sponsor Account Summary:");
    for account in &sponsor_stats {
        let balance_info = if let Some(balance) = &account.current_balance {
            format!("{} XLM", balance)
        } else {
            "Balance unknown".to_string()
        };

        let status = if account.is_active {
            "✅ Active"
        } else {
            "❌ Inactive"
        };
        let key_status = if account.encrypted_secret_key.is_some() {
            "🔐 Encrypted"
        } else {
            "❌ No Key"
        };

        info!(
            "   {} - {} - {} - Sponsored: {} txs",
            account.account_name,
            status,
            key_status,
            account.transactions_sponsored.unwrap_or(0)
        );
        info!(
            "     Balance: {} | Public Key: {}",
            balance_info, account.public_key
        );
    }

    Ok(sponsor_stats.len())
}

fn validate_environment_variables() {
    let important_vars = [
        "DATABASE_URL",
        "JWT_SECRET",
        "STELLAR_NETWORK",
        "MASTER_ENCRYPTION_KEY",
        "PLATFORM_PAYMENT_PUBLIC_KEY",
        "SPONSORSHIP_FEE_ACCOUNT_PUBLIC",
        "TESTNET_USDC_ISSUER",
        "PLATFORM_FEE_PERCENTAGE",
        "TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE",
        "GAS_FEE_MARGIN_PERCENTAGE",
        "SPONSOR_MINIMUM_BALANCE",
        "SPONSOR_LOW_BALANCE_ALERT_THRESHOLD",
        "EMAIL_FROM",
        "EMAIL_FROM_SUPPORT",
        "APP_URL",
    ];

    // Check important variables
    let mut missing_important = Vec::new();
    for var in important_vars.iter() {
        if env::var(var).is_err() {
            missing_important.push(*var);
        }
    }

    if !missing_important.is_empty() {
        error!("❌ Missing important environment variables:");
        for var in &missing_important {
            error!("   - {}", var);
        }
        error!("💡 Please set these variables in your .env file");
        std::process::exit(1);
    }

    // Validate percentage values
    if let Ok(platform_fee) = env::var("PLATFORM_FEE_PERCENTAGE") {
        match platform_fee.parse::<f64>() {
            Ok(fee) if fee < 0.0 || fee > 50.0 => {
                error!("❌ PLATFORM_FEE_PERCENTAGE must be between 0 and 50");
                std::process::exit(1);
            }
            Err(_) => {
                error!("❌ PLATFORM_FEE_PERCENTAGE must be a valid number");
                std::process::exit(1);
            }
            _ => {}
        }
    }

    if let Ok(sponsorship_fee) = env::var("TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE") {
        match sponsorship_fee.parse::<f64>() {
            Ok(fee) if fee < 0.0 || fee > 50.0 => {
                error!("❌ TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE must be between 0 and 50");
                std::process::exit(1);
            }
            Err(_) => {
                error!("❌ TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE must be a valid number");
                std::process::exit(1);
            }
            _ => {}
        }
    }

    // Validate Stellar public keys format
    let public_key_vars = [
        "PLATFORM_PAYMENT_PUBLIC_KEY",
        "SPONSORSHIP_FEE_ACCOUNT_PUBLIC",
    ];
    for var in public_key_vars.iter() {
        if let Ok(key) = env::var(var) {
            if !key.starts_with('G') || key.len() != 56 {
                error!(
                    "❌ {} must be a valid Stellar public key (starts with G, 56 characters)",
                    var
                );
                std::process::exit(1);
            }
        }
    }

    // TODO: Validate sponsor secret keys

    // Validate network configuration
    if let Ok(network) = env::var("STELLAR_NETWORK") {
        if network != "testnet" && network != "mainnet" {
            error!("❌ STELLAR_NETWORK must be either 'testnet' or 'mainnet'");
            std::process::exit(1);
        }

        if network == "mainnet" {
            warn!("⚠️  Running on Stellar MAINNET");
        } else {
            info!("🧪 Running on Stellar TESTNET");
        }
    }

    // Display configuration summary
    info!("📋 Configuration Summary:");
    info!(
        "   Platform Fee: {}%",
        env::var("PLATFORM_FEE_PERCENTAGE").unwrap_or_else(|_| "5.0".to_string())
    );
    info!(
        "   Sponsorship Fee: {}%",
        env::var("TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE").unwrap_or_else(|_| "2.5".to_string())
    );
    info!(
        "   Gas Margin: {}%",
        env::var("GAS_FEE_MARGIN_PERCENTAGE").unwrap_or_else(|_| "20".to_string())
    );
    info!(
        "   Sponsor Min Balance: {} XLM",
        env::var("SPONSOR_MINIMUM_BALANCE").unwrap_or_else(|_| "200".to_string())
    );
    info!(
        "   Network: {}",
        env::var("STELLAR_NETWORK").unwrap_or_else(|_| "testnet".to_string())
    );
}
