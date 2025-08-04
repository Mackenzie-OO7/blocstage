pub mod models;
pub mod services;
pub mod controllers;
pub mod middleware;

use actix_web::{
    web, App, HttpServer, HttpResponse, Responder,
    middleware::{Logger, DefaultHeaders, Compress},
};
use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use sqlx::{pool, postgres::PgPoolOptions};
use dotenv::dotenv;
use std::{env, time::Duration};
use log::{info, error, warn};
use serde_json::json;

use crate::services::scheduler::SchedulerService;
use crate::services::sponsor_manager::SponsorManager;

use blocstage::controllers::configure_routes;
use blocstage::api_info;

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "service": "blocstage-api",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
// Moved this to lib.rs
// // API info endpoint. TODO: this will be moved to the /api scope
// pub async fn api_info() -> impl Responder {
//     HttpResponse::Ok().json(json!({
//         "name": "BlocStage Ticketing API",
//         "version": env!("CARGO_PKG_VERSION"),
//         "description": "Decentralized ticketing platform on Stellar",
//         "endpoints": {
//             "health": "/health",
//             "api_docs": "/api",
//             "auth": "/api/auth/*",
//             "events": "/api/events/*",
//             "tickets": "/api/tickets/*",
//             "users": "/api/users/*",
//             "transactions": "/api/transactions/*",
//             "admin": "/api/admin/*"
//         }
//     }))
// }

// 404 handler for undefined routes
async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json(json!({
        "error": "Endpoint not found",
        "message": "The requested resource does not exist",
        "available_endpoints": "/api for API documentation"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();
    
    info!("Starting Blocstage Ticketing Platform API v{}", env!("CARGO_PKG_VERSION"));
    
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let server_host = env::var("SERVER_HOST")
        .unwrap_or_else(|_| "0.0.0.0".to_string());
    let server_port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("SERVER_PORT must be a valid port number");
    
    validate_environment_variables();
    
    info!("Connecting to database...");
    let db_pool = PgPoolOptions::new()
        .max_connections(20) // Max connections for production
        .min_connections(5)  // Keep minimum connections alive
        .acquire_timeout(Duration::from_secs(30)) // Connection timeout
        .idle_timeout(Duration::from_secs(600))   // 10 minutes idle timeout
        .max_lifetime(Duration::from_secs(1800))  // 30 minutes max lifetime
        .connect(&database_url)
        .await
        .expect("Failed to create database pool");
    
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
            info!("✅ {} sponsor accounts initialized and validated", sponsor_count);
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
    
    // rate limiting (100 requests per minute per IP)
    let governor_conf = GovernorConfigBuilder::default()
        .requests_per_minute(100)
        .burst_size(20) // allow burst of 20 requests
        .finish()
        .unwrap();
    
    info!("Starting HTTP server on {}:{}", server_host, server_port);
    info!("API documentation available at: http://{}:{}/api", server_host, server_port);
    info!("Health check available at: http://{}:{}/health", server_host, server_port);
    
    // Start HTTP server
    HttpServer::new(move || {
        let cors_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173".to_string());
        
        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _req_head| {
                cors_origins.split(',')
                    .any(|allowed| allowed.trim() == origin.to_str().unwrap_or(""))
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
            .allowed_headers(vec![
                "Content-Type",
                "Authorization", 
                "Accept",
                "X-Requested-With",
                "Origin"
            ])
            .expose_headers(vec!["Content-Length", "X-Request-ID"])
            .max_age(3600) // Cache preflight for 1 hour
            .supports_credentials();
        
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            
            // JSON payload limits (10MB max)
            .app_data(web::JsonConfig::default()
                .limit(10 * 1024 * 1024) // 10MB
                .error_handler(|err, _req| {
                    error!("JSON payload error: {}", err);
                    actix_web::error::InternalError::from_response(
                        err,
                        HttpResponse::BadRequest().json(json!({
                            "error": "Invalid JSON payload",
                            "message": "Request body contains invalid JSON or exceeds size limit"
                        }))
                    ).into()
                })
            )
            
            // form data limits
            .app_data(web::FormConfig::default()
                .limit(5 * 1024 * 1024) // 5MB
                .error_handler(|err, _req| {
                    error!("Form payload error: {}", err);
                    actix_web::error::InternalError::from_response(
                        err,
                        HttpResponse::BadRequest().json(json!({
                            "error": "Invalid form data",
                            "message": "Form data is invalid or exceeds size limit"
                        }))
                    ).into()
                })
            )
            
            // Security and performance middleware
            .wrap(cors)
            .wrap(Governor::new(&governor_conf)) // Rate limit
            .wrap(Compress::default()) // Response compression
            .wrap(Logger::new(
                r#"%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#
            ))
            
            // Security headers
            .wrap(DefaultHeaders::new()
                .add(("X-Content-Type-Options", "nosniff"))
                .add(("X-Frame-Options", "DENY"))
                .add(("X-XSS-Protection", "1; mode=block"))
                .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                .add(("Content-Security-Policy", 
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'"))
                .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
                .add(("Permissions-Policy", "geolocation=(), microphone=(), camera=()"))
            )
            
            // System endpoints
            .route("/health", web::get().to(health_check))
            
            // API routes (includes /api root now)
            .configure(configure_routes)
            
            // 404 handler for all other routes
            .default_service(web::route().to(not_found))
    })
    .bind(format!("{}:{}", server_host, server_port))?
    .workers(num_cpus::get())
    .shutdown_timeout(30) // 30 second shutdown
    .run()
    .await
}

async fn initialize_sponsor_system(pool: &sqlx::PgPool) -> Result<usize, Box<dyn std::error::Error>> {
    let sponsor_manager = SponsorManager::new(pool.clone())?;
    
    // Initialize sponsor accounts from environment
    sponsor_manager.initialize_sponsor_accounts().await?;
    
    // Get and validate sponsor statistics
    let sponsor_stats = sponsor_manager.get_sponsor_statistics().await?;
    let active_sponsors = sponsor_stats.iter().filter(|s| s.is_active).count();
    
    if active_sponsors == 0 {
        return Err("No active sponsor accounts available for fee sponsorship".into());
    }

    info!("📊 Sponsor Account Summary:");
    for account in &sponsor_stats {
        let balance_info = if let Some(balance) = &account.current_balance {
            format!("{} XLM", balance)
        } else {
            "Balance unknown".to_string()
        };
        
        let status = if account.is_active { "✅ Active" } else { "❌ Inactive" };
        info!("   {} - {} - Sponsored: {} txs", 
            account.account_name, 
            status, 
            account.transactions_sponsored.unwrap_or(0));
        info!("Balance: {}", balance_info);
    }

    Ok(sponsor_stats.len())
}

fn validate_environment_variables() {
    let required_vars = [
        "DATABASE_URL",
        "JWT_SECRET",
        "STELLAR_NETWORK",
        "MASTER_ENCRYPTION_KEY",
        "PLATFORM_WALLET_PUBLIC_KEY",
        "SPONSORSHIP_FEE_ACCOUNT_PUBLIC",
        "SPONSOR_ACCOUNT_1_SECRET",
    ];
    
    let important_vars = [
        "TESTNET_USDC_ISSUER",
        "PLATFORM_FEE_PERCENTAGE",
        "TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE",
        "GAS_FEE_MARGIN_PERCENTAGE",
        "SPONSOR_MINIMUM_BALANCE",
        "SPONSOR_LOW_BALANCE_ALERT_THRESHOLD",
        "SPONSOR_ACCOUNT_2_SECRET",
        "SPONSOR_ACCOUNT_3_SECRET",
    ];

    let optional_vars = [
        "SERVER_HOST",
        "SERVER_PORT",
        "LOCAL_STORAGE_DIR",
        "NFT_ISSUER_PUBLIC_KEY",
        "NFT_ISSUER_SECRET_KEY",
        "EMAIL_FROM",
        "SPONSOR_BALANCE_CHECK_INTERVAL",
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

    // Check important variables
    let mut missing_important = Vec::new();
    for var in important_vars.iter() {
        if env::var(var).is_err() {
            missing_important.push(*var);
        }
    }

    if !missing_important.is_empty() {
        warn!("⚠️  Missing important environment variables (using defaults):");
        for var in &missing_important {
            warn!("   - {}", var);
        }
    }

    // Check optional variables
    let mut missing_optional = Vec::new();
    for var in optional_vars.iter() {
        if env::var(var).is_err() {
            missing_optional.push(*var);
        }
    }

    if !missing_optional.is_empty() {
        info!("ℹ️  Optional environment variables not set:");
        for var in &missing_optional {
            info!("   - {} (using default)", var);
        }
    }

    // Validate specific values
    validate_specific_configurations();

    info!("✅ Environment validation completed successfully");
}

/// Validate specific configuration values
fn validate_specific_configurations() {
    // Validate JWT secret length
    if let Ok(jwt_secret) = env::var("JWT_SECRET") {
        if jwt_secret.len() < 32 {
            error!("❌ JWT_SECRET must be at least 32 characters long for security");
            std::process::exit(1);
        }
    }

    // Validate master encryption key
    if let Ok(master_key) = env::var("MASTER_ENCRYPTION_KEY") {
        if master_key.len() != 64 {
            error!("❌ MASTER_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)");
            std::process::exit(1);
        }
    }

    // Validate fee percentages
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
    let public_key_vars = ["PLATFORM_PAYMENT_PUBLIC_KEY", "SPONSORSHIP_FEE_ACCOUNT_PUBLIC"];
    for var in public_key_vars.iter() {
        if let Ok(key) = env::var(var) {
            if !key.starts_with('G') || key.len() != 56 {
                error!("❌ {} must be a valid Stellar public key (starts with G, 56 characters)", var);
                std::process::exit(1);
            }
        }
    }

    // Validate sponsor secret keys format
    let mut sponsor_counter = 1;
    while let Ok(secret) = env::var(&format!("SPONSOR_ACCOUNT_{}_SECRET", sponsor_counter)) {
        if !secret.starts_with('S') || secret.len() != 56 {
            error!("❌ SPONSOR_ACCOUNT_{}_SECRET must be a valid Stellar secret key (starts with S, 56 characters)", sponsor_counter);
            std::process::exit(1);
        }
        sponsor_counter += 1;
    }

    if sponsor_counter == 1 {
        error!("❌ At least one sponsor account (SPONSOR_ACCOUNT_1_SECRET) must be configured");
        std::process::exit(1);
    } else {
        info!("✅ Found {} sponsor account(s) configured", sponsor_counter - 1);
    }

    // Validate network configuration
    if let Ok(network) = env::var("STELLAR_NETWORK") {
        if network != "testnet" && network != "mainnet" {
            error!("❌ STELLAR_NETWORK must be either 'testnet' or 'mainnet'");
            std::process::exit(1);
        }
        
        if network == "mainnet" {
            warn!("⚠️  Running on Stellar MAINNET - real money will be involved!");
        } else {
            info!("🧪 Running on Stellar TESTNET - safe for development");
        }
    }

    // Display configuration summary
    info!("📋 Configuration Summary:");
    info!("   Platform Fee: {}%", env::var("PLATFORM_FEE_PERCENTAGE").unwrap_or_else(|_| "5.0".to_string()));
    info!("   Sponsorship Fee: {}%", env::var("TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE").unwrap_or_else(|_| "2.5".to_string()));
    info!("   Gas Margin: {}%", env::var("GAS_FEE_MARGIN_PERCENTAGE").unwrap_or_else(|_| "20".to_string()));
    info!("   Sponsor Min Balance: {} XLM", env::var("SPONSOR_MINIMUM_BALANCE").unwrap_or_else(|_| "200".to_string()));
    info!("   Network: {}", env::var("STELLAR_NETWORK").unwrap_or_else(|_| "testnet".to_string()));
}