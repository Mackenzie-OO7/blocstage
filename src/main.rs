pub mod models;
pub mod services;
pub mod controllers;
pub mod middleware;

use actix_web::{
    web, App, HttpServer, HttpResponse, Responder,
    middleware::{Logger, DefaultHeaders, Compress},
    http::header::{CONTENT_TYPE, CACHE_CONTROL},
};
use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use sqlx::postgres::PgPoolOptions;
use dotenv::dotenv;
use std::{env, time::Duration};
use log::{info, error, warn};
use serde_json::json;

use crate::controllers::configure_routes;

// Health check endpoint for load balancers and monitoring
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "service": "blocstage-api",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// API info endpoint
// TODO: better description when i'm not so tired
async fn api_info() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "name": "Blocstage Ticketing API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Decentralized ticketing platform with Stellar blockchain integration",
        "endpoints": {
            "health": "/health",
            "api_docs": "/api",
            "auth": "/api/auth/*",
            "events": "/api/events/*",
            "tickets": "/api/tickets/*",
            "users": "/api/users/*",
            "transactions": "/api/transactions/*",
            "admin": "/api/admin/*"
        }
    }))
}

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
    // Load environment variables from .env file
    dotenv().ok();
    
    // Initialize structured logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();
    
    info!("Starting Blocstage Ticketing Platform API v{}", env!("CARGO_PKG_VERSION"));
    
    // Get configuration from environment variables
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let server_host = env::var("SERVER_HOST")
        .unwrap_or_else(|_| "0.0.0.0".to_string());
    let server_port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("SERVER_PORT must be a valid port number");
    
    // Validate required environment variables
    validate_environment_variables();
    
    // Create database connection pool with optimized settings
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
    
    // Test database connection
    match sqlx::query("SELECT 1").fetch_one(&db_pool).await {
        Ok(_) => info!("Database connection successful"),
        Err(e) => {
            error!("Database connection failed: {}", e);
            std::process::exit(1);
        }
    }
    
    // Run database migrations
    info!("Running database migrations...");
    match sqlx::migrate!("./migrations").run(&db_pool).await {
        Ok(_) => info!("Database migrations completed successfully"),
        Err(e) => {
            error!("Database migration failed: {}", e);
            std::process::exit(1);
        }
    }
    
    // Configure rate limiting (100 requests per minute per IP)
    let governor_conf = GovernorConfigBuilder::default()
        .requests_per_minute(100)
        .burst_size(20) // Allow burst of 20 requests
        .finish()
        .unwrap();
    
    info!("Starting HTTP server on {}:{}", server_host, server_port);
    info!("API documentation available at: http://{}:{}/api", server_host, server_port);
    info!("Health check available at: http://{}:{}/health", server_host, server_port);
    
    // Start HTTP server
    HttpServer::new(move || {
        // Configure CORS - moved inside closure to fix lifetime issues
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
            // Add database pool to app data
            .app_data(web::Data::new(db_pool.clone()))
            
            // Configure JSON payload limits (10MB max)
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
            
            // Configure form data limits
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
            .wrap(Governor::new(&governor_conf)) // Rate limiting
            .wrap(Compress::default()) // Response compression
            .wrap(Logger::new(
                r#"%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#
            )) // Request logging
            
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
            
            // API routes
            .configure(configure_routes)
            
            // System endpoints
            .route("/health", web::get().to(health_check))
            .route("/api", web::get().to(api_info))
            
            // 404 handler for all other routes
            .default_service(web::route().to(not_found))
    })
    .bind(format!("{}:{}", server_host, server_port))?
    .workers(num_cpus::get()) // Use all available CPU cores
    .shutdown_timeout(30) // 30 second graceful shutdown
    .run()
    .await
}

// Validate that all required environment variables are set
fn validate_environment_variables() {
    let required_vars = [
        "DATABASE_URL",
        "JWT_SECRET",
        "STELLAR_NETWORK",
    ];
    
    let optional_vars = [
        "SERVER_HOST",
        "SERVER_PORT", 
        "CORS_ALLOWED_ORIGINS",
        "SMTP_SERVER",
        "SMTP_USERNAME", 
        "SMTP_PASSWORD",
        "EMAIL_FROM",
        "APP_URL",
        "PLATFORM_WALLET_PUBLIC_KEY",
        "PLATFORM_PAYMENT_SECRET",
        "NFT_ISSUER_PUBLIC_KEY",
        "NFT_ISSUER_SECRET_KEY",
        "S3_BUCKET_NAME",
        "S3_BASE_URL",
        "LOCAL_STORAGE_DIR",
    ];
    
    // Check required variables
    let mut missing_required = Vec::new();
    for var in required_vars.iter() {
        if env::var(var).is_err() {
            missing_required.push(*var);
        }
    }
    
    if !missing_required.is_empty() {
        error!("Missing required environment variables: {}", missing_required.join(", "));
        error!("Please set these variables in your .env file or environment");
        std::process::exit(1);
    }
    
    // Warn about missing optional variables
    let mut missing_optional = Vec::new();
    for var in optional_vars.iter() {
        if env::var(var).is_err() {
            missing_optional.push(*var);
        }
    }
    
    if !missing_optional.is_empty() {
        warn!("Optional environment variables not set: {}", missing_optional.join(", "));
        warn!("Some features may not work without these variables");
    }
    
    // Validate JWT secret strength
    if let Ok(jwt_secret) = env::var("JWT_SECRET") {
        if jwt_secret.len() < 32 {
            error!("JWT_SECRET must be at least 32 characters long for security");
            std::process::exit(1);
        }
    }
    
    info!("Environment validation completed successfully");
}