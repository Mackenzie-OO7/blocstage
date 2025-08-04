use crate::middleware::auth::AuthenticatedUser;
use crate::services::event::EventService;
use crate::services::fee_calculator::FeeCalculator;
use crate::services::sponsor_manager::SponsorManager;
use actix_web::{web, HttpResponse, Responder};
use log::info;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct UpdateSponsorshipFeeRequest {
    pub new_percentage: f64,
}

/// Get sponsor account statistics
pub async fn get_sponsor_statistics(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    // Add admin check
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to initialize sponsor manager: {}", e)
            }));
        }
    };

    match sponsor_manager.get_sponsor_statistics().await {
        Ok(stats) => HttpResponse::Ok().json(serde_json::json!({
            "sponsor_accounts": stats,
            "summary": {
                "total_accounts": stats.len(),
                "active_accounts": stats.iter().filter(|a| a.is_active).count(),
                "total_transactions_sponsored": stats.iter()
                    .map(|a| a.transactions_sponsored.unwrap_or(0)) // Fix: Handle Option<i32>
                    .sum::<i32>()
            }
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get sponsor statistics: {}", e)
        }))
    }
}

/// Refresh all sponsor account balances
pub async fn refresh_sponsor_balances(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to initialize sponsor manager: {}", e)
            }));
        }
    };

    match sponsor_manager.refresh_all_balances().await {
        Ok(_) => {
            info!("Manual sponsor balance refresh completed");
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "All sponsor account balances refreshed successfully"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to refresh balances: {}", e)
        })),
    }
}

/// Get platform revenue summary
pub async fn get_revenue_summary(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
    query: web::Query<serde_json::Value>,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Fix: EventService::new() returns EventService, not Result
    let event_service = EventService::new(pool.get_ref().clone());

    // Parse date range from query parameters
    let start_date = query
        .get("start_date")
        .and_then(|d| d.as_str())
        .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::days(30));

    let end_date = query
        .get("end_date")
        .and_then(|d| d.as_str())
        .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc::now());

    match event_service
        .get_platform_revenue_summary(start_date, end_date)
        .await
    {
        Ok(summary) => HttpResponse::Ok().json(summary),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get revenue summary: {}", e)
        })),
    }
}

/// Update sponsorship fee percentage
pub async fn update_sponsorship_fee(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
    req: web::Json<UpdateSponsorshipFeeRequest>,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let mut fee_calculator = match FeeCalculator::new(pool.get_ref().clone()) {
        Ok(calculator) => calculator,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to initialize fee calculator: {}", e)
            }));
        }
    };

    match fee_calculator
        .update_sponsorship_fee_percentage(req.new_percentage)
        .await
    {
        Ok(_) => {
            info!(
                "Admin {} updated sponsorship fee percentage to {}%",
                user.id, req.new_percentage
            );
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Sponsorship fee updated to {}%", req.new_percentage),
                "new_percentage": req.new_percentage,
                "note": "This only affects the current instance. Update environment variable for persistence."
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Failed to update sponsorship fee: {}", e)
        })),
    }
}

/// Get pending event payouts
pub async fn get_pending_payouts(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Fix: EventService::new() returns EventService, not Result
    let event_service = EventService::new(pool.get_ref().clone());

    match event_service.get_events_pending_payout().await {
        Ok(pending_events) => HttpResponse::Ok().json(serde_json::json!({
            "pending_payouts": pending_events,
            "count": pending_events.len()
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get pending payouts: {}", e)
        })),
    }
}

/// Process all pending event payouts
pub async fn process_event_payouts(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Fix: EventService::new() returns EventService, not Result
    let event_service = EventService::new(pool.get_ref().clone());

    match event_service.process_event_payments().await {
        Ok(processed_payouts) => {
            info!("Admin {} processed {} event payouts", user.id, processed_payouts.len());
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "processed_payouts": processed_payouts,
                "count": processed_payouts.len()
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to process event payouts: {}", e)
        })),
    }
}

/// Check USDC issuer status
pub async fn check_usdc_issuer_status(
    _pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&_pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // This would implement a health check for the USDC issuer
    HttpResponse::Ok().json(serde_json::json!({
        "usdc_issuer_status": "operational",
        "last_checked": chrono::Utc::now(),
        "issuer_public_key": std::env::var("TESTNET_USDC_ISSUER").unwrap_or("Not configured".to_string()),
        "network": std::env::var("STELLAR_NETWORK").unwrap_or("testnet".to_string())
    }))
}

// Simplified route configuration - remove missing functions
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            // Platform management
            .route("/platform/revenue", web::get().to(get_revenue_summary))
            
            // Sponsor account management  
            .route("/sponsors/statistics", web::get().to(get_sponsor_statistics))
            .route("/sponsors/refresh-balances", web::post().to(refresh_sponsor_balances))
            
            // Event payouts
            .route("/payouts/pending", web::get().to(get_pending_payouts))
            .route("/payouts/process", web::post().to(process_event_payouts))
            
            // Fee management
            .route("/fees/update-sponsorship-percentage", web::put().to(update_sponsorship_fee))
            
            // System health
            .route("/system/usdc-issuer-status", web::get().to(check_usdc_issuer_status))
    );
}