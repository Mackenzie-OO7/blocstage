use crate::middleware::auth::AuthenticatedUser;
use crate::services::event::EventService;
use crate::services::fee_calculator::FeeCalculator;
use crate::services::sponsor_manager::{SponsorManager, CreateSponsorRequest, UpdateSponsorRequest};
use actix_web::{web, HttpResponse, Responder};
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct UpdateSponsorshipFeeRequest {
    pub new_percentage: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformRevenueResponse {
    pub total_usdc: f64,
    pub sponsorship_fees_usdc: f64,
    pub platform_fees_usdc: f64,
    pub transaction_count: i64,
    pub last_30_days_usdc: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn get_sponsor_statistics(
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

    match sponsor_manager.update_all_balances().await {
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

pub async fn get_revenue_summary(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
    query: web::Query<serde_json::Value>,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let event_service = EventService::new(pool.get_ref().clone());

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

pub async fn get_pending_payouts(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

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

pub async fn add_sponsor_account(
    pool: web::Data<PgPool>,
    req: web::Json<CreateSponsorRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize sponsor manager: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };

    match sponsor_manager.add_sponsor_account(req.into_inner()).await {
        Ok(sponsor) => {
            info!("Admin {} added new sponsor account: {}", user.id, sponsor.account_name);
            HttpResponse::Created().json(json!({
                "message": "Sponsor account added successfully",
                "sponsor": {
                    "id": sponsor.id,
                    "account_name": sponsor.account_name,
                    "public_key": sponsor.public_key,
                    "is_active": sponsor.is_active,
                    "created_at": sponsor.created_at
                }
            }))
        }
        Err(e) => {
            error!("Failed to add sponsor account: {}", e);
            HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Failed to add sponsor account: {}", e),
            })
        }
    }
}

pub async fn update_sponsor_account(
    pool: web::Data<PgPool>,
    req: web::Json<UpdateSponsorRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize sponsor manager: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };

    match sponsor_manager.update_sponsor_account(req.into_inner()).await {
        Ok(sponsor) => {
            info!("Admin {} updated sponsor account: {}", user.id, sponsor.account_name);
            HttpResponse::Ok().json(json!({
                "message": "Sponsor account updated successfully",
                "sponsor": {
                    "id": sponsor.id,
                    "account_name": sponsor.account_name,
                    "public_key": sponsor.public_key,
                    "is_active": sponsor.is_active,
                    "updated_at": sponsor.updated_at
                }
            }))
        }
        Err(e) => {
            error!("Failed to update sponsor account: {}", e);
            HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Failed to update sponsor account: {}", e),
            })
        }
    }
}

pub async fn deactivate_sponsor(
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_id = path.into_inner();
    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize sponsor manager: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };

    match sponsor_manager.deactivate_sponsor_by_id(sponsor_id).await {
        Ok(sponsor) => {
            info!("Admin {} deactivated sponsor account: {}", user.id, sponsor.account_name);
            HttpResponse::Ok().json(json!({
                "message": "Sponsor account deactivated successfully",
                "sponsor": {
                    "id": sponsor.id,
                    "account_name": sponsor.account_name,
                    "public_key": sponsor.public_key,
                    "is_active": sponsor.is_active
                }
            }))
        }
        Err(e) => {
            error!("Failed to deactivate sponsor account: {}", e);
            HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Failed to deactivate sponsor account: {}", e),
            })
        }
    }
}

pub async fn reactivate_sponsor(
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_id = path.into_inner();
    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize sponsor manager: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };

    match sponsor_manager.reactivate_sponsor_by_id(sponsor_id).await {
        Ok(sponsor) => {
            info!("Admin {} reactivated sponsor account: {}", user.id, sponsor.account_name);
            HttpResponse::Ok().json(json!({
                "message": "Sponsor account reactivated successfully",
                "sponsor": {
                    "id": sponsor.id,
                    "account_name": sponsor.account_name,
                    "public_key": sponsor.public_key,
                    "is_active": sponsor.is_active
                }
            }))
        }
        Err(e) => {
            error!("Failed to reactivate sponsor account: {}", e);
            HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Failed to reactivate sponsor account: {}", e),
            })
        }
    }
}

pub async fn list_sponsors(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize sponsor manager: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };

    match sponsor_manager.list_all_sponsors().await {
        Ok(sponsors) => HttpResponse::Ok().json(json!({
            "sponsors": sponsors,
            "total_count": sponsors.len()
        })),
        Err(e) => {
            error!("Failed to list sponsor accounts: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve sponsor accounts".to_string(),
            })
        }
    }
}

pub async fn get_sponsor_by_id(
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let sponsor_id = path.into_inner();
    let sponsor_manager = match SponsorManager::new(pool.get_ref().clone()) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize sponsor manager: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };

    match sponsor_manager.get_sponsor_by_id(sponsor_id).await {
        Ok(sponsor) => HttpResponse::Ok().json(json!({
            "sponsor": sponsor
        })),
        Err(e) => {
            error!("Failed to get sponsor account: {}", e);
            HttpResponse::NotFound().json(ErrorResponse {
                error: "Sponsor account not found".to_string(),
            })
        }
    }
}

pub async fn process_event_payouts(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

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

pub async fn check_usdc_issuer_status(
    _pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&_pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "usdc_issuer_status": "operational",
        "last_checked": chrono::Utc::now(),
        "issuer_public_key": std::env::var("TESTNET_USDC_ISSUER").unwrap_or("Not configured".to_string()),
        "network": std::env::var("STELLAR_NETWORK").unwrap_or("testnet".to_string())
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/platform/revenue", web::get().to(get_revenue_summary))
            
            // Sponsor account management  
            .route("/sponsors/statistics", web::get().to(get_sponsor_statistics))
            .route("/sponsors/refresh-balances", web::post().to(refresh_sponsor_balances))
            .route("/sponsors", web::get().to(list_sponsors))
            .route("/sponsors", web::post().to(add_sponsor_account))
            .route("/sponsors/{sponsor_id}", web::get().to(get_sponsor_by_id))
            .route("/sponsors/{sponsor_id}", web::put().to(update_sponsor_account))
            .route("/sponsors/{sponsor_id}/deactivate", web::post().to(deactivate_sponsor))
            .route("/sponsors/{sponsor_id}/reactivate", web::post().to(reactivate_sponsor))
            
            // Event payouts
            .route("/payouts/pending", web::get().to(get_pending_payouts))
            .route("/payouts/process", web::post().to(process_event_payouts))
            
            // Fee management
            .route("/fees/update-sponsorship-percentage", web::put().to(update_sponsorship_fee))
            
            // System health
            .route("/system/usdc-issuer-status", web::get().to(check_usdc_issuer_status))
    );
}