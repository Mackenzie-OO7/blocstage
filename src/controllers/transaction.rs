use actix_web::{web, HttpResponse, Responder};
use crate::models::transaction::{Transaction,};
use crate::middleware::auth::AuthenticatedUser;
use sqlx::PgPool;
use uuid::Uuid;
use log::{error, info};
use serde::{Serialize};

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn get_transaction_by_id(
    pool: web::Data<PgPool>,
    transaction_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match Transaction::find_by_id(&pool, *transaction_id).await {
        Ok(Some(transaction)) => {
            if transaction.user_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to view this transaction".to_string(),
                });
            }
            
            HttpResponse::Ok().json(transaction)
        },
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Transaction not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch transaction: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch transaction. Please try again.".to_string(),
            })
        },
    }
}

pub async fn get_user_transactions(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    match Transaction::find_by_user(&pool, user.id).await {
        Ok(transactions) => HttpResponse::Ok().json(transactions),
        Err(e) => {
            error!("Failed to fetch user transactions: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your transaction history. Please try again.".to_string(),
            })
        },
    }
}

pub async fn generate_receipt(
    pool: web::Data<PgPool>,
    transaction_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match Transaction::find_by_id(&pool, *transaction_id).await {
        Ok(Some(transaction)) => {
            if transaction.user_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to generate a receipt for this transaction".to_string(),
                });
            }
            
            match transaction.generate_receipt().await {
                Ok(receipt_url) => {
                    info!("Receipt generated for transaction {}", transaction_id);
                    HttpResponse::Ok().json(serde_json::json!({
                        "receipt_url": receipt_url,
                        "message": "Receipt has been generated successfully"
                    }))
                },
                Err(e) => {
                    error!("Failed to generate receipt: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to generate receipt. Please try again.".to_string(),
                    })
                },
            }
        },
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Transaction not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch transaction: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch transaction. Please try again.".to_string(),
            })
        },
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/transactions")
            .route("", web::get().to(get_user_transactions))
            .route("/{transaction_id}", web::get().to(get_transaction_by_id))
            .route("/{transaction_id}/receipt", web::post().to(generate_receipt))
    );
}