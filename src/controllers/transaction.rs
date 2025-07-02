use actix_web::{web, HttpResponse, Responder};
use crate::models::transaction::{Transaction, RefundRequest};
use crate::middleware::auth::AuthenticatedUser;
use sqlx::PgPool;
use uuid::Uuid;
use log::{error, info};
use serde::{Deserialize, Serialize};

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

pub async fn request_refund(
    pool: web::Data<PgPool>,
    refund_data: web::Json<RefundRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    match crate::models::ticket::Ticket::find_by_id(&pool, refund_data.ticket_id).await {
        Ok(Some(ticket)) => {
            if ticket.owner_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to refund this ticket".to_string(),
                });
            }
            
            match Transaction::find_by_ticket(&pool, refund_data.ticket_id).await {
                Ok(Some(transaction)) => {
                    if transaction.status != "completed" {
                        return HttpResponse::BadRequest().json(ErrorResponse {
                            error: "Only completed transactions can be refunded".to_string(),
                        });
                    }
                    
                    if transaction.refund_amount.is_some() {
                        return HttpResponse::BadRequest().json(ErrorResponse {
                            error: "This transaction has already been refunded".to_string(),
                        });
                    }
                    
                    match transaction.process_refund(&pool, refund_data.amount.clone(), refund_data.reason.clone()).await {
                        Ok(updated_transaction) => {
                            info!("Refund processed for transaction {}", transaction.id);
                            
                            match ticket.update_status(&pool, "refunded").await {
                                Ok(_) => {
                                    // We might need to increase the available ticket count
                                    // But that would be handled in the ticket controller's cancel endpoint
                                    HttpResponse::Ok().json(serde_json::json!({
                                        "transaction": updated_transaction,
                                        "message": "Refund has been processed successfully"
                                    }))
                                },
                                Err(e) => {
                                    error!("Failed to update ticket status after refund: {}", e);
                                    HttpResponse::InternalServerError().json(ErrorResponse {
                                        error: "Refund processed but failed to update ticket status".to_string(),
                                    })
                                },
                            }
                        },
                        Err(e) => {
                            error!("Failed to process refund: {}", e);
                            
                            let error_message = if e.to_string().contains("cannot exceed original") {
                                "Refund amount cannot exceed the original transaction amount."
                            } else {
                                "Failed to process refund. Please try again."
                            };
                            
                            HttpResponse::BadRequest().json(ErrorResponse {
                                error: error_message.to_string(),
                            })
                        },
                    }
                },
                Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
                    error: "No transaction found for this ticket".to_string(),
                }),
                Err(e) => {
                    error!("Failed to fetch transaction: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to fetch transaction. Please try again.".to_string(),
                    })
                },
            }
        },
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Ticket not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch ticket: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify ticket ownership. Please try again.".to_string(),
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
            .route("/refund", web::post().to(request_refund))
    );
}