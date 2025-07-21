use crate::middleware::auth::AuthenticatedUser;
use crate::models::event::Event;
use crate::models::ticket::CheckInRequest;
use crate::models::ticket_type::{CreateTicketTypeRequest, TicketType};
use crate::services::ticket::TicketService;
use actix_web::{web, HttpResponse, Responder};
use anyhow::Result;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct TransferTicketRequest {
    recipient_id: Uuid,
}

async fn create_ticket(pool: &PgPool) -> Result<TicketService> {
    TicketService::new(pool.clone()).await
}

// TICKET TYPE MANAGEMENT
pub async fn create_ticket_type(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    ticket_data: web::Json<CreateTicketTypeRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _event =
        match crate::middleware::auth::check_event_ownership(&pool, user.id, *event_id).await {
            Ok(event) => event,
            Err(response) => return response,
        };

    match TicketType::create(&pool, *event_id, ticket_data.into_inner()).await {
        Ok(ticket_type) => {
            info!(
                "Ticket type created: {} for event {} by user {}",
                ticket_type.id, event_id, user.id
            );
            HttpResponse::Created().json(ticket_type)
        }
        Err(e) => {
            error!("Failed to create ticket type: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to create ticket type. Please try again.".to_string(),
            })
        }
    }
}

pub async fn get_ticket_types(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
) -> impl Responder {
    match TicketType::find_by_event(&pool, *event_id).await {
        Ok(ticket_types) => HttpResponse::Ok().json(ticket_types),
        Err(e) => {
            error!("Failed to fetch ticket types: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch ticket types. Please try again.".to_string(),
            })
        }
    }
}

pub async fn update_ticket_type_status(
    pool: web::Data<PgPool>,
    path: web::Path<(Uuid, bool)>,
    user: AuthenticatedUser,
) -> impl Responder {
    let (ticket_type_id, is_active) = path.into_inner();

    let ticket_type = match TicketType::find_by_id(&pool, ticket_type_id).await {
        Ok(Some(ticket_type)) => ticket_type,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Ticket type not found".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to fetch ticket type: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch ticket type. Please try again.".to_string(),
            });
        }
    };

    let _event =
        match crate::middleware::auth::check_event_ownership(&pool, user.id, ticket_type.event_id)
            .await
        {
            Ok(event) => event,
            Err(response) => return response,
        };

    match ticket_type.set_active_status(&pool, is_active).await {
        Ok(updated) => {
            info!(
                "Ticket type {} status updated to {} by user {}",
                ticket_type_id, is_active, user.id
            );
            HttpResponse::Ok().json(updated)
        }
        Err(e) => {
            error!("Failed to update ticket type status: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to update ticket type status. Please try again.".to_string(),
            })
        }
    }
}

// TICKET PURCHASING

pub async fn claim_free_ticket(
    pool: web::Data<PgPool>,
    ticket_type_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match TicketService::new(pool.get_ref().clone()).await {
        Ok(ticket_service) => {
            match ticket_service.claim_free_ticket(*ticket_type_id, user.id).await {
                Ok(ticket) => {
                    info!(
                        "Free ticket claimed successfully: ticket_id={}, user_id={}",
                        ticket.id, user.id
                    );
                    HttpResponse::Ok().json(serde_json::json!({
                        "success": true,
                        "message": "Free ticket claimed successfully!",
                        "ticket": ticket
                    }))
                }
                Err(e) => {
                    error!("Failed to claim free ticket: {}", e);
                    
                    let error_message = if e.to_string().contains("not free") {
                        "This ticket type is not free. Use the purchase endpoint instead."
                    } else if e.to_string().contains("already ended") {
                        "Cannot claim tickets for this event as it has already ended."
                    } else if e.to_string().contains("No tickets remaining") {
                        "Sorry, no free tickets remaining for this event."
                    } else if e.to_string().contains("already have a free ticket") {
                        "You already have a free ticket for this event."
                    } else if e.to_string().contains("not yet available") {
                        "Free tickets are not yet available for this event."
                    } else {
                        "Failed to claim free ticket. Please try again."
                    };

                    HttpResponse::BadRequest().json(ErrorResponse {
                        error: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

pub async fn purchase_ticket(
    pool: web::Data<PgPool>,
    ticket_type_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match TicketService::new(pool.get_ref().clone()).await {
        Ok(ticket_service) => {
            match ticket_service.purchase_ticket(*ticket_type_id, user.id).await {
                Ok((ticket, transaction)) => {
                    info!(
                        "Paid ticket purchased successfully: ticket_id={}, user_id={}, transaction_id={}",
                        ticket.id, user.id, transaction.id
                    );
                    HttpResponse::Ok().json(serde_json::json!({
                        "success": true,
                        "message": "Ticket purchased successfully!",
                        "ticket": ticket,
                        "transaction": transaction
                    }))
                }
                Err(e) => {
                    error!("Failed to purchase ticket: {}", e);
                    
                    let error_message = if e.to_string().contains("is free") {
                        "This ticket type is free. Use the claim endpoint instead."
                    } else if e.to_string().contains("Stellar wallet") {
                        "You need to set up a Stellar wallet before purchasing paid tickets."
                    } else if e.to_string().contains("already ended") {
                        "Cannot purchase tickets for this event as it has already ended."
                    } else if e.to_string().contains("No tickets remaining") {
                        "Sorry, no tickets remaining for this event."
                    } else if e.to_string().contains("not yet available") {
                        "Tickets are not yet available for this event."
                    } else {
                        "Failed to purchase ticket. Please try again."
                    };

                    HttpResponse::BadRequest().json(ErrorResponse {
                        error: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

// TICKET VERIFICATION

pub async fn verify_ticket(pool: web::Data<PgPool>, ticket_id: web::Path<Uuid>) -> impl Responder {
    match create_ticket(&pool).await {
        Ok(ticket) => match ticket.verify_ticket(*ticket_id).await {
            Ok(is_valid) => HttpResponse::Ok().json(serde_json::json!({
                "is_valid": is_valid,
                "message": if is_valid { "Ticket is valid" } else { "Ticket is not valid" }
            })),
            Err(e) => {
                error!("Failed to verify ticket: {}", e);

                let error_message = if e.to_string().contains("Ticket not found") {
                    "Ticket not found"
                } else {
                    "Failed to verify ticket. Please try again."
                };

                HttpResponse::BadRequest().json(ErrorResponse {
                    error: error_message.to_string(),
                })
            }
        },
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

pub async fn check_in_ticket(
    pool: web::Data<PgPool>,
    data: web::Json<CheckInRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    // the check-in user has to be verified or say a staff member
    let _verified_user = match crate::middleware::auth::require_verified_user(&pool, user.id).await
    {
        Ok(user) => user,
        Err(response) => return response,
    };
    match create_ticket(&pool).await {
        Ok(ticket) => match ticket.check_in_ticket(data.ticket_id, user.id).await {
            Ok(ticket) => {
                info!(
                    "Ticket checked in: {} by verified staff {}",
                    ticket.id, user.id
                );
                HttpResponse::Ok().json(serde_json::json!({
                    "ticket": ticket,
                    "message": "Ticket has been successfully checked in"
                }))
            }
            Err(e) => {
                error!("Failed to check in ticket: {}", e);

                let error_message = if e.to_string().contains("Ticket is not valid") {
                    "This ticket is not valid for check-in."
                } else if e.to_string().contains("already been checked in") {
                    "This ticket has already been checked in."
                } else {
                    "Failed to check in ticket. Please try again."
                };

                HttpResponse::BadRequest().json(ErrorResponse {
                    error: error_message.to_string(),
                })
            }
        },
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

// TICKET MANAGEMENT

pub async fn generate_pdf_ticket(
    pool: web::Data<PgPool>,
    ticket_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match crate::models::ticket::Ticket::find_by_id(&pool, *ticket_id).await {
        Ok(Some(ticket)) => {
            if ticket.owner_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to access this ticket".to_string(),
                });
            }

            // PDF generation
            match create_ticket(&pool).await {
                Ok(ticket) => match ticket.generate_pdf_ticket(*ticket_id).await {
                    Ok(pdf_url) => {
                        info!("PDF ticket generated: {} for user {}", ticket_id, user.id);
                        HttpResponse::Ok().json(serde_json::json!({
                            "pdf_url": pdf_url,
                            "message": "Ticket PDF has been generated successfully"
                        }))
                    }
                    Err(e) => {
                        error!("Failed to generate PDF ticket: {}", e);
                        HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "Failed to generate PDF ticket. Please try again.".to_string(),
                        })
                    }
                },
                Err(e) => {
                    error!("Failed to initialize ticket service: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    })
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Ticket not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch ticket: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify ticket ownership. Please try again.".to_string(),
            })
        }
    }
}

pub async fn convert_to_nft(
    pool: web::Data<PgPool>,
    ticket_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match crate::models::ticket::Ticket::find_by_id(&pool, *ticket_id).await {
        Ok(Some(ticket)) => {
            if ticket.owner_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to convert this ticket".to_string(),
                });
            }

            // NFT conversion
            match create_ticket(&pool).await {
                Ok(ticket) => match ticket.convert_to_nft(*ticket_id).await {
                    Ok(ticket) => {
                        info!(
                            "Ticket converted to NFT: {} for user {}",
                            ticket_id, user.id
                        );
                        HttpResponse::Ok().json(serde_json::json!({
                            "ticket": ticket,
                            "message": "Ticket has been successfully converted to an NFT"
                        }))
                    }
                    Err(e) => {
                        error!("Failed to convert ticket to NFT: {}", e);

                        let error_message = if e.to_string().contains("already an NFT") {
                            "This ticket is already an NFT."
                        } else if e.to_string().contains("Only valid tickets") {
                            "Only valid tickets can be converted to NFTs."
                        } else {
                            "Failed to convert ticket to NFT. Please try again."
                        };

                        HttpResponse::BadRequest().json(ErrorResponse {
                            error: error_message.to_string(),
                        })
                    }
                },
                Err(e) => {
                    error!("Failed to initialize ticket service: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    })
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Ticket not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch ticket: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify ticket ownership. Please try again.".to_string(),
            })
        }
    }
}

pub async fn transfer_ticket(
    pool: web::Data<PgPool>,
    ticket_id: web::Path<Uuid>,
    data: web::Json<TransferTicketRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    // ownership is checked in the service
    match create_ticket(&pool).await {
        Ok(ticket) => {
            match ticket
                .transfer_ticket(*ticket_id, user.id, data.recipient_id)
                .await
            {
                Ok(ticket) => {
                    info!(
                        "Ticket transferred: {} from user {} to user {}",
                        ticket_id, user.id, data.recipient_id
                    );
                    HttpResponse::Ok().json(serde_json::json!({
                        "ticket": ticket,
                        "message": "Ticket has been successfully transferred"
                    }))
                }
                Err(e) => {
                    error!("Failed to transfer ticket: {}", e);

                    let error_message = if e.to_string().contains("not owned by the sender") {
                        "You don't own this ticket."
                    } else if e.to_string().contains("not valid for transfer") {
                        "This ticket is not valid for transfer."
                    } else if e.to_string().contains("Recipient user not found") {
                        "Recipient user not found."
                    } else {
                        "Failed to transfer ticket. Please try again."
                    };

                    HttpResponse::BadRequest().json(ErrorResponse {
                        error: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

// pub async fn cancel_ticket(
//     pool: web::Data<PgPool>,
//     ticket_id: web::Path<Uuid>,
//     user: AuthenticatedUser,
// ) -> impl Responder {
//     match create_ticket(&pool).await {
//         Ok(ticket) => match ticket.cancel_ticket(*ticket_id, user.id).await {
//             Ok(_) => {
//                 info!("Ticket cancelled: {} by user {}", ticket_id, user.id);
//                 HttpResponse::Ok().json(serde_json::json!({
//                         "message": "Ticket has been successfully cancelled and refund has been processed"
//                     }))
//             }
//             Err(e) => {
//                 error!("Failed to cancel ticket: {}", e);

//                 let error_message = if e.to_string().contains("You don't own this ticket") {
//                     "You don't own this ticket."
//                 } else if e.to_string().contains("Ticket cannot be cancelled") {
//                     "This ticket cannot be cancelled."
//                 } else {
//                     "Failed to cancel ticket. Please try again."
//                 };

//                 HttpResponse::BadRequest().json(ErrorResponse {
//                     error: error_message.to_string(),
//                 })
//             }
//         },
//         Err(e) => {
//             error!("Failed to initialize ticket service: {}", e);
//             HttpResponse::InternalServerError().json(ErrorResponse {
//                 error: "Internal server error".to_string(),
//             })
//         }
//     }
// }

pub async fn get_user_tickets(pool: web::Data<PgPool>, user: AuthenticatedUser) -> impl Responder {
    match create_ticket(&pool).await {
        Ok(ticket) => match ticket.get_user_tickets(user.id).await {
            Ok(tickets) => HttpResponse::Ok().json(tickets),
            Err(e) => {
                error!("Failed to fetch user tickets: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to fetch your tickets. Please try again.".to_string(),
                })
            }
        },
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

// ADMIN ENDPOINTS

pub async fn admin_get_all_tickets(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    match sqlx::query_as!(
        crate::models::ticket::Ticket,
        "SELECT * FROM tickets ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(&**pool)
    .await
    {
        Ok(tickets) => {
            info!("Admin {} accessed all tickets", user.id);
            HttpResponse::Ok().json(tickets)
        }
        Err(e) => {
            error!("Failed to fetch all tickets for admin: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch tickets".to_string(),
            })
        }
    }
}

pub async fn admin_cancel_any_ticket(
    pool: web::Data<PgPool>,
    ticket_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let ticket = match crate::models::ticket::Ticket::find_by_id(&pool, *ticket_id).await {
        Ok(Some(ticket)) => ticket,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Ticket not found".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to fetch ticket for admin cancellation: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch ticket".to_string(),
            });
        }
    };

    match create_ticket(&pool).await {
        Ok(ticket_service) => {
            match ticket_service
                .cancel_ticket(*ticket_id, ticket.owner_id)
                .await
            {
                Ok(_) => {
                    warn!(
                        "Admin {} cancelled ticket {} owned by user {}",
                        user.id, ticket_id, ticket.owner_id
                    );
                    HttpResponse::Ok().json(serde_json::json!({
                    "message": "Ticket has been cancelled by admin and refund has been processed"
                }))
                }
                Err(e) => {
                    error!("Failed to cancel ticket as admin: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to cancel ticket".to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            })
        }
    }
}

// ============ ROUTE CONFIGURATION ============

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/events/{event_id}/tickets")
            .route("", web::get().to(get_ticket_types))
            .route("", web::post().to(create_ticket_type)),
    )
    .service(
        web::scope("/tickets")
            .route("/my-tickets", web::get().to(get_user_tickets))
            .route(
                "/{ticket_id}/generate-pdf",
                web::post().to(generate_pdf_ticket),
            )
            .route(
                "/{ticket_id}/convert-to-nft",
                web::post().to(convert_to_nft),
            )
            .route("/{ticket_id}/transfer", web::post().to(transfer_ticket))
            // .route("/{ticket_id}/cancel", web::post().to(cancel_ticket)),
    )
    .service(
        web::scope("/ticket-types")
            .route(
                "/{ticket_type_id}/purchase",
                web::post().to(purchase_ticket),
            )
            .route(
                "/{ticket_type_id}/claim",
                web::post().to(claim_free_ticket),
            )
            .route(
                "/{ticket_type_id}/{is_active}",
                web::put().to(update_ticket_type_status),
            ),
    )
    .service(
        web::scope("/ticket-verification")
            .route("/{ticket_id}", web::get().to(verify_ticket))
            .route("/check-in", web::post().to(check_in_ticket)),
    )
    .service(
        web::scope("/admin/tickets")
            // Admin-only ticket ops
            .route("", web::get().to(admin_get_all_tickets))
            .route(
                "/{ticket_id}/cancel",
                web::post().to(admin_cancel_any_ticket),
            ),
    );
}
