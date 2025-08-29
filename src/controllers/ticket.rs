use crate::controllers::admin_filters::{
    AdminTicketFilters, AdminTicketView, PageInfo,
    PaginatedTicketsResponse,
};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::event::Event;
use crate::models::ticket::CheckInRequest;
use crate::models::ticket_type::{CreateTicketTypeRequest, TicketType};
use crate::services::ticket::TicketService;
use actix_web::{web, HttpResponse, Responder};
use anyhow::Result;
use bigdecimal::BigDecimal;
use chrono::{Utc};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct TransferTicketRequest {
    recipient_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct AdminCancelTicketRequest {
    reason: String,
}


async fn create_ticket(pool: &PgPool) -> Result<TicketService> {
    TicketService::new(pool.clone()).await
}

// TICKET TYPE MANAGEMENT
pub async fn create_ticket_type(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    ticket_type_data: web::Json<CreateTicketTypeRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let event = match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                message: "Event not found".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to fetch event: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Failed to fetch event".to_string(),
            });
        }
    };

    if event.organizer_id != user.id {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "You don't have permission to create ticket types for this event".to_string(),
        });
    }

    let updated_event = match event.update_status_if_needed(&pool).await {
        Ok(event) => event,
        Err(e) => {
            error!("Failed to update event status: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Failed to validate event status".to_string(),
            });
        }
    };

    let effective_status = updated_event.get_effective_status();
    match effective_status.as_str() {
        "ended" => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                message: format!(
                    "Cannot create a new ticket for an event that has already ended. This event ended on {}",
                    updated_event.end_time.format("%B %d, %Y at %H:%M UTC")
                ),
            });
        }
        "cancelled" => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                message: "Cannot create a new ticket for a cancelled event".to_string(),
            });
        }
        "ongoing" => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                message: format!(
                    "Cannot create a new ticket for an event that is currently ongoing. (This event started at {})",
                    updated_event.start_time.format("%B %d, %Y at %H:%M UTC")
                ),
            });
        }
        "scheduled" | "active" => {}
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                message: "Event is not in a valid state for creating ticket types".to_string(),
            });
        }
    }

    // don't allow ticket creation too close to event start
    let now = Utc::now();
    let time_until_event = updated_event.start_time - now;
    if time_until_event < chrono::Duration::hours(1) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "Cannot create a new ticket less than 1 hour before the event starts"
                .to_string(),
        });
    }

    match TicketType::create(&pool, *event_id, ticket_type_data.into_inner()).await {
        Ok(ticket_type) => {
            info!(
                "Ticket type created: {} for event {} by user {}",
                ticket_type.id, event_id, user.id
            );
            HttpResponse::Created().json(ticket_type)
        }
        Err(e) => {
            error!("Failed to create ticket type: {}", e);

            let error_message = if e.to_string().contains("Price is required") {
                "Price is required for paid tickets"
            } else if e.to_string().contains("Currency is required") {
                "Currency is required for paid tickets"
            } else {
                "Failed to create ticket type. Please check your input and try again."
            };

            HttpResponse::BadRequest().json(ErrorResponse {
                message: error_message.to_string(),
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
                message: "Failed to fetch ticket types. Please try again.".to_string(),
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
                message: "Ticket type not found".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to fetch ticket type: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Failed to fetch ticket type. Please try again.".to_string(),
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
                message: "Failed to update ticket type status. Please try again.".to_string(),
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
            match ticket_service
                .claim_free_ticket(*ticket_type_id, user.id)
                .await
            {
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
                        message: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
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
            match ticket_service
                .purchase_ticket(*ticket_type_id, user.id)
                .await
            {
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
                        message: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
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
                    message: error_message.to_string(),
                })
            }
        },
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
            })
        }
    }
}

pub async fn check_in_ticket(
    pool: web::Data<PgPool>,
    data: web::Json<CheckInRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
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
                    message: error_message.to_string(),
                })
            }
        },
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
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
                    message: "You don't have permission to access this ticket".to_string(),
                });
            }

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
                            message: "Failed to generate PDF ticket. Please try again.".to_string(),
                        })
                    }
                },
                Err(e) => {
                    error!("Failed to initialize ticket service: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        message: "Internal server error".to_string(),
                    })
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            message: "Ticket not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch ticket: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Failed to verify ticket ownership. Please try again.".to_string(),
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
                        message: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
            })
        }
    }
}

pub async fn get_user_tickets(pool: web::Data<PgPool>, user: AuthenticatedUser) -> impl Responder {
    match create_ticket(&pool).await {
        Ok(ticket) => match ticket.get_user_tickets(user.id).await {
            Ok(tickets) => HttpResponse::Ok().json(tickets),
            Err(e) => {
                error!("Failed to fetch user tickets: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    message: "Failed to fetch your tickets. Please try again.".to_string(),
                })
            }
        },
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
            })
        }
    }
}

// ADMIN ENDPOINTS
pub async fn admin_get_all_tickets(
    pool: web::Data<PgPool>,
    query: web::Query<AdminTicketFilters>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let mut filters = query.into_inner();
    filters.validate();

    match get_filtered_tickets(&pool, &filters).await {
        Ok(response) => {
            info!(
                "Admin {} accessed filtered tickets (total: {}, page: {})",
                user.id, response.total_count, response.page_info.current_page
            );
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            error!("Failed to fetch filtered tickets for admin: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Failed to fetch tickets".to_string(),
            })
        }
    }
}

async fn get_filtered_tickets(
    pool: &PgPool,
    filters: &AdminTicketFilters,
) -> Result<PaginatedTicketsResponse, sqlx::Error> {
    let limit = filters.limit.unwrap();
    let offset = filters.offset.unwrap();

    let base_query = r#"
        SELECT 
            t.id as ticket_id,
            t.status as ticket_status,
            t.created_at as ticket_created_at,
            t.updated_at as ticket_updated_at,
            
            e.id as event_id,
            e.title as event_title,
            e.start_time as event_start_time,
            e.status as event_status,
            
            tt.name as ticket_type_name,
            tt.is_free,
            tt.price,
            tt.currency,
            
            u.id as owner_id,
            u.email as owner_email,
            u.username as owner_username,
            
            tr.id as transaction_id,
            tr.status as transaction_status,
            tr.amount as amount_paid
            
        FROM tickets t
        JOIN ticket_types tt ON t.ticket_type_id = tt.id
        JOIN events e ON tt.event_id = e.id
        JOIN users u ON t.owner_id = u.id
        LEFT JOIN transactions tr ON t.id = tr.ticket_id
    "#;

    let search_pattern = filters
        .search
        .as_ref()
        .map(|search| format!("%{}%", search));

    let mut where_conditions = Vec::new();
    let mut param_count = 1;

    if filters.status.is_some() {
        where_conditions.push(format!("t.status = ${}", param_count));
        param_count += 1;
    }

    if filters.event_id.is_some() {
        where_conditions.push(format!("e.id = ${}", param_count));
        param_count += 1;
    }

    if filters.user_id.is_some() {
        where_conditions.push(format!("u.id = ${}", param_count));
        param_count += 1;
    }

    if filters.is_free.is_some() {
        where_conditions.push(format!("tt.is_free = ${}", param_count));
        param_count += 1;
    }

    if filters.search.is_some() {
        where_conditions.push(format!(
            "(e.title ILIKE ${} OR u.email ILIKE ${} OR tt.name ILIKE ${})",
            param_count, param_count, param_count
        ));
        param_count += 1;
    }

    if filters.purchased_after.is_some() {
        where_conditions.push(format!("t.created_at >= ${}", param_count));
        param_count += 1;
    }

    if filters.purchased_before.is_some() {
        where_conditions.push(format!("t.created_at <= ${}", param_count));
        param_count += 1;
    }

    if filters.transaction_status.is_some() {
        where_conditions.push(format!("tr.status = ${}", param_count));
        param_count += 1;
    }

    let where_clause = if where_conditions.is_empty() {
        "".to_string()
    } else {
        format!("WHERE {}", where_conditions.join(" AND "))
    };

    let sort_column = match filters.sort_by.as_ref().unwrap().as_str() {
        "event_start" => "e.start_time",
        "amount" => "tr.amount",
        "updated_at" => "t.updated_at",
        "owner_email" => "u.email",
        "ticket_type" => "tt.name",
        "status" => "t.status",
        _ => "t.created_at",
    };

    let sort_order = filters.sort_order.as_ref().unwrap();

    let final_query = format!(
        "{} {} ORDER BY {} {} LIMIT ${} OFFSET ${}",
        base_query,
        where_clause,
        sort_column,
        sort_order,
        param_count,
        param_count + 1
    );

    let count_query = format!(
        "SELECT COUNT(*) as total FROM tickets t 
         JOIN ticket_types tt ON t.ticket_type_id = tt.id
         JOIN events e ON tt.event_id = e.id
         JOIN users u ON t.owner_id = u.id
         LEFT JOIN transactions tr ON t.id = tr.ticket_id {}",
        where_clause
    );

    let mut main_query = sqlx::query(&final_query);
    let mut count_query_builder = sqlx::query_scalar::<_, i64>(&count_query);

    if let Some(status) = &filters.status {
        main_query = main_query.bind(status);
        count_query_builder = count_query_builder.bind(status);
    }

    if let Some(event_id) = &filters.event_id {
        main_query = main_query.bind(event_id);
        count_query_builder = count_query_builder.bind(event_id);
    }

    if let Some(user_id) = &filters.user_id {
        main_query = main_query.bind(user_id);
        count_query_builder = count_query_builder.bind(user_id);
    }

    if let Some(is_free) = &filters.is_free {
        main_query = main_query.bind(is_free);
        count_query_builder = count_query_builder.bind(is_free);
    }

    if let Some(_) = &filters.search {
        if let Some(pattern) = &search_pattern {
            main_query = main_query.bind(pattern);
            count_query_builder = count_query_builder.bind(pattern);
        }
    }

    if let Some(purchased_after) = &filters.purchased_after {
        main_query = main_query.bind(purchased_after);
        count_query_builder = count_query_builder.bind(purchased_after);
    }

    if let Some(purchased_before) = &filters.purchased_before {
        main_query = main_query.bind(purchased_before);
        count_query_builder = count_query_builder.bind(purchased_before);
    }

    if let Some(transaction_status) = &filters.transaction_status {
        main_query = main_query.bind(transaction_status);
        count_query_builder = count_query_builder.bind(transaction_status);
    }

    main_query = main_query.bind(limit).bind(offset);

    let total_count = count_query_builder.fetch_one(pool).await?;
    let rows = main_query.fetch_all(pool).await?;

    let mut tickets = Vec::new();
    for row in rows {
        tickets.push(AdminTicketView {
            ticket_id: row.get("ticket_id"),
            ticket_status: row.get("ticket_status"),
            created_at: row.get("ticket_created_at"),
            updated_at: row.get("ticket_updated_at"),

            event_id: row.get("event_id"),
            event_title: row.get("event_title"),
            event_start_time: row.get("event_start_time"),
            event_status: row.get("event_status"),

            ticket_type_name: row.get("ticket_type_name"),
            is_free: row.get("is_free"),
            price: row
                .get::<Option<BigDecimal>, _>("price")
                .map(|p| p.to_string()),
            currency: row.get("currency"),

            owner_id: row.get("owner_id"),
            owner_email: row.get("owner_email"),
            owner_username: row.get("owner_username"),

            transaction_id: row.get("transaction_id"),
            transaction_status: row.get("transaction_status"),
            amount_paid: row
                .get::<Option<BigDecimal>, _>("amount_paid")
                .map(|a| a.to_string()),
        });
    }

    let total_pages = (total_count + limit - 1) / limit;
    let current_page = (offset / limit) + 1;

    let page_info = PageInfo {
        limit,
        offset,
        total_pages,
        current_page,
        has_next: current_page < total_pages,
        has_previous: current_page > 1,
    };

    Ok(PaginatedTicketsResponse {
        tickets,
        total_count,
        page_info,
    })
}

pub async fn admin_cancel_any_ticket(
    pool: web::Data<PgPool>,
    ticket_id: web::Path<Uuid>,
    cancel_data: web::Json<AdminCancelTicketRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };

    match TicketService::new(pool.get_ref().clone()).await {
        Ok(ticket_service) => {
            match ticket_service
                .admin_cancel_ticket(*ticket_id, user.id, cancel_data.reason.clone())
                .await
            {
                Ok(cancelled_ticket) => {
                    info!(
                        "Admin {} successfully cancelled ticket {} - Reason: {}",
                        user.id, ticket_id, cancel_data.reason
                    );
                    HttpResponse::Ok().json(serde_json::json!({
                        "success": true,
                        "message": "Ticket cancelled successfully (no refund processed)",
                        "ticket": cancelled_ticket,
                        "action": "admin_cancelled",
                        "reason": cancel_data.reason
                    }))
                }
                Err(e) => {
                    error!("Admin ticket cancellation failed: {}", e);

                    let error_message = if e.to_string().contains("not found") {
                        "Ticket not found"
                    } else if e.to_string().contains("cannot be cancelled") {
                        "This ticket cannot be cancelled - it may already be cancelled or used"
                    } else {
                        "Failed to cancel ticket"
                    };

                    HttpResponse::BadRequest().json(ErrorResponse {
                        message: error_message.to_string(),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Internal server error".to_string(),
            })
        }
    }
}

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
            .route("/{ticket_id}/transfer", web::post().to(transfer_ticket)),
    )
    .service(
        web::scope("/ticket-types")
            .route(
                "/{ticket_type_id}/purchase",
                web::post().to(purchase_ticket),
            )
            .route("/{ticket_type_id}/claim", web::post().to(claim_free_ticket))
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
            .route("", web::get().to(admin_get_all_tickets))
            .route(
                "/{ticket_id}/cancel",
                web::post().to(admin_cancel_any_ticket),
            ),
    );
}
