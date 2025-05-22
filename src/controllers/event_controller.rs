use actix_web::{web, HttpResponse, Responder};
use crate::models::event::{CreateEventRequest, UpdateEventRequest, SearchEventsRequest, Event};
use crate::middleware::auth::AuthenticatedUser;
use sqlx::PgPool;
use uuid::Uuid;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct PaginationParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

// EVENT CREATION AND MANAGEMENT

pub async fn create_event(
    pool: web::Data<PgPool>,
    event_data: web::Json<CreateEventRequest>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    let _verified_user = match crate::middleware::auth::require_verified_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    
    match Event::create(&pool, user.id, event_data.into_inner()).await {
        Ok(event) => {
            info!("Event created: {} by verified user {}", event.id, user.id);
            HttpResponse::Created().json(event)
        },
        Err(e) => {
            error!("Failed to create event: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to create event. Please try again.".to_string(),
            })
        },
    }
}

pub async fn update_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    event_data: web::Json<UpdateEventRequest>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    let _event = match crate::middleware::auth::check_event_ownership(&pool, user.id, *event_id).await {
        Ok(event) => event,
        Err(response) => return response,
    };
    
    match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => {
            match event.update(&pool, event_data.into_inner()).await {
                Ok(updated_event) => {
                    info!("Event updated: {} by user {}", event.id, user.id);
                    HttpResponse::Ok().json(updated_event)
                },
                Err(e) => {
                    error!("Failed to update event: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to update event. Please try again.".to_string(),
                    })
                },
            }
        },
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Event not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch event for update: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event. Please try again.".to_string(),
            })
        },
    }
}

pub async fn cancel_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    let event = match crate::middleware::auth::check_event_ownership(&pool, user.id, *event_id).await {
        Ok(event) => event,
        Err(response) => return response,
    };
    
    match event.cancel(&pool).await {
        Ok(_) => {
            info!("Event cancelled: {} by user {}", event.id, user.id);
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Event has been cancelled successfully"
            }))
        },
        Err(e) => {
            error!("Failed to cancel event: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to cancel event. Please try again.".to_string(),
            })
        },
    }
}

// PUBLIC ENDPOINTS

pub async fn get_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
) -> impl Responder {
    match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => HttpResponse::Ok().json(event),
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Event not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch event: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event. Please try again.".to_string(),
            })
        },
    }
}

pub async fn search_events(
    pool: web::Data<PgPool>,
    query: web::Query<SearchEventsRequest>,
) -> impl Responder {
    match Event::search(&pool, query.into_inner()).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(e) => {
            error!("Failed to search events: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to search events. Please try again.".to_string(),
            })
        },
    }
}

pub async fn get_all_events(
    pool: web::Data<PgPool>,
    query: web::Query<PaginationParams>,
) -> impl Responder {
    let search_request = SearchEventsRequest {
        query: None,
        category: None,
        location: None,
        start_date: None,
        end_date: None,
        tags: None,
        limit: query.limit,
        offset: query.offset,
    };
    
    match Event::search(&pool, search_request).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(e) => {
            error!("Failed to fetch all events: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch events. Please try again.".to_string(),
            })
        },
    }
}

// ORGANIZER-SPECIFIC ENDPOINTS

pub async fn get_events_by_organizer(
    pool: web::Data<PgPool>,
    user: web::ReqData<AuthenticatedUser>,
    _query: web::Query<PaginationParams>, // not used yet, but ready for pagination
) -> impl Responder {
    match Event::find_by_organizer(&pool, user.id).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(e) => {
            error!("Failed to fetch organizer events for user {}: {}", user.id, e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch events. Please try again.".to_string(),
            })
        },
    }
}

pub async fn get_event_analytics(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    let _event = match crate::middleware::auth::check_event_ownership(&pool, user.id, *event_id).await {
        Ok(event) => event,
        Err(response) => return response,
    };
    
    let analytics = match get_event_stats(&pool, *event_id).await {
        Ok(stats) => stats,
        Err(e) => {
            error!("Failed to fetch event analytics: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event analytics. Please try again.".to_string(),
            });
        }
    };
    
    info!("Event analytics accessed: {} by organizer {}", event_id, user.id);
    HttpResponse::Ok().json(analytics)
}

async fn get_event_stats(pool: &PgPool, event_id: Uuid) -> Result<serde_json::Value, sqlx::Error> {
    let stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(DISTINCT t.id) as total_tickets_sold,
            COUNT(DISTINCT CASE WHEN t.status = 'valid' THEN t.id END) as valid_tickets,
            COUNT(DISTINCT CASE WHEN t.status = 'used' THEN t.id END) as used_tickets,
            COUNT(DISTINCT CASE WHEN t.status = 'cancelled' THEN t.id END) as cancelled_tickets,
            COALESCE(SUM(CASE WHEN tr.status = 'completed' THEN tr.amount ELSE 0 END), 0) as total_revenue,
            COUNT(DISTINCT tt.id) as ticket_types_count
        FROM ticket_types tt
        LEFT JOIN tickets t ON tt.id = t.ticket_type_id
        LEFT JOIN transactions tr ON t.id = tr.ticket_id
        WHERE tt.event_id = $1
        "#,
        event_id
    )
    .fetch_one(pool)
    .await?;

    Ok(serde_json::json!({
        "event_id": event_id,
        "total_tickets_sold": stats.total_tickets_sold.unwrap_or(0),
        "valid_tickets": stats.valid_tickets.unwrap_or(0),
        "used_tickets": stats.used_tickets.unwrap_or(0),
        "cancelled_tickets": stats.cancelled_tickets.unwrap_or(0),
        "total_revenue": stats.total_revenue,
        "ticket_types_count": stats.ticket_types_count.unwrap_or(0)
    }))
}

// ADMIN ENDPOINTS

pub async fn admin_get_all_events(
    pool: web::Data<PgPool>,
    user: web::ReqData<AuthenticatedUser>,
    query: web::Query<PaginationParams>,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    
    match sqlx::query_as!(
        Event,
        "SELECT * FROM events ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        limit, offset
    )
    .fetch_all(&**pool)
    .await {
        Ok(events) => {
            info!("Admin {} accessed all events", user.id);
            HttpResponse::Ok().json(events)
        },
        Err(e) => {
            error!("Failed to fetch all events for admin: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch events".to_string(),
            })
        }
    }
}

pub async fn admin_cancel_any_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    
    let event = match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Event not found".to_string(),
            });
        },
        Err(e) => {
            error!("Failed to fetch event for admin cancellation: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event".to_string(),
            });
        }
    };
    
    match event.cancel(&pool).await {
        Ok(_) => {
            warn!("Admin {} cancelled event {} (organizer: {})", user.id, event_id, event.organizer_id);
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Event has been cancelled by admin"
            }))
        },
        Err(e) => {
            error!("Failed to cancel event as admin: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to cancel event".to_string(),
            })
        },
    }
}

pub async fn admin_get_event_details(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    
    let event = match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Event not found".to_string(),
            });
        },
        Err(e) => {
            error!("Failed to fetch event for admin: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event".to_string(),
            });
        }
    };
    
    let organizer = match crate::middleware::auth::get_user_display_info(&pool, event.organizer_id).await {
        Ok(user_info) => user_info,
        Err(_) => {
            info!("Admin {} accessed event {} (organizer info unavailable)", user.id, event_id);
            return HttpResponse::Ok().json(event);
        }
    };
    
    // Get event analytics
    let analytics = match get_event_stats(&pool, *event_id).await {
        Ok(stats) => stats,
        Err(e) => {
            error!("Failed to fetch event analytics for admin: {}", e);
            serde_json::json!({ "error": "Analytics unavailable" })
        }
    };
    
    info!("Admin {} accessed detailed event info for {}", user.id, event_id);
    
    HttpResponse::Ok().json(serde_json::json!({
        "event": event,
        "organizer": organizer,
        "analytics": analytics
    }))
}

// ROUTE CONFIGURATION

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/events")
            // Public routes
            .route("", web::get().to(get_all_events))
            .route("/{event_id}", web::get().to(get_event))
            .route("/search", web::get().to(search_events))
            
            // Authenticated routes (organizers)
            .route("", web::post().to(create_event))
            .route("/{event_id}", web::put().to(update_event))
            .route("/{event_id}/cancel", web::post().to(cancel_event))
            .route("/organizer", web::get().to(get_events_by_organizer))
            .route("/{event_id}/analytics", web::get().to(get_event_analytics))
    )
    .service(
        web::scope("/admin/events")
            // Admin-only event operations
            .route("", web::get().to(admin_get_all_events))
            .route("/{event_id}", web::get().to(admin_get_event_details))
            .route("/{event_id}/cancel", web::post().to(admin_cancel_any_event))
    );
}