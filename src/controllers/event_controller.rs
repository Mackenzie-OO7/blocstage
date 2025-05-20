use actix_web::{web, HttpResponse, Responder};
use crate::models::event::{CreateEventRequest, UpdateEventRequest, SearchEventsRequest, Event};
use crate::middleware::auth::AuthenticatedUser;
use sqlx::PgPool;
use uuid::Uuid;
use log::{error, info};
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

pub async fn create_event(
    pool: web::Data<PgPool>,
    event_data: web::Json<CreateEventRequest>,
    user: web::ReqData<AuthenticatedUser>,
) -> impl Responder {
    match Event::create(&pool, user.id, event_data.into_inner()).await {
        Ok(event) => {
            info!("Event created: {} by user {}", event.id, user.id);
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
    match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => {
            if event.organizer_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to update this event".to_string(),
                });
            }
            
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
    match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => {
            if event.organizer_id != user.id {
                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "You don't have permission to cancel this event".to_string(),
                });
            }
            
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
        },
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Event not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch event for cancellation: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event. Please try again.".to_string(),
            })
        },
    }
}

pub async fn get_events_by_organizer(
    pool: web::Data<PgPool>,
    user: web::ReqData<AuthenticatedUser>,
    query: web::Query<PaginationParams>,
) -> impl Responder {
    match Event::find_by_organizer(&pool, user.id).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(e) => {
            error!("Failed to fetch organizer events: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch events. Please try again.".to_string(),
            })
        },
    }
}

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

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/events")
            // Public routes
            .route("", web::get().to(get_all_events))
            .route("/{event_id}", web::get().to(get_event))
            .route("/search", web::get().to(search_events))
            
            // Authenticated routes
            .route("", web::post().to(create_event))
            .route("/{event_id}", web::put().to(update_event))
            .route("/{event_id}/cancel", web::post().to(cancel_event))
            .route("/organizer", web::get().to(get_events_by_organizer))
    );
}