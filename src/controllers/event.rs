use crate::controllers::admin_filters::{
    AdminEventFilters, AdminEventView, PageInfo, PaginatedEventsResponse,
};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::event::{CreateEventRequest, Event, SearchEventsRequest, UpdateEventRequest};
use crate::models::event_organizer::{
    AddOrganizerRequest, EventOrganizer, UpdateOrganizerPermissionsRequest,
};
use crate::models::User;
use crate::services::StellarService;
use actix_web::{web, HttpResponse, Responder};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

// EVENT CREATION AND MANAGEMENT

// pub async fn create_event(
//     pool: web::Data<PgPool>,
//     event_data: web::Json<CreateEventRequest>,
//     user: AuthenticatedUser,
// ) -> impl Responder {
//     let _verified_user = match crate::middleware::auth::require_verified_user(&pool, user.id).await {
//         Ok(user) => user,
//         Err(response) => return response,
//     };

//     match Event::create(&pool, user.id, event_data.into_inner()).await {
//         Ok(event) => {
//             info!("Event created: {} by verified user {}", event.id, user.id);
//             HttpResponse::Created().json(event)
//         },
//         Err(e) => {
//             error!("Failed to create event: {}", e);
//             HttpResponse::InternalServerError().json(ErrorResponse {
//                 error: "Failed to create event. Please try again.".to_string(),
//             })
//         },
//     }
// }

// debug
pub async fn create_event(
    pool: web::Data<PgPool>,
    event_data: web::Json<CreateEventRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    info!("🎪 Event creation attempt by user: {}", user.id);
    info!("📝 Event data: {:?}", event_data);

    // Check if user is verified
    let _verified_user = match crate::middleware::auth::require_verified_user(&pool, user.id).await
    {
        Ok(user) => {
            info!("✅ User {} is verified", user.id);
            user
        }
        Err(response) => {
            warn!("❌ User {} verification failed", user.id);
            return response;
        }
    };

    // Attempt to create event
    match Event::create(&pool, user.id, event_data.into_inner()).await {
        Ok(event) => {
            info!(
                "✅ Event created successfully: {} by verified user {}",
                event.id, user.id
            );
            HttpResponse::Created().json(event)
        }
        Err(e) => {
            error!("❌ Failed to create event for user {}: {}", user.id, e);

            // More specific error messages
            let error_message = if e.to_string().contains("duplicate key") {
                "An event with this information already exists."
            } else if e.to_string().contains("null value") {
                "Missing required event information."
            } else if e.to_string().contains("foreign key") {
                "Invalid user or reference data."
            } else if e.to_string().contains("check constraint") {
                "Invalid event data format."
            } else {
                &format!("Database error: {}", e)
            };

            HttpResponse::InternalServerError().json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

pub async fn update_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    event_data: web::Json<UpdateEventRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _event = match crate::middleware::auth::check_event_permission(
        &pool,
        user.id,
        *event_id,
        "edit_event",
    )
    .await
    {
        Ok(event) => event,
        Err(response) => return response,
    };

    match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => match event.update(&pool, event_data.into_inner()).await {
            Ok(updated_event) => {
                info!("Event updated: {} by organizer {}", event.id, user.id);
                HttpResponse::Ok().json(updated_event)
            }
            Err(e) => {
                error!("Failed to update event: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to update event. Please try again.".to_string(),
                })
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
        }
    }
}

pub async fn cancel_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let event =
        match crate::middleware::auth::check_event_ownership(&pool, user.id, *event_id).await {
            Ok(event) => event,
            Err(response) => return response,
        };

    match event.cancel(&pool).await {
        Ok(_) => {
            info!("Event cancelled: {} by user {}", event.id, user.id);
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Event has been cancelled successfully"
            }))
        }
        Err(e) => {
            error!("Failed to cancel event: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to cancel event. Please try again.".to_string(),
            })
        }
    }
}

// PUBLIC ENDPOINTS
pub async fn get_event(pool: web::Data<PgPool>, event_id: web::Path<Uuid>) -> impl Responder {
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
        }
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
        }
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
        }
    }
}

// ORGANIZER-SPECIFIC ENDPOINTS
pub async fn get_events_by_organizer(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
    _query: web::Query<PaginationParams>,
) -> impl Responder {
    match Event::find_by_organizer(&pool, user.id).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(e) => {
            error!(
                "Failed to fetch organizer events for user {}: {}",
                user.id, e
            );
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch events. Please try again.".to_string(),
            })
        }
    }
}

pub async fn get_event_analytics(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _event =
        match crate::middleware::auth::check_event_ownership(&pool, user.id, *event_id).await {
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

    info!(
        "Event analytics accessed: {} by organizer {}",
        event_id, user.id
    );
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

// EVENT ORGANIZERS

pub async fn get_event_organizers(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    match EventOrganizer::is_organizer(&pool, *event_id, user.id).await {
        Ok(false) => {
            return HttpResponse::Forbidden().json(ErrorResponse {
                error: "Only event organizers can view organizer list".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to check organizer status: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify permissions".to_string(),
            });
        }
        Ok(true) => {}
    }

    match EventOrganizer::get_event_organizers_with_info(&pool, *event_id).await {
        Ok(organizers) => {
            info!(
                "User {} accessed organizers list for event {}. Found {} organizers",
                user.id,
                event_id,
                organizers.len()
            );
            HttpResponse::Ok().json(serde_json::json!({
                "organizers": organizers,
                "total_count": organizers.len()
            }))
        }
        Err(e) => {
            error!("Failed to fetch event organizers: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch organizers".to_string(),
            })
        }
    }
}

pub async fn add_event_organizer(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    organizer_data: web::Json<AddOrganizerRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    match EventOrganizer::is_organizer(&pool, *event_id, user.id).await {
        Ok(false) => {
            return HttpResponse::Forbidden().json(ErrorResponse {
                error: "Only existing organizers can add new organizers".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to check organizer status: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify permissions".to_string(),
            });
        }
        Ok(true) => {}
    }

    let new_user_id =
        match EventOrganizer::find_user_by_identifier(&pool, &organizer_data.identifier).await {
            Ok(Some(user_id)) => user_id,
            Ok(None) => {
                return HttpResponse::NotFound().json(ErrorResponse {
                    error: format!("User not found: {}", organizer_data.identifier),
                });
            }
            Err(e) => {
                error!("Failed to find user: {}", e);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to search for user".to_string(),
                });
            }
        };

    match EventOrganizer::add_organizer(&pool, *event_id, new_user_id, user.id).await {
        Ok(organizer) => {
            info!(
                "User {} added {} as organizer for event {}",
                user.id, new_user_id, event_id
            );
            HttpResponse::Created().json(serde_json::json!({
                "success": true,
                "message": "Organizer added successfully",
                "organizer": organizer
            }))
        }
        Err(e) => {
            error!("Failed to add organizer: {}", e);

            let error_message = if e.to_string().contains("already an organizer") {
                "This user is already an organizer for this event"
            } else if e.to_string().contains("Maximum 4 organizers") {
                "Cannot add more organizers. Maximum of 4 organizers allowed per event"
            } else {
                "Failed to add organizer"
            };

            HttpResponse::BadRequest().json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

pub async fn remove_event_organizer(
    pool: web::Data<PgPool>,
    path: web::Path<(Uuid, Uuid)>, // (event_id, user_id)
    user: AuthenticatedUser,
) -> impl Responder {
    let (event_id, organizer_user_id) = path.into_inner();

    match EventOrganizer::is_owner(&pool, event_id, user.id).await {
        Ok(false) => {
            return HttpResponse::Forbidden().json(ErrorResponse {
                error: "Only the event owner can remove organizers".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to check owner status: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify permissions".to_string(),
            });
        }
        Ok(true) => {}
    }

    match EventOrganizer::remove_organizer(&pool, event_id, organizer_user_id, user.id).await {
        Ok(()) => {
            info!(
                "Owner {} removed organizer {} from event {}",
                user.id, organizer_user_id, event_id
            );
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Organizer removed successfully"
            }))
        }
        Err(e) => {
            error!("Failed to remove organizer: {}", e);

            let error_message = if e.to_string().contains("Cannot remove the event owner") {
                "Cannot remove the event owner"
            } else if e.to_string().contains("not an organizer") {
                "User is not an organizer for this event"
            } else {
                "Failed to remove organizer"
            };

            HttpResponse::BadRequest().json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

pub async fn update_organizer_permissions(
    pool: web::Data<PgPool>,
    path: web::Path<(Uuid, Uuid)>, // (event_id, user_id)
    permissions_data: web::Json<UpdateOrganizerPermissionsRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    let (event_id, organizer_user_id) = path.into_inner();

    match EventOrganizer::is_owner(&pool, event_id, user.id).await {
        Ok(false) => {
            return HttpResponse::Forbidden().json(ErrorResponse {
                error: "Only the event owner can update organizer permissions".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to check owner status: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify permissions".to_string(),
            });
        }
        Ok(true) => {}
    }

    match EventOrganizer::update_permissions(
        &pool,
        event_id,
        organizer_user_id,
        permissions_data.permissions.clone(),
        user.id,
    )
    .await
    {
        Ok(updated_organizer) => {
            info!(
                "Owner {} updated permissions for organizer {} on event {}",
                user.id, organizer_user_id, event_id
            );
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Organizer permissions updated successfully",
                "organizer": updated_organizer
            }))
        }
        Err(e) => {
            error!("Failed to update organizer permissions: {}", e);

            let error_message = if e.to_string().contains("Cannot update owner permissions") {
                "Cannot update owner permissions"
            } else if e.to_string().contains("not an organizer") {
                "User is not an organizer for this event"
            } else {
                "Failed to update permissions"
            };

            HttpResponse::BadRequest().json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

// ADMIN ENDPOINTS

pub async fn admin_cancel_any_event(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
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
        }
        Err(e) => {
            error!("Failed to fetch event for admin cancellation: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event".to_string(),
            });
        }
    };

    match event.cancel(&pool).await {
        Ok(_) => {
            warn!(
                "Admin {} cancelled event {} (organizer: {})",
                user.id, event_id, event.organizer_id
            );
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Event has been cancelled by admin"
            }))
        }
        Err(e) => {
            error!("Failed to cancel event as admin: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to cancel event".to_string(),
            })
        }
    }
}

pub async fn admin_get_event_details(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
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
        }
        Err(e) => {
            error!("Failed to fetch event for admin: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event".to_string(),
            });
        }
    };

    let organizer =
        match crate::middleware::auth::get_user_display_info(&pool, event.organizer_id).await {
            Ok(user_info) => user_info,
            Err(_) => {
                info!(
                    "Admin {} accessed event {} (organizer info unavailable)",
                    user.id, event_id
                );
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

    info!(
        "Admin {} accessed detailed event info for {}",
        user.id, event_id
    );

    HttpResponse::Ok().json(serde_json::json!({
        "event": event,
        "organizer": organizer,
        "analytics": analytics
    }))
}

pub async fn admin_get_all_events(
    pool: web::Data<PgPool>,
    query: web::Query<AdminEventFilters>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let mut filters = query.into_inner();
    filters.validate();

    match get_filtered_events(&pool, &filters).await {
        Ok(response) => {
            info!(
                "Admin {} accessed filtered events (total: {}, page: {})",
                user.id, response.total_count, response.page_info.current_page
            );
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            error!("Failed to fetch filtered events for admin: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch events".to_string(),
            })
        }
    }
}

async fn get_filtered_events(
    pool: &PgPool,
    filters: &AdminEventFilters,
) -> Result<PaginatedEventsResponse, sqlx::Error> {
    let limit = filters.limit.unwrap();
    let offset = filters.offset.unwrap();

    let base_query = r#"
        SELECT 
            e.id as event_id,
            e.title,
            e.description,
            e.location,
            e.category,
            e.status,
            e.start_time,
            e.end_time,
            e.created_at,
            e.updated_at,
            
            u.id as organizer_id,
            u.email as organizer_email,
            u.username as organizer_username,
            
            COALESCE(stats.total_ticket_types, 0) as total_ticket_types,
            COALESCE(stats.total_tickets_sold, 0) as total_tickets_sold,
            COALESCE(stats.total_revenue, 0) as total_revenue,
            COALESCE(stats.tickets_remaining, 0) as tickets_remaining
            
        FROM events e
        JOIN users u ON e.organizer_id = u.id
        LEFT JOIN (
            SELECT 
                tt.event_id,
                COUNT(DISTINCT tt.id) as total_ticket_types,
                COUNT(DISTINCT t.id) as total_tickets_sold,
                SUM(CASE WHEN tr.status = 'completed' AND tr.amount > 0 THEN tr.amount ELSE 0 END) as total_revenue,
                SUM(COALESCE(tt.remaining, 0)) as tickets_remaining
            FROM ticket_types tt
            LEFT JOIN tickets t ON tt.id = t.ticket_type_id AND t.status = 'valid'
            LEFT JOIN transactions tr ON t.id = tr.ticket_id
            GROUP BY tt.event_id
        ) stats ON e.id = stats.event_id
    "#;

    let location_pattern = filters.location.as_ref().map(|loc| format!("%{}%", loc));
    let search_pattern = filters
        .search
        .as_ref()
        .map(|search| format!("%{}%", search));

    let mut where_conditions = Vec::new();
    let mut param_count = 1;

    if filters.status.is_some() {
        where_conditions.push(format!("e.status = ${}", param_count));
        param_count += 1;
    }

    if filters.category.is_some() {
        where_conditions.push(format!("e.category = ${}", param_count));
        param_count += 1;
    }

    if filters.location.is_some() {
        where_conditions.push(format!("e.location ILIKE ${}", param_count));
        param_count += 1;
    }

    if filters.organizer_id.is_some() {
        where_conditions.push(format!("e.organizer_id = ${}", param_count));
        param_count += 1;
    }

    if filters.search.is_some() {
        where_conditions.push(format!(
            "(e.title ILIKE ${} OR e.description ILIKE ${})",
            param_count, param_count
        ));
        param_count += 1;
    }

    if filters.start_date.is_some() {
        where_conditions.push(format!("e.start_time >= ${}", param_count));
        param_count += 1;
    }

    if filters.end_date.is_some() {
        where_conditions.push(format!("e.end_time <= ${}", param_count));
        param_count += 1;
    }

    let where_clause = if where_conditions.is_empty() {
        "".to_string()
    } else {
        format!("WHERE {}", where_conditions.join(" AND "))
    };

    let sort_column = match filters.sort_by.as_ref().unwrap().as_str() {
        "start_time" => "e.start_time",
        "title" => "e.title",
        "updated_at" => "e.updated_at",
        "status" => "e.status",
        "category" => "e.category",
        _ => "e.created_at",
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
        "SELECT COUNT(*) as total FROM events e 
         JOIN users u ON e.organizer_id = u.id {}",
        where_clause
    );

    let mut main_query = sqlx::query(&final_query);
    let mut count_query_builder = sqlx::query_scalar::<_, i64>(&count_query);

    if let Some(status) = &filters.status {
        main_query = main_query.bind(status);
        count_query_builder = count_query_builder.bind(status);
    }

    if let Some(category) = &filters.category {
        main_query = main_query.bind(category);
        count_query_builder = count_query_builder.bind(category);
    }

    if let Some(_) = &filters.location {
        if let Some(pattern) = &location_pattern {
            main_query = main_query.bind(pattern);
            count_query_builder = count_query_builder.bind(pattern);
        }
    }

    if let Some(organizer_id) = &filters.organizer_id {
        main_query = main_query.bind(organizer_id);
        count_query_builder = count_query_builder.bind(organizer_id);
    }

    if let Some(_) = &filters.search {
        if let Some(pattern) = &search_pattern {
            main_query = main_query.bind(pattern);
            count_query_builder = count_query_builder.bind(pattern);
        }
    }

    if let Some(start_date) = &filters.start_date {
        main_query = main_query.bind(start_date);
        count_query_builder = count_query_builder.bind(start_date);
    }

    if let Some(end_date) = &filters.end_date {
        main_query = main_query.bind(end_date);
        count_query_builder = count_query_builder.bind(end_date);
    }

    main_query = main_query.bind(limit).bind(offset);

    let total_count = count_query_builder.fetch_one(pool).await?;
    let rows = main_query.fetch_all(pool).await?;

    let mut events = Vec::new();
    for row in rows {
        let status: String = row.get("status");
        let start_time: DateTime<Utc> = row.get("start_time");
        let end_time: DateTime<Utc> = row.get("end_time");
        let now = Utc::now();

        let effective_status = match status.as_str() {
            "cancelled" => "cancelled".to_string(),
            "draft" => "draft".to_string(),
            _ => {
                if now >= end_time {
                    "ended".to_string()
                } else if now >= start_time {
                    "ongoing".to_string()
                } else {
                    "scheduled".to_string()
                }
            }
        };

        events.push(AdminEventView {
            event_id: row.get("event_id"),
            title: row.get("title"),
            description: row.get("description"),
            location: row.get("location"),
            category: row.get("category"),
            status: row.get("status"),
            effective_status,
            start_time: row.get("start_time"),
            end_time: row.get("end_time"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),

            organizer_id: row.get("organizer_id"),
            organizer_email: row.get("organizer_email"),
            organizer_username: row.get("organizer_username"),

            total_ticket_types: row.get("total_ticket_types"),
            total_tickets_sold: row.get("total_tickets_sold"),
            total_revenue: row
                .get::<Option<BigDecimal>, _>("total_revenue")
                .map(|r| r.to_string()),
            tickets_remaining: row.get("tickets_remaining"),
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

    Ok(PaginatedEventsResponse {
        events,
        total_count,
        page_info,
    })
}

pub async fn get_event_financial_summary(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let event_service = crate::services::event::EventService::new(pool.get_ref().clone());

    match event_service.get_event_financial_summary(*event_id).await {
        Ok(summary) => {
            info!(
                "Admin {} accessed financial summary for event {}",
                user.id, event_id
            );
            HttpResponse::Ok().json(summary)
        }
        Err(e) => {
            error!("Failed to get event financial summary: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch financial summary".to_string(),
            })
        }
    }
}

pub async fn pay_organizer(
    pool: web::Data<PgPool>,
    event_id: web::Path<Uuid>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // 1. Verify payout eligibility
    let existing_payout = match sqlx::query!(
        "SELECT transaction_hash FROM event_payouts WHERE event_id = $1",
        *event_id
    )
    .fetch_optional(&**pool)
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to check existing payout: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to verify payout status".to_string(),
            });
        }
    };

    if existing_payout.is_some() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Event has already been paid out".to_string(),
        });
    }

    // 2. Calculate total revenue from the event
    let revenue_result = match sqlx::query!(
        r#"
        SELECT 
            COALESCE(SUM(
                CASE 
                    WHEN t.transaction_sponsorship_fee IS NOT NULL 
                    THEN t.amount - t.transaction_sponsorship_fee
                    ELSE t.amount
                END
            ), 0) as revenue
        FROM transactions t
        JOIN tickets tk ON t.ticket_id = tk.id
        JOIN ticket_types tt ON tk.ticket_type_id = tt.id
        WHERE 
            tt.event_id = $1 
            AND t.status = 'completed'
            AND t.currency = 'USDC'
        "#,
        *event_id
    )
    .fetch_one(&**pool)
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to calculate event revenue: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to calculate event revenue".to_string(),
            });
        }
    };

    let total_revenue_usdc = revenue_result
        .revenue
        .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
        .unwrap_or(0.0);

    if total_revenue_usdc <= 0.0 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "No revenue available for payout".to_string(),
        });
    }

    // 3. Get event and organizer info
    let event = match Event::find_by_id(&pool, *event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Event not found".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to fetch event: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch event".to_string(),
            });
        }
    };

    let organizer = match User::find_by_id(&pool, event.organizer_id).await {
        Ok(Some(organizer)) => organizer,
        Ok(None) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Event organizer not found".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to fetch organizer: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch organizer".to_string(),
            });
        }
    };

    let organizer_wallet = match &organizer.stellar_public_key {
        Some(wallet) => wallet.clone(),
        None => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Organizer does not have a Stellar wallet".to_string(),
            });
        }
    };

    // 4. Verify organizer has USDC trustline
    let stellar = match StellarService::new() {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize Stellar service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize payment service".to_string(),
            });
        }
    };

    if !stellar
        .has_usdc_trustline(&organizer_wallet)
        .await
        .unwrap_or(false)
    {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Organizer needs to set up USDC trustline first".to_string(),
        });
    }

    // 5. Get platform configuration
    let platform_secret = match std::env::var("PLATFORM_PAYMENT_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            error!("Platform payment secret not configured");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Payment system not configured".to_string(),
            });
        }
    };

    let platform_fee_percentage = std::env::var("PLATFORM_FEE_PERCENTAGE")
        .unwrap_or_else(|_| "5.0".to_string())
        .parse::<f64>()
        .unwrap_or(5.0);

    // 6. Process payment using your existing method
    let payout_result = match stellar
        .send_organizer_payment(&platform_secret, &organizer_wallet, total_revenue_usdc)
        .await
    {
        Ok(result) => result, // result is OrganizerPaymentResult
        Err(e) => {
            error!("Failed to process organizer payout: {}", e);
            let error_message = if e.to_string().contains("insufficient") {
                "Platform has insufficient balance for payout"
            } else {
                "Failed to process payment"
            };
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: error_message.to_string(),
            });
        }
    };

    // Extract the transaction hash for database storage
    let tx_hash = &payout_result.transaction_hash;

    // 7. Record payout in database
    let organizer_payout = total_revenue_usdc * (1.0 - platform_fee_percentage / 100.0);
    let record_result = sqlx::query!(
        r#"
        INSERT INTO event_payouts (event_id, transaction_hash, amount, paid_at)
        VALUES ($1, $2, $3, NOW())
        "#,
        *event_id,
        tx_hash,
        bigdecimal::BigDecimal::try_from(organizer_payout)
            .map_err(|e| anyhow::anyhow!("Invalid payout amount: {}", e))
            .unwrap()
    )
    .execute(&**pool)
    .await;

    if let Err(e) = record_result {
        error!("Failed to record payout: {}", e);
        // Payment succeeded but recording failed - this is critical
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Payment processed but failed to record. Contact support.".to_string(),
        });
    }

    // 8. Success response
    info!(
        "Admin {} triggered manual payout for event {}: {} USDC → {} USDC to organizer (tx: {})",
        user.id, event_id, total_revenue_usdc, organizer_payout, tx_hash
    );

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Manual payout processed successfully",
        "transaction_hash": tx_hash,
        "event_id": *event_id,
        "total_revenue": format!("{:.2}", total_revenue_usdc),
        "organizer_payout": format!("{:.2}", organizer_payout),
        "platform_fee": format!("{:.2}", total_revenue_usdc * (platform_fee_percentage / 100.0)),
        "currency": "USDC",
        "gas_fee_xlm": payout_result.gas_fee_xlm,
        "usdc_amount_sent": payout_result.usdc_amount_sent
    }))
}

// ROUTE CONFIGURATION
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/events")
            .route("/search", web::get().to(search_events))
            .route("/organizer", web::get().to(get_events_by_organizer))
            .route("", web::get().to(get_all_events))
            .route("", web::post().to(create_event))
            .route("/{event_id}", web::get().to(get_event))
            .route("/{event_id}", web::put().to(update_event))
            .route("/{event_id}/cancel", web::post().to(cancel_event))
            .route("/{event_id}/analytics", web::get().to(get_event_analytics))
            .route(
                "/{event_id}/organizers",
                web::get().to(get_event_organizers),
            )
            .route(
                "/{event_id}/organizers",
                web::post().to(add_event_organizer),
            )
            .route(
                "/{event_id}/organizers/{user_id}",
                web::delete().to(remove_event_organizer),
            )
            .route(
                "/{event_id}/organizers/{user_id}/permissions",
                web::put().to(update_organizer_permissions),
            ),
    )
    .service(
        web::scope("/admin/events")
            .route("", web::get().to(admin_get_all_events))
            .route("/{event_id}", web::get().to(admin_get_event_details))
            .route("/{event_id}/cancel", web::post().to(admin_cancel_any_event))
            .route(
                "/{event_id}/financial-summary",
                web::get().to(get_event_financial_summary),
            )
            .route("/{event_id}/trigger-payout", web::post().to(pay_organizer)),
    );
}
