use crate::models::event::Event;
use crate::models::user::User;
use crate::services::auth::AuthService;
use actix_web::{
    dev::Payload, error::ErrorUnauthorized, http, web, Error, FromRequest, HttpRequest,
    HttpResponse, Result as ActixResult,
};
use futures::future::{ready, Ready};
use log::{error, warn, info, debug};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub id: Uuid,
}

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        info!("🔑 Auth middleware called for: {}", req.path());
        
        let auth_header = match req.headers().get(http::header::AUTHORIZATION) {
            Some(header) => {
                info!("✅ Authorization header found");
                header
            },
            None => {
                warn!("❌ Request without authorization header");
                return ready(Err(ErrorUnauthorized("Authorization header required")));
            }
        };

        let auth_str = match auth_header.to_str() {
            Ok(str) => {
                info!("✅ Authorization header parsed successfully");
                str
            },
            Err(_) => {
                warn!("❌ Invalid authorization header format");
                return ready(Err(ErrorUnauthorized("Invalid authorization header format")));
            }
        };

        if !auth_str.starts_with("Bearer ") {
            warn!("❌ Authorization header without Bearer scheme");
            return ready(Err(ErrorUnauthorized("Bearer token required")));
        }

        let token = &auth_str[7..];
        info!("🎫 Token extracted, length: {}", token.len());

        if token.trim().is_empty() {
            warn!("❌ Empty token provided");
            return ready(Err(ErrorUnauthorized("Token cannot be empty")));
        }

        let pool = match req.app_data::<web::Data<sqlx::PgPool>>() {
            Some(pool) => {
                info!("🗄️ Database pool found");
                pool
            },
            None => {
                error!("❌ Database pool not found in app data");
                return ready(Err(ErrorUnauthorized("Internal server error")));
            }
        };

        let auth = match AuthService::new(pool.get_ref().clone()) {
            Ok(service) => {
                info!("🔧 Auth service created successfully");
                service
            },
            Err(e) => {
                error!("❌ Failed to create auth service: {}", e);
                return ready(Err(ErrorUnauthorized("Internal server error")));
            }
        };

        match auth.verify_token(token) {
            Ok(user_id) => {
                info!("🎉 Token verified successfully for user: {}", user_id);
                ready(Ok(AuthenticatedUser { id: user_id }))
            },
            Err(e) => {
                warn!("❌ Token verification failed: {}", e);
                ready(Err(ErrorUnauthorized("Invalid or expired token")))
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub stellar_public_key: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserDisplayInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditUserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub ip_address: Option<String>,
}

// for profile endpoints, to get full user details
pub async fn get_user_profile(pool: &PgPool, user_id: Uuid) -> Result<UserProfile, HttpResponse> {
    let user = match User::find_by_id(pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("User not found: {}", user_id);
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User profile not found"
            })));
        }
        Err(e) => {
            error!("Database error fetching user profile: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user profile"
            })));
        }
    };

    if user.status == "deleted" {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Account has been deleted"
        })));
    }

    Ok(UserProfile {
        id: user.id,
        username: user.username,
        email: user.email,
        email_verified: user.email_verified,
        stellar_public_key: user.stellar_public_key,
        created_at: user.created_at,
        status: user.status,
    })
}

// check if user has admin role
pub async fn require_admin_user(pool: &PgPool, user_id: Uuid) -> Result<User, HttpResponse> {
    let user = match User::find_by_id(pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("User not found for admin check: {}", user_id);
            return Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            })));
        }
        Err(e) => {
            error!("Database error during admin check: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    if user.status == "deleted" {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Account has been deleted"
        })));
    }

    if user.role != "admin" {
        warn!("Non-admin user {} attempted admin access", user_id);
        return Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    Ok(user)
}

pub async fn require_verified_user(pool: &PgPool, user_id: Uuid) -> Result<User, HttpResponse> {
    let user = match User::find_by_id(pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("User not found for verification check: {}", user_id);
            return Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            })));
        }
        Err(e) => {
            error!("Database error during verification check: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    if user.status == "deleted" {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Account has been deleted"
        })));
    }

    if !user.email_verified {
        warn!("Unverified user {} attempted verified-only action", user_id);
        return Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Email verification required. Please verify your email to access this feature."
        })));
    }

    Ok(user)
}

// verify user owns an event
pub async fn check_event_ownership(
    pool: &PgPool,
    user_id: Uuid,
    event_id: Uuid,
) -> Result<Event, HttpResponse> {
    let user = match User::find_by_id(pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            })));
        }
        Err(e) => {
            error!("Database error fetching user for ownership check: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    if user.status == "deleted" {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Account has been deleted"
        })));
    }

    let event = match Event::find_by_id(pool, event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => {
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Event not found"
            })));
        }
        Err(e) => {
            error!("Database error fetching event for ownership check: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    if event.organizer_id != user_id {
        warn!(
            "User {} attempted to access event {} they don't own",
            user_id, event_id
        );
        return Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You don't have permission to access this event"
        })));
    }

    Ok(event)
}

// fetch basic user info for UI
pub async fn get_user_display_info(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserDisplayInfo, HttpResponse> {
    let user = match User::find_by_id(pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            error!("Database error fetching user display info: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user information"
            })));
        }
    };

    if user.status == "deleted" {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Account has been deleted"
        })));
    }

    Ok(UserDisplayInfo {
        id: user.id,
        username: user.username,
        email: user.email,
    })
}

// get user info for logging purposes
pub async fn get_user_for_audit(
    pool: &PgPool,
    user_id: Uuid,
    ip_address: Option<String>,
) -> Result<AuditUserInfo, ()> {
    // this doesn't return HTTP errors since it's for logging
    // if it fails, we just log the error and return a placeholder
    let user = match User::find_by_id(pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!("User not found for audit logging: {}", user_id);
            return Err(());
        }
        Err(e) => {
            error!("Database error during audit logging: {}", e);
            return Err(());
        }
    };

    Ok(AuditUserInfo {
        id: user.id,
        username: user.username,
        email: user.email,
        ip_address,
    })
}