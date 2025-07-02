use actix_web::{web, HttpResponse, Responder, ResponseError};
use sqlx::PgPool;
use crate::models::user::{CreateUserRequest, LoginRequest, VerifyEmailRequest, RequestPasswordResetRequest, ResetPasswordRequest};
use crate::services::auth::AuthService;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use crate::middleware::auth::AuthenticatedUser;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

pub async fn register(
    pool: web::Data<sqlx::PgPool>,
    user_data: web::Json<CreateUserRequest>,
) -> impl Responder {
    let auth = match AuthService::new(pool.get_ref().clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize auth service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };
    
    match auth.register(user_data.into_inner()).await {
        Ok(user) => {
            info!("User registered successfully: {}", user.id);
            HttpResponse::Created().json(user)
        },
        Err(e) => {
            // for now, log the actual error but don't expose it directly
            error!("Registration failed: {}", e);
            
            if e.to_string().contains("Email already registered") {
                HttpResponse::BadRequest().json(ErrorResponse {
                    error: "Email already registered".to_string(),
                })
            } else {
                HttpResponse::BadRequest().json(ErrorResponse {
                    error: "Registration failed. Please check your information and try again.".to_string(),
                })
            }
        },
    }
}

pub async fn login(
    pool: web::Data<sqlx::PgPool>,
    login_data: web::Json<LoginRequest>,
) -> impl Responder {
    let auth = match AuthService::new(pool.get_ref().clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize auth service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };
    
    match auth.login(login_data.into_inner()).await {
        Ok(token) => {
            HttpResponse::Ok().json(serde_json::json!({
                "token": token,
                "message": "Login successful"
            }))
        },
        Err(e) => {
            // for now, log the error but return a generic message for security
            error!("Login failed: {}", e);
            
            let error_message = if e.to_string().contains("Email not verified") {
                "Email not verified. Please check your inbox and verify your email first."
            } else if e.to_string().contains("Account has been deleted") {
                "This account has been deleted."
            } else {
                "Invalid email or password."
            };
            
            HttpResponse::Unauthorized().json(ErrorResponse {
                error: error_message.to_string(),
            })
        },
    }
}

pub async fn verify_email(
    pool: web::Data<sqlx::PgPool>,
    data: web::Query<VerifyEmailRequest>,
) -> impl Responder {
    let auth = match AuthService::new(pool.get_ref().clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize auth service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };
    
    match auth.verify_email(&data.token).await {
        Ok(_) => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Email verified successfully. You can now log in."
            }))
        },
        Err(e) => {
            error!("Email verification failed: {}", e);
            HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid or expired verification token.".to_string(),
            })
        },
    }
}

pub async fn request_password_reset(
    pool: web::Data<sqlx::PgPool>,
    data: web::Json<RequestPasswordResetRequest>,
) -> impl Responder {
    let auth = match AuthService::new(pool.get_ref().clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize auth service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };
    
    // for now, always return success to not leak user existence
    match auth.request_password_reset(&data.email).await {
        Ok(_) => {},
        Err(e) => error!("Password reset request failed: {}", e),
    }
    
    HttpResponse::Ok().json(serde_json::json!({
        "message": "If your email is registered, a password reset link has been sent."
    }))
}

pub async fn reset_password(
    pool: web::Data<sqlx::PgPool>,
    data: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    let auth = match AuthService::new(pool.get_ref().clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize auth service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };
    
    match auth.reset_password(&data.token, &data.new_password).await {
        Ok(_) => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Password has been reset successfully. You can now log in with your new password."
            }))
        },
        Err(e) => {
            error!("Password reset failed: {}", e);
            
            let error_message = if e.to_string().contains("Password must be at least") {
                "Password must be at least 8 characters long."
            } else {
                "Invalid or expired reset token."
            };
            
            HttpResponse::BadRequest().json(ErrorResponse {
                error: error_message.to_string(),
            })
        },
    }
}

pub async fn delete_account(
    pool: web::Data<sqlx::PgPool>,
    auth_user: AuthenticatedUser,
) -> impl Responder {
    let auth = match AuthService::new(pool.get_ref().clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to initialize auth service: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Internal server error".to_string(),
            });
        }
    };
    
    match auth.delete_account(auth_user.id).await {
        Ok(_) => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Your account has been successfully deleted."
            }))
        },
        Err(e) => {
            error!("Account deletion failed: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to delete account. Please try again later.".to_string(),
            })
        },
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/verify-email", web::get().to(verify_email))
            .route("/request-password-reset", web::post().to(request_password_reset))
            .route("/reset-password", web::post().to(reset_password))
            .route("/delete-account", web::delete().to(delete_account))
    );
}

pub async fn admin_dashboard(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    
    // TODO: leter on, put admin logic here...
    HttpResponse::Ok().json("Admin dashboard data")
}