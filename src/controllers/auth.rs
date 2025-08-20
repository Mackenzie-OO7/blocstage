use crate::middleware::auth::AuthenticatedUser;
use crate::models::user::{
    CreateUserRequest, LoginRequest, RequestPasswordResetRequest, ResetPasswordRequest,
    VerifyEmailRequest,
};
use crate::services::auth::AuthService;
use crate::services::RedisService;
use crate::services::stellar::StellarService;
use crate::services::email::EmailService;
use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use log::{error, info, warn};
use serde::{Serialize};
use sqlx::PgPool;
use std::fmt;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

pub async fn register(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    user_data: web::Json<CreateUserRequest>,
) -> impl Responder {
    info!("👤 Registration attempt for email: {}", user_data.email);

    if user_data.email.trim().is_empty()
        || user_data.username.trim().is_empty()
        || user_data.password.trim().is_empty()
        || user_data.first_name.trim().is_empty()
        || user_data.last_name.trim().is_empty()
    {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "All fields are required.".to_string(),
        });
    }

    if !user_data.email.contains('@') {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid email format.".to_string(),
        });
    }

    if user_data.password.len() < 8 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Password must be at least 8 characters long.".to_string(),
        });
    }

    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.register(user_data.into_inner()).await {
        Ok(user) => HttpResponse::Created().json(serde_json::json!({
            "message": "Registration successful! Please check your email to verify your account.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "email_verified": user.email_verified
            }
        })),
        Err(e) => {
            error!("Registration failed: {}", e);

            let error_message = if e.to_string().contains("Email already") {
                "Email address is already registered."
            } else if e.to_string().contains("Username already") {
                "Username is already taken."
            } else if e.to_string().contains("at least 8 characters") {
                "Password must be at least 8 characters long."
            } else {
                "Registration failed. Please try again."
            };

            let mut status_code = if e.to_string().contains("already") {
                HttpResponse::Conflict()
            } else {
                HttpResponse::BadRequest()
            };

            status_code.json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

pub async fn login(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    req: HttpRequest,
    login_data: web::Json<LoginRequest>,
) -> impl Responder {
    let ip_address = extract_ip_address(&req);
    let user_agent = extract_user_agent(&req);

    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth
        .login(login_data.into_inner(), ip_address, user_agent)
        .await
    {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({
            "token": token,
            "message": "Login successful"
        })),
        Err(e) => {
            // for now, log the error but return a generic message for security
            error!("Login failed: {}", e);

            let error_str = e.to_string();

            let error_message = if error_str.contains("Too many login attempts. Wait a minute, or 15!") {
                error_str
            } else if error_str.contains("Email not verified") {
                "Email not verified. Please check your inbox and verify your email first."
                    .to_string()
            } else if error_str.contains("Account has been deleted") {
                "This account has been deleted.".to_string()
            } else {
                "Invalid email or password.".to_string()
            };

            if e.to_string().contains("Too many login attempts. Wait a minute, or 15!") {
                HttpResponse::TooManyRequests().json(ErrorResponse {
                    error: error_message.to_string(),
                })
            } else {
                HttpResponse::Unauthorized().json(ErrorResponse {
                    error: error_message.to_string(),
                })
            }
        }
    }
}

pub async fn verify_email(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    data: web::Query<VerifyEmailRequest>,
) -> impl Responder {
    info!(
        "📧 Email verification attempt with token: {}...",
        &data.token[0..10.min(data.token.len())]
    );

    if data.token.trim().is_empty() {
        warn!("❌ Email verification failed: Empty token provided");
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Verification token is required.".to_string(),
        });
    }

    if data.token.len() < 32 || data.token.len() > 255 {
        warn!("❌ Email verification failed: Invalid token length");
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid verification token format.".to_string(),
        });
    }

    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.verify_email(&data.token).await {
        Ok(user) => {
            info!(
                "✅ Email verification successful for user: {} ({})",
                user.id, user.email
            );
            
            if let Some(email) = email_service.as_ref().map(|d| d.get_ref()) {
                if let Err(e) = email.send_welcome_email(&user.email, &user.first_name).await {
                    error!("Failed to send welcome email to {}: {}", user.email, e);
                } else {
                    info!("📧 Welcome email sent to {} after verification", user.email);
                }
            }
            
            HttpResponse::Ok().json(SuccessResponse {
                message: "Email verified successfully. Welcome to BlocStage! You can now log in.".to_string(),
            })
        }
        Err(e) => {
            error!("Email verification failed: {}", e);

            let error_message = if e.to_string().contains("Invalid verification token") {
                "Invalid verification token format."
            } else if e.to_string().contains("expired") {
                "Verification token has expired. Please request a new verification email."
            } else {
                "Invalid or expired verification token."
            };

            HttpResponse::BadRequest().json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

pub async fn request_password_reset(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    data: web::Json<RequestPasswordResetRequest>,
) -> impl Responder {
    info!("🔑 Password reset request for email: {}", data.email);

    if data.email.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Email is required.".to_string(),
        });
    }

    if !data.email.contains('@') || data.email.len() > 255 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid email format.".to_string(),
        });
    }

    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.request_password_reset(&data.email).await {
        Ok(_) => {
            info!(
                "✅ Password reset process initiated for email: {}",
                data.email
            );
            HttpResponse::Ok().json(SuccessResponse {
                message: "If your email is registered, a password reset link has been sent."
                    .to_string(),
            })
        }
        Err(e) => {
            error!("Password reset request failed: {}", e);

            if e.to_string().contains("wait before requesting") {
                HttpResponse::TooManyRequests().json(ErrorResponse {
                    error: "Please wait before requesting another password reset.".to_string(),
                })
            } else if e.to_string().contains("verify your email") {
                HttpResponse::BadRequest().json(ErrorResponse {
                    error: "Please verify your email before requesting password reset.".to_string(),
                })
            } else {
                HttpResponse::Ok().json(SuccessResponse {
                    message: "If your email is registered, a password reset link has been sent."
                        .to_string(),
                })
            }
        }
    }
}

pub async fn reset_password(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    data: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    info!(
        "🔐 Password reset attempt with token: {}...",
        &data.token[0..10.min(data.token.len())]
    );

    if data.token.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Reset token is required.".to_string(),
        });
    }

    if data.new_password.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "New password is required.".to_string(),
        });
    }

    if data.token.len() < 32 || data.token.len() > 255 {
        warn!("❌ Password reset failed: Invalid token length");
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid reset token format.".to_string(),
        });
    }

    if data.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Password must be at least 8 characters long.".to_string(),
        });
    }

    if data.new_password.len() > 128 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Password must be less than 128 characters.".to_string(),
        });
    }

    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.reset_password(&data.token, &data.new_password).await {
        Ok(_) => {
            info!("✅ Password reset successful");
            HttpResponse::Ok().json(SuccessResponse {
                message: "Password has been reset successfully. You can now log in with your new password.".to_string(),
            })
        }
        Err(e) => {
            error!("Password reset failed: {}", e);

            let error_message = if e.to_string().contains("at least 8 characters") {
                "Password must be at least 8 characters long."
            } else if e.to_string().contains("Invalid reset token") {
                "Invalid reset token format."
            } else if e.to_string().contains("expired") {
                "Reset token has expired. Please request a new password reset."
            } else {
                "Invalid or expired reset token."
            };

            HttpResponse::BadRequest().json(ErrorResponse {
                error: error_message.to_string(),
            })
        }
    }
}

pub async fn logout(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    req: HttpRequest,
    user: AuthenticatedUser,
) -> impl Responder {
    let token = match req.headers().get("authorization") {
        Some(header) => match header.to_str() {
            Ok(auth_str) if auth_str.starts_with("Bearer ") => &auth_str[7..],
            _ => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "Invalid authorization header".to_string(),
                });
            }
        },
        None => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Authorization header required".to_string(),
            });
        }
    };

    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.logout(user.id, token).await {
        Ok(_) => {
            info!("✅ User {} logged out successfully", user.id);
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Logged out successfully"
            }))
        }
        Err(e) => {
            error!("Logout failed: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to logout. Please try again.".to_string(),
            })
        }
    }
}

pub async fn logout_all(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    user: AuthenticatedUser,
) -> impl Responder {
    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.logout_all_sessions(user.id).await {
        Ok(_) => {
            info!("✅ User {} logged out from all devices", user.id);
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Logged out from all devices successfully"
            }))
        }
        Err(e) => {
            error!("Logout all failed: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to logout from all devices. Please try again.".to_string(),
            })
        }
    }
}

pub async fn delete_account(
    pool: web::Data<sqlx::PgPool>,
    stellar: web::Data<Arc<StellarService>>,
    redis: Option<web::Data<Arc<RedisService>>>,
    email_service: Option<web::Data<Arc<EmailService>>>,
    auth_user: AuthenticatedUser,
) -> impl Responder {
    let auth = AuthService::new_with_services(
        pool.get_ref().clone(),
        stellar.get_ref().clone(),
        redis.as_ref().map(|d| d.get_ref().clone()),
        email_service.as_ref().map(|d| d.get_ref().clone()),
    );

    match auth.delete_account(auth_user.id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Your account has been successfully deleted."
        })),
        Err(e) => {
            error!("Account deletion failed: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to delete account. Please try again later.".to_string(),
            })
        }
    }
}

pub async fn get_active_sessions(
    _pool: web::Data<sqlx::PgPool>,
    redis: web::Data<Option<Arc<RedisService>>>,
    user: AuthenticatedUser,
) -> impl Responder {
    let Some(redis) = redis.get_ref() else {
        return HttpResponse::ServiceUnavailable().json(ErrorResponse {
            error: "Redis not configured".to_string(),
        });
    };

    match redis.get_user_active_sessions(user.id).await {
        Ok(sessions) => {
            info!(
                "✅ User {} retrieved {} active sessions",
                user.id,
                sessions.len()
            );
            HttpResponse::Ok().json(serde_json::json!({
                "sessions": sessions,
                "total_count": sessions.len()
            }))
        }
        Err(e) => {
            error!("Failed to get active sessions: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve active sessions".to_string(),
            })
        }
    }
}

pub async fn revoke_session(
    _pool: web::Data<sqlx::PgPool>,
    redis: web::Data<Option<Arc<RedisService>>>,
    path: web::Path<String>, // JWT ID
    user: AuthenticatedUser,
) -> impl Responder {
    let jwt_id = path.into_inner();

    let Some(redis) = redis.get_ref() else {
        return HttpResponse::ServiceUnavailable().json(ErrorResponse {
            error: "Redis not configured".to_string(),
        });
    };

    match redis.revoke_specific_session(user.id, &jwt_id).await {
        Ok(was_revoked) => {
            if was_revoked {
                info!("✅ User {} revoked session: {}", user.id, jwt_id);
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "Session revoked successfully"
                }))
            } else {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: "Session not found or already revoked".to_string(),
                })
            }
        }
        Err(e) => {
            error!("Failed to revoke session: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to revoke session".to_string(),
            })
        }
    }
}

fn extract_ip_address(req: &HttpRequest) -> Option<String> {
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }

    req.connection_info().peer_addr().map(|addr| {
        if let Some(ip) = addr.split(':').next() {
            ip.to_string()
        } else {
            addr.to_string()
        }
    })
}

fn extract_user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|ua| ua.to_string())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/logout-all", web::post().to(logout_all))
            .route("/verify-email", web::get().to(verify_email))
            .route(
                "/request-password-reset",
                web::post().to(request_password_reset),
            )
            .route("/reset-password", web::post().to(reset_password))
            .route("/delete-account", web::delete().to(delete_account))
            .route("/sessions", web::get().to(get_active_sessions))
            .route("/sessions/{jwt_id}", web::delete().to(revoke_session)),
    );
}

pub async fn admin_dashboard(pool: web::Data<PgPool>, user: AuthenticatedUser) -> impl Responder {
    let _admin_user = match crate::middleware::auth::require_admin_user(&pool, user.id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // TODO: leter on, put admin logic here...
    HttpResponse::Ok().json("Admin dashboard data")
}
