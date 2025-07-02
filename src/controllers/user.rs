use crate::middleware::auth::AuthenticatedUser;
use crate::models::user::User;
use crate::services::stellar::StellarService;
use actix_web::{web, HttpResponse, Responder};
use anyhow::Result;
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct UpdateProfileRequest {
    username: Option<String>,
    // TODO: email updates would require verification
}

#[derive(Debug, Deserialize)]
struct UpdatePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct GenerateWalletRequest {
    // TODO: add options
}

pub async fn get_profile(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => HttpResponse::Ok().json(user_profile),
        Ok(None) => {
            // But this shouldn't happen if middleware is working well
            error!("User found in token but not in database: {}", user.id);
            HttpResponse::NotFound().json(ErrorResponse {
                error: "User profile not found".to_string(),
            })
        }
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn update_profile(
    pool: web::Data<PgPool>,
    profile_data: web::Json<UpdateProfileRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            if let Some(username) = &profile_data.username {
                let username_exists = sqlx::query!(
                    "SELECT id FROM users WHERE username = $1 AND id != $2",
                    username,
                    user.id
                )
                .fetch_optional(&**pool)
                .await;

                match username_exists {
                    Ok(Some(_)) => {
                        return HttpResponse::BadRequest().json(ErrorResponse {
                            error: "Username is already taken".to_string(),
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("Database error checking username: {}", e);
                        return HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "Failed to update profile. Please try again.".to_string(),
                        });
                    }
                }

                let updated_user = sqlx::query_as!(
                    User,
                    r#"
                    UPDATE users
                    SET username = $1, updated_at = NOW()
                    WHERE id = $2
                    RETURNING *
                    "#,
                    username,
                    user.id
                )
                .fetch_one(&**pool)
                .await;

                match updated_user {
                    Ok(user) => {
                        info!("User profile updated: {}", user.id);
                        return HttpResponse::Ok().json(user);
                    }
                    Err(e) => {
                        error!("Failed to update user profile: {}", e);
                        return HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "Failed to update profile. Please try again.".to_string(),
                        });
                    }
                }
            }

            HttpResponse::Ok().json(user_profile)
        }
        Ok(None) => {
            error!("User found in token but not in database: {}", user.id);
            HttpResponse::NotFound().json(ErrorResponse {
                error: "User profile not found".to_string(),
            })
        }
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn update_password(
    pool: web::Data<PgPool>,
    password_data: web::Json<UpdatePasswordRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            match bcrypt::verify(&password_data.current_password, &user_profile.password_hash) {
                Ok(true) => {
                    if password_data.new_password.len() < 8 {
                        return HttpResponse::BadRequest().json(ErrorResponse {
                            error: "New password must be at least 8 characters long".to_string(),
                        });
                    }

                    match bcrypt::hash(&password_data.new_password, 10) {
                        Ok(new_hash) => {
                            let updated_user = sqlx::query_as!(
                                User,
                                r#"
                                UPDATE users
                                SET password_hash = $1, updated_at = NOW()
                                WHERE id = $2
                                RETURNING *
                                "#,
                                new_hash,
                                user.id
                            )
                            .fetch_one(&**pool)
                            .await;

                            match updated_user {
                                Ok(_) => {
                                    info!("Password updated for user: {}", user.id);
                                    HttpResponse::Ok().json(serde_json::json!({
                                        "message": "Your password has been updated successfully"
                                    }))
                                }
                                Err(e) => {
                                    error!("Failed to update password in database: {}", e);
                                    HttpResponse::InternalServerError().json(ErrorResponse {
                                        error: "Failed to update password. Please try again."
                                            .to_string(),
                                    })
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to hash new password: {}", e);
                            HttpResponse::InternalServerError().json(ErrorResponse {
                                error: "Failed to update password. Please try again.".to_string(),
                            })
                        }
                    }
                }
                Ok(false) => HttpResponse::BadRequest().json(ErrorResponse {
                    error: "Current password is incorrect".to_string(),
                }),
                Err(e) => {
                    error!("Error verifying password: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to verify current password. Please try again.".to_string(),
                    })
                }
            }
        }
        Ok(None) => {
            error!("User found in token but not in database: {}", user.id);
            HttpResponse::NotFound().json(ErrorResponse {
                error: "User profile not found".to_string(),
            })
        }
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn get_wallet_info(
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            let stellar = match StellarService::new() {
                Ok(service) => service,
                Err(e) => {
                    error!("Failed to initialize Stellar service: {}", e);
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to connect to blockchain service. Please try again."
                            .to_string(),
                    });
                }
            };

            let public_key = match &user_profile.stellar_public_key {
                Some(key) => key.clone(),
                None => {
                    return HttpResponse::NotFound().json(ErrorResponse {
                        error: "No wallet found for this account".to_string(),
                    });
                }
            };

            let balance_future = async {
                if let Some(key) = &user_profile.stellar_public_key {
                    match stellar.get_xlm_balance(key).await {
                        Ok(balance) => Some(balance),
                        Err(e) => {
                            error!("Failed to fetch balance from Stellar: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            };

            match balance_future.await {
                Some(balance) => HttpResponse::Ok().json(serde_json::json!({
                    "public_key": public_key,
                    "balance": balance,
                    "currency": "XLM"
                })),
                None => HttpResponse::Ok().json(serde_json::json!({
                    "public_key": public_key,
                    "balance": null,
                    "currency": "XLM"
                })),
            }
        }
        Ok(None) => {
            error!("User found in token but not in database: {}", user.id);
            HttpResponse::NotFound().json(ErrorResponse {
                error: "User profile not found".to_string(),
            })
        }
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn generate_wallet(
    pool: web::Data<PgPool>,
    _request: web::Json<GenerateWalletRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            if user_profile.stellar_public_key.is_some() {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "You already have a wallet. Please use the existing wallet.".to_string(),
                });
            }

            let stellar = match StellarService::new() {
                Ok(service) => service,
                Err(e) => {
                    error!("Failed to initialize Stellar service: {}", e);
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to connect to blockchain service. Please try again."
                            .to_string(),
                    });
                }
            };

            match stellar.generate_keypair() {
                Ok((public_key, secret_key)) => {
                    match user_profile
                        .update_stellar_keys(&pool, &public_key, &secret_key)
                        .await
                    {
                        Ok(updated_user) => {
                            info!("Stellar wallet generated for user: {}", user.id);
                            HttpResponse::Ok().json(serde_json::json!({
                                "message": "Wallet has been generated successfully",
                                "public_key": public_key
                            }))
                        }
                        Err(e) => {
                            error!("Failed to update user with new Stellar keys: {}", e);
                            HttpResponse::InternalServerError().json(ErrorResponse {
                                error: "Failed to update user with new wallet. Please try again."
                                    .to_string(),
                            })
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to generate Stellar keypair: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to generate wallet. Please try again.".to_string(),
                    })
                }
            }
        }
        Ok(None) => {
            error!("User found in token but not in database: {}", user.id);
            HttpResponse::NotFound().json(ErrorResponse {
                error: "User profile not found".to_string(),
            })
        }
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn get_user_by_id(
    pool: web::Data<PgPool>,
    user_id: web::Path<Uuid>,
    current_user: AuthenticatedUser,
) -> impl Responder {
    let is_self = current_user.id == *user_id;

    if !is_self {
        let _admin_user =
            match crate::middleware::auth::require_admin_user(&**pool, current_user.id).await {
                Ok(user) => user,
                Err(response) => return response,
            };
    }

    match User::find_by_id(&pool, *user_id).await {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "User not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch user: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch user. Please try again.".to_string(),
            })
        }
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/me", web::get().to(get_profile))
            .route("/me", web::put().to(update_profile))
            .route("/me/password", web::put().to(update_password))
            .route("/me/wallet", web::get().to(get_wallet_info))
            .route("/me/wallet", web::post().to(generate_wallet))
            .route("/test-auth", web::get().to(test_auth))
            .route("/simple-test", web::get().to(simple_test))
            .route("/{user_id}", web::get().to(get_user_by_id)),
    );
}

// test & debug
pub async fn test_auth(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Authentication working!",
        "user_id": user.id.to_string()
    }))
}

pub async fn simple_test() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Server is working!"
    }))
}
