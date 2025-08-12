use crate::models::user::User;
use crate::services::stellar::StellarService;
use crate::services::RedisService;
use crate::{middleware::auth::AuthenticatedUser};
use actix_web::{web, HttpResponse, Responder};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    username: Option<String>,
    // TODO: email updates would require verification
}

#[derive(Debug, Deserialize)]
pub struct UpdatePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Serialize)]
pub struct WalletInfo {
    pub public_key: String,
    pub usdc_balance: Option<f64>,
    pub has_usdc_trustline: bool,
    pub primary_currency: String,
}

#[derive(Serialize)]
pub struct WalletSetupStatus {
    pub has_wallet: bool,
    pub has_usdc_trustline: bool,
    pub usdc_balance: Option<f64>,
    pub setup_required: Vec<String>,
    pub ready_for_payments: bool,
}

#[derive(Debug, Deserialize)]
pub struct GenerateWalletRequest {
    // TODO: add options
}

pub async fn get_profile(
    pool: web::Data<PgPool>, 
    user: AuthenticatedUser
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
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

pub async fn get_wallet_info(pool: web::Data<PgPool>, user: AuthenticatedUser) -> impl Responder {
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

            let _xlm_balance = match stellar.get_xlm_balance(&public_key).await {
                Ok(balance) => Some(balance),
                Err(e) => {
                    error!("Failed to fetch XLM balance: {}", e);
                    None
                }
            };

            let (usdc_balance, has_trustline) = match stellar.get_usdc_balance(&public_key).await {
                Ok(balance) => (Some(balance), true),
                Err(_) => {
                    // Check if it's a trustline issue or account issue
                    match stellar.has_usdc_trustline(&public_key).await {
                        Ok(has_trustline) => (None, has_trustline),
                        Err(_) => (None, false),
                    }
                }
            };

            let wallet_info = WalletInfo {
                public_key,
                usdc_balance,
                has_usdc_trustline: has_trustline,
                primary_currency: "USDC".to_string(),
            };

            HttpResponse::Ok().json(wallet_info)
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

pub async fn get_wallet_setup_status(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            let mut setup_required = Vec::new();
            let mut ready_for_payments = true;

            let has_wallet = user_profile.stellar_public_key.is_some();
            if !has_wallet {
                setup_required.push("Create Stellar wallet".to_string());
                ready_for_payments = false;
            }

            let (has_usdc_trustline, usdc_balance) =
                if let Some(public_key) = &user_profile.stellar_public_key {
                    let stellar = match StellarService::new() {
                        Ok(service) => service,
                        Err(_) => {
                            return HttpResponse::InternalServerError().json(ErrorResponse {
                                error: "Failed to connect to blockchain service".to_string(),
                            });
                        }
                    };

                    let has_trustline = stellar
                        .has_usdc_trustline(public_key)
                        .await
                        .unwrap_or(false);
                    let balance = if has_trustline {
                        stellar.get_usdc_balance(public_key).await.ok()
                    } else {
                        None
                    };

                    if !has_trustline {
                        setup_required.push("Create USDC trustline".to_string());
                        ready_for_payments = false;
                    }

                    (has_trustline, balance)
                } else {
                    (false, None)
                };

            let status = WalletSetupStatus {
                has_wallet,
                has_usdc_trustline,
                usdc_balance,
                setup_required,
                ready_for_payments,
            };

            HttpResponse::Ok().json(status)
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "User profile not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn create_usdc_trustline(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            if user_profile.stellar_public_key.is_none() {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "User must have a Stellar wallet before creating USDC trustline"
                        .to_string(),
                });
            }

            if user_profile.stellar_secret_key_encrypted.is_none() {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "User wallet is incomplete. Please contact support.".to_string(),
                });
            }

            let stellar = match StellarService::new() {
                Ok(service) => service,
                Err(e) => {
                    error!("Failed to initialize Stellar service: {}", e);
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to initialize blockchain service".to_string(),
                    });
                }
            };

            let usdc_issuer = std::env::var("TESTNET_USDC_ISSUER").unwrap_or_else(|_| {
                "GD34GBHUVW66SULHJMFXEA24G6WBTNV5RNQTZ6CQ7NXFL2XMN53BMMOJ".to_string()
            });

            let sponsor_manager =
                match crate::services::sponsor_manager::SponsorManager::new(pool.get_ref().clone())
                {
                    Ok(manager) => manager,
                    Err(e) => {
                        error!("Failed to initialize sponsor manager: {}", e);
                        return HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "Sponsorship service unavailable".to_string(),
                        });
                    }
                };

            let sponsor_info = match sponsor_manager.get_available_sponsor().await {
                Ok(sponsor) => sponsor,
                Err(e) => {
                    error!("Failed to get available sponsor: {}", e);
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "No sponsor accounts available. Please try again later.".to_string(),
                    });
                }
            };

            match stellar
                .create_asset_trustline(
                    &user_profile.stellar_secret_key_encrypted.unwrap(),
                    "USDC",
                    &usdc_issuer,
                    Some(&sponsor_info.secret_key),
                )
                .await
            {
                Ok(tx_hash) => {
                    info!("USDC trustline created for user {}: {}", user.id, tx_hash);
                    let gas_fee_xlm = stellar.sponsored_gas_fee();

                    if let Err(e) = sponsor_manager
                        .record_sponsorship_usage(&sponsor_info.public_key, gas_fee_xlm)
                        .await
                    {
                        warn!("Failed to record sponsor usage: {}", e);
                    }
                    HttpResponse::Ok().json(serde_json::json!({
                        "success": true,
                        "sponsored": true,
                        "gas_fee_covered": format!("{:.7} XLM", gas_fee_xlm),
                        "message": "USDC trustline created successfully",
                        "transaction_hash": tx_hash,
                        "next_steps": [
                            "Your wallet can now receive USDC",
                            "You can now purchase tickets with USDC",
                            "Fund your wallet with USDC to start making purchases"
                        ]
                    }))
                }
                Err(e) => {
                    error!("Failed to create USDC trustline: {}", e);
                    HttpResponse::InternalServerError().json(ErrorResponse {
                        error: format!("Failed to create USDC trustline: {}", e),
                    })
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "User profile not found".to_string(),
        }),
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch your profile. Please try again.".to_string(),
            })
        }
    }
}

pub async fn get_funding_instructions(
    pool: web::Data<sqlx::PgPool>,
    user: AuthenticatedUser,
) -> impl Responder {
    match User::find_by_id(&pool, user.id).await {
        Ok(Some(user_profile)) => {
            let public_key = match &user_profile.stellar_public_key {
                Some(key) => key.clone(),
                None => {
                    return HttpResponse::BadRequest().json(ErrorResponse {
                        error: "User must have a Stellar wallet to receive funding instructions"
                            .to_string(),
                    });
                }
            };

            // Check trustline status
            let stellar = match StellarService::new() {
                Ok(service) => service,
                Err(_) => {
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to connect to blockchain service".to_string(),
                    });
                }
            };

            let has_trustline = stellar
                .has_usdc_trustline(&public_key)
                .await
                .unwrap_or(false);

            let instructions = if has_trustline {
                let network_name = match std::env::var("STELLAR_NETWORK")
                    .unwrap_or_else(|_| "testnet".to_string())
                    .as_str()
                {
                    "mainnet" => "Stellar Mainnet",
                    _ => "Stellar Testnet",
                };

                serde_json::json!({
                "wallet_address": public_key,
                "currency": "USDC",
                "network": network_name,
                "ready_to_receive": true,
                            "instructions": [
                                "Your wallet is ready to receive USDC",
                                "Send USDC to your wallet address above",
                                "Make sure the sender uses the Stellar network",
                                "Funds typically arrive within seconds",
                                "You can then use USDC to purchase event tickets"
                            ],
                            "important_notes": [
                                "Only send USDC on the Stellar network to this address",
                                "Do not send other cryptocurrencies to this address",
                                "Always double-check the network before sending"
                            ]
                        })
            } else {
                serde_json::json!({
                    "wallet_address": public_key,
                    "currency": "USDC",
                    "ready_to_receive": false,
                    "setup_required": "USDC trustline must be created first",
                    "instructions": [
                        "You need to create a USDC trustline before receiving funds",
                        "Use the 'Create USDC Trustline' endpoint first",
                        "After trustline creation, you can receive USDC at the address above"
                    ]
                })
            };

            HttpResponse::Ok().json(instructions)
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "User profile not found".to_string(),
        }),
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

pub async fn send_notification(
    redis: web::Data<Option<RedisService>>,
    user: AuthenticatedUser,
    data: web::Json<serde_json::Value>,
) -> impl Responder {
    // Check rate limit
    if let Some(redis) = redis.as_ref() {
        let rate_limit_key = format!("RATE_LIMIT:NOTIFICATIONS:{}", user.id);
        match redis.check_rate_limit(&rate_limit_key, 10, 3600).await { // 10 per hour
            Ok(allowed) => {
                if !allowed {
                    return HttpResponse::TooManyRequests().json(json!({
                        "error": "Too many notifications sent. Please try again later."
                    }));
                }
            }
            Err(e) => {
                warn!("Rate limit check failed: {}", e);
                // Continue without rate limiting if Redis is down
            }
        }
    }

    //TODO:put notification logic here...
    HttpResponse::Ok().json(json!({
        "message": "Notification sent successfully"
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/me", web::get().to(get_profile))
            .route("/me", web::put().to(update_profile))
            .route("/me/password", web::put().to(update_password))
            .route("/me/wallet", web::get().to(get_wallet_info))
            .route("me/wallet/trustline", web::post().to(create_usdc_trustline))
            .route("me/wallet/funding", web::get().to(get_funding_instructions))
            .route("/me/wallet/generate", web::post().to(generate_wallet))
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
