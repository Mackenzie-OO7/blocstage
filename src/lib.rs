pub mod models;
pub mod services;
pub mod controllers;
pub mod middleware;

use actix_web::{HttpResponse, Responder};
use serde_json::json;

pub use controllers::configure_routes;

pub async fn api_info() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "name": "BlocStage Ticketing API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Decentralized ticketing platform on Stellar",
        "endpoints": {
            "health": "/health",
            "api_docs": "/api",
            "auth": "/api/auth/*",
            "events": "/api/events/*",
            "tickets": "/api/tickets/*",
            "users": "/api/users/*",
            "transactions": "/api/transactions/*",
            "admin": "/api/admin/*"
        }
    }))
}