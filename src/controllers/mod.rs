pub mod admin_filters;
pub mod auth;
pub mod event;
pub mod ticket;
pub mod transaction;
pub mod user;

use actix_web::web;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("", web::get().to(crate::api_info))
            .configure(auth::configure)
            .configure(ticket::configure)
            .configure(event::configure)
            .configure(transaction::configure)
            .configure(user::configure)
            // .configure(admin_filters::configure)
    );
}
