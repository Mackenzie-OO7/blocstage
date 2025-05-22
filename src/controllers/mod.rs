pub mod auth_controller;
pub mod event_controller;
pub mod ticket_controller;
pub mod transaction_controller;
pub mod user_controller;

use actix_web::web;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(auth_controller::configure)
            .configure(event_controller::configure)
            .configure(ticket_controller::configure)
            .configure(transaction_controller::configure)
            .configure(user_controller::configure)
    );
}