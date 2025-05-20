pub mod auth_controller;
pub mod event_controller;
pub mod ticket_controller;
pub mod transaction_controller;
pub mod user_controller;

use actix_web::web;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    auth_controller::configure(cfg);
    event_controller::configure(cfg);
    ticket_controller::configure(cfg);
    transaction_controller::configure(cfg);
    user_controller::configure(cfg);
}