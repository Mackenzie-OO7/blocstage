use crate::services::ticket::TicketService;
use actix_web::{web, HttpResponse, Responder};
use log::{error, info};
use sqlx::PgPool;
use uuid::Uuid;

async fn create_ticket_service(pool: &PgPool) -> anyhow::Result<TicketService> {
    TicketService::new(pool.clone()).await
}

pub async fn web_check_in(
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let ticket_id = path.into_inner();
    
    match create_ticket_service(&pool).await {
        Ok(ticket_service) => {
            match ticket_service.web_check_in_ticket(ticket_id).await {
                Ok(ticket) => {
                    info!("✅ Web check-in successful for ticket: {}", ticket_id);
                    
                    HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .body(create_success_page(&ticket.id.to_string()))
                }
                Err(e) => {
                    error!("❌ Web check-in failed for ticket {}: {}", ticket_id, e);
                    
                    HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .body(create_error_page(&e.to_string()))
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize ticket service: {}", e);
            HttpResponse::InternalServerError()
                .content_type("text/html; charset=utf-8")
                .body(create_error_page("System error occurred"))
        }
    }
}

fn create_success_page(ticket_id: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check-in Successful - BlocStage</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }}
        .success-icon {{
            font-size: 72px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #28a745;
            margin: 0 0 20px 0;
            font-size: 28px;
        }}
        p {{
            color: #666;
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 30px;
        }}
        .ticket-id {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            color: #495057;
            margin-bottom: 20px;
            border-left: 4px solid #28a745;
        }}
        .timestamp {{
            font-size: 12px;
            color: #aaa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Check-in Successful!</h1>
        <p>Welcome to the event! Your ticket has been validated and you're all set to enter.</p>
        <div class="ticket-id">
            Ticket ID: {}
        </div>
        <div class="timestamp">
            Checked in at: {}
        </div>
    </div>
</body>
</html>
        "#,
        ticket_id,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
}

fn create_error_page(error_message: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check-in Error - BlocStage</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }}
        .error-icon {{
            font-size: 72px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #dc3545;
            margin: 0 0 20px 0;
            font-size: 28px;
        }}
        p {{
            color: #666;
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 30px;
        }}
        .error-message {{
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 20px;
            border-left: 4px solid #dc3545;
        }}
        .help-text {{
            font-size: 12px;
            color: #aaa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>Check-in Failed</h1>
        <p>We couldn't process your ticket check-in.</p>
        <div class="error-message">
            {}
        </div>
        <div class="help-text">
            Please contact event staff for assistance if this error persists.
        </div>
    </div>
</body>
</html>
        "#,
        error_message
    )
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/check-in")
            .route("/{ticket_id}", web::get().to(web_check_in))
    );
}