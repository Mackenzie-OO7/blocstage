use anyhow::{anyhow, Result};
use crate::models::{event::Event, ticket::Ticket, ticket_type::TicketType, user::User};
use qrcode::QrCode;
use qrcode::render::svg;

pub struct PdfGenerator;

impl PdfGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_ticket_pdf(
        &self,
        ticket: &Ticket,
        ticket_type: &TicketType,
        event: &Event,
        user: &User,
    ) -> Result<Vec<u8>> {
        let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "https://blocstage.com".to_string());
        let qr_url = format!("{}/check-in/{}", app_url, ticket.id);

        let event_date = event.start_time.format("%B %d, %Y at %I:%M %p UTC").to_string();
        let purchase_date = ticket.created_at.format("%B %d, %Y at %I:%M %p UTC").to_string();

        let price_str = if let Some(price) = &ticket_type.price {
            if !ticket_type.is_free {
                let currency = ticket_type.currency.as_deref().unwrap_or("USD");
                format!("{} {}", price, currency)
            } else {
                "FREE".to_string()
            }
        } else {
            "FREE".to_string()
        };

        let qr_code = QrCode::new(&qr_url)
            .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
        
        let qr_svg = qr_code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .build();

        let html_content = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlocStage Ticket - {}</title>
    <style>
        @media print {{
            body {{ margin: 0; }}
            .no-print {{ display: none; }}
        }}
        body {{ 
            font-family: Arial, sans-serif; 
            margin: 20px;
            background: white;
            color: #333;
            line-height: 1.4;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .ticket {{
            border: 3px solid #2c3e50;
            border-radius: 12px;
            padding: 30px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .title {{
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
            margin: 0;
            letter-spacing: 4px;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.1);
        }}
        .subtitle {{
            font-size: 14px;
            color: #6c757d;
            margin: 10px 0 0 0;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        .details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 25px 0;
        }}
        .detail-item {{
            margin-bottom: 15px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            border: 1px solid #dee2e6;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .label {{
            font-weight: bold;
            color: #2c3e50;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}
        .value {{
            color: #495057;
            font-size: 14px;
            word-wrap: break-word;
        }}
        .qr-section {{
            text-align: center;
            border: 3px solid #007bff;
            border-radius: 15px;
            padding: 30px;
            background: white;
            margin: 30px 0;
            box-shadow: 0 2px 8px rgba(0,123,255,0.2);
        }}
        .qr-title {{
            font-weight: bold;
            font-size: 18px;
            margin-bottom: 20px;
            color: #007bff;
            letter-spacing: 3px;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.1);
        }}
        .qr-code {{
            display: inline-block;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}
        .qr-url {{
            margin: 20px 0 0 0; 
            font-size: 11px; 
            color: #6c757d;
            word-break: break-all;
            font-family: monospace;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }}
        .instructions {{
            background: linear-gradient(135deg, #e3f2fd 0%, #f0f8ff 100%);
            border-left: 5px solid #2196f3;
            padding: 20px;
            margin: 30px 0;
            border-radius: 0 10px 10px 0;
            box-shadow: 0 2px 4px rgba(33,150,243,0.2);
        }}
        .instructions h3 {{
            margin: 0 0 15px 0;
            color: #1976d2;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        .instructions ul {{
            margin: 0;
            padding-left: 25px;
            font-size: 14px;
        }}
        .instructions li {{
            margin-bottom: 8px;
            line-height: 1.5;
        }}
        .footer {{
            text-align: center;
            font-size: 11px;
            color: #6c757d;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #dee2e6;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }}
        .ticket-id {{
            font-family: monospace;
            background: #e9ecef;
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid #ced4da;
            font-size: 12px;
            word-break: break-all;
        }}
        .no-print {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="ticket">
        <div class="details">
            <div>
                <div class="detail-item">
                    <div class="label">Event</div>
                    <div class="value">{}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Date & Time</div>
                    <div class="value">{}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Ticket Type</div>
                    <div class="value">{}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Owner</div>
                    <div class="value">{}</div>
                </div>
            </div>
            <div>
                <div class="detail-item">
                    <div class="label">Price</div>
                    <div class="value">{}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Purchase Date</div>
                    <div class="value">{}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Ticket ID</div>
                    <div class="value ticket-id">{}</div>
                </div>
            </div>
        </div>

        <div class="qr-section">
            <div class="qr-title">🎫 SCAN QR CODE FOR ENTRY</div>
            <div class="qr-code">
                {}
            </div>
        </div>

        <div class="footer">
            ⭐ Generated by BlocStage • Powered by Stellar ⭐<br>
        </div>
    </div>
</body>
</html>"#,
            event.title,
            event.title,
            event_date,
            ticket_type.name,
            user.username,
            price_str,
            purchase_date,
            ticket.id,
            qr_svg,
        );

        Ok(html_content.into_bytes())
    }
}