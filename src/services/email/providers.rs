use super::{EmailProvider, EmailRequest, TemplateEmailRequest};
use anyhow::{Result, anyhow};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use reqwest::Client;
use serde_json::json;
use std::env;

#[derive(Debug)]
pub struct SmtpProvider {
    mailer: SmtpTransport,
}

impl SmtpProvider {
    pub async fn new() -> Result<Self> {
        let smtp_server = env::var("SMTP_SERVER").unwrap_or_else(|_| "localhost".to_string());
        let smtp_port: u16 = env::var("SMTP_PORT")
            .unwrap_or_else(|_| "1025".to_string())
            .parse()
            .unwrap_or(587);
        let smtp_username = env::var("SMTP_USERNAME").unwrap_or_default();
        let smtp_password = env::var("SMTP_PASSWORD").unwrap_or_default();


        let mailer = if smtp_server == "localhost" || smtp_server == "127.0.0.1" {
            // MailHog: no TLS, no auth
            SmtpTransport::builder_dangerous(&smtp_server)
                .port(smtp_port)
                .build()
        } else {
            // real SMTP servers:use TLS and auth
            let mut builder = SmtpTransport::relay(&smtp_server)?
                .port(smtp_port);

            if !smtp_username.is_empty() && !smtp_password.is_empty() {
                let creds = Credentials::new(smtp_username, smtp_password);
                builder = builder.credentials(creds);
            }

            builder.build()
        };
        log::info!("✅ SMTP provider initialized: {}:{}", smtp_server, smtp_port);

        Ok(Self { mailer })
    }
}

#[async_trait::async_trait]
impl EmailProvider for SmtpProvider {
    async fn send_email(&self, request: EmailRequest) -> Result<String> {
        let email = Message::builder()
            .from(format!("{} <{}>", 
                request.from_name.unwrap_or_else(|| "BlocStage".to_string()), 
                request.from
            ).parse()?)
            .to(format!("{} <{}>", 
                request.to_name.unwrap_or_default(), 
                request.to
            ).parse()?)
            .subject(request.subject)
            .body(request.html_body)?;

        let _response = self.mailer.send(&email)?;
        Ok(format!("smtp-{}", uuid::Uuid::new_v4().to_string()))
    }

    async fn send_template_email(&self, _request: TemplateEmailRequest) -> Result<String> {
        Err(anyhow!("Template emails not supported for SMTP provider. Use send_email instead."))
    }

    async fn health_check(&self) -> Result<bool> {
        Ok(true)
    }

    fn provider_name(&self) -> &'static str {
        "SMTP"
    }
}

#[derive(Debug)]
pub struct SendGridProvider {
    client: Client,
    api_key: String,
}

impl SendGridProvider {
    pub async fn new() -> Result<Self> {
        let api_key = env::var("SENDGRID_API_KEY")
            .map_err(|_| anyhow!("SENDGRID_API_KEY not set for production email"))?;

        let client = Client::new();

        // Test the API key
        let test_response = client
            .get("https://api.sendgrid.com/v3/user/account")
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await?;

        if !test_response.status().is_success() {
            return Err(anyhow!("SendGrid API key validation failed"));
        }

        log::info!("✅ SendGrid provider initialized successfully");

        Ok(Self { client, api_key })
    }

    async fn send_request(&self, payload: serde_json::Value) -> Result<String> {
        let response = self.client
            .post("https://api.sendgrid.com/v3/mail/send")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            // SendGrid returns the message ID in the X-Message-Id header
            let message_id = response
                .headers()
                .get("X-Message-Id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            Ok(message_id)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow!("SendGrid API error: {}", error_text))
        }
    }
}

#[async_trait::async_trait]
impl EmailProvider for SendGridProvider {
    async fn send_email(&self, request: EmailRequest) -> Result<String> {
        let payload = json!({
            "personalizations": [{
                "to": [{
                    "email": request.to,
                    "name": request.to_name.unwrap_or_default()
                }]
            }],
            "from": {
                "email": request.from,
                "name": request.from_name.unwrap_or_else(|| "BlocStage".to_string())
            },
            "subject": request.subject,
            "content": [
                {
                    "type": "text/plain", 
                    "value": request.text_body.unwrap_or_else(|| "Please view this email in HTML format.".to_string())
                },
                {
                    "type": "text/html",
                    "value": request.html_body
                }
            ]
        });

        self.send_request(payload).await
    }

    async fn send_template_email(&self, request: TemplateEmailRequest) -> Result<String> {
        let payload = json!({
            "personalizations": [{
                "to": [{
                    "email": request.to,
                    "name": request.to_name.unwrap_or_default()
                }],
                "dynamic_template_data": request.template_data
            }],
            "from": {
                "email": request.from,
                "name": request.from_name.unwrap_or_else(|| "BlocStage".to_string())
            },
            "template_id": request.template_id
        });

        self.send_request(payload).await
    }

    async fn health_check(&self) -> Result<bool> {
        let response = self.client
            .get("https://api.sendgrid.com/v3/user/account")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &'static str {
        "SendGrid"
    }
}