use super::{EmailProvider, EmailRequest, TemplateEmailRequest};
use anyhow::{Result, anyhow};
use reqwest::Client;
use serde_json::json;
use std::env;
use base64::engine::general_purpose;
use base64::Engine;

#[derive(Debug)]
pub struct SendGridProvider {
    client: Client,
    api_key: String,
}

impl SendGridProvider {
    pub async fn new() -> Result<Self> {
        let api_key = env::var("SENDGRID_API_KEY")
            .map_err(|_| anyhow!("SENDGRID_API_KEY not set"))?;

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
        let mut payload = json!({
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

        if let Some(attachments) = request.attachments {
            let mut attachment_array = Vec::new();
            for attachment in attachments {
                let encoded_content = general_purpose::STANDARD.encode(&attachment.content);
                attachment_array.push(json!({
                    "content": encoded_content,
                    "type": attachment.content_type,
                    "filename": attachment.filename,
                    "disposition": "attachment"
                }));
            }
            payload["attachments"] = json!(attachment_array);
        }

        self.send_request(payload).await
    }

    async fn send_template_email(&self, request: TemplateEmailRequest) -> Result<String> {
        let mut payload = json!({
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

        if let Some(attachments_json) = request.template_data.get("attachments") {
            if let Ok(attachments) = serde_json::from_str::<Vec<crate::services::email::EmailAttachment>>(attachments_json) {
                let mut attachment_array = Vec::new();
                for attachment in attachments {
                    let encoded_content = general_purpose::STANDARD.encode(&attachment.content);
                    attachment_array.push(json!({
                        "content": encoded_content,
                        "type": attachment.content_type,
                        "filename": attachment.filename,
                        "disposition": "attachment"
                    }));
                }
                payload["attachments"] = json!(attachment_array);
            }
        }

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