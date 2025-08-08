use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod providers;
pub mod templates;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRequest {
    pub to: String,
    pub to_name: Option<String>,
    pub subject: String,
    pub html_body: String,
    pub text_body: Option<String>,
    pub from: String,
    pub from_name: Option<String>,
}

#[async_trait::async_trait]
pub trait EmailProvider: Send + Sync {
    async fn send_email(&self, request: EmailRequest) -> Result<String>; // Returns message ID
    async fn health_check(&self) -> Result<bool>;
    fn provider_name(&self) -> &'static str;
}

pub struct EmailService {
    provider: Box<dyn EmailProvider>,
    template_renderer: templates::TemplateRenderer,
}

impl std::fmt::Debug for EmailService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailService")
            .field("provider", &"<EmailProvider>")
            .field("template_renderer", &self.template_renderer)
            .finish()
    }
}

impl EmailService {
    pub async fn new() -> Result<Self> {
        let provider = Self::create_provider().await?;
        let template_renderer = templates::TemplateRenderer::new()?;
        
        Ok(Self {
            provider,
            template_renderer,
        })
    }

    async fn create_provider() -> Result<Box<dyn EmailProvider>> {
        let env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        
        match env.as_str() {
            "production" => {
                log::info!("🚀 Initializing SendGrid email provider for production");
                Ok(Box::new(providers::SendGridProvider::new().await?))
            }
            _ => {
                log::info!("🛠️ Initializing SMTP email provider for development");
                Ok(Box::new(providers::SmtpProvider::new().await?))
            }
        }
    }

    pub async fn send_raw_email(&self, request: EmailRequest) -> Result<String> {
        self.provider.send_email(request).await
    }

    pub async fn send_verification_email(&self, to_email: &str, to_name: &str, token: &str) -> Result<()> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
            token
        );

        let mut context = HashMap::new();
        context.insert("user_name", to_name);
        context.insert("verification_url", &verification_url);
        context.insert("app_name", "BlocStage");

        let html_body = self.template_renderer.render("email_verification", &context)?;
        let text_body = format!(
            "Hi {},\n\nPlease verify your email by clicking this link: {}\n\nThanks,\nBlocStage Team",
            to_name, verification_url
        );

        let request = EmailRequest {
            to: to_email.to_string(),
            to_name: Some(to_name.to_string()),
            subject: "Verify Your BlocStage Account".to_string(),
            html_body,
            text_body: Some(text_body),
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "noreply@blocstage.com".to_string()),
            from_name: Some("BlocStage".to_string()),
        };

        let message_id = self.provider.send_email(request).await?;
        log::info!("✅ Verification email sent to {}: {}", to_email, message_id);
        
        Ok(())
    }

    pub async fn send_password_reset_email(&self, to_email: &str, to_name: &str, token: &str) -> Result<()> {
        let reset_url = format!(
            "{}/reset-password?token={}",
            std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
            token
        );

        let mut context = HashMap::new();
        context.insert("user_name", to_name);
        context.insert("reset_url", &reset_url);
        context.insert("app_name", "BlocStage");

        let html_body = self.template_renderer.render("password_reset", &context)?;
        let text_body = format!(
            "Hi {},\n\nReset your password by clicking this link: {}\n\nIf you didn't request this, please ignore this email.\n\nThanks,\nBlocStage Team",
            to_name, reset_url
        );

        let request = EmailRequest {
            to: to_email.to_string(),
            to_name: Some(to_name.to_string()),
            subject: "Reset Your BlocStage Password".to_string(),
            html_body,
            text_body: Some(text_body),
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "noreply@blocstage.com".to_string()),
            from_name: Some("BlocStage".to_string()),
        };

        let message_id = self.provider.send_email(request).await?;
        log::info!("✅ Password reset email sent to {}: {}", to_email, message_id);
        
        Ok(())
    }

    pub async fn send_password_changed_email(&self, to_email: &str, to_name: &str) -> Result<()> {
        let mut context = HashMap::new();
        context.insert("user_name", to_name);
        context.insert("app_name", "BlocStage");

        let html_body = self.template_renderer.render("password_changed", &context)?;
        let text_body = format!(
            "Hi {},\n\nYour password has been successfully changed.\n\nIf you didn't make this change, please contact support immediately.\n\nThanks,\nBlocStage Team",
            to_name
        );

        let request = EmailRequest {
            to: to_email.to_string(),
            to_name: Some(to_name.to_string()),
            subject: "Password Changed - BlocStage".to_string(),
            html_body,
            text_body: Some(text_body),
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "noreply@blocstage.com".to_string()),
            from_name: Some("BlocStage".to_string()),
        };

        let message_id = self.provider.send_email(request).await?;
        log::info!("✅ Password changed email sent to {}: {}", to_email, message_id);
        
        Ok(())
    }

    pub async fn send_account_deleted_email(&self, to_email: &str, to_name: &str) -> Result<()> {
        let mut context = HashMap::new();
        context.insert("user_name", to_name);
        context.insert("app_name", "BlocStage");

        let html_body = self.template_renderer.render("account_deleted", &context)?;
        let text_body = format!(
            "Hi {},\n\nYour BlocStage account has been successfully deleted.\n\nThanks for being part of our community.\n\nBlocStage Team",
            to_name
        );

        let request = EmailRequest {
            to: to_email.to_string(),
            to_name: Some(to_name.to_string()),
            subject: "Account Deleted - BlocStage".to_string(),
            html_body,
            text_body: Some(text_body),
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "noreply@blocstage.com".to_string()),
            from_name: Some("BlocStage".to_string()),
        };

        let message_id = self.provider.send_email(request).await?;
        log::info!("✅ Account deleted email sent to {}: {}", to_email, message_id);
        
        Ok(())
    }

    pub async fn health_check(&self) -> Result<bool> {
        self.provider.health_check().await
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.provider_name()
    }
}