use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEmailRequest {
    pub to: String,
    pub to_name: Option<String>,
    pub template_id: String,
    pub template_data: HashMap<String, String>,
    pub from: String,
    pub from_name: Option<String>,
}

#[async_trait::async_trait]
pub trait EmailProvider: Send + Sync {
    async fn send_email(&self, request: EmailRequest) -> Result<String>; // Returns message ID
    async fn send_template_email(&self, request: TemplateEmailRequest) -> Result<String>; // Returns message ID
    async fn health_check(&self) -> Result<bool>;
    fn provider_name(&self) -> &'static str;
}

#[derive(Clone)]
pub struct EmailService {
    provider: Arc<dyn EmailProvider>,
    template_renderer: templates::TemplateRenderer,
    sendgrid_templates: templates::SendGridTemplates,
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
        let sendgrid_templates = templates::SendGridTemplates::new();
        
        Ok(Self {
            provider,
            template_renderer,
            sendgrid_templates,
        })
    }

    pub async fn global() -> Result<Arc<Self>> {
        static EMAIL_GLOBAL: OnceLock<Arc<EmailService>> = OnceLock::new();
        if let Some(svc) = EMAIL_GLOBAL.get() {
            return Ok(svc.clone());
        }
        let created = Arc::new(EmailService::new().await?);
        let _ = EMAIL_GLOBAL.set(created.clone());
        Ok(created)
    }

    async fn create_provider() -> Result<Arc<dyn EmailProvider>> {
        let env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        
        match env.as_str() {
            "production" => {
                log::info!("🚀 Initializing SendGrid email provider for production");
                Ok(Arc::new(providers::SendGridProvider::new().await?))
            }
            _ => {
                log::info!("🛠️ Initializing SMTP email provider for development");
                Ok(Arc::new(providers::SmtpProvider::new().await?))
            }
        }
    }

    pub async fn send_raw_email(&self, request: EmailRequest) -> Result<String> {
        self.provider.as_ref().send_email(request).await
    }

    fn should_use_templates(&self) -> bool {
        self.provider.provider_name() == "SendGrid" && 
        std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) == "production"
    }

    pub async fn send_verification_email(&self, to_email: &str, first_name: &str, token: &str) -> Result<()> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
            token
        );

        if self.should_use_templates() {
            let mut template_data = HashMap::new();
            template_data.insert("first_name".to_string(), first_name.to_string());
            template_data.insert("verification_url".to_string(), verification_url);
            template_data.insert("app_name".to_string(), "BlocStage".to_string());
            template_data.insert("app_url".to_string(), std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()));

            let request = TemplateEmailRequest {
                to: to_email.to_string(),
                to_name: Some(first_name.to_string()),
                template_id: self.sendgrid_templates.email_verification.clone(),
                template_data,
                from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
                from_name: Some("BlocStage".to_string()),
            };

            let message_id = self.provider.as_ref().send_template_email(request).await?;
            log::info!("✅ Verification email (template) sent to {}: {}", to_email, message_id);
        } else {
            let mut context = HashMap::new();
            context.insert("first_name", first_name);
            context.insert("verification_url", &verification_url);
            context.insert("app_name", "BlocStage");

            let html_body = self.template_renderer.render("email_verification", &context)?;
            let text_body = format!(
                "Hi {},\n\nPlease verify your email by clicking this link: {}\n\nThanks,\nBlocStage Team",
                first_name, verification_url
            );

            let request = EmailRequest {
                to: to_email.to_string(),
                to_name: Some(first_name.to_string()),
                subject: "Verify Your BlocStage Account".to_string(),
                html_body,
                text_body: Some(text_body),
                from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
                from_name: Some("BlocStage".to_string()),
            };

            let message_id = self.provider.as_ref().send_email(request).await?;
            log::info!("✅ Verification email sent to {}: {}", to_email, message_id);
        }
        
        Ok(())
    }

    pub async fn send_password_reset_email(&self, to_email: &str, first_name: &str, token: &str) -> Result<()> {
        let reset_url = format!(
            "{}/reset-password?token={}",
            std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
            token
        );

        if self.should_use_templates() {
            let mut template_data = HashMap::new();
            template_data.insert("first_name".to_string(), first_name.to_string());
            template_data.insert("reset_url".to_string(), reset_url);
            template_data.insert("app_name".to_string(), "BlocStage".to_string());
            template_data.insert("app_url".to_string(), std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()));
            template_data.insert("user_email".to_string(), to_email.to_string());

            let request = TemplateEmailRequest {
                to: to_email.to_string(),
                to_name: Some(first_name.to_string()),
                template_id: self.sendgrid_templates.password_reset.clone(),
                template_data,
                from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
                from_name: Some("BlocStage".to_string()),
            };

            let message_id = self.provider.as_ref().send_template_email(request).await?;
            log::info!("✅ Password reset email (template) sent to {}: {}", to_email, message_id);
        } else {
            let mut context = HashMap::new();
            context.insert("first_name", first_name);
            context.insert("reset_url", &reset_url);
            context.insert("app_name", "BlocStage");

            let html_body = self.template_renderer.render("password_reset", &context)?;
            let text_body = format!(
                "Hi {},\n\nReset your password by clicking this link: {}\n\nIf you didn't request this, please ignore this email.\n\nThanks,\nBlocStage Team",
                first_name, reset_url
            );

            let request = EmailRequest {
                to: to_email.to_string(),
                to_name: Some(first_name.to_string()),
                subject: "Reset Your BlocStage Password".to_string(),
                html_body,
                text_body: Some(text_body),
                from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
                from_name: Some("BlocStage".to_string()),
            };

            let message_id = self.provider.as_ref().send_email(request).await?;
            log::info!("✅ Password reset email sent to {}: {}", to_email, message_id);
        }
        
        Ok(())
    }

    pub async fn send_welcome_email(&self, to_email: &str, first_name: &str) -> Result<()> {
        if self.should_use_templates() {
            let mut template_data = HashMap::new();
            template_data.insert("first_name".to_string(), first_name.to_string());
            template_data.insert("app_name".to_string(), "BlocStage".to_string());
            template_data.insert("app_url".to_string(), std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()));
            template_data.insert("user_email".to_string(), to_email.to_string());

            let request = TemplateEmailRequest {
                to: to_email.to_string(),
                to_name: Some(first_name.to_string()),
                template_id: self.sendgrid_templates.welcome.clone(),
                template_data,
                from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
                from_name: Some("BlocStage".to_string()),
            };

            let message_id = self.provider.as_ref().send_template_email(request).await?;
            log::info!("✅ Welcome email (template) sent to {}: {}", to_email, message_id);
        } else {
            let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
            let mut context = HashMap::new();
            context.insert("first_name", first_name);
            context.insert("app_name", "BlocStage");
            context.insert("app_url", &app_url);

            let html_body = self.template_renderer.render("welcome", &context)?;
            let text_body = format!(
                "Hi {},\n\nWelcome to BlocStage! Your account has been successfully created and verified.\n\nExplore events at: {}\n\nThanks,\nBlocStage Team",
                first_name, 
                std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
            );

            let request = EmailRequest {
                to: to_email.to_string(),
                to_name: Some(first_name.to_string()),
                subject: format!("Welcome to BlocStage, {}!", first_name),
                html_body,
                text_body: Some(text_body),
                from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
                from_name: Some("BlocStage".to_string()),
            };

            let message_id = self.provider.as_ref().send_email(request).await?;
            log::info!("✅ Welcome email sent to {}: {}", to_email, message_id);
        }
        
        Ok(())
    }

    pub async fn send_password_changed_email(&self, to_email: &str, first_name: &str) -> Result<()> {
        let mut context = HashMap::new();
        context.insert("first_name", first_name);
        context.insert("app_name", "BlocStage");

        let html_body = self.template_renderer.render("password_changed", &context)?;
        let text_body = format!(
            "Hi {},\n\nYour password has been successfully changed.\n\nIf you didn't make this change, please contact support immediately.\n\nThanks,\nBlocStage Team",
            first_name
        );

        let request = EmailRequest {
            to: to_email.to_string(),
            to_name: Some(first_name.to_string()),
            subject: "Password Changed - BlocStage".to_string(),
            html_body,
            text_body: Some(text_body),
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
            from_name: Some("BlocStage".to_string()),
        };

        let message_id = self.provider.as_ref().send_email(request).await?;
        log::info!("✅ Password changed email sent to {}: {}", to_email, message_id);
        
        Ok(())
    }

    pub async fn send_account_deleted_email(&self, to_email: &str, first_name: &str) -> Result<()> {
        let mut context = HashMap::new();
        context.insert("first_name", first_name);
        context.insert("app_name", "BlocStage");

        let html_body = self.template_renderer.render("account_deleted", &context)?;
        let text_body = format!(
            "Hi {},\n\nYour BlocStage account has been successfully deleted.\n\nThanks for being part of our community.\n\nBlocStage Team",
            first_name
        );

        let request = EmailRequest {
            to: to_email.to_string(),
            to_name: Some(first_name.to_string()),
            subject: "Account Deleted - BlocStage".to_string(),
            html_body,
            text_body: Some(text_body),
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "no-reply@blocstage.com".to_string()),
            from_name: Some("BlocStage".to_string()),
        };

        let message_id = self.provider.as_ref().send_email(request).await?;
        log::info!("✅ Account deleted email sent to {}: {}", to_email, message_id);
        
        Ok(())
    }

    pub async fn health_check(&self) -> Result<bool> {
        self.provider.as_ref().health_check().await
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.as_ref().provider_name()
    }
}