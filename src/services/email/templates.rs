use anyhow::Result;
use handlebars::Handlebars;
use std::collections::HashMap;
use std::env;

#[derive(Debug, Clone)]
pub struct TemplateRenderer {
    handlebars: Handlebars<'static>,
}

#[derive(Debug, Clone)]
pub struct SendGridTemplates {
    pub email_verification: String,
    pub password_reset: String,
    pub welcome: String,
    pub password_changed: String,
    pub account_deleted: String,
}

impl SendGridTemplates {
    pub fn new() -> Self {
        Self {
            email_verification: env::var("SENDGRID_TEMPLATE_EMAIL_VERIFICATION")
                .unwrap_or_else(|_| "d-b81b5459733843fea19aab027e9b2c93".to_string()),
            password_reset: env::var("SENDGRID_TEMPLATE_PASSWORD_RESET")
                .unwrap_or_else(|_| "d-c6d9883b870e446f823673a4acff4d3b".to_string()),
            welcome: env::var("SENDGRID_TEMPLATE_WELCOME")
                .unwrap_or_else(|_| "d-42940cc92e02478aa9b16d81d13fc905".to_string()),
            password_changed: env::var("SENDGRID_TEMPLATE_PASSWORD_CHANGED")
                .unwrap_or_else(|_| "d-placeholder-changed".to_string()),
            account_deleted: env::var("SENDGRID_TEMPLATE_ACCOUNT_DELETED")
                .unwrap_or_else(|_| "d-placeholder-deleted".to_string()),
        }
    }
}

impl TemplateRenderer {
    pub fn new() -> Result<Self> {
        let mut handlebars = Handlebars::new();

        // Register templates for SMTP fallback
        handlebars.register_template_string("email_verification", EMAIL_VERIFICATION_TEMPLATE)?;
        handlebars.register_template_string("password_reset", PASSWORD_RESET_TEMPLATE)?;
        handlebars.register_template_string("password_changed", PASSWORD_CHANGED_TEMPLATE)?;
        handlebars.register_template_string("account_deleted", ACCOUNT_DELETED_TEMPLATE)?;
        handlebars.register_template_string("welcome", WELCOME_TEMPLATE)?;

        Ok(Self { handlebars })
    }

    pub fn render(&self, template_name: &str, data: &HashMap<&str, &str>) -> Result<String> {
        let rendered = self.handlebars.render(template_name, data)?;
        Ok(rendered)
    }
}

// Base email template
const EMAIL_BASE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{subject}} - {{app_name}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #ddd; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }
        .button:hover { background: #5a6fd8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{app_name}}</h1>
            <p>Decentralized Event Ticketing</p>
        </div>
        <div class="content">
            {{{body}}}
        </div>
        <div class="footer">
            <p>© 2025 {{app_name}}. All rights reserved.</p>
            <p>This email was sent to you as part of your {{app_name}} account activity.</p>
        </div>
    </div>
</body>
</html>
"#;

const EMAIL_VERIFICATION_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email - {{app_name}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #ddd; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .button:hover { background: #5a6fd8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{app_name}}</h1>
            <p>Decentralized Event Ticketing</p>
        </div>
        <div class="content">
            <h2>Welcome, {{first_name}}! 🎉</h2>
            <p>Thank you for joining {{app_name}}! To complete your registration and start exploring amazing events, please verify your email address.</p>
            
            <div style="text-align: center;">
                <a href="{{verification_url}}" class="button">Verify Email Address</a>
            </div>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style="background: #f8f9fa; padding: 10px; border-radius: 5px; word-break: break-all;">{{verification_url}}</p>
            
            <p><strong>Why verify your email?</strong></p>
            <ul>
                <li>✅ Access all {{app_name}} features</li>
                <li>🎫 Purchase and manage event tickets</li>
                <li>📧 Receive important account notifications</li>
                <li>🔒 Keep your account secure</li>
            </ul>
            
            <p>If you didn't create an account with {{app_name}}, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2025 {{app_name}}. All rights reserved.</p>
            <p>This email was sent to you as part of your {{app_name}} account registration.</p>
        </div>
    </div>
</body>
</html>
"#;

const PASSWORD_RESET_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password - {{app_name}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #ddd; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .button:hover { background: #c82333; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{app_name}}</h1>
            <p>Password Reset Request</p>
        </div>
        <div class="content">
            <h2>Hi {{first_name}}, 🔐</h2>
            <p>We received a request to reset the password for your {{app_name}} account.</p>
            
            <div style="text-align: center;">
                <a href="{{reset_url}}" class="button">Reset Password</a>
            </div>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style="background: #f8f9fa; padding: 10px; border-radius: 5px; word-break: break-all;">{{reset_url}}</p>
            
            <div class="warning">
                <p><strong>⚠️ Security Notice:</strong></p>
                <ul>
                    <li>This link will expire in 24 hours</li>
                    <li>You can only use this link once</li>
                    <li>If you didn't request this reset, please ignore this email</li>
                </ul>
            </div>
            
            <p>If you continue to have problems, please contact our support team.</p>
        </div>
        <div class="footer">
            <p>© 2025 {{app_name}}. All rights reserved.</p>
            <p>This email was sent because a password reset was requested for your account.</p>
        </div>
    </div>
</body>
</html>
"#;

const PASSWORD_CHANGED_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed - {{app_name}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #ddd; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }
        .success { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{app_name}}</h1>
            <p>Password Successfully Changed</p>
        </div>
        <div class="content">
            <h2>Hi {{first_name}}, ✅</h2>
            
            <div class="success">
                <p><strong>Your password has been successfully changed!</strong></p>
            </div>
            
            <p>Your {{app_name}} account password was recently updated. You can now log in using your new password.</p>
            
            <p><strong>What this means:</strong></p>
            <ul>
                <li>🔒 Your account is now secured with your new password</li>
                <li>📱 You may need to log in again on your devices</li>
                <li>🔐 All previous login sessions have been invalidated</li>
            </ul>
            
            <p><strong>⚠️ If you didn't make this change:</strong></p>
            <p>Please contact our support team immediately at support@blocstage.com</p>
        </div>
        <div class="footer">
            <p>© 2025 {{app_name}}. All rights reserved.</p>
            <p>This email was sent to confirm your password change.</p>
        </div>
    </div>
</body>
</html>
"#;

const WELCOME_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - {{app_name}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #ddd; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }
        .button:hover { background: #218838; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to {{app_name}}!</h1>
            <p>🎉 Your account is ready!</p>
        </div>
        <div class="content">
            <h2>Hi {{first_name}},</h2>
            <p>Welcome to {{app_name}} - the future of event ticketing! Your account has been successfully created and verified.</p>
            
            <div style="text-align: center;">
                <a href="{{app_url}}/dashboard" class="button">Explore Events</a>
            </div>
            
            <p><strong>🚀 What you can do now:</strong></p>
            <ul>
                <li>🎫 <strong>Buy Tickets:</strong> Secure, blockchain-powered ticket purchases</li>
                <li>🔒 <strong>Own Your Tickets:</strong> True ownership with NFT technology</li>
                <li>💱 <strong>Transfer & Resell:</strong> Safely transfer tickets to friends</li>
                <li>📱 <strong>Mobile Access:</strong> Access tickets from anywhere</li>
                <li>🎪 <strong>Create Events:</strong> Become an event organizer</li>
            </ul>
            
            <p>Thanks for joining the {{app_name}} community!</p>
            <p><em>The {{app_name}} Team</em></p>
        </div>
        <div class="footer">
            <p>© 2025 {{app_name}}. All rights reserved.</p>
            <p>This email was sent because you created a {{app_name}} account.</p>
        </div>
    </div>
</body>
</html>
"#;

const ACCOUNT_DELETED_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Deleted - {{app_name}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #6c757d 0%, #495057 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #ddd; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{app_name}}</h1>
            <p>Account Deletion Confirmed</p>
        </div>
        <div class="content">
            <h2>Goodbye {{first_name}} 👋</h2>
            
            <p>Your {{app_name}} account has been successfully deleted as requested.</p>
            
            <p><strong>What happens next:</strong></p>
            <ul>
                <li>🗑️ All your account data has been permanently removed</li>
                <li>🎫 Any active tickets have been cancelled</li>
                <li>💳 Pending refunds will be processed within 3-5 business days</li>
                <li>📧 You'll stop receiving emails from us</li>
            </ul>
            
            <p>Thank you for being part of the {{app_name}} community. We're sorry to see you go!</p>
            
            <p>If you change your mind, you're always welcome to create a new account.</p>
            
        </div>
        <div class="footer">
            <p>© 2025 {{app_name}}. All rights reserved.</p>
            <p>This is the final email you'll receive from us.</p>
        </div>
    </div>
</body>
</html>
"#;