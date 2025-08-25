use anyhow::{anyhow, Result};
use serde_json::json;
use std::env;
use log::info;

#[derive(Clone)]
pub struct StorageService {
    base_url: String,
    bucket: String,
    service_key: String,
}

impl StorageService {
    pub fn new() -> Result<Self> {
        let base_url = env::var("STORAGE_URL")
            .or_else(|_| env::var("SUPABASE_URL"))
            .map_err(|_| anyhow!("STORAGE_URL environment variable not set"))?;
        let service_key = env::var("STORAGE_SERVICE_KEY")
            .or_else(|_| env::var("SUPABASE_SERVICE_ROLE_KEY"))
            .map_err(|_| anyhow!("STORAGE_SERVICE_KEY environment variable not set"))?;
        let bucket = env::var("STORAGE_BUCKET")
            .unwrap_or_else(|_| "ticket-pdfs".to_string());

        Ok(Self {
            base_url,
            bucket,
            service_key,
        })
    }

    pub async fn upload_pdf(&self, file_path: &str, content: Vec<u8>) -> Result<String> {
        let full_path = format!("{}/{}", self.bucket, file_path);
        
        let client = reqwest::Client::new();
        let upload_url = format!("{}/storage/v1/object/{}", self.base_url, full_path);

        let response = client
            .post(&upload_url)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("apikey", &self.service_key)
            .header("Content-Type", "text/html")
            .header("x-upsert", "true")
            .body(content)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to upload to storage: {}", error_text));
        }

        let public_url = format!("{}/storage/v1/object/public/{}", self.base_url, full_path);
        info!("📄 PDF uploaded to storage: {}", public_url);
        
        Ok(public_url)
    }

    pub async fn delete_pdf(&self, file_path: &str) -> Result<()> {
        let full_path = format!("{}/{}", self.bucket, file_path);
        
        let client = reqwest::Client::new();
        let delete_url = format!("{}/storage/v1/object/{}", self.base_url, full_path);

        let response = client
            .delete(&delete_url)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("apikey", &self.service_key)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to delete from storage: {}", error_text));
        }

        info!("🗑️ PDF deleted from storage: {}", full_path);
        Ok(())
    }

    pub async fn get_download_url(&self, file_path: &str, expires_in: Option<u64>) -> Result<String> {
        let full_path = format!("{}/{}", self.bucket, file_path);
        let expires = expires_in.unwrap_or(3600); // Default 1 hour
        
        let client = reqwest::Client::new();
        let signed_url_endpoint = format!("{}/storage/v1/object/sign/{}", self.base_url, full_path);

        let response = client
            .post(&signed_url_endpoint)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("apikey", &self.service_key)
            .header("Content-Type", "application/json")
            .json(&json!({
                "expiresIn": expires
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to create signed URL: {}", error_text));
        }

        let response_json: serde_json::Value = response.json().await?;
        let signed_url = response_json["signedURL"]
            .as_str()
            .ok_or_else(|| anyhow!("Invalid response from storage service"))?;

        let full_signed_url = format!("{}{}", self.base_url, signed_url);
        Ok(full_signed_url)
    }
}