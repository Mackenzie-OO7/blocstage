use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgArguments, Arguments};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use log::{info, error};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub organizer_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: String, // "active", "cancelled", "completed"
    pub banner_image_url: Option<String>,
    pub category: Option<String>,
    #[sqlx(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEventRequest {
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub banner_image_url: Option<String>,
    pub category: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEventRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub banner_image_url: Option<String>,
    pub category: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SearchEventsRequest {
    pub query: Option<String>,
    pub category: Option<String>,
    pub location: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub tags: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Event {
     pub async fn create(pool: &PgPool, organizer_id: Uuid, event: CreateEventRequest) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        // just debug logging
        info!("🎪 Creating event with:");
        info!("   - id: {}", id);
        info!("   - organizer_id: {}", organizer_id);
        info!("   - title: {}", event.title);
        info!("   - start_time: {}", event.start_time);
        info!("   - end_time: {}", event.end_time);
        info!("   - tags: {:?}", event.tags);
        
        let tags_json: Option<serde_json::Value> = match event.tags {
            Some(tags) => {
                let json_val = serde_json::to_value(tags)?;
                info!("   - tags converted to JSON: {}", json_val);
                Some(json_val)
            },
            None => {
                info!("   - no tags provided");
                None
            }
        };
        
        let event = sqlx::query_as!(
            Event,
            r#"
            INSERT INTO events (
                id, organizer_id, title, description, location, 
                start_time, end_time, created_at, updated_at,
                status, banner_image_url, category, tags
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
            id, organizer_id, event.title, event.description, event.location, 
            event.start_time, event.end_time, now, now,
            "active", event.banner_image_url, event.category, 
            tags_json
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("❌ Database error creating event: {}", e);
            e
        })?;
        
        info!("✅ Event created successfully: {}", event.id);
        Ok(event)
    }
    
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let event = sqlx::query_as!(
            Event,
            r#"SELECT * FROM events WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(event)
    }
    
    pub async fn find_by_organizer(pool: &PgPool, organizer_id: Uuid) -> Result<Vec<Self>> {
        let events = sqlx::query_as!(
            Event,
            r#"SELECT * FROM events WHERE organizer_id = $1 ORDER BY created_at DESC"#,
            organizer_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(events)
    }
    
    pub async fn update(&self, pool: &PgPool, update: UpdateEventRequest) -> Result<Self> {
        let now = Utc::now();
        
        let mut query = String::from("UPDATE events SET updated_at = $1");
        let mut args = PgArguments::default();
        args.add(now);
        
        let mut param_index = 2;
        
        // add each field that is provided in the update request
        if let Some(title) = &update.title {
            query.push_str(&format!(", title = ${}", param_index));
            args.add(title);
            param_index += 1;
        }
        
        if let Some(description) = &update.description {
            query.push_str(&format!(", description = ${}", param_index));
            args.add(description);
            param_index += 1;
        }
        
        if let Some(location) = &update.location {
            query.push_str(&format!(", location = ${}", param_index));
            args.add(location);
            param_index += 1;
        }
        
        if let Some(start_time) = &update.start_time {
            query.push_str(&format!(", start_time = ${}", param_index));
            args.add(start_time);
            param_index += 1;
        }
        
        if let Some(end_time) = &update.end_time {
            query.push_str(&format!(", end_time = ${}", param_index));
            args.add(end_time);
            param_index += 1;
        }
        
        if let Some(banner_image_url) = &update.banner_image_url {
            query.push_str(&format!(", banner_image_url = ${}", param_index));
            args.add(banner_image_url);
            param_index += 1;
        }
        
        if let Some(category) = &update.category {
            query.push_str(&format!(", category = ${}", param_index));
            args.add(category);
            param_index += 1;
        }
        
        if let Some(tags) = &update.tags {
            query.push_str(&format!(", tags = ${}", param_index));
            args.add(tags);
            param_index += 1;
        }
        
        query.push_str(&format!(" WHERE id = ${} RETURNING *", param_index));
        args.add(self.id);
        
        let event = sqlx::query_as_with::<_, Event, _>(&query, args)
            .fetch_one(pool)
            .await?;
        
        Ok(event)
    }
    
    pub async fn cancel(&self, pool: &PgPool) -> Result<Self> {
        let event = sqlx::query_as!(
            Event,
            r#"
            UPDATE events
            SET status = 'cancelled', updated_at = $1
            WHERE id = $2
            RETURNING *
            "#,
            Utc::now(), self.id
        )
        .fetch_one(pool)
        .await?;
        
        Ok(event)
    }
    
    pub async fn search(pool: &PgPool, search: SearchEventsRequest) -> Result<Vec<Self>> {
        let mut query = String::from("SELECT * FROM events WHERE status != 'cancelled'");
        let mut args = PgArguments::default();
        let mut param_index = 1;
        
        // add search conditions based on the provided parameters
        if let Some(q) = &search.query {
            let pattern = format!("%{}%", q);
            query.push_str(&format!(" AND (title ILIKE ${} OR description ILIKE ${})", 
                param_index, param_index));
            args.add(pattern);
            param_index += 1;
        }
        
        if let Some(category) = &search.category {
            query.push_str(&format!(" AND category = ${}", param_index));
            args.add(category);
            param_index += 1;
        }
        
        if let Some(location) = &search.location {
            let pattern = format!("%{}%", location);
            query.push_str(&format!(" AND location ILIKE ${}", param_index));
            args.add(pattern);
            param_index += 1;
        }
        
        if let Some(start_date) = &search.start_date {
            query.push_str(&format!(" AND start_time >= ${}", param_index));
            args.add(start_date);
            param_index += 1;
        }
        
        if let Some(end_date) = &search.end_date {
            query.push_str(&format!(" AND end_time <= ${}", param_index));
            args.add(end_date);
            param_index += 1;
        }
        
        if let Some(tags) = &search.tags {
            if !tags.is_empty() {
                // convert tags array to JSONB array for proper PostgreSQL comparison
                let tags_json = serde_json::to_value(tags)?;
                query.push_str(&format!(" AND tags @> ${}", param_index));
                args.add(tags_json);
                param_index += 1;
            }
        }
        
        query.push_str(" ORDER BY start_time ASC");
        
        // add limit and offset with proper typecasting
        let limit = search.limit.unwrap_or(10);
        query.push_str(&format!(" LIMIT ${}", param_index));
        args.add(limit);
        param_index += 1;
        
        let offset = search.offset.unwrap_or(0);
        query.push_str(&format!(" OFFSET ${}", param_index));
        args.add(offset);
        
        let events = sqlx::query_as_with::<_, Event, _>(&query, args)
            .fetch_all(pool)
            .await
            .map_err(|e| anyhow::anyhow!("Database error during search: {}", e))?;
        
        Ok(events)
    }
}