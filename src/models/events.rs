use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;

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
}

#[derive(Debug, Deserialize)]
pub struct CreateEventRequest {
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

impl Event {
    pub async fn create(pool: &PgPool, organizer_id: Uuid, event: CreateEventRequest) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let event = sqlx::query_as!(
            Event,
            r#"
            INSERT INTO events (id, organizer_id, title, description, location, start_time, end_time, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
            id, organizer_id, event.title, event.description, event.location, 
            event.start_time, event.end_time, now, now
        )
        .fetch_one(pool)
        .await?;
        
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
}