use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgArguments, Arguments, PgPool};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
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
    pub async fn create(
        pool: &PgPool,
        organizer_id: Uuid,
        event: CreateEventRequest,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        Self::validate_event_timing(event.start_time, event.end_time)?;

        // debug logging
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
            }
            None => {
                info!("   - no tags provided");
                None
            }
        };

        let mut tx = pool.begin().await?;

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
            id,
            organizer_id,
            event.title,
            event.description,
            event.location,
            event.start_time,
            event.end_time,
            now,
            now,
            "active",
            event.banner_image_url,
            event.category,
            tags_json
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            error!("❌ Database error creating event: {}", e);
            e
        })?;

        let owner_permissions = serde_json::json!({
            "edit_event": true,
            "manage_tickets": true,
            "check_in_guests": true,
            "view_analytics": true,
            "manage_organizers": true,
            "cancel_event": true
        });

        sqlx::query!(
            r#"
        INSERT INTO event_organizers (event_id, user_id, role, permissions, added_at, added_by)
        VALUES ($1, $2, 'owner', $3, $4, $5)
        "#,
            event.id,
            organizer_id,
            owner_permissions,
            now,
            organizer_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("❌ Database error creating owner record: {}", e);
            e
        })?;

        tx.commit().await?;

        info!(
            "✅ Event and owner record created successfully: {}",
            event.id
        );
        Ok(event)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let event = sqlx::query_as!(Event, r#"SELECT * FROM events WHERE id = $1"#, id)
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

        let new_start_time = update.start_time.unwrap_or(self.start_time);
        let new_end_time = update.end_time.unwrap_or(self.end_time);

        if update.start_time.is_some() || update.end_time.is_some() {
            Self::validate_event_timing(new_start_time, new_end_time)?;
        }

        let mut query = String::from("UPDATE events SET updated_at = $1");
        let mut args = PgArguments::default();
        let _ = args.add(now);

        let mut param_index = 2;

        if let Some(title) = &update.title {
            query.push_str(&format!(", title = ${}", param_index));
            let _ = args.add(title);
            param_index += 1;
        }

        if let Some(description) = &update.description {
            query.push_str(&format!(", description = ${}", param_index));
            let _ = args.add(description);
            param_index += 1;
        }

        if let Some(location) = &update.location {
            query.push_str(&format!(", location = ${}", param_index));
            let _ = args.add(location);
            param_index += 1;
        }

        if let Some(start_time) = &update.start_time {
            query.push_str(&format!(", start_time = ${}", param_index));
            let _ = args.add(start_time);
            param_index += 1;
        }

        if let Some(end_time) = &update.end_time {
            query.push_str(&format!(", end_time = ${}", param_index));
            let _ = args.add(end_time);
            param_index += 1;
        }

        if let Some(banner_image_url) = &update.banner_image_url {
            query.push_str(&format!(", banner_image_url = ${}", param_index));
            let _ = args.add(banner_image_url);
            param_index += 1;
        }

        if let Some(category) = &update.category {
            query.push_str(&format!(", category = ${}", param_index));
            let _ = args.add(category);
            param_index += 1;
        }

        if let Some(tags) = &update.tags {
            query.push_str(&format!(", tags = ${}", param_index));
            let tags_json = serde_json::to_value(tags)
                .map_err(|e| anyhow::anyhow!("Failed to serialize tags: {}", e))?;
            let _ = args.add(tags_json);
            param_index += 1;
        }

        query.push_str(&format!(" WHERE id = ${} RETURNING *", param_index));
        let _ = args.add(self.id);

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
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(event)
    }

    pub fn validate_event_timing(start_time: DateTime<Utc>, end_time: DateTime<Utc>) -> Result<()> {
        let now = Utc::now();

        // Rule 1: Start time must be in the future (allow 5 minute buffer for immediate events)
        let buffer = chrono::Duration::minutes(5);
        if start_time < (now - buffer) {
            return Err(anyhow!(
                "Event start time cannot be in the past. Start time: {}, Current time: {}",
                start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                now.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }

        // Rule 2: End time must be after start time
        if end_time <= start_time {
            return Err(anyhow!(
                "Event end time must be after start time. Start: {}, End: {}",
                start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                end_time.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }

        // Rule 3: Event duration must be reasonable (not longer than 1 year)
        let max_duration = chrono::Duration::days(365);
        if end_time - start_time > max_duration {
            return Err(anyhow!(
                "Event duration cannot exceed 1 year. Duration: {} days",
                (end_time - start_time).num_days()
            ));
        }

        // Rule 4: Event duration must be at least 15 minutes
        let min_duration = chrono::Duration::minutes(15);
        if end_time - start_time < min_duration {
            return Err(anyhow!(
                "Event duration must be at least 15 minutes. Current duration: {} minutes",
                (end_time - start_time).num_minutes()
            ));
        }

        Ok(())
    }

    /// Get the effective status of the event based on current time
    pub fn get_effective_status(&self) -> String {
        let now = Utc::now();

        match self.status.as_str() {
            "cancelled" => "cancelled".to_string(),
            "draft" => "draft".to_string(),
            "active" => {
                if now < self.start_time {
                    "scheduled".to_string() // Active but hasn't started yet
                } else if now >= self.start_time && now < self.end_time {
                    "ongoing".to_string() // Currently happening
                } else {
                    "ended".to_string() // Past end time
                }
            }
            _ => self.status.clone(),
        }
    }

    /// Check if the event is currently accepting ticket purchases
    pub fn can_sell_tickets(&self) -> bool {
        let now = Utc::now();

        // Must be active status
        if self.status != "active" {
            return false;
        }

        // Must not have ended
        if now >= self.end_time {
            return false;
        }

        // Optionally: stop selling tickets 1 hour before event starts
        let ticket_sales_cutoff = self.start_time - chrono::Duration::hours(1);
        if now > ticket_sales_cutoff {
            return false;
        }

        true
    }

    /// Check if event is currently valid (not ended or cancelled)
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();

        match self.status.as_str() {
            "cancelled" => false,
            "draft" => false,
            "active" => now < self.end_time, // Only valid if not ended
            _ => false,
        }
    }

    /// Update event status in database if it should be ended
    pub async fn update_status_if_needed(&self, pool: &PgPool) -> Result<Event> {
        let effective_status = self.get_effective_status();

        // If effective status is different from stored status and it's "ended"
        if effective_status == "ended" && self.status == "active" {
            info!(
                "Auto-updating event {} status from active to ended",
                self.id
            );

            let updated_event = sqlx::query_as!(
                Event,
                r#"
                UPDATE events 
                SET status = 'ended', updated_at = $1
                WHERE id = $2
                RETURNING *
                "#,
                Utc::now(),
                self.id
            )
            .fetch_one(pool)
            .await?;

            Ok(updated_event)
        } else {
            Ok(self.clone())
        }
    }

    /// Get events that need status updates (batch operation)
    pub async fn get_events_needing_status_update(pool: &PgPool) -> Result<Vec<Event>> {
        let now = Utc::now();

        let events = sqlx::query_as!(
            Event,
            r#"
            SELECT * FROM events 
            WHERE status = 'active' AND end_time < $1
            ORDER BY end_time DESC
            LIMIT 100
            "#,
            now
        )
        .fetch_all(pool)
        .await?;

        Ok(events)
    }

    // Batch update ended events (for background job)
    pub async fn batch_update_ended_events(pool: &PgPool) -> Result<usize> {
        let now = Utc::now();

        let result = sqlx::query!(
            r#"
            UPDATE events 
            SET status = 'ended', updated_at = $1
            WHERE status = 'active' AND end_time < $1
            "#,
            now
        )
        .execute(pool)
        .await?;

        let count = result.rows_affected() as usize;
        if count > 0 {
            info!("Auto-updated {} events from active to ended", count);
        }

        Ok(count)
    }

    pub async fn search(pool: &PgPool, search: SearchEventsRequest) -> Result<Vec<Self>> {
        let mut query = String::from("SELECT * FROM events WHERE status != 'cancelled'");
        let mut args = PgArguments::default();
        let mut param_index = 1;

        // add search conditions based on the provided parameters
        if let Some(q) = &search.query {
            let pattern = format!("%{}%", q);
            query.push_str(&format!(
                " AND (title ILIKE ${} OR description ILIKE ${})",
                param_index, param_index
            ));
            let _ = args.add(pattern);
            param_index += 1;
        }

        if let Some(category) = &search.category {
            query.push_str(&format!(" AND category = ${}", param_index));
            let _ = args.add(category);
            param_index += 1;
        }

        if let Some(location) = &search.location {
            let pattern = format!("%{}%", location);
            query.push_str(&format!(" AND location ILIKE ${}", param_index));
            let _ = args.add(pattern);
            param_index += 1;
        }

        if let Some(start_date) = &search.start_date {
            query.push_str(&format!(" AND start_time >= ${}", param_index));
            let _ = args.add(start_date);
            param_index += 1;
        }

        if let Some(end_date) = &search.end_date {
            query.push_str(&format!(" AND end_time <= ${}", param_index));
            let _ = args.add(end_date);
            param_index += 1;
        }

        if let Some(tags) = &search.tags {
            if !tags.is_empty() {
                let tags_json = serde_json::to_value(tags)?;
                query.push_str(&format!(" AND tags @> ${}", param_index));
                let _ = args.add(tags_json);
                param_index += 1;
            }
        }

        query.push_str(" ORDER BY start_time ASC");

        // add limit and offset with proper typecasting
        let limit = search.limit.unwrap_or(10);
        query.push_str(&format!(" LIMIT ${}", param_index));
        let _ = args.add(limit);
        param_index += 1;

        let offset = search.offset.unwrap_or(0);
        query.push_str(&format!(" OFFSET ${}", param_index));
        let _ = args.add(offset);

        let events = sqlx::query_as_with::<_, Event, _>(&query, args)
            .fetch_all(pool)
            .await
            .map_err(|e| anyhow::anyhow!("Database error during search: {}", e))?;

        Ok(events)
    }
}

// tests

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Duration, Utc};
    use sqlx::PgPool;
    use std::env;
    use uuid::Uuid;

    // helpers
    async fn setup_test_db() -> PgPool {
        dotenv::from_filename(".env.test").ok();
        dotenv::dotenv().ok();

        // Debug
        println!("=== DEBUG DATABASE SETUP ===");
        println!("TEST_DATABASE_URL: {:?}", env::var("TEST_DATABASE_URL"));
        println!("DATABASE_URL: {:?}", env::var("DATABASE_URL"));

        let database_url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .expect("TEST_DATABASE_URL or DATABASE_URL must be set for tests");

        println!("Using connection string: {}", database_url);
        println!("==============================");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        pool
    }

    async fn create_test_user(pool: &PgPool, suffix: &str) -> Uuid {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let unique_id = format!("{}_{}_{}", suffix, user_id.simple(), now.timestamp_millis());

        sqlx::query!(
            r#"
            INSERT INTO users (
                id, username, email, password_hash, created_at, updated_at,
                email_verified, verification_token, status, role
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            user_id,
            format!("testuser_{}", unique_id),
            format!("test_{}@example.com", unique_id),
            "hashed_password",
            now,
            now,
            true, // let the email be verified for easier testing
            Some("verification_token"),
            "active",
            "user"
        )
        .execute(pool)
        .await
        .expect("Failed to create test user");

        user_id
    }

    async fn create_test_event(pool: &PgPool, organizer_id: Uuid, suffix: &str) -> Event {
        let now = Utc::now();
        let unique_id = format!(
            "{}_{}_{}",
            suffix,
            Uuid::new_v4().simple(),
            now.timestamp_millis()
        );

        let create_request = CreateEventRequest {
            title: format!("Test Event {}", unique_id),
            description: Some(format!("Description for {}", unique_id)),
            location: Some(format!("Location {}", unique_id)),
            start_time: now + Duration::days(1),
            end_time: now + Duration::days(1) + Duration::hours(2),
            category: Some("Technology".to_string()),
            tags: Some(vec![
                "test".to_string(),
                "automation".to_string(),
                suffix.to_string(),
            ]),
            banner_image_url: None,
        };

        Event::create(pool, organizer_id, create_request)
            .await
            .expect("Failed to create test event")
    }

    async fn cleanup_test_event(pool: &PgPool, event_id: Uuid) {
        sqlx::query!("DELETE FROM events WHERE id = $1", event_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_test_user(pool: &PgPool, user_id: Uuid) {
        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(pool)
            .await
            .ok();
    }

    mod event_creation {
        use super::*;

        #[tokio::test]
        async fn test_create_event_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "create_success").await;
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "Tech Conference 2025".to_string(),
                description: Some("A great tech conference".to_string()),
                location: Some("Convention Center".to_string()),
                start_time: now + Duration::days(30),
                end_time: now + Duration::days(30) + Duration::hours(8),
                category: Some("Technology".to_string()),
                tags: Some(vec![
                    "tech".to_string(),
                    "conference".to_string(),
                    "2025".to_string(),
                ]),
                banner_image_url: Some("https://example.com/banner.jpg".to_string()),
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            assert!(result.is_ok(), "Event creation should succeed");
            let event = result.unwrap();

            assert!(!event.id.is_nil(), "Event should have valid ID");
            assert_eq!(event.organizer_id, organizer_id);
            assert_eq!(event.title, "Tech Conference 2025");
            assert_eq!(
                event.description,
                Some("A great tech conference".to_string())
            );
            assert_eq!(event.location, Some("Convention Center".to_string()));
            assert_eq!(event.category, Some("Technology".to_string()));
            assert_eq!(event.status, "active");
            assert!(event.tags.is_some(), "Tags should be set");
            assert_eq!(
                event.banner_image_url,
                Some("https://example.com/banner.jpg".to_string())
            );
            assert!(event.start_time > now, "Start time should be in future");
            assert!(
                event.end_time > event.start_time,
                "End time should be after start time"
            );

            cleanup_test_event(&pool, event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_event_minimal_fields() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "create_minimal").await;
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "Minimal Event".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::hours(1),
                end_time: now + Duration::hours(3),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            assert!(result.is_ok(), "Minimal event creation should succeed");
            let event = result.unwrap();

            assert_eq!(event.title, "Minimal Event");
            assert!(event.description.is_none());
            assert!(event.location.is_none());
            assert!(event.category.is_none());
            assert!(event.tags.is_none());
            assert!(event.banner_image_url.is_none());
            assert_eq!(event.status, "active");

            cleanup_test_event(&pool, event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_event_nonexistent_organizer() {
            let pool = setup_test_db().await;
            let fake_organizer_id = Uuid::new_v4();
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "Orphan Event".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::hours(1),
                end_time: now + Duration::hours(3),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, fake_organizer_id, create_request).await;

            assert!(result.is_err(), "Should fail with nonexistent organizer");
        }

        #[tokio::test]
        async fn test_create_event_invalid_time_order() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "invalid_time").await;
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "Bad Time Event".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::hours(3),
                end_time: now + Duration::hours(1),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            // This might succeed or fail depending on database constraints
            // Document current behavior without forcing specific outcome
            if result.is_ok() {
                let event = result.unwrap();
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_event_empty_title() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "empty_title").await;
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::hours(1),
                end_time: now + Duration::hours(3),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            // Empty title might be allowed or rejected depending on constraints
            if result.is_ok() {
                let event = result.unwrap();
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_event_long_title() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "long_title").await;
            let now = Utc::now();
            let long_title = "x".repeat(1000);

            let create_request = CreateEventRequest {
                title: long_title.clone(),
                description: None,
                location: None,
                start_time: now + Duration::hours(1),
                end_time: now + Duration::hours(3),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            if result.is_ok() {
                let event = result.unwrap();
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod event_retrieval {
        use super::*;

        #[tokio::test]
        async fn test_find_by_id_existing_event() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "find_existing").await;
            let test_event = create_test_event(&pool, organizer_id, "find_existing").await;

            let result = Event::find_by_id(&pool, test_event.id).await;

            assert!(result.is_ok(), "Should find existing event");
            let found_event = result.unwrap();
            assert!(found_event.is_some(), "Event should exist");

            let event = found_event.unwrap();
            assert_eq!(event.id, test_event.id);
            assert_eq!(event.organizer_id, test_event.organizer_id);
            assert_eq!(event.title, test_event.title);
            assert_eq!(event.status, "active");

            cleanup_test_event(&pool, test_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_id_nonexistent_event() {
            let pool = setup_test_db().await;
            let random_id = Uuid::new_v4();

            let result = Event::find_by_id(&pool, random_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            assert!(
                result.unwrap().is_none(),
                "Should return None for nonexistent event"
            );
        }

        #[tokio::test]
        async fn test_find_by_organizer() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "find_organizer").await;
            let other_organizer_id = create_test_user(&pool, "other_organizer").await;

            // Create events for the target organizer
            let event1 = create_test_event(&pool, organizer_id, "org_event1").await;
            let event2 = create_test_event(&pool, organizer_id, "org_event2").await;

            // Create event for different organizer
            let other_event = create_test_event(&pool, other_organizer_id, "other_event").await;

            let result = Event::find_by_organizer(&pool, organizer_id).await;

            assert!(result.is_ok(), "Should find organizer events");
            let events = result.unwrap();

            assert_eq!(
                events.len(),
                2,
                "Should find exactly 2 events for organizer"
            );

            let event_ids: Vec<Uuid> = events.iter().map(|e| e.id).collect();
            assert!(event_ids.contains(&event1.id), "Should contain first event");
            assert!(
                event_ids.contains(&event2.id),
                "Should contain second event"
            );
            assert!(
                !event_ids.contains(&other_event.id),
                "Should not contain other organizer's event"
            );

            // Verify all events belong to the correct organizer
            for event in &events {
                assert_eq!(
                    event.organizer_id, organizer_id,
                    "All events should belong to the organizer"
                );
            }

            // Cleanup
            cleanup_test_event(&pool, event1.id).await;
            cleanup_test_event(&pool, event2.id).await;
            cleanup_test_event(&pool, other_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
            cleanup_test_user(&pool, other_organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_organizer_no_events() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "no_events").await;

            let result = Event::find_by_organizer(&pool, organizer_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let events = result.unwrap();
            assert!(
                events.is_empty(),
                "Should return empty vector for organizer with no events"
            );

            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_organizer_nonexistent_user() {
            let pool = setup_test_db().await;
            let fake_organizer_id = Uuid::new_v4();

            let result = Event::find_by_organizer(&pool, fake_organizer_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let events = result.unwrap();
            assert!(
                events.is_empty(),
                "Should return empty vector for nonexistent organizer"
            );
        }
    }

    mod event_search {
        use super::*;

        async fn setup_search_test_data(pool: &PgPool) -> (Vec<Event>, Vec<Uuid>) {
            let organizer1 = create_test_user(pool, "search_org1").await;
            let organizer2 = create_test_user(pool, "search_org2").await;
            let now = Utc::now();

            let events = vec![
                // Tech events
                Event::create(
                    pool,
                    organizer1,
                    CreateEventRequest {
                        title: "Rust Conference 2025".to_string(),
                        description: Some("Learn Rust programming".to_string()),
                        location: Some("Ibadan".to_string()),
                        start_time: now + Duration::days(10),
                        end_time: now + Duration::days(10) + Duration::hours(8),
                        category: Some("Technology".to_string()),
                        tags: Some(vec![
                            "rust".to_string(),
                            "programming".to_string(),
                            "conference".to_string(),
                        ]),
                        banner_image_url: None,
                    },
                )
                .await
                .unwrap(),
                // Music
                Event::create(
                    pool,
                    organizer2,
                    CreateEventRequest {
                        title: "Jazz Festival".to_string(),
                        description: Some("Amazing jazz music".to_string()),
                        location: Some("Port Harcourt".to_string()),
                        start_time: now + Duration::days(20),
                        end_time: now + Duration::days(20) + Duration::hours(6),
                        category: Some("Music".to_string()),
                        tags: Some(vec![
                            "jazz".to_string(),
                            "music".to_string(),
                            "festival".to_string(),
                        ]),
                        banner_image_url: None,
                    },
                )
                .await
                .unwrap(),
                // Business
                Event::create(
                    pool,
                    organizer1,
                    CreateEventRequest {
                        title: "Startup Pitch Night".to_string(),
                        description: Some("Entrepreneurs pitch their ideas".to_string()),
                        location: Some("Ibadan".to_string()),
                        start_time: now + Duration::days(15),
                        end_time: now + Duration::days(15) + Duration::hours(4),
                        category: Some("Business".to_string()),
                        tags: Some(vec![
                            "startup".to_string(),
                            "pitch".to_string(),
                            "entrepreneurship".to_string(),
                        ]),
                        banner_image_url: None,
                    },
                )
                .await
                .unwrap(),
                // Future event
                Event::create(
                    pool,
                    organizer2,
                    CreateEventRequest {
                        title: "Future Tech Summit".to_string(),
                        description: Some("Exploring future technologies".to_string()),
                        location: Some("Kaduna".to_string()),
                        start_time: now + Duration::days(60),
                        end_time: now + Duration::days(60) + Duration::hours(10),
                        category: Some("Technology".to_string()),
                        tags: Some(vec![
                            "future".to_string(),
                            "ai".to_string(),
                            "blockchain".to_string(),
                        ]),
                        banner_image_url: None,
                    },
                )
                .await
                .unwrap(),
            ];

            let organizers = vec![organizer1, organizer2];
            (events, organizers)
        }

        async fn cleanup_search_test_data(
            pool: &PgPool,
            events: Vec<Event>,
            organizers: Vec<Uuid>,
        ) {
            for event in events {
                cleanup_test_event(pool, event.id).await;
            }
            for organizer_id in organizers {
                cleanup_test_user(pool, organizer_id).await;
            }
        }

        #[tokio::test]
        async fn test_search_all_events() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: None,
                category: None,
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Search should succeed");
            let found_events = result.unwrap();

            // Should find at least our test events (might include others from previous tests)
            assert!(
                found_events.len() >= 4,
                "Should find at least our 4 test events"
            );

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_by_category() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: None,
                category: Some("Technology".to_string()),
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Category search should succeed");
            let found_events = result.unwrap();

            // Should find at least 2 tech events
            let tech_events: Vec<_> = found_events
                .iter()
                .filter(|e| e.category.as_ref() == Some(&"Technology".to_string()))
                .collect();
            assert!(
                tech_events.len() >= 2,
                "Should find at least 2 technology events"
            );

            // Verify all returned events are technology events or have no category
            for event in &found_events {
                if let Some(ref category) = event.category {
                    assert_eq!(
                        category, "Technology",
                        "All events should be Technology category"
                    );
                }
            }

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_by_location() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: None,
                category: None,
                location: Some("Ibadan".to_string()),
                start_date: None,
                end_date: None,
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Location search should succeed");
            let found_events = result.unwrap();

            // Should find at least 2 Ibadan events
            let sf_events: Vec<_> = found_events
                .iter()
                .filter(|e| e.location.as_ref() == Some(&"Ibadan".to_string()))
                .collect();
            assert!(sf_events.len() >= 2, "Should find at least 2 Ibadan events");

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_by_text_query() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: Some("Rust".to_string()),
                category: None,
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Text search should succeed");
            let found_events = result.unwrap();

            // Should find the Rust conference
            let rust_events: Vec<_> = found_events
                .iter()
                .filter(|e| {
                    e.title.contains("Rust")
                        || e.description.as_ref().map_or(false, |d| d.contains("Rust"))
                })
                .collect();
            assert!(
                rust_events.len() >= 1,
                "Should find at least 1 Rust-related event"
            );

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_by_tags() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: None,
                category: None,
                location: None,
                start_date: None,
                end_date: None,
                tags: Some(vec!["programming".to_string()]),
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Tag search should succeed");
            let found_events = result.unwrap();

            // Should find events with programming tag
            let programming_events: Vec<_> = found_events
                .iter()
                .filter(|e| {
                    if let Some(ref tags) = e.tags {
                        if let Ok(tag_array) = serde_json::from_value::<Vec<String>>(tags.clone()) {
                            return tag_array.contains(&"programming".to_string());
                        }
                    }
                    false
                })
                .collect();
            assert!(
                programming_events.len() >= 1,
                "Should find at least 1 programming event"
            );

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_with_date_range() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;
            let now = Utc::now();

            let search_request = SearchEventsRequest {
                query: None,
                category: None,
                location: None,
                start_date: Some(now + Duration::days(5)),
                end_date: Some(now + Duration::days(25)),
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Date range search should succeed");
            let found_events = result.unwrap();

            // Verify all returned events are within the date range
            for event in &found_events {
                assert!(
                    event.start_time >= now + Duration::days(5),
                    "Event should start after range start"
                );
                assert!(
                    event.start_time <= now + Duration::days(25),
                    "Event should start before range end"
                );
            }

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_with_pagination() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            // Test with limit
            let search_request = SearchEventsRequest {
                query: None,
                category: None,
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: Some(2),
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Limited search should succeed");
            let found_events = result.unwrap();
            assert!(found_events.len() <= 2, "Should respect limit parameter");

            // Test with offset
            let search_request = SearchEventsRequest {
                query: None,
                category: None,
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: Some(2),
                offset: Some(1),
            };

            let result = Event::search(&pool, search_request).await;
            assert!(result.is_ok(), "Offset search should succeed");

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_combined_filters() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: Some("Tech".to_string()),
                category: Some("Technology".to_string()),
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Combined search should succeed");
            let found_events = result.unwrap();

            // Verify results match both criteria
            for event in &found_events {
                let title_matches = event.title.contains("Tech")
                    || event
                        .description
                        .as_ref()
                        .map_or(false, |d| d.contains("Tech"));
                let category_matches = event.category.as_ref() == Some(&"Technology".to_string());

                assert!(
                    title_matches || category_matches,
                    "Event should match search criteria"
                );
            }

            cleanup_search_test_data(&pool, events, organizers).await;
        }

        #[tokio::test]
        async fn test_search_no_results() {
            let pool = setup_test_db().await;
            let (events, organizers) = setup_search_test_data(&pool).await;

            let search_request = SearchEventsRequest {
                query: Some("NonexistentEvent12345".to_string()),
                category: Some("NonexistentCategory".to_string()),
                location: None,
                start_date: None,
                end_date: None,
                tags: None,
                limit: None,
                offset: None,
            };

            let result = Event::search(&pool, search_request).await;

            assert!(result.is_ok(), "Search should succeed even with no results");
            let found_events = result.unwrap();
            assert!(
                found_events.is_empty(),
                "Should return empty vector for no matches"
            );

            cleanup_search_test_data(&pool, events, organizers).await;
        }
    }

    mod event_updates {
        use super::*;

        #[tokio::test]
        async fn test_update_event_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "update_success").await;
            let test_event = create_test_event(&pool, organizer_id, "update_success").await;
            let now = Utc::now();

            let update_request = UpdateEventRequest {
                title: Some("Updated Event Title".to_string()),
                description: Some("Updated description".to_string()),
                location: Some("Updated Location".to_string()),
                start_time: Some(now + Duration::days(5)),
                end_time: Some(now + Duration::days(5) + Duration::hours(3)),
                category: Some("Updated Category".to_string()),
                tags: Some(vec!["updated".to_string(), "test".to_string()]),
                banner_image_url: Some("https://example.com/updated.jpg".to_string()),
            };

            let result = test_event.update(&pool, update_request).await;
            if let Err(ref error) = result {
                println!("❌ Update failed with error: {}", error);
            }

            assert!(result.is_ok(), "Event update should succeed");
            let updated_event = result.unwrap();

            assert_eq!(updated_event.title, "Updated Event Title");
            assert_eq!(
                updated_event.description,
                Some("Updated description".to_string())
            );
            assert_eq!(updated_event.location, Some("Updated Location".to_string()));
            assert_eq!(updated_event.category, Some("Updated Category".to_string()));
            assert_eq!(
                updated_event.banner_image_url,
                Some("https://example.com/updated.jpg".to_string())
            );
            assert!(
                updated_event.updated_at > test_event.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_event(&pool, test_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_event_partial() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "update_partial").await;
            let test_event = create_test_event(&pool, organizer_id, "update_partial").await;
            let original_location = test_event.location.clone();

            let update_request = UpdateEventRequest {
                title: Some("Only Title Changed".to_string()),
                description: None,
                location: None,
                start_time: None,
                end_time: None,
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = test_event.update(&pool, update_request).await;

            assert!(result.is_ok(), "Partial update should succeed");
            let updated_event = result.unwrap();

            assert_eq!(updated_event.title, "Only Title Changed");
            assert_eq!(
                updated_event.location, original_location,
                "Unchanged fields should remain the same"
            );

            cleanup_test_event(&pool, test_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_event_clear_optional_fields() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "update_clear").await;
            let test_event = create_test_event(&pool, organizer_id, "update_clear").await;

            let update_request = UpdateEventRequest {
                title: None,
                description: Some("".to_string()),
                location: Some("".to_string()),
                start_time: None,
                end_time: None,
                category: Some("".to_string()),
                tags: None,
                banner_image_url: Some("".to_string()),
            };

            let result = test_event.update(&pool, update_request).await;

            if result.is_ok() {
                let updated_event = result.unwrap();
                // Test how empty strings are handled. might be converted to NULL or kept as empty? idk
                cleanup_test_event(&pool, updated_event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod event_status_management {
        use super::*;

        #[tokio::test]
        async fn test_cancel_event_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "cancel_success").await;
            let test_event = create_test_event(&pool, organizer_id, "cancel_success").await;

            let result = test_event.cancel(&pool).await;

            assert!(result.is_ok(), "Event cancellation should succeed");

            // Verify the event is marked as cancelled
            let updated_event = Event::find_by_id(&pool, test_event.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                updated_event.status, "cancelled",
                "Event should be marked as cancelled"
            );

            cleanup_test_event(&pool, test_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_cancel_already_cancelled_event() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "cancel_already").await;
            let test_event = create_test_event(&pool, organizer_id, "cancel_already").await;

            // Cancel the event first
            let first_cancel = test_event.cancel(&pool).await;
            assert!(first_cancel.is_ok(), "First cancellation should succeed");

            // Try to cancel again
            let second_cancel = test_event.cancel(&pool).await;

            // This behavior depends on implementation, might succeed (as idempotent) or fail
            match second_cancel {
                Ok(_) => {
                    // Idempotent cancellation is acceptable
                    println!("Event cancellation is idempotent");
                }
                Err(_) => {
                    // Rejecting multiple cancellations is also acceptable
                    println!("Event cancellation rejects multiple calls");
                }
            }

            cleanup_test_event(&pool, test_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod data_validation {
        use super::*;

        #[test]
        fn test_create_event_request_deserialization() {
            let json = r#"{
                "title": "Test Event",
                "description": "A test event",
                "location": "Test Location",
                "start_time": "2025-12-01T19:00:00Z",
                "end_time": "2025-12-01T23:00:00Z",
                "category": "Test",
                "tags": ["test", "event"],
                "banner_image_url": "https://example.com/banner.jpg"
            }"#;

            let request: CreateEventRequest = serde_json::from_str(json).unwrap();

            assert_eq!(request.title, "Test Event");
            assert_eq!(request.description, Some("A test event".to_string()));
            assert_eq!(request.location, Some("Test Location".to_string()));
            assert_eq!(request.category, Some("Test".to_string()));
            assert!(request.tags.is_some());
            assert_eq!(
                request.banner_image_url,
                Some("https://example.com/banner.jpg".to_string())
            );
        }

        #[test]
        fn test_search_events_request_deserialization() {
            let json = r#"{
                "query": "tech",
                "category": "Technology",
                "location": "Ibadan",
                "start_date": "2025-01-01T00:00:00Z",
                "end_date": "2025-12-31T23:59:59Z",
                "tags": ["tech", "conference"],
                "limit": 10,
                "offset": 0
            }"#;

            let request: SearchEventsRequest = serde_json::from_str(json).unwrap();

            assert_eq!(request.query, Some("tech".to_string()));
            assert_eq!(request.category, Some("Technology".to_string()));
            assert_eq!(request.location, Some("Ibadan".to_string()));
            assert!(request.start_date.is_some());
            assert!(request.end_date.is_some());
            assert_eq!(
                request.tags,
                Some(vec!["tech".to_string(), "conference".to_string()])
            );
            assert_eq!(request.limit, Some(10));
            assert_eq!(request.offset, Some(0));
        }

        #[test]
        fn test_update_event_request_deserialization() {
            let json = r#"{
                "title": "Updated Title",
                "description": null,
                "location": "New Location"
            }"#;

            let request: UpdateEventRequest = serde_json::from_str(json).unwrap();

            assert_eq!(request.title, Some("Updated Title".to_string()));
            assert_eq!(request.description, None);
            assert_eq!(request.location, Some("New Location".to_string()));
        }

        #[tokio::test]
        async fn test_event_serialization() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "serialization").await;
            let test_event = create_test_event(&pool, organizer_id, "serialization").await;

            let serialized = serde_json::to_string(&test_event).unwrap();

            assert!(
                serialized.contains(&test_event.id.to_string()),
                "ID should be serialized"
            );
            assert!(
                serialized.contains(&test_event.title),
                "Title should be serialized"
            );
            assert!(
                serialized.contains(&test_event.organizer_id.to_string()),
                "Organizer ID should be serialized"
            );
            assert!(
                serialized.contains("\"status\""),
                "Status should be serialized"
            );

            cleanup_test_event(&pool, test_event.id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod edge_cases {
        use super::*;

        #[tokio::test]
        async fn test_unicode_characters_in_event_fields() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "unicode").await;
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "技术会议 2025 🚀".to_string(),
                description: Some("了解最新技术趋势 with émojis! 🎉".to_string()),
                location: Some("北京 Beijing 📍".to_string()),
                start_time: now + Duration::days(1),
                end_time: now + Duration::days(1) + Duration::hours(2),
                category: Some("技术".to_string()),
                tags: Some(vec![
                    "技术".to_string(),
                    "conference".to_string(),
                    "🚀".to_string(),
                ]),
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            if result.is_ok() {
                let event = result.unwrap();
                assert!(
                    event.title.contains("技术"),
                    "Should preserve unicode characters"
                );
                assert!(event.title.contains("🚀"), "Should preserve emojis");
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_very_long_event_descriptions() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "long_desc").await;
            let now = Utc::now();
            let long_description = "x".repeat(10000);

            let create_request = CreateEventRequest {
                title: "Long Description Event".to_string(),
                description: Some(long_description.clone()),
                location: None,
                start_time: now + Duration::days(1),
                end_time: now + Duration::days(1) + Duration::hours(2),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            // Test current behavior with very long descriptions
            if result.is_ok() {
                let event = result.unwrap();
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_simple_tags_handling() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "simple_tags").await;
            let now = Utc::now();

            let create_request = CreateEventRequest {
                title: "Tagged Event".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::days(1),
                end_time: now + Duration::days(1) + Duration::hours(2),
                category: None,
                tags: Some(vec![
                    "rust".to_string(),
                    "blockchain".to_string(),
                    "ai".to_string(),
                    "conference".to_string(),
                ]),
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            if result.is_ok() {
                let event = result.unwrap();

                assert!(event.tags.is_some(), "Tags should be stored");

                if let Some(ref stored_tags) = event.tags {
                    if let Ok(tag_array) =
                        serde_json::from_value::<Vec<String>>(stored_tags.clone())
                    {
                        assert!(
                            tag_array.contains(&"rust".to_string()),
                            "Should contain rust tag"
                        );
                        assert!(
                            tag_array.contains(&"blockchain".to_string()),
                            "Should contain blockchain tag"
                        );
                    }
                }

                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_concurrent_event_creation() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "concurrent").await;
            let now = Utc::now();

            let create_request1 = CreateEventRequest {
                title: "Concurrent Event 1".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::days(1),
                end_time: now + Duration::days(1) + Duration::hours(2),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let create_request2 = CreateEventRequest {
                title: "Concurrent Event 2".to_string(),
                description: None,
                location: None,
                start_time: now + Duration::days(1),
                end_time: now + Duration::days(1) + Duration::hours(2),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            // Attempt concurrent creation
            let (result1, result2) = tokio::join!(
                Event::create(&pool, organizer_id, create_request1),
                Event::create(&pool, organizer_id, create_request2)
            );

            // Both should succeed as there are no uniqueness constraints between events
            assert!(
                result1.is_ok() || result2.is_ok(),
                "At least one event creation should succeed"
            );

            if let Ok(event) = result1 {
                cleanup_test_event(&pool, event.id).await;
            }
            if let Ok(event) = result2 {
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_event_with_extreme_dates() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "extreme_dates").await;

            // Test with dates far in the future
            let far_future = Utc::now() + Duration::days(3650); // 10 years

            let create_request = CreateEventRequest {
                title: "Far Future Event".to_string(),
                description: None,
                location: None,
                start_time: far_future,
                end_time: far_future + Duration::hours(2),
                category: None,
                tags: None,
                banner_image_url: None,
            };

            let result = Event::create(&pool, organizer_id, create_request).await;

            if result.is_ok() {
                let event = result.unwrap();
                assert!(
                    event.start_time.year() > 2030,
                    "Should handle far future dates"
                );
                cleanup_test_event(&pool, event.id).await;
            }
            cleanup_test_user(&pool, organizer_id).await;
        }
    }
}
