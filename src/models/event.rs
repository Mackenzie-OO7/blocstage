use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgArguments, Arguments, PgPool};
use uuid::Uuid;

mod flexible_datetime {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Try RFC3339 format first (with timezone)
        if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
            return Ok(dt.with_timezone(&Utc));
        }

        // Try format with seconds (YYYY-MM-DDTHH:MM:SS)
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S") {
            return Ok(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }

        // Try format without seconds (YYYY-MM-DDTHH:MM)
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M") {
            return Ok(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }

        Err(serde::de::Error::custom(format!(
            "Invalid datetime format: {}",
            s
        )))
    }

    pub fn deserialize_option<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                // Try RFC3339 format first (with timezone)
                if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
                    return Ok(Some(dt.with_timezone(&Utc)));
                }

                // Try format with seconds (YYYY-MM-DDTHH:MM:SS)
                if let Ok(naive_dt) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S") {
                    return Ok(Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc)));
                }

                // Try format without seconds (YYYY-MM-DDTHH:MM)
                if let Ok(naive_dt) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M") {
                    return Ok(Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc)));
                }

                Err(serde::de::Error::custom(format!(
                    "Invalid datetime format: {}",
                    s
                )))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub organizer_id: Uuid,
    pub short_code: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: String, // "active", "cancelled", "completed"
    pub image_url: Option<String>,
    pub category: Option<String>,
    #[sqlx(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct EventSession {
    pub id: Uuid,
    pub event_id: Uuid,
    pub title: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub speaker_name: Option<String>,
    pub speaker_user_id: Option<Uuid>,
    pub image_url: Option<String>,
    pub session_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventWithSessions {
    #[serde(flatten)]
    pub event: Event,
    pub sessions: Vec<EventSession>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEventSessionRequest {
    pub title: String,
    #[serde(deserialize_with = "flexible_datetime::deserialize")]
    pub start_time: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime::deserialize")]
    pub end_time: DateTime<Utc>,
    pub speaker_name: Option<String>,
    pub speaker_user_id: Option<Uuid>,
    pub image_url: Option<String>,
    pub session_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEventSessionRequest {
    pub title: Option<String>,
    #[serde(deserialize_with = "flexible_datetime::deserialize_option")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "flexible_datetime::deserialize_option")]
    pub end_time: Option<DateTime<Utc>>,
    pub speaker_name: Option<String>,
    pub speaker_user_id: Option<Uuid>,
    pub image_url: Option<String>,
    pub session_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEventRequest {
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    #[serde(deserialize_with = "flexible_datetime::deserialize")]
    pub start_time: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime::deserialize")]
    pub end_time: DateTime<Utc>,
    pub image_url: Option<String>,
    pub category: Option<String>,
    pub tags: Option<Vec<String>>,
    pub sessions: Option<Vec<CreateEventSessionRequest>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEventRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    #[serde(deserialize_with = "flexible_datetime::deserialize_option")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "flexible_datetime::deserialize_option")]
    pub end_time: Option<DateTime<Utc>>,
    pub image_url: Option<String>,
    pub category: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SearchEventsRequest {
    pub query: Option<String>,
    pub category: Option<String>,
    pub location: Option<String>,
    #[serde(deserialize_with = "flexible_datetime::deserialize_option")]
    pub start_date: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "flexible_datetime::deserialize_option")]
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
    ) -> Result<EventWithSessions> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        Self::validate_event_timing(event.start_time, event.end_time)?;

        // Validate sessions if provided
        if let Some(ref sessions) = event.sessions {
            Self::validate_sessions(sessions, event.start_time, event.end_time)?;
        }

        let short_code = Self::generate_unique_short_code(pool).await?;

        info!("🎪 Creating event with:");
        info!("   - id: {}", id);
        info!("   - short_code: {}", short_code);
        info!("   - organizer_id: {}", organizer_id);
        info!("   - title: {}", event.title);
        info!("   - start_time: {}", event.start_time);
        info!("   - end_time: {}", event.end_time);
        info!("   - tags: {:?}", event.tags);
        info!(
            "   - sessions: {} sessions",
            event.sessions.as_ref().map_or(0, |s| s.len())
        );

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

        let created_event = sqlx::query_as!(
            Event,
            r#"
        INSERT INTO events (
            id, organizer_id, short_code, title, description, location,
            start_time, end_time, created_at, updated_at,
            status, image_url, category, tags
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING *
        "#,
            id,
            organizer_id,
            short_code,
            event.title,
            event.description,
            event.location,
            event.start_time,
            event.end_time,
            now,
            now,
            "active",
            event.image_url,
            event.category,
            tags_json
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            error!("❌ Database error creating event: {}", e);
            e
        })?;

        // Create event owner record
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
            created_event.id,
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

        // Create sessions if provided
        let mut created_sessions = Vec::new();
        if let Some(sessions) = event.sessions {
            for (index, session_req) in sessions.into_iter().enumerate() {
                let session_id = Uuid::new_v4();
                let session_order = session_req.session_order.unwrap_or(index as i32);

                // Create session directly in transaction (inline)
                let created_session = sqlx::query_as!(
                    EventSession,
                    r#"
            INSERT INTO event_sessions (
                id, event_id, title, start_time, end_time,
                speaker_name, speaker_user_id, image_url, session_order,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
                    session_id,
                    created_event.id,
                    session_req.title,
                    session_req.start_time,
                    session_req.end_time,
                    session_req.speaker_name,
                    session_req.speaker_user_id,
                    session_req.image_url,
                    session_order,
                    now,
                    now
                )
                .fetch_one(&mut *tx)
                .await?;

                created_sessions.push(created_session);
            }
        }

        tx.commit().await?;

        info!(
            "✅ Event and sessions created successfully: {}",
            created_event.id
        );

        Ok(EventWithSessions {
            event: created_event,
            sessions: created_sessions,
        })
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let event = sqlx::query_as!(Event, r#"SELECT * FROM events WHERE id = $1"#, id)
            .fetch_optional(pool)
            .await?;

        Ok(event)
    }

    pub async fn find_by_id_with_sessions(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<Option<EventWithSessions>> {
        let event = Self::find_by_id(pool, id).await?;

        if let Some(event) = event {
            let sessions = EventSession::find_by_event_id(pool, id).await?;
            Ok(Some(EventWithSessions { event, sessions }))
        } else {
            Ok(None)
        }
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

        if let Some(image_url) = &update.image_url {
            query.push_str(&format!(", image_url = ${}", param_index));
            let _ = args.add(image_url);
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

        // allow 5 minute buffer for immediate events
        let buffer = chrono::Duration::minutes(5);
        if start_time < (now - buffer) {
            return Err(anyhow!(
                "Event start time cannot be in the past. Start time: {}, Current time: {}",
                start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                now.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }

        if end_time <= start_time {
            return Err(anyhow!(
                "Event end time must be after start time. Start: {}, End: {}",
                start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                end_time.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }

        // Event duration must be reasonable (not longer than 1 year)
        let max_duration = chrono::Duration::days(365);
        if end_time - start_time > max_duration {
            return Err(anyhow!(
                "Event duration cannot exceed 1 year. Duration: {} days",
                (end_time - start_time).num_days()
            ));
        }

        // Event duration must be at least 15 mins
        let min_duration = chrono::Duration::minutes(15);
        if end_time - start_time < min_duration {
            return Err(anyhow!(
                "Event duration must be at least 15 minutes. Duration: {} minutes",
                (end_time - start_time).num_minutes()
            ));
        }

        Ok(())
    }

    fn validate_sessions(
        sessions: &[CreateEventSessionRequest],
        event_start: DateTime<Utc>,
        event_end: DateTime<Utc>,
    ) -> Result<()> {
        for (index, session) in sessions.iter().enumerate() {
            if session.end_time <= session.start_time {
                return Err(anyhow!(
                    "Session {} end time must be after start time",
                    index + 1
                ));
            }

            if session.start_time < event_start || session.end_time > event_end {
                return Err(anyhow!(
                    "Session {} must be within event timeframe ({} to {})",
                    index + 1,
                    event_start.format("%Y-%m-%d %H:%M:%S UTC"),
                    event_end.format("%Y-%m-%d %H:%M:%S UTC")
                ));
            }

            // Sessions can be any duration the user sets (as long as end time is after start time)
        }

        Ok(())
    }

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
                    "ended".to_string()
                }
            }
            _ => self.status.clone(),
        }
    }

    pub fn can_sell_tickets(&self) -> bool {
        let now = Utc::now();

        if self.status != "active" {
            return false;
        }

        if now >= self.end_time {
            return false;
        }

        // Optionally: stop selling tickets 1 hour before event starts (to allow for better planning?)
        let ticket_sales_cutoff = self.start_time - chrono::Duration::hours(1);
        if now > ticket_sales_cutoff {
            return false;
        }

        true
    }

    pub fn is_valid(&self) -> bool {
        let now = Utc::now();

        match self.status.as_str() {
            "cancelled" => false,
            "draft" => false,
            "active" => now < self.end_time,
            _ => false,
        }
    }

    /// Update event status in database if it should be ended
    pub async fn update_status_if_needed(&self, pool: &PgPool) -> Result<Event> {
        let effective_status = self.get_effective_status();

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

    /// batch operation for background job to find events that need status updates
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

        // add search conditions based on the provided params
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

    pub async fn find_by_short_code(pool: &PgPool, short_code: &str) -> Result<Option<Self>> {
        let event = sqlx::query_as!(
            Event,
            r#"SELECT * FROM events WHERE short_code = $1"#,
            short_code
        )
        .fetch_optional(pool)
        .await?;

        Ok(event)
    }

    async fn generate_unique_short_code(pool: &PgPool) -> Result<String> {
        const MAX_RETRIES: usize = 10;

        for _ in 0..MAX_RETRIES {
            let code = Self::generate_short_code(6);

            let exists = sqlx::query_scalar!(
                "SELECT EXISTS(SELECT 1 FROM events WHERE short_code = $1)",
                code
            )
            .fetch_one(pool)
            .await?;

            if !exists.unwrap_or(true) {
                return Ok(code);
            }
        }

        Err(anyhow!(
            "Failed to generate unique short code after {} retries",
            MAX_RETRIES
        ))
    }

    fn generate_short_code(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                 ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 0123456789";

        let mut rng = rand::rng();
        (0..length)
            .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
            .collect()
    }
}

impl EventSession {
    pub async fn create(
        pool: &PgPool,
        event_id: Uuid,
        session: CreateEventSessionRequest,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let next_order = sqlx::query_scalar!(
            "SELECT COALESCE(MAX(session_order), -1) + 1 FROM event_sessions WHERE event_id = $1",
            event_id
        )
        .fetch_one(pool)
        .await?
        .unwrap_or(0);

        let session_order = session.session_order.unwrap_or(next_order);

        let created_session = sqlx::query_as!(
            EventSession,
            r#"
            INSERT INTO event_sessions (
                id, event_id, title, start_time, end_time,
                speaker_name, speaker_user_id, image_url, session_order,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
            id,
            event_id,
            session.title,
            session.start_time,
            session.end_time,
            session.speaker_name,
            session.speaker_user_id,
            session.image_url,
            session_order,
            now,
            now
        )
        .fetch_one(pool)
        .await?;

        Ok(created_session)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let session = sqlx::query_as!(
            EventSession,
            "SELECT * FROM event_sessions WHERE id = $1",
            id
        )
        .fetch_optional(pool)
        .await?;

        Ok(session)
    }

    pub async fn find_by_event_id(pool: &PgPool, event_id: Uuid) -> Result<Vec<Self>> {
        let sessions = sqlx::query_as!(
            EventSession,
            "SELECT * FROM event_sessions WHERE event_id = $1 ORDER BY session_order ASC, start_time ASC",
            event_id
        )
        .fetch_all(pool)
        .await?;

        Ok(sessions)
    }

    pub async fn update(&self, pool: &PgPool, update: UpdateEventSessionRequest) -> Result<Self> {
        let now = Utc::now();

        let mut query = String::from("UPDATE event_sessions SET updated_at = $1");
        let mut args = PgArguments::default();
        let _ = args.add(now);
        let mut param_index = 2;

        if let Some(title) = &update.title {
            query.push_str(&format!(", title = ${}", param_index));
            let _ = args.add(title);
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

        if let Some(speaker_name) = &update.speaker_name {
            query.push_str(&format!(", speaker_name = ${}", param_index));
            let _ = args.add(speaker_name);
            param_index += 1;
        }

        if let Some(speaker_user_id) = &update.speaker_user_id {
            query.push_str(&format!(", speaker_user_id = ${}", param_index));
            let _ = args.add(speaker_user_id);
            param_index += 1;
        }

        if let Some(image_url) = &update.image_url {
            query.push_str(&format!(", image_url = ${}", param_index));
            let _ = args.add(image_url);
            param_index += 1;
        }

        if let Some(session_order) = &update.session_order {
            query.push_str(&format!(", session_order = ${}", param_index));
            let _ = args.add(session_order);
            param_index += 1;
        }

        query.push_str(&format!(" WHERE id = ${} RETURNING *", param_index));
        let _ = args.add(self.id);

        let session = sqlx::query_as_with::<_, EventSession, _>(&query, args)
            .fetch_one(pool)
            .await?;

        Ok(session)
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<()> {
        sqlx::query!("DELETE FROM event_sessions WHERE id = $1", self.id)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn set_image_url(&self, pool: &PgPool, image_url: &str) -> Result<Self> {
        let now = Utc::now();

        let session = sqlx::query_as!(
            EventSession,
            r#"
            UPDATE event_sessions 
            SET image_url = $1, updated_at = $2 
            WHERE id = $3 
            RETURNING *
            "#,
            image_url,
            now,
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(session)
    }

    pub async fn reorder_sessions(
        pool: &PgPool,
        event_id: Uuid,
        session_orders: Vec<(Uuid, i32)>,
    ) -> Result<()> {
        let mut tx = pool.begin().await?;

        for (session_id, new_order) in session_orders {
            sqlx::query!(
                "UPDATE event_sessions SET session_order = $1, updated_at = $2 WHERE id = $3 AND event_id = $4",
                new_order,
                Utc::now(),
                session_id,
                event_id
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub fn is_currently_active(&self) -> bool {
        let now = Utc::now();
        now >= self.start_time && now < self.end_time
    }

    pub fn can_upload_files(&self, event: &Event) -> bool {
        // Can only upload files if event is still valid
        event.is_valid()
    }
}

impl EventWithSessions {
    // pub fn get_effective_status(&self) -> String {
    //     self.event.get_effective_status()
    // }

    // pub fn is_valid(&self) -> bool {
    //     self.event.is_valid()
    // }

    pub fn get_current_session(&self) -> Option<EventSession> {
        let now = Utc::now();
        self.sessions
            .iter()
            .find(|s| now >= s.start_time && now < s.end_time)
            .cloned()
    }

    pub fn get_upcoming_sessions(&self) -> Vec<EventSession> {
        let now = Utc::now();
        self.sessions
            .iter()
            .filter(|s| s.start_time > now)
            .cloned()
            .collect()
    }
}
