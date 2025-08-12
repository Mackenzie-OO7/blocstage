use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RedisHealth {
    pub status: String,
    pub latency_ms: u64,
}

#[derive(Clone)]
pub struct RedisService {
    pub(crate) connection: ConnectionManager,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub data: T,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub user_id: Uuid,
    pub jwt_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub login_time: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

impl<T> CacheEntry<T> {
    pub fn new(data: T, ttl_seconds: Option<u64>) -> Self {
        Self {
            data,
            created_at: chrono::Utc::now(),
            ttl_seconds,
        }
    }
}

impl RedisService {
    pub async fn new() -> Result<Self> {
        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        info!(
            "🔗 Connecting to Redis: {}",
            redis_url.replace(&redis_url[8..], "[hidden]")
        );

        let client = Client::open(redis_url)?;
        let connection = client.get_connection_manager().await.map_err(|e| {
            error!("❌ Failed to connect to Redis: {}", e);
            anyhow!("Failed to establish Redis connection: {}", e)
        })?;

        info!("✅ Redis connection established successfully");

        Ok(Self { connection })
    }

    // Test Redis connection
    pub async fn ping(&self) -> Result<String> {
        let mut conn = self.connection.clone();
        let response: String = conn.ping().await?;
        Ok(response)
    }

    pub async fn cache_user_profile<T>(
        &self,
        user_id: Uuid,
        profile: &T,
        ttl_seconds: u64,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let key = format!("USER_PROFILE:{}", user_id);
        let cache_entry = CacheEntry::new(profile, Some(ttl_seconds));
        let serialized = serde_json::to_string(&cache_entry)?;

        let mut conn = self.connection.clone();
        let _: () = conn
            .set_ex(&key, serialized, ttl_seconds)
            .await
            .map_err(|e| {
                warn!("Failed to cache user profile for {}: {}", user_id, e);
                anyhow!("Failed to cache user profile: {}", e)
            })?;

        debug!(
            "✅ User profile cached: {} (TTL: {}s)",
            user_id, ttl_seconds
        );
        Ok(())
    }

    pub async fn get_cached_user_profile<T>(&self, user_id: Uuid) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key = format!("USER_PROFILE:{}", user_id);
        let mut conn = self.connection.clone();

        let cached: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| anyhow!("Failed to retrieve cached user profile: {}", e))?;

        match cached {
            Some(data) => {
                let cache_entry: CacheEntry<T> = serde_json::from_str(&data)
                    .map_err(|e| anyhow!("Failed to deserialize cached profile: {}", e))?;
                debug!("✅ User profile cache hit: {}", user_id);
                Ok(Some(cache_entry.data))
            }
            None => {
                debug!("⚠️ User profile cache miss: {}", user_id);
                Ok(None)
            }
        }
    }

    pub async fn invalidate_user_profile(&self, user_id: Uuid) -> Result<()> {
        let key = format!("USER_PROFILE:{}", user_id);
        let mut conn = self.connection.clone();
        let _: () = conn.del(&key).await?;
        debug!("🗑️ User profile cache invalidated: {}", user_id);
        Ok(())
    }

    pub async fn cache_user_permissions(
        &self,
        user_id: Uuid,
        permissions: &[String],
        ttl_seconds: u64,
    ) -> Result<()> {
        let key = format!("USER_PERMISSIONS:{}", user_id);
        let cache_entry = CacheEntry::new(permissions, Some(ttl_seconds));
        let serialized = serde_json::to_string(&cache_entry)?;

        let mut conn = self.connection.clone();
        let _: () = conn.set_ex(&key, serialized, ttl_seconds).await?;
        debug!(
            "✅ User permissions cached: {} ({} permissions)",
            user_id,
            permissions.len()
        );
        Ok(())
    }

    pub async fn get_cached_user_permissions(&self, user_id: Uuid) -> Result<Option<Vec<String>>> {
        let key = format!("USER_PERMISSIONS:{}", user_id);
        let mut conn = self.connection.clone();

        let cached: Option<String> = conn.get(&key).await?;
        match cached {
            Some(data) => {
                let cache_entry: CacheEntry<Vec<String>> = serde_json::from_str(&data)?;
                Ok(Some(cache_entry.data))
            }
            None => Ok(None),
        }
    }

    pub async fn add_user_session(
        &self,
        user_id: Uuid,
        jwt_id: &str,
        ttl_seconds: u64,
    ) -> Result<()> {
        let key = format!("USER_SESSIONS:{}", user_id);
        let mut conn = self.connection.clone();

        let _: () = conn.sadd(&key, jwt_id).await?;
        let _: () = conn.expire(&key, ttl_seconds as i64).await?;

        debug!("✅ Session added for user {}: {}", user_id, jwt_id);
        Ok(())
    }

    pub async fn is_session_active(&self, user_id: Uuid, jwt_id: &str) -> Result<bool> {
        let key = format!("USER_SESSIONS:{}", user_id);
        let mut conn = self.connection.clone();
        let is_member: bool = conn.sismember(&key, jwt_id).await?;
        Ok(is_member)
    }

    pub async fn invalidate_all_user_sessions_with_metadata(&self, user_id: Uuid) -> Result<()> {
        let session_key = format!("USER_SESSIONS:{}", user_id);
        let mut conn = self.connection.clone();
        
        let jwt_ids: Vec<String> = conn.smembers(&session_key).await.unwrap_or_default();
        
        // Remove all session metadata
        for jwt_id in jwt_ids {
            let metadata_key = format!("SESSION_INFO:{}", jwt_id);
            let _: () = conn.del(&metadata_key).await?;
        }
        
        // Remove the session set
        let _: () = conn.del(&session_key).await?;
        
        info!("🗑️ All sessions and metadata invalidated for user: {}", user_id);
        Ok(())
    }

    pub async fn cache_user_active_tickets<T>(
        &self,
        user_id: Uuid,
        tickets: &[T],
        ttl_seconds: u64,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let key = format!("USER_ACTIVE_TICKETS:{}", user_id);
        let cache_entry = CacheEntry::new(tickets, Some(ttl_seconds));
        let serialized = serde_json::to_string(&cache_entry)?;

        let mut conn = self.connection.clone();
        let _: () = conn.set_ex(&key, serialized, ttl_seconds).await?;
        debug!(
            "✅ Active tickets cached for user {}: {} tickets",
            user_id,
            tickets.len()
        );
        Ok(())
    }

    pub async fn get_cached_user_active_tickets<T>(&self, user_id: Uuid) -> Result<Option<Vec<T>>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key = format!("USER_ACTIVE_TICKETS:{}", user_id);
        let mut conn = self.connection.clone();

        let cached: Option<String> = conn.get(&key).await?;
        match cached {
            Some(data) => {
                let cache_entry: CacheEntry<Vec<T>> = serde_json::from_str(&data)?;
                Ok(Some(cache_entry.data))
            }
            None => Ok(None),
        }
    }

    pub async fn cache_event_analytics<T>(
        &self,
        event_id: Uuid,
        analytics: &T,
        ttl_seconds: u64,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let key = format!("EVENT_ANALYTICS:{}", event_id);
        let cache_entry = CacheEntry::new(analytics, Some(ttl_seconds));
        let serialized = serde_json::to_string(&cache_entry)?;

        let mut conn = self.connection.clone();
        let _: () = conn.set_ex(&key, serialized, ttl_seconds).await?;
        debug!("✅ Event analytics cached: {}", event_id);
        Ok(())
    }

    pub async fn get_cached_event_analytics<T>(&self, event_id: Uuid) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key = format!("EVENT_ANALYTICS:{}", event_id);
        let mut conn = self.connection.clone();

        let cached: Option<String> = conn.get(&key).await?;
        match cached {
            Some(data) => {
                let cache_entry: CacheEntry<T> = serde_json::from_str(&data)?;
                Ok(Some(cache_entry.data))
            }
            None => Ok(None),
        }
    }

    pub async fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_seconds: u64,
    ) -> Result<bool> {
        let mut conn = self.connection.clone();

        let current: Option<u32> = conn.get(key).await?;
        let count = current.unwrap_or(0);

        if count >= limit {
            debug!(
                "🚫 Rate limit exceeded for key: {} ({}/{})",
                key, count, limit
            );
            return Ok(false);
        }

        let new_count: u32 = conn.incr(key, 1).await?;

        if new_count == 1 {
            let _: () = conn.expire(key, window_seconds as i64).await?;
        }

        debug!(
            "✅ Rate limit check passed for key: {} ({}/{})",
            key, new_count, limit
        );
        Ok(true)
    }

    pub async fn get_rate_limit_remaining(&self, key: &str, limit: u32) -> Result<u32> {
        let mut conn = self.connection.clone();
        let current: Option<u32> = conn.get(key).await?;
        let used = current.unwrap_or(0);
        Ok(limit.saturating_sub(used))
    }

    pub async fn set_with_expiry(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.connection.clone();
        let _: () = conn.set_ex(key, value, ttl_seconds).await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.connection.clone();
        let value: Option<String> = conn.get(key).await?;
        Ok(value)
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self.connection.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }

    pub async fn exists(&self, key: &str) -> Result<bool> {
        let mut conn = self.connection.clone();
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }

    pub async fn health_check(&self) -> Result<RedisHealth> {
        let start = std::time::Instant::now();

        match self.ping().await {
            Ok(_) => {
                let latency = start.elapsed();
                Ok(RedisHealth {
                    status: "healthy".to_string(),
                    latency_ms: latency.as_millis() as u64,
                })
            }
            Err(e) => {
                error!("Redis health check failed: {}", e);
                Ok(RedisHealth {
                    status: format!("unhealthy: {}", e),
                    latency_ms: 0,
                })
            }
        }
    }

    pub async fn add_user_session_with_metadata(
        &self,
        user_id: Uuid,
        jwt_id: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl_seconds: u64,
    ) -> Result<()> {
        let session_key = format!("USER_SESSIONS:{}", user_id);
        let metadata_key = format!("SESSION_INFO:{}", jwt_id);

        let now = chrono::Utc::now();
        let session_metadata = SessionMetadata {
            user_id,
            jwt_id: jwt_id.to_string(),
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
            login_time: now,
            last_activity: now,
        };

        let mut conn = self.connection.clone();

        let _: () = conn.sadd(&session_key, jwt_id).await?;
        let _: () = conn.expire(&session_key, ttl_seconds as i64).await?;

        // Store detailed session metadata
        let metadata_json = serde_json::to_string(&session_metadata)?;
        let _: () = conn
            .set_ex(&metadata_key, metadata_json, ttl_seconds)
            .await?;

        debug!(
            "✅ Session with metadata added for user {}: {} from {:?}",
            user_id, jwt_id, ip_address
        );
        Ok(())
    }

    pub async fn get_user_active_sessions(&self, user_id: Uuid) -> Result<Vec<SessionMetadata>> {
        let session_key = format!("USER_SESSIONS:{}", user_id);
        let mut conn = self.connection.clone();

        let jwt_ids: Vec<String> = conn.smembers(&session_key).await?;

        let mut sessions = Vec::new();

        for jwt_id in jwt_ids {
            let metadata_key = format!("SESSION_INFO:{}", jwt_id);
            if let Ok(Some(metadata_json)) = conn.get::<_, Option<String>>(&metadata_key).await {
                if let Ok(session_metadata) =
                    serde_json::from_str::<SessionMetadata>(&metadata_json)
                {
                    sessions.push(session_metadata);
                }
            }
        }

        // Sort by most recent activity first
        sessions.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        Ok(sessions)
    }

    pub async fn update_session_activity(&self, jwt_id: &str) -> Result<()> {
        let metadata_key = format!("SESSION_INFO:{}", jwt_id);
        let mut conn = self.connection.clone();

        if let Ok(Some(metadata_json)) = conn.get::<_, Option<String>>(&metadata_key).await {
            if let Ok(mut session_metadata) =
                serde_json::from_str::<SessionMetadata>(&metadata_json)
            {
                session_metadata.last_activity = chrono::Utc::now();

                // Save back to Redis (keep original TTL)
                let updated_json = serde_json::to_string(&session_metadata)?;
                let _: () = conn.set(&metadata_key, updated_json).await?;
            }
        }

        Ok(())
    }

    pub async fn remove_user_session_with_metadata(
        &self,
        user_id: Uuid,
        jwt_id: &str,
    ) -> Result<()> {
        let session_key = format!("USER_SESSIONS:{}", user_id);
        let metadata_key = format!("SESSION_INFO:{}", jwt_id);

        let mut conn = self.connection.clone();

        let _: () = conn.srem(&session_key, jwt_id).await?;

        let _: () = conn.del(&metadata_key).await?;

        debug!(
            "🗑️ Session and metadata removed for user {}: {}",
            user_id, jwt_id
        );
        Ok(())
    }

    /// Revoke a specific session by JWT ID
    pub async fn revoke_specific_session(&self, user_id: Uuid, jwt_id: &str) -> Result<bool> {
        let session_key = format!("USER_SESSIONS:{}", user_id);
        let mut conn = self.connection.clone();

        let exists: bool = conn.sismember(&session_key, jwt_id).await?;

        if exists {
            self.remove_user_session_with_metadata(user_id, jwt_id)
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn safe_cache_user_profile<T>(&self, user_id: Uuid, profile: &T, ttl_seconds: u64)
    where
        T: Serialize,
    {
        if let Err(e) = self.cache_user_profile(user_id, profile, ttl_seconds).await {
            warn!("Failed to cache user profile for {}: {}", user_id, e);
            // Don't propagate error; caching failures shouldn't break application flow
        }
    }

    pub async fn safe_get_cached_user_profile<T>(&self, user_id: Uuid) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.get_cached_user_profile(user_id).await {
            Ok(profile) => profile,
            Err(e) => {
                warn!("Failed to get cached user profile for {}: {}", user_id, e);
                None
            }
        }
    }
}
