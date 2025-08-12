use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct EventOrganizer {
    pub id: Uuid,
    pub event_id: Uuid,
    pub user_id: Uuid,
    pub role: String, // owner or organizer
    pub permissions: JsonValue,
    pub added_at: DateTime<Utc>,
    pub added_by: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OrganizerPermissions {
    pub edit_event: bool,
    pub manage_tickets: bool,
    pub check_in_guests: bool,
    pub view_analytics: bool,
    pub manage_organizers: bool,
    pub cancel_event: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddOrganizerRequest {
    pub identifier: String, // username or email
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizerPermissionsRequest {
    pub permissions: OrganizerPermissions,
}

#[derive(Debug, Serialize)]
pub struct OrganizerInfo {
    pub organizer: EventOrganizer,
    pub user_info: OrganizerUserInfo,
}

#[derive(Debug, Serialize)]
pub struct OrganizerUserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

impl EventOrganizer {
    pub async fn add_organizer(
        pool: &PgPool,
        event_id: Uuid,
        user_id: Uuid,
        added_by: Uuid,
    ) -> Result<Self> {
        if Self::is_organizer(pool, event_id, user_id).await? {
            return Err(anyhow::anyhow!(
                "User is already an organizer for this event"
            ));
        }

        let count = Self::count_organizers(pool, event_id).await?;
        if count >= 4 {
            return Err(anyhow::anyhow!("Max 4 organizers allowed per event"));
        }

        let default_permissions = serde_json::json!({
            "edit_event": true,
            "manage_tickets": true,
            "check_in_guests": true,
            "view_analytics": true,
            "manage_organizers": false,
            "cancel_event": false
        });

        let organizer = sqlx::query_as!(
            EventOrganizer,
            r#"
            INSERT INTO event_organizers (event_id, user_id, role, permissions, added_by)
            VALUES ($1, $2, 'organizer', $3, $4)
            RETURNING id, event_id, user_id, role, permissions, added_at, added_by
            "#,
            event_id,
            user_id,
            default_permissions,
            added_by
        )
        .fetch_one(pool)
        .await?;

        Ok(organizer)
    }

    /// owner-only operation
    pub async fn remove_organizer(
        pool: &PgPool,
        event_id: Uuid,
        user_id: Uuid,
        removed_by: Uuid,
    ) -> Result<()> {
        let organizer = Self::get_organizer(pool, event_id, user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User is not an organizer for this event"))?;

        if organizer.role == "owner" {
            return Err(anyhow::anyhow!("Cannot remove the event owner"));
        }

        if !Self::is_owner(pool, event_id, removed_by).await? {
            return Err(anyhow::anyhow!(
                "Only the event owner can remove organizers"
            ));
        }

        sqlx::query!(
            "DELETE FROM event_organizers WHERE event_id = $1 AND user_id = $2 AND role != 'owner'",
            event_id,
            user_id
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// owner-only operation
    pub async fn update_permissions(
        pool: &PgPool,
        event_id: Uuid,
        user_id: Uuid,
        permissions: OrganizerPermissions,
        updated_by: Uuid,
    ) -> Result<Self> {
        if !Self::is_owner(pool, event_id, updated_by).await? {
            return Err(anyhow::anyhow!(
                "Only the event owner can update permissions"
            ));
        }

        let organizer = Self::get_organizer(pool, event_id, user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User is not an organizer for this event"))?;

        if organizer.role == "owner" {
            return Err(anyhow::anyhow!("Cannot update owner permissions"));
        }

        let permissions_json = serde_json::to_value(permissions)?;

        let updated_organizer = sqlx::query_as!(
            EventOrganizer,
            r#"
            UPDATE event_organizers 
            SET permissions = $3
            WHERE event_id = $1 AND user_id = $2 AND role != 'owner'
            RETURNING id, event_id, user_id, role, permissions, added_at, added_by
            "#,
            event_id,
            user_id,
            permissions_json
        )
        .fetch_one(pool)
        .await?;

        Ok(updated_organizer)
    }

    pub async fn get_event_organizers_with_info(
        pool: &PgPool,
        event_id: Uuid,
    ) -> Result<Vec<OrganizerInfo>> {
        let rows = sqlx::query!(
            r#"
            SELECT 
                eo.id, eo.event_id, eo.user_id, eo.role, eo.permissions, eo.added_at, eo.added_by,
                u.username, u.email
            FROM event_organizers eo
            JOIN users u ON eo.user_id = u.id
            WHERE eo.event_id = $1
            ORDER BY 
                CASE WHEN eo.role = 'owner' THEN 1 ELSE 2 END,
                eo.added_at ASC
            "#,
            event_id
        )
        .fetch_all(pool)
        .await?;

        let organizers = rows.into_iter()
            .map(|row| OrganizerInfo {
                organizer: EventOrganizer {
                    id: row.id,
                    event_id: row.event_id,
                    user_id: row.user_id,
                    role: row.role,
                    permissions: row.permissions,
                    added_at: row.added_at,
                    added_by: row.added_by,
                },
                user_info: OrganizerUserInfo {
                    id: row.user_id,
                    username: row.username,
                    email: row.email,
                },
            })
            .collect();

        Ok(organizers)
    }

    pub async fn is_organizer(pool: &PgPool, event_id: Uuid, user_id: Uuid) -> Result<bool> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM event_organizers WHERE event_id = $1 AND user_id = $2",
            event_id,
            user_id
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    pub async fn is_owner(pool: &PgPool, event_id: Uuid, user_id: Uuid) -> Result<bool> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM event_organizers WHERE event_id = $1 AND user_id = $2 AND role = 'owner'",
            event_id,
            user_id
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    pub async fn get_organizer(
        pool: &PgPool,
        event_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>> {
        let organizer = sqlx::query_as!(
            EventOrganizer,
            r#"
            SELECT id, event_id, user_id, role, permissions, added_at, added_by
            FROM event_organizers 
            WHERE event_id = $1 AND user_id = $2
            "#,
            event_id,
            user_id
        )
        .fetch_optional(pool)
        .await?;

        Ok(organizer)
    }

    pub async fn count_organizers(pool: &PgPool, event_id: Uuid) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM event_organizers WHERE event_id = $1",
            event_id
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0))
    }

    pub async fn has_permission(
        pool: &PgPool,
        event_id: Uuid,
        user_id: Uuid,
        permission: &str,
    ) -> Result<bool> {
        let organizer = Self::get_organizer(pool, event_id, user_id).await?;

        match organizer {
            Some(org) => {
                let permissions: OrganizerPermissions = serde_json::from_value(org.permissions)?;
                let has_perm = match permission {
                    "edit_event" => permissions.edit_event,
                    "manage_tickets" => permissions.manage_tickets,
                    "check_in_guests" => permissions.check_in_guests,
                    "view_analytics" => permissions.view_analytics,
                    "manage_organizers" => permissions.manage_organizers,
                    "cancel_event" => permissions.cancel_event,
                    _ => false,
                };
                Ok(has_perm)
            }
            None => Ok(false),
        }
    }

    /// find user by username or email
    pub async fn find_user_by_identifier(pool: &PgPool, identifier: &str) -> Result<Option<Uuid>> {
        let user_id = sqlx::query_scalar!(
            r#"
            SELECT id FROM users 
            WHERE username = $1 OR email = $1
            LIMIT 1
            "#,
            identifier
        )
        .fetch_optional(pool)
        .await?;

        Ok(user_id)
    }
}
