use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Ticket {
    pub id: Uuid,
    pub ticket_type_id: Uuid,
    pub owner_id: Uuid,
    pub status: String,
    pub qr_code: Option<String>,
    pub nft_identifier: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub checked_in_at: Option<DateTime<Utc>>,
    pub checked_in_by: Option<Uuid>,
    pub pdf_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CheckInRequest {
    pub ticket_id: Uuid,
}

impl Ticket {
    pub async fn create(
        pool: &PgPool,
        ticket_type_id: Uuid,
        owner_id: Uuid,
        qr_code: Option<String>,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let ticket = sqlx::query_as!(
            Ticket,
            r#"
        INSERT INTO tickets (
            id, ticket_type_id, owner_id, status, qr_code, 
            created_at, updated_at, checked_in_at, checked_in_by, pdf_url
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        "#,
            id,
            ticket_type_id,
            owner_id,
            "valid",
            qr_code,
            now,
            now,
            Option::<DateTime<Utc>>::None,
            Option::<Uuid>::None,
            Option::<String>::None
        )
        .fetch_one(pool)
        .await?;

        Ok(ticket)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let ticket = sqlx::query_as!(Ticket, r#"SELECT * FROM tickets WHERE id = $1"#, id)
            .fetch_optional(pool)
            .await?;

        Ok(ticket)
    }

    pub async fn find_by_owner(pool: &PgPool, owner_id: Uuid) -> Result<Vec<Self>> {
        let tickets = sqlx::query_as!(
            Ticket,
            r#"SELECT * FROM tickets WHERE owner_id = $1"#,
            owner_id
        )
        .fetch_all(pool)
        .await?;

        Ok(tickets)
    }

    pub async fn update_status(&self, pool: &PgPool, status: &str) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            status,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(ticket)
    }

    pub async fn update_owner(&self, pool: &PgPool, new_owner_id: Uuid) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET owner_id = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            new_owner_id,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(ticket)
    }

    pub async fn set_nft_identifier(&self, pool: &PgPool, nft_identifier: &str) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET nft_identifier = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            nft_identifier,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(ticket)
    }

    pub async fn set_pdf_url(&self, pool: &PgPool, pdf_url: &str) -> Result<Self> {
        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET pdf_url = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            pdf_url,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(ticket)
    }

    pub async fn check_in(&self, pool: &PgPool, checked_in_by: Uuid) -> Result<Self> {
        if self.status != "valid" {
            anyhow::bail!("Ticket is not valid for check-in (status: {})", self.status);
        }

        if self.checked_in_at.is_some() {
            anyhow::bail!("Ticket has already been checked in");
        }

        let now = Utc::now();

        let ticket = sqlx::query_as!(
            Ticket,
            r#"
            UPDATE tickets
            SET 
                status = 'used',
                checked_in_at = $1,
                checked_in_by = $2,
                updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
            now,
            checked_in_by,
            now,
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(ticket)
    }

    pub async fn verify_authenticity(&self, pool: &PgPool) -> Result<bool> {
        if let Some(nft_id) = &self.nft_identifier {
            let count = sqlx::query!(
                r#"
                SELECT COUNT(*) as count 
                FROM tickets 
                WHERE nft_identifier = $1 AND id = $2
                "#,
                nft_id,
                self.id
            )
            .fetch_one(pool)
            .await?
            .count
            .unwrap_or(0);

            return Ok(count > 0);
        }

        let count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count 
            FROM tickets 
            WHERE id = $1 AND status = 'valid'
            "#,
            self.id
        )
        .fetch_one(pool)
        .await?
        .count
        .unwrap_or(0);

        Ok(count > 0)
    }
}

// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ticket_type::{CreateTicketTypeRequest, TicketType};
    use bigdecimal::BigDecimal;
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use std::env;
    use std::str::FromStr;
    use uuid::Uuid;

    // helper fns
    async fn setup_test_db() -> PgPool {
        dotenv::from_filename(".env.test").ok();
        dotenv::dotenv().ok();

        // Debug: Print what environment variables are loaded
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
            true,
            Some("verification_token"),
            "active",
            "user"
        )
        .execute(pool)
        .await
        .expect("Failed to create test user");

        user_id
    }

    async fn create_test_event(pool: &PgPool, organizer_id: Uuid, suffix: &str) -> Uuid {
        let event_id = Uuid::new_v4();
        let now = Utc::now();
        let unique_id = format!(
            "{}_{}_{}",
            suffix,
            event_id.simple(),
            now.timestamp_millis()
        );

        sqlx::query!(
            r#"
            INSERT INTO events (
                id, organizer_id, title, description, location,
                start_time, end_time, created_at, updated_at, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            event_id,
            organizer_id,
            format!("Test Event {}", unique_id),
            Some(format!("Description for {}", unique_id)),
            Some("Test Location"),
            now + Duration::days(1),
            now + Duration::days(1) + Duration::hours(2),
            now,
            now,
            "active"
        )
        .execute(pool)
        .await
        .expect("Failed to create test event");

        event_id
    }

    async fn create_test_ticket_type(pool: &PgPool, event_id: Uuid, suffix: &str) -> TicketType {
        let create_request = CreateTicketTypeRequest {
            name: format!("Test Ticket Type {}", suffix),
            description: Some(format!("Description for {}", suffix)),
            price: Some(BigDecimal::from_str("50.00").unwrap()),
            currency: Some("XLM".to_string()),
            total_supply: Some(100),
        };

        TicketType::create(pool, event_id, create_request)
            .await
            .expect("Failed to create test ticket type")
    }

    async fn create_test_ticket(
        pool: &PgPool,
        ticket_type_id: Uuid,
        owner_id: Uuid,
        qr_code: Option<String>,
    ) -> Ticket {
        Ticket::create(pool, ticket_type_id, owner_id, qr_code)
            .await
            .expect("Failed to create test ticket")
    }

    // Cleanup 
    async fn cleanup_test_ticket(pool: &PgPool, ticket_id: Uuid) {
        sqlx::query!("DELETE FROM tickets WHERE id = $1", ticket_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_test_ticket_type(pool: &PgPool, ticket_type_id: Uuid) {
        sqlx::query!("DELETE FROM ticket_types WHERE id = $1", ticket_type_id)
            .execute(pool)
            .await
            .ok();
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

    mod ticket_creation {
        use super::*;

        #[tokio::test]
        async fn test_create_ticket_success() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "create_ticket").await;
            let organizer_id = create_test_user(&pool, "organizer").await;
            let event_id = create_test_event(&pool, organizer_id, "create_ticket").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "create_ticket").await;

            let qr_code = Some("test_qr_code_12345".to_string());
            let result = Ticket::create(&pool, ticket_type.id, owner_id, qr_code.clone()).await;

            assert!(result.is_ok(), "Ticket creation should succeed");
            let ticket = result.unwrap();

            assert!(!ticket.id.is_nil(), "Ticket should have valid ID");
            assert_eq!(ticket.ticket_type_id, ticket_type.id);
            assert_eq!(ticket.owner_id, owner_id);
            assert_eq!(ticket.status, "valid");
            assert_eq!(ticket.qr_code, qr_code);
            assert!(
                ticket.nft_identifier.is_none(),
                "New ticket should not have NFT identifier"
            );
            assert!(
                ticket.checked_in_at.is_none(),
                "New ticket should not be checked in"
            );
            assert!(
                ticket.checked_in_by.is_none(),
                "New ticket should not have check-in user"
            );
            assert!(
                ticket.pdf_url.is_none(),
                "New ticket should not have PDF URL"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_ticket_without_qr_code() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "no_qr").await;
            let organizer_id = create_test_user(&pool, "organizer_no_qr").await;
            let event_id = create_test_event(&pool, organizer_id, "no_qr").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "no_qr").await;

            let result = Ticket::create(&pool, ticket_type.id, owner_id, None).await;

            assert!(
                result.is_ok(),
                "Ticket creation without QR code should succeed"
            );
            let ticket = result.unwrap();

            assert!(ticket.qr_code.is_none(), "Ticket should not have QR code");
            assert_eq!(ticket.status, "valid");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_ticket_nonexistent_ticket_type() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nonexistent_type").await;
            let fake_ticket_type_id = Uuid::new_v4();

            let result = Ticket::create(&pool, fake_ticket_type_id, owner_id, None).await;

            assert!(result.is_err(), "Should fail with nonexistent ticket type");

            cleanup_test_user(&pool, owner_id).await;
        }

        #[tokio::test]
        async fn test_create_ticket_nonexistent_owner() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "nonexistent_owner").await;
            let event_id = create_test_event(&pool, organizer_id, "nonexistent_owner").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nonexistent_owner").await;
            let fake_owner_id = Uuid::new_v4();

            let result = Ticket::create(&pool, ticket_type.id, fake_owner_id, None).await;

            assert!(result.is_err(), "Should fail with nonexistent owner");

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_multiple_tickets_same_parameters() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "multiple_tickets").await;
            let organizer_id = create_test_user(&pool, "organizer_multiple").await;
            let event_id = create_test_event(&pool, organizer_id, "multiple_tickets").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "multiple_tickets").await;

            let qr_code = Some("shared_qr_code".to_string());
            let ticket1 = Ticket::create(&pool, ticket_type.id, owner_id, qr_code.clone())
                .await
                .unwrap();
            let ticket2 = Ticket::create(&pool, ticket_type.id, owner_id, qr_code.clone())
                .await
                .unwrap();

            assert_ne!(ticket1.id, ticket2.id, "Tickets should have unique IDs");
            assert_eq!(ticket1.qr_code, ticket2.qr_code, "QR codes can be the same");

            cleanup_test_ticket(&pool, ticket1.id).await;
            cleanup_test_ticket(&pool, ticket2.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_retrieval {
        use super::*;

        #[tokio::test]
        async fn test_find_by_id_existing_ticket() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "find_existing").await;
            let organizer_id = create_test_user(&pool, "organizer_find").await;
            let event_id = create_test_event(&pool, organizer_id, "find_existing").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "find_existing").await;
            let ticket =
                create_test_ticket(&pool, ticket_type.id, owner_id, Some("qr_123".to_string()))
                    .await;

            let result = Ticket::find_by_id(&pool, ticket.id).await;

            assert!(result.is_ok(), "Should find existing ticket");
            let found_ticket = result.unwrap();
            assert!(found_ticket.is_some(), "Ticket should exist");

            let t = found_ticket.unwrap();
            assert_eq!(t.id, ticket.id);
            assert_eq!(t.ticket_type_id, ticket.ticket_type_id);
            assert_eq!(t.owner_id, ticket.owner_id);
            assert_eq!(t.status, ticket.status);
            assert_eq!(t.qr_code, ticket.qr_code);

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_id_nonexistent_ticket() {
            let pool = setup_test_db().await;
            let random_id = Uuid::new_v4();

            let result = Ticket::find_by_id(&pool, random_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            assert!(
                result.unwrap().is_none(),
                "Should return None for nonexistent ticket"
            );
        }

        #[tokio::test]
        async fn test_find_by_owner() {
            let pool = setup_test_db().await;
            let owner1_id = create_test_user(&pool, "owner1").await;
            let owner2_id = create_test_user(&pool, "owner2").await;
            let organizer_id = create_test_user(&pool, "organizer_owner").await;
            let event_id = create_test_event(&pool, organizer_id, "find_by_owner").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "find_by_owner").await;

            // Create tickets for owner1
            let ticket1 =
                create_test_ticket(&pool, ticket_type.id, owner1_id, Some("qr_1".to_string()))
                    .await;
            let ticket2 =
                create_test_ticket(&pool, ticket_type.id, owner1_id, Some("qr_2".to_string()))
                    .await;

            // Create ticket for owner2
            let ticket3 =
                create_test_ticket(&pool, ticket_type.id, owner2_id, Some("qr_3".to_string()))
                    .await;

            let result = Ticket::find_by_owner(&pool, owner1_id).await;

            assert!(result.is_ok(), "Should find owner tickets");
            let tickets = result.unwrap();
            assert_eq!(tickets.len(), 2, "Should find exactly 2 tickets for owner1");

            let ticket_ids: Vec<Uuid> = tickets.iter().map(|t| t.id).collect();
            assert!(ticket_ids.contains(&ticket1.id), "Should contain ticket1");
            assert!(ticket_ids.contains(&ticket2.id), "Should contain ticket2");
            assert!(
                !ticket_ids.contains(&ticket3.id),
                "Should not contain other owner's ticket"
            );

            // Verify all tickets belong to correct owner
            for ticket in &tickets {
                assert_eq!(
                    ticket.owner_id, owner1_id,
                    "All tickets should belong to owner1"
                );
            }

            cleanup_test_ticket(&pool, ticket1.id).await;
            cleanup_test_ticket(&pool, ticket2.id).await;
            cleanup_test_ticket(&pool, ticket3.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner1_id).await;
            cleanup_test_user(&pool, owner2_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_owner_no_tickets() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "no_tickets").await;

            let result = Ticket::find_by_owner(&pool, owner_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let tickets = result.unwrap();
            assert!(
                tickets.is_empty(),
                "Should return empty vector for owner with no tickets"
            );

            cleanup_test_user(&pool, owner_id).await;
        }

        #[tokio::test]
        async fn test_find_by_owner_nonexistent_owner() {
            let pool = setup_test_db().await;
            let fake_owner_id = Uuid::new_v4();

            let result = Ticket::find_by_owner(&pool, fake_owner_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let tickets = result.unwrap();
            assert!(
                tickets.is_empty(),
                "Should return empty vector for nonexistent owner"
            );
        }
    }

    mod ticket_status_management {
        use super::*;

        #[tokio::test]
        async fn test_update_status_success() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "update_status").await;
            let organizer_id = create_test_user(&pool, "organizer_status").await;
            let event_id = create_test_event(&pool, organizer_id, "update_status").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "update_status").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            assert_eq!(ticket.status, "valid", "Initial status should be valid");

            let result = ticket.update_status(&pool, "cancelled").await;

            assert!(result.is_ok(), "Status update should succeed");
            let updated_ticket = result.unwrap();

            assert_eq!(updated_ticket.status, "cancelled");
            assert!(
                updated_ticket.updated_at > ticket.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_status_various_statuses() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "various_status").await;
            let organizer_id = create_test_user(&pool, "organizer_various").await;
            let event_id = create_test_event(&pool, organizer_id, "various_status").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "various_status").await;

            let statuses = vec!["valid", "used", "cancelled", "transferred", "refunded"];

            for status in statuses {
                let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;
                let result = ticket.update_status(&pool, status).await;

                assert!(result.is_ok(), "Should update to status: {}", status);
                assert_eq!(result.unwrap().status, status);

                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_status_empty_string() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "empty_status").await;
            let organizer_id = create_test_user(&pool, "organizer_empty").await;
            let event_id = create_test_event(&pool, organizer_id, "empty_status").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "empty_status").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let result = ticket.update_status(&pool, "").await;

            // This might succeed or fail depending on database constraints
            if result.is_ok() {
                assert_eq!(result.unwrap().status, "");
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_status_very_long_status() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "long_status").await;
            let organizer_id = create_test_user(&pool, "organizer_long").await;
            let event_id = create_test_event(&pool, organizer_id, "long_status").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "long_status").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let long_status = "a".repeat(100); // Very long status
            let result = ticket.update_status(&pool, &long_status).await;

            // This might succeed or fail depending on database field length
            if result.is_ok() {
                let updated = result.unwrap();
                assert!(updated.status.len() <= 50 || updated.status == long_status);
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_ownership_management {
        use super::*;

        #[tokio::test]
        async fn test_update_owner_success() {
            let pool = setup_test_db().await;
            let original_owner_id = create_test_user(&pool, "original_owner").await;
            let new_owner_id = create_test_user(&pool, "new_owner").await;
            let organizer_id = create_test_user(&pool, "organizer_transfer").await;
            let event_id = create_test_event(&pool, organizer_id, "update_owner").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "update_owner").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, original_owner_id, None).await;

            let result = ticket.update_owner(&pool, new_owner_id).await;

            assert!(result.is_ok(), "Owner update should succeed");
            let updated_ticket = result.unwrap();

            assert_eq!(updated_ticket.owner_id, new_owner_id);
            assert!(
                updated_ticket.updated_at > ticket.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, original_owner_id).await;
            cleanup_test_user(&pool, new_owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_owner_same_owner() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "same_owner").await;
            let organizer_id = create_test_user(&pool, "organizer_same").await;
            let event_id = create_test_event(&pool, organizer_id, "same_owner").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "same_owner").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let result = ticket.update_owner(&pool, owner_id).await;

            assert!(result.is_ok(), "Setting same owner should succeed");
            let updated_ticket = result.unwrap();
            assert_eq!(updated_ticket.owner_id, owner_id);

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_update_owner_nonexistent_new_owner() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nonexistent_new").await;
            let organizer_id = create_test_user(&pool, "organizer_nonexistent").await;
            let event_id = create_test_event(&pool, organizer_id, "nonexistent_new").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nonexistent_new").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;
            let fake_owner_id = Uuid::new_v4();

            let result = ticket.update_owner(&pool, fake_owner_id).await;

            assert!(result.is_err(), "Should fail with nonexistent new owner");
            // Should fail due to foreign key constraint

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_nft_management {
        use super::*;

        #[tokio::test]
        async fn test_set_nft_identifier_success() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nft_success").await;
            let organizer_id = create_test_user(&pool, "organizer_nft").await;
            let event_id = create_test_event(&pool, organizer_id, "nft_success").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nft_success").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let nft_id = "TKT123456789ABC";
            let result = ticket.set_nft_identifier(&pool, nft_id).await;

            assert!(result.is_ok(), "Setting NFT identifier should succeed");
            let updated_ticket = result.unwrap();

            assert_eq!(updated_ticket.nft_identifier, Some(nft_id.to_string()));
            assert!(
                updated_ticket.updated_at > ticket.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_nft_identifier_overwrite() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nft_overwrite").await;
            let organizer_id = create_test_user(&pool, "organizer_overwrite").await;
            let event_id = create_test_event(&pool, organizer_id, "nft_overwrite").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nft_overwrite").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            // Set initial NFT identifier
            let first_nft_id = "TKT111111111111";
            let ticket_with_nft = ticket
                .set_nft_identifier(&pool, first_nft_id)
                .await
                .unwrap();

            // Overwrite with new NFT identifier
            let second_nft_id = "TKT222222222222";
            let result = ticket_with_nft
                .set_nft_identifier(&pool, second_nft_id)
                .await;

            assert!(result.is_ok(), "Overwriting NFT identifier should succeed");
            let final_ticket = result.unwrap();
            assert_eq!(final_ticket.nft_identifier, Some(second_nft_id.to_string()));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_nft_identifier_empty_string() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nft_empty").await;
            let organizer_id = create_test_user(&pool, "organizer_empty_nft").await;
            let event_id = create_test_event(&pool, organizer_id, "nft_empty").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nft_empty").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let result = ticket.set_nft_identifier(&pool, "").await;

            // Should succeed with empty string
            assert!(
                result.is_ok(),
                "Setting empty NFT identifier should succeed"
            );
            let updated_ticket = result.unwrap();
            assert_eq!(updated_ticket.nft_identifier, Some("".to_string()));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_nft_identifier_very_long() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nft_long").await;
            let organizer_id = create_test_user(&pool, "organizer_long_nft").await;
            let event_id = create_test_event(&pool, organizer_id, "nft_long").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nft_long").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let long_nft_id = "TKT".to_string() + &"A".repeat(500);
            let result = ticket.set_nft_identifier(&pool, &long_nft_id).await;

            // This might succeed or fail depending on database field length
            if result.is_ok() {
                let updated = result.unwrap();
                assert!(updated.nft_identifier.is_some());
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_pdf_management {
        use super::*;

        #[tokio::test]
        async fn test_set_pdf_url_success() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "pdf_success").await;
            let organizer_id = create_test_user(&pool, "organizer_pdf").await;
            let event_id = create_test_event(&pool, organizer_id, "pdf_success").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "pdf_success").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let pdf_url = "https://example.com/tickets/12345.pdf";
            let result = ticket.set_pdf_url(&pool, pdf_url).await;

            assert!(result.is_ok(), "Setting PDF URL should succeed");
            let updated_ticket = result.unwrap();

            assert_eq!(updated_ticket.pdf_url, Some(pdf_url.to_string()));
            assert!(
                updated_ticket.updated_at > ticket.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_pdf_url_overwrite() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "pdf_overwrite").await;
            let organizer_id = create_test_user(&pool, "organizer_pdf_over").await;
            let event_id = create_test_event(&pool, organizer_id, "pdf_overwrite").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "pdf_overwrite").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            // Set initial PDF URL
            let first_url = "https://example.com/old.pdf";
            let ticket_with_pdf = ticket.set_pdf_url(&pool, first_url).await.unwrap();

            // Overwrite with new PDF URL
            let second_url = "https://example.com/new.pdf";
            let result = ticket_with_pdf.set_pdf_url(&pool, second_url).await;

            assert!(result.is_ok(), "Overwriting PDF URL should succeed");
            let final_ticket = result.unwrap();
            assert_eq!(final_ticket.pdf_url, Some(second_url.to_string()));

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_pdf_url_various_formats() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "pdf_formats").await;
            let organizer_id = create_test_user(&pool, "organizer_formats").await;
            let event_id = create_test_event(&pool, organizer_id, "pdf_formats").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "pdf_formats").await;

            let urls = vec![
                "https://example.com/ticket.pdf",
                "http://localhost:8080/storage/tickets/123.pdf",
                "/local/path/ticket.pdf",
                "s3://bucket/tickets/456.pdf",
                "https://cdn.example.com/very/long/path/to/ticket/file.pdf",
            ];

            for url in urls {
                let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;
                let result = ticket.set_pdf_url(&pool, url).await;

                assert!(result.is_ok(), "Should accept URL format: {}", url);
                assert_eq!(result.unwrap().pdf_url, Some(url.to_string()));

                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_check_in {
        use super::*;

        #[tokio::test]
        async fn test_check_in_success() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "checkin_success").await;
            let staff_id = create_test_user(&pool, "staff_checkin").await;
            let organizer_id = create_test_user(&pool, "organizer_checkin").await;
            let event_id = create_test_event(&pool, organizer_id, "checkin_success").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "checkin_success").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            assert_eq!(ticket.status, "valid");
            assert!(ticket.checked_in_at.is_none());
            assert!(ticket.checked_in_by.is_none());

            let result = ticket.check_in(&pool, staff_id).await;

            assert!(result.is_ok(), "Check-in should succeed");
            let checked_in_ticket = result.unwrap();

            assert_eq!(checked_in_ticket.status, "used");
            assert!(
                checked_in_ticket.checked_in_at.is_some(),
                "Should have check-in timestamp"
            );
            assert_eq!(checked_in_ticket.checked_in_by, Some(staff_id));
            assert!(
                checked_in_ticket.updated_at > ticket.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, staff_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_check_in_invalid_status() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "checkin_invalid").await;
            let staff_id = create_test_user(&pool, "staff_invalid").await;
            let organizer_id = create_test_user(&pool, "organizer_invalid").await;
            let event_id = create_test_event(&pool, organizer_id, "checkin_invalid").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "checkin_invalid").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            // Cancel the ticket first to make it invalid for check-in
            let cancelled_ticket = ticket.update_status(&pool, "cancelled").await.unwrap();
            assert_eq!(
                cancelled_ticket.status, "cancelled",
                "Ticket should be cancelled"
            );
            assert!(
                cancelled_ticket.checked_in_at.is_none(),
                "Cancelled ticket should not have check-in timestamp"
            );
            assert!(
                cancelled_ticket.checked_in_by.is_none(),
                "Cancelled ticket should not have check-in staff"
            );

            // Attempt to check in the cancelled ticket (should fail)
            let result = cancelled_ticket.check_in(&pool, staff_id).await;
            assert!(result.is_err(), "Check-in should fail for cancelled ticket");

            // Verify ticket state is completely unchanged after failed check-in attempt
            let ticket_after_failed_checkin =
                Ticket::find_by_id(&pool, ticket.id).await.unwrap().unwrap();
            assert_eq!(
                ticket_after_failed_checkin.status, "cancelled",
                "Status should remain 'cancelled'"
            );
            assert!(
                ticket_after_failed_checkin.checked_in_at.is_none(),
                "Should still have no check-in timestamp"
            );
            assert!(
                ticket_after_failed_checkin.checked_in_by.is_none(),
                "Should still have no check-in staff"
            );

            // Verify no other data was corrupted
            assert_eq!(ticket_after_failed_checkin.id, ticket.id);
            assert_eq!(ticket_after_failed_checkin.owner_id, ticket.owner_id);
            assert_eq!(
                ticket_after_failed_checkin.ticket_type_id,
                ticket.ticket_type_id
            );
            assert_eq!(ticket_after_failed_checkin.qr_code, ticket.qr_code);
            assert_eq!(
                ticket_after_failed_checkin.nft_identifier,
                ticket.nft_identifier
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, staff_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_check_in_already_checked_in() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "already_checked").await;
            let staff1_id = create_test_user(&pool, "staff1").await;
            let staff2_id = create_test_user(&pool, "staff2").await;
            let organizer_id = create_test_user(&pool, "organizer_already").await;
            let event_id = create_test_event(&pool, organizer_id, "already_checked").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "already_checked").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            // First check-in (should succeed)
            let checked_in_ticket = ticket.check_in(&pool, staff1_id).await.unwrap();

            // Verify first check-in worked correctly
            assert_eq!(checked_in_ticket.status, "used");
            assert!(
                checked_in_ticket.checked_in_at.is_some(),
                "Should have check-in timestamp"
            );
            assert_eq!(
                checked_in_ticket.checked_in_by,
                Some(staff1_id),
                "Should record first staff member"
            );
            let original_checkin_time = checked_in_ticket.checked_in_at.unwrap();

            // Second check-in attempt (should fail)
            let result = checked_in_ticket.check_in(&pool, staff2_id).await;
            assert!(result.is_err(), "Second check-in attempt should fail");

            // check ticket state is completely unchanged after failed attempt
            let ticket_after_failed_attempt =
                Ticket::find_by_id(&pool, ticket.id).await.unwrap().unwrap();
            assert_eq!(
                ticket_after_failed_attempt.status, "used",
                "Status should remain 'used'"
            );
            assert_eq!(
                ticket_after_failed_attempt.checked_in_by,
                Some(staff1_id),
                "Should still show original staff member"
            );
            assert_eq!(
                ticket_after_failed_attempt.checked_in_at,
                Some(original_checkin_time),
                "Check-in timestamp should be unchanged"
            );

            // confirm no data corruption occurred
            assert_eq!(ticket_after_failed_attempt.id, ticket.id);
            assert_eq!(ticket_after_failed_attempt.owner_id, ticket.owner_id);
            assert_eq!(
                ticket_after_failed_attempt.ticket_type_id,
                ticket.ticket_type_id
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, staff1_id).await;
            cleanup_test_user(&pool, staff2_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_check_in_nonexistent_staff() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "nonexistent_staff").await;
            let organizer_id = create_test_user(&pool, "organizer_nonstaff").await;
            let event_id = create_test_event(&pool, organizer_id, "nonexistent_staff").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "nonexistent_staff").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;
            let fake_staff_id = Uuid::new_v4();

            let result = ticket.check_in(&pool, fake_staff_id).await;

            // This might succeed or fail depending on foreign key constraints
            // If there's no FK constraint on checked_in_by, it might succeed
            if result.is_err() {
                // Expected if there's a FK constraint
                assert!(true, "Check-in with nonexistent staff should fail");
            } else {
                // If it succeeds, verify the data
                let checked_ticket = result.unwrap();
                assert_eq!(checked_ticket.checked_in_by, Some(fake_staff_id));
            }

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_authenticity_verification {
        use super::*;

        #[tokio::test]
        async fn test_verify_authenticity_valid_ticket() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "verify_valid").await;
            let organizer_id = create_test_user(&pool, "organizer_verify").await;
            let event_id = create_test_event(&pool, organizer_id, "verify_valid").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "verify_valid").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            let result = ticket.verify_authenticity(&pool).await;

            assert!(result.is_ok(), "Authenticity verification should succeed");
            assert!(result.unwrap(), "Valid ticket should be authentic");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_verify_authenticity_with_nft() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "verify_nft").await;
            let organizer_id = create_test_user(&pool, "organizer_nft_verify").await;
            let event_id = create_test_event(&pool, organizer_id, "verify_nft").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "verify_nft").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            // Set NFT identifier
            let nft_ticket = ticket.set_nft_identifier(&pool, "TKT123456").await.unwrap();

            let result = nft_ticket.verify_authenticity(&pool).await;

            assert!(result.is_ok(), "NFT ticket verification should succeed");
            assert!(result.unwrap(), "Valid NFT ticket should be authentic");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_verify_authenticity_cancelled_ticket() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "verify_cancelled").await;
            let organizer_id = create_test_user(&pool, "organizer_cancelled").await;
            let event_id = create_test_event(&pool, organizer_id, "verify_cancelled").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "verify_cancelled").await;
            let ticket = create_test_ticket(&pool, ticket_type.id, owner_id, None).await;

            // Cancel the ticket
            let cancelled_ticket = ticket.update_status(&pool, "cancelled").await.unwrap();

            let result = cancelled_ticket.verify_authenticity(&pool).await;

            assert!(result.is_ok(), "Verification should complete");
            assert!(!result.unwrap(), "Cancelled ticket should not be authentic");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod data_validation_and_serialization {
        use super::*;

        #[tokio::test]
        async fn test_ticket_serialization() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "serialization").await;
            let organizer_id = create_test_user(&pool, "organizer_serial").await;
            let event_id = create_test_event(&pool, organizer_id, "serialization").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "serialization").await;
            let ticket =
                create_test_ticket(&pool, ticket_type.id, owner_id, Some("qr_code".to_string()))
                    .await;

            let serialized = serde_json::to_string(&ticket).unwrap();

            assert!(
                serialized.contains(&ticket.id.to_string()),
                "ID should be serialized"
            );
            assert!(
                serialized.contains(&ticket.ticket_type_id.to_string()),
                "Ticket type ID should be serialized"
            );
            assert!(
                serialized.contains(&ticket.owner_id.to_string()),
                "Owner ID should be serialized"
            );
            assert!(
                serialized.contains("\"status\""),
                "Status should be serialized"
            );
            assert!(
                serialized.contains("qr_code"),
                "QR code should be serialized"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[test]
        fn test_check_in_request_deserialization() {
            let json = r#"{"ticket_id": "550e8400-e29b-41d4-a716-446655440000"}"#;

            let request: CheckInRequest = serde_json::from_str(json).unwrap();
            assert_eq!(
                request.ticket_id.to_string(),
                "550e8400-e29b-41d4-a716-446655440000"
            );
        }

        #[tokio::test]
        async fn test_ticket_with_all_fields_populated() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "all_fields").await;
            let staff_id = create_test_user(&pool, "staff_all").await;
            let organizer_id = create_test_user(&pool, "organizer_all").await;
            let event_id = create_test_event(&pool, organizer_id, "all_fields").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "all_fields").await;
            let ticket =
                create_test_ticket(&pool, ticket_type.id, owner_id, Some("full_qr".to_string()))
                    .await;

            let nft_ticket = ticket.set_nft_identifier(&pool, "NFT123").await.unwrap();
            let pdf_ticket = nft_ticket
                .set_pdf_url(&pool, "https://example.com/ticket.pdf")
                .await
                .unwrap();
            let checked_ticket = pdf_ticket.check_in(&pool, staff_id).await.unwrap();

            assert!(checked_ticket.qr_code.is_some());
            assert!(checked_ticket.nft_identifier.is_some());
            assert!(checked_ticket.pdf_url.is_some());
            assert!(checked_ticket.checked_in_at.is_some());
            assert!(checked_ticket.checked_in_by.is_some());
            assert_eq!(checked_ticket.status, "used");

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, staff_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod edge_cases_and_security {
        use super::*;

        #[tokio::test]
        async fn test_unicode_in_qr_code() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "unicode_qr").await;
            let organizer_id = create_test_user(&pool, "organizer_unicode").await;
            let event_id = create_test_event(&pool, organizer_id, "unicode_qr").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "unicode_qr").await;

            let unicode_qr = "QR코드🎫票券";
            let result = Ticket::create(
                &pool,
                ticket_type.id,
                owner_id,
                Some(unicode_qr.to_string()),
            )
            .await;

            if result.is_ok() {
                let ticket = result.unwrap();
                assert_eq!(ticket.qr_code, Some(unicode_qr.to_string()));
                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_very_long_qr_code() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "long_qr").await;
            let organizer_id = create_test_user(&pool, "organizer_long_qr").await;
            let event_id = create_test_event(&pool, organizer_id, "long_qr").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "long_qr").await;

            let long_qr = "QR".to_string() + &"A".repeat(1000);
            let result =
                Ticket::create(&pool, ticket_type.id, owner_id, Some(long_qr.clone())).await;

            if result.is_ok() {
                let ticket = result.unwrap();
                assert!(ticket.qr_code.is_some());
                cleanup_test_ticket(&pool, ticket.id).await;
            }

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_concurrent_ticket_creation() {
            let pool = setup_test_db().await;
            let owner_id = create_test_user(&pool, "concurrent").await;
            let organizer_id = create_test_user(&pool, "organizer_concurrent").await;
            let event_id = create_test_event(&pool, organizer_id, "concurrent").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "concurrent").await;

            // Attempt concurrent ticket creation
            let (result1, result2) = tokio::join!(
                Ticket::create(&pool, ticket_type.id, owner_id, Some("qr1".to_string())),
                Ticket::create(&pool, ticket_type.id, owner_id, Some("qr2".to_string()))
            );

            // Both should succeed
            assert!(
                result1.is_ok(),
                "First concurrent ticket creation should succeed"
            );
            assert!(
                result2.is_ok(),
                "Second concurrent ticket creation should succeed"
            );

            let ticket1 = result1.unwrap();
            let ticket2 = result2.unwrap();
            assert_ne!(ticket1.id, ticket2.id, "Tickets should have unique IDs");

            cleanup_test_ticket(&pool, ticket1.id).await;
            cleanup_test_ticket(&pool, ticket2.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, owner_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_ticket_lifecycle_complete() {
            let pool = setup_test_db().await;
            let original_owner = create_test_user(&pool, "lifecycle_original").await;
            let new_owner = create_test_user(&pool, "lifecycle_new").await;
            let staff_id = create_test_user(&pool, "lifecycle_staff").await;
            let organizer_id = create_test_user(&pool, "organizer_lifecycle").await;
            let event_id = create_test_event(&pool, organizer_id, "lifecycle").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "lifecycle").await;

            // Create ticket
            let ticket = create_test_ticket(
                &pool,
                ticket_type.id,
                original_owner,
                Some("lifecycle_qr".to_string()),
            )
            .await;
            assert_eq!(ticket.status, "valid");

            // Transfer ownership
            let transferred_ticket = ticket.update_owner(&pool, new_owner).await.unwrap();
            assert_eq!(transferred_ticket.owner_id, new_owner);

            // Convert to NFT
            let nft_ticket = transferred_ticket
                .set_nft_identifier(&pool, "LIFECYCLE_NFT")
                .await
                .unwrap();
            assert!(nft_ticket.nft_identifier.is_some());

            // Generate PDF
            let pdf_ticket = nft_ticket
                .set_pdf_url(&pool, "https://example.com/lifecycle.pdf")
                .await
                .unwrap();
            assert!(pdf_ticket.pdf_url.is_some());

            // Check in
            let final_ticket = pdf_ticket.check_in(&pool, staff_id).await.unwrap();
            assert_eq!(final_ticket.status, "used");
            assert!(final_ticket.checked_in_at.is_some());

            // Verify authenticity at end
            let is_authentic = final_ticket.verify_authenticity(&pool).await.unwrap();
            assert!(
                is_authentic,
                "Ticket should still be authentic after complete lifecycle"
            );

            cleanup_test_ticket(&pool, ticket.id).await;
            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, original_owner).await;
            cleanup_test_user(&pool, new_owner).await;
            cleanup_test_user(&pool, staff_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }
}
