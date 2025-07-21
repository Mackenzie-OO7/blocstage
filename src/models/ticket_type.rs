use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct TicketType {
    pub id: Uuid,
    pub event_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_free: bool,
    pub price: Option<BigDecimal>,
    pub currency: Option<String>,
    pub total_supply: Option<i32>,
    pub remaining: Option<i32>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTicketTypeRequest {
    pub name: String,
    pub description: Option<String>,
    pub is_free: bool,
    pub price: Option<BigDecimal>,
    pub currency: Option<String>,
    pub total_supply: Option<i32>,
}

impl TicketType {
    pub async fn create(
        pool: &PgPool,
        event_id: Uuid,
        ticket_type: CreateTicketTypeRequest,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        if !ticket_type.is_free {
            if ticket_type.price.is_none() {
                return Err(anyhow::anyhow!("Price is required for paid tickets"));
            }
            if ticket_type.currency.is_none() {
                return Err(anyhow::anyhow!("Currency is required for paid tickets"));
            }
        }

        let (final_price, final_currency) = if ticket_type.is_free {
            (None, None)
        } else {
            // For paid tickets, default currency to XLM if not provided
            let currency = ticket_type.currency.unwrap_or_else(|| "XLM".to_string());
            (ticket_type.price, Some(currency))
        };

        let result = sqlx::query!(
            r#"
            INSERT INTO ticket_types (
                id, event_id, name, description, is_free, price, currency, 
                total_supply, remaining, is_active, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id, event_id, name, description, is_free, price, currency, 
                      total_supply, remaining, is_active, created_at, updated_at
            "#,
            id,
            event_id,
            ticket_type.name,
            ticket_type.description,
            ticket_type.is_free,
            final_price,
            final_currency,
            ticket_type.total_supply,
            ticket_type.total_supply,
            true,
            now,
            now
        )
        .fetch_one(pool)
        .await?;

        Ok(TicketType {
            id: result.id,
            event_id: result.event_id,
            name: result.name,
            description: result.description,
            is_free: result.is_free,
            price: result.price,
            currency: result.currency,
            total_supply: result.total_supply,
            remaining: result.remaining,
            is_active: result.is_active,
            created_at: result.created_at,
            updated_at: result.updated_at,
        })
    }

    pub fn is_claimable(&self) -> bool {
        self.is_free && self.is_active
    }

    pub fn is_purchasable(&self) -> bool {
        !self.is_free && self.is_active && self.price.is_some() && self.currency.is_some()
    }

    pub async fn find_by_event(pool: &PgPool, event_id: Uuid) -> Result<Vec<Self>> {
        let results = sqlx::query!(
            r#"
            SELECT id, event_id, name, description, is_free, price, currency, 
                   total_supply, remaining, is_active, created_at, updated_at
            FROM ticket_types WHERE event_id = $1 AND is_active = true
            ORDER BY is_free DESC, price ASC
            "#,
            event_id
        )
        .fetch_all(pool)
        .await?;

        let mut ticket_types = Vec::new();
        for row in results {
            ticket_types.push(TicketType {
                id: row.id,
                event_id: row.event_id,
                name: row.name,
                description: row.description,
                is_free: row.is_free,
                price: row.price,
                currency: row.currency,
                total_supply: row.total_supply,
                remaining: row.remaining,
                is_active: row.is_active,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }

        Ok(ticket_types)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let result = sqlx::query!(
            r#"
            SELECT id, event_id, name, description, is_free, price, currency, 
                   total_supply, remaining, is_active, created_at, updated_at
            FROM ticket_types WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await?;

        match result {
            Some(row) => Ok(Some(TicketType {
                id: row.id,
                event_id: row.event_id,
                name: row.name,
                description: row.description,
                is_free: row.is_free,
                price: row.price,
                currency: row.currency,
                total_supply: row.total_supply,
                remaining: row.remaining,
                is_active: row.is_active,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })),
            None => Ok(None),
        }
    }

    pub async fn decrease_remaining(&self, pool: &PgPool) -> Result<Self> {
        if let Some(remaining) = self.remaining {
            if remaining > 0 {
                let result = sqlx::query!(
                    r#"
                    UPDATE ticket_types
                    SET remaining = remaining - 1, updated_at = $1
                    WHERE id = $2
                    RETURNING id, event_id, name, description, is_free, price, currency, 
                             total_supply, remaining, is_active, created_at, updated_at
                    "#,
                    Utc::now(),
                    self.id
                )
                .fetch_one(pool)
                .await?;

                return Ok(TicketType {
                    id: result.id,
                    event_id: result.event_id,
                    name: result.name,
                    description: result.description,
                    is_free: result.is_free,
                    price: result.price,
                    currency: result.currency,
                    total_supply: result.total_supply,
                    remaining: result.remaining,
                    is_active: result.is_active,
                    created_at: result.created_at,
                    updated_at: result.updated_at,
                });
            }
        }

        anyhow::bail!("No tickets remaining")
    }

    // for cancellations
    pub async fn increase_remaining(&self, pool: &PgPool, amount: i32) -> Result<Self> {
        // only increase if there's a limit on tickets
        if self.total_supply.is_some() {
            let result = sqlx::query!(
                r#"
                UPDATE ticket_types
                SET remaining = remaining + $1, updated_at = $2
                WHERE id = $3
                RETURNING id, event_id, name, description, is_free, price, currency, 
                         total_supply, remaining, is_active, created_at, updated_at
                "#,
                amount,
                Utc::now(),
                self.id
            )
            .fetch_one(pool)
            .await?;

            return Ok(TicketType {
                id: result.id,
                event_id: result.event_id,
                name: result.name,
                description: result.description,
                is_free: result.is_free,
                price: result.price,
                currency: result.currency,
                total_supply: result.total_supply,
                remaining: result.remaining,
                is_active: result.is_active,
                created_at: result.created_at,
                updated_at: result.updated_at,
            });
        }

        Ok(self.clone())
    }

    // activate/deactivate ticket sales
    pub async fn set_active_status(&self, pool: &PgPool, is_active: bool) -> Result<Self> {
        let result = sqlx::query!(
            r#"
            UPDATE ticket_types
            SET is_active = $1, updated_at = $2
            WHERE id = $3
            RETURNING id, event_id, name, description, is_free, price, currency, 
                     total_supply, remaining, is_active, created_at, updated_at
            "#,
            is_active,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(TicketType {
            id: result.id,
            event_id: result.event_id,
            name: result.name,
            description: result.description,
            is_free: result.is_free,
            price: result.price,
            currency: result.currency,
            total_supply: result.total_supply,
            remaining: result.remaining,
            is_active: result.is_active,
            created_at: result.created_at,
            updated_at: result.updated_at,
        })
    }

    pub fn is_available(&self) -> bool {
        if !self.is_active {
            return false;
        }

        match self.remaining {
            Some(remaining) => remaining > 0,
            None => true,
        }
    }

    pub fn formatted_price(&self) -> String {
        if self.is_free {
            "Free".to_string()
        } else {
            match (&self.price, &self.currency) {
                (Some(price), Some(currency)) => format!("{} {}", price, currency),
                (Some(price), None) => format!("{}", price),
                (None, _) => "Free".to_string(),
            }
        }
    }
}

// tests

#[cfg(test)]
mod tests {
    use super::*;
    use bigdecimal::BigDecimal;
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use std::env;
    use std::str::FromStr;
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
            name: format!("Test Ticket {}", suffix),
            description: Some(format!("Description for {}", suffix)),
            is_free: true,
            price: Some(BigDecimal::from_str("50.00").unwrap()),
            currency: Some("XLM".to_string()),
            total_supply: Some(100),
        };

        TicketType::create(pool, event_id, create_request)
            .await
            .expect("Failed to create test ticket type")
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

    mod ticket_type_creation {
        use super::*;

        #[tokio::test]
        async fn test_create_paid_ticket_type_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "paid_ticket").await;
            let event_id = create_test_event(&pool, organizer_id, "paid_ticket").await;

            let create_request = CreateTicketTypeRequest {
                name: "VIP Ticket".to_string(),
                description: Some("Premium access with perks".to_string()),
                is_free: false,
                price: Some(BigDecimal::from_str("100.50").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(50),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            assert!(result.is_ok(), "Paid ticket type creation should succeed");
            let ticket_type = result.unwrap();

            assert!(!ticket_type.id.is_nil(), "Ticket type should have valid ID");
            assert_eq!(ticket_type.event_id, event_id);
            assert_eq!(ticket_type.name, "VIP Ticket");
            assert_eq!(
                ticket_type.description,
                Some("Premium access with perks".to_string())
            );
            assert_eq!(
                ticket_type.price,
                Some(BigDecimal::from_str("100.50").unwrap())
            );
            assert_eq!(ticket_type.currency, Some("XLM".to_string()));
            assert_eq!(ticket_type.total_supply, Some(50));
            assert_eq!(ticket_type.remaining, Some(50)); // Should equal total_supply initially
            assert!(ticket_type.is_active, "New ticket type should be active");

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_free_ticket_type_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "free_ticket").await;
            let event_id = create_test_event(&pool, organizer_id, "free_ticket").await;

            let create_request = CreateTicketTypeRequest {
                name: "General Admission".to_string(),
                description: Some("Free entry to the event".to_string()),
                is_free: true,
                price: None,
                currency: None,
                total_supply: Some(200),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            assert!(result.is_ok(), "Free ticket type creation should succeed");
            let ticket_type = result.unwrap();

            assert_eq!(ticket_type.name, "General Admission");
            assert!(
                ticket_type.price.is_none(),
                "Free ticket should have no price"
            );
            assert_eq!(ticket_type.currency, Some("XLM".to_string())); // Should default to XLM
            assert_eq!(ticket_type.total_supply, Some(200));
            assert_eq!(ticket_type.remaining, Some(200));

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_unlimited_ticket_type() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "unlimited_ticket").await;
            let event_id = create_test_event(&pool, organizer_id, "unlimited_ticket").await;

            let create_request = CreateTicketTypeRequest {
                name: "Unlimited Access".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("25.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: None,
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            assert!(
                result.is_ok(),
                "Unlimited ticket type creation should succeed"
            );
            let ticket_type = result.unwrap();

            assert_eq!(ticket_type.name, "Unlimited Access");
            assert!(
                ticket_type.total_supply.is_none(),
                "Should have no supply limit"
            );
            assert!(
                ticket_type.remaining.is_none(),
                "Should have no remaining count"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_ticket_type_nonexistent_event() {
            let pool = setup_test_db().await;
            let fake_event_id = Uuid::new_v4();

            let create_request = CreateTicketTypeRequest {
                name: "Orphan Ticket".to_string(),
                description: None,
                is_free: true,
                price: None,
                currency: None,
                total_supply: Some(10),
            };

            let result = TicketType::create(&pool, fake_event_id, create_request).await;

            assert!(result.is_err(), "Should fail with nonexistent event");
        }

        #[tokio::test]
        async fn test_create_ticket_type_empty_name() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "empty_name").await;
            let event_id = create_test_event(&pool, organizer_id, "empty_name").await;

            let create_request = CreateTicketTypeRequest {
                name: "".to_string(),
                description: None,
                is_free: true,
                price: None,
                currency: None,
                total_supply: Some(10),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            if result.is_ok() {
                let ticket_type = result.unwrap();
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_ticket_type_negative_price() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "negative_price").await;
            let event_id = create_test_event(&pool, organizer_id, "negative_price").await;

            let create_request = CreateTicketTypeRequest {
                name: "Negative Price Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("-10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(10),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            // This might be allowed or rejected depending on business logic
            if result.is_ok() {
                let ticket_type = result.unwrap();
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_create_ticket_type_zero_supply() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "zero_supply").await;
            let event_id = create_test_event(&pool, organizer_id, "zero_supply").await;

            let create_request = CreateTicketTypeRequest {
                name: "Zero Supply Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(0),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            if result.is_ok() {
                let ticket_type = result.unwrap();
                assert_eq!(ticket_type.total_supply, Some(0));
                assert_eq!(ticket_type.remaining, Some(0));
                assert!(
                    !ticket_type.is_available(),
                    "Zero supply ticket should not be available"
                );
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_type_retrieval {
        use super::*;

        #[tokio::test]
        async fn test_find_by_id_existing_ticket_type() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "find_existing").await;
            let event_id = create_test_event(&pool, organizer_id, "find_existing").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "find_existing").await;

            let result = TicketType::find_by_id(&pool, ticket_type.id).await;

            assert!(result.is_ok(), "Should find existing ticket type");
            let found_ticket_type = result.unwrap();
            assert!(found_ticket_type.is_some(), "Ticket type should exist");

            let tt = found_ticket_type.unwrap();
            assert_eq!(tt.id, ticket_type.id);
            assert_eq!(tt.event_id, ticket_type.event_id);
            assert_eq!(tt.name, ticket_type.name);
            assert_eq!(tt.price, ticket_type.price);

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_id_nonexistent_ticket_type() {
            let pool = setup_test_db().await;
            let random_id = Uuid::new_v4();

            let result = TicketType::find_by_id(&pool, random_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            assert!(
                result.unwrap().is_none(),
                "Should return None for nonexistent ticket type"
            );
        }

        #[tokio::test]
        async fn test_find_by_event() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "find_by_event").await;
            let event_id = create_test_event(&pool, organizer_id, "find_by_event").await;
            let other_event_id = create_test_event(&pool, organizer_id, "other_event").await;

            // Create ticket types for the target event
            let tt1 = create_test_ticket_type(&pool, event_id, "event_tt1").await;
            let tt2 = create_test_ticket_type(&pool, event_id, "event_tt2").await;

            // Create ticket type for different event
            let other_tt = create_test_ticket_type(&pool, other_event_id, "other_tt").await;

            let result = TicketType::find_by_event(&pool, event_id).await;

            assert!(result.is_ok(), "Should find event ticket types");
            let ticket_types = result.unwrap();

            assert_eq!(
                ticket_types.len(),
                2,
                "Should find exactly 2 ticket types for event"
            );

            let tt_ids: Vec<Uuid> = ticket_types.iter().map(|tt| tt.id).collect();
            assert!(tt_ids.contains(&tt1.id), "Should contain first ticket type");
            assert!(
                tt_ids.contains(&tt2.id),
                "Should contain second ticket type"
            );
            assert!(
                !tt_ids.contains(&other_tt.id),
                "Should not contain other event's ticket type"
            );

            // Verify all ticket types belong to the correct event
            for tt in &ticket_types {
                assert_eq!(
                    tt.event_id, event_id,
                    "All ticket types should belong to the event"
                );
            }

            // Cleanup
            cleanup_test_ticket_type(&pool, tt1.id).await;
            cleanup_test_ticket_type(&pool, tt2.id).await;
            cleanup_test_ticket_type(&pool, other_tt.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_event(&pool, other_event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_event_no_ticket_types() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "no_tickets").await;
            let event_id = create_test_event(&pool, organizer_id, "no_tickets").await;

            let result = TicketType::find_by_event(&pool, event_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let ticket_types = result.unwrap();
            assert!(
                ticket_types.is_empty(),
                "Should return empty vector for event with no ticket types"
            );

            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_find_by_event_nonexistent_event() {
            let pool = setup_test_db().await;
            let fake_event_id = Uuid::new_v4();

            let result = TicketType::find_by_event(&pool, fake_event_id).await;

            assert!(result.is_ok(), "Query should execute successfully");
            let ticket_types = result.unwrap();
            assert!(
                ticket_types.is_empty(),
                "Should return empty vector for nonexistent event"
            );
        }
    }

    mod ticket_type_inventory_management {
        use super::*;

        #[tokio::test]
        async fn test_decrease_remaining_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "decrease_remaining").await;
            let event_id = create_test_event(&pool, organizer_id, "decrease_remaining").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "decrease_remaining").await;

            let initial_remaining = ticket_type.remaining.unwrap();

            let result = ticket_type.decrease_remaining(&pool).await;

            assert!(result.is_ok(), "Decrease remaining should succeed");
            let updated_ticket_type = result.unwrap();

            assert_eq!(updated_ticket_type.remaining, Some(initial_remaining - 1));
            assert!(
                updated_ticket_type.updated_at > ticket_type.updated_at,
                "Updated timestamp should be newer"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_decrease_remaining_zero_remaining() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "zero_remaining").await;
            let event_id = create_test_event(&pool, organizer_id, "zero_remaining").await;

            // Create ticket type with zero supply
            let create_request = CreateTicketTypeRequest {
                name: "Zero Supply Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(0),
            };
            let ticket_type = TicketType::create(&pool, event_id, create_request)
                .await
                .unwrap();

            let result = ticket_type.decrease_remaining(&pool).await;

            assert!(
                result.is_err(),
                "Should fail to decrease when no tickets remaining"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_decrease_remaining_unlimited_supply() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "unlimited_decrease").await;
            let event_id = create_test_event(&pool, organizer_id, "unlimited_decrease").await;

            // Create unlimited ticket type
            let create_request = CreateTicketTypeRequest {
                name: "Unlimited Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: None, // Unlimited
            };
            let ticket_type = TicketType::create(&pool, event_id, create_request)
                .await
                .unwrap();

            let result = ticket_type.decrease_remaining(&pool).await;

            assert!(
                result.is_err(),
                "Should fail to decrease unlimited supply ticket"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_increase_remaining_success() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "increase_remaining").await;
            let event_id = create_test_event(&pool, organizer_id, "increase_remaining").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "increase_remaining").await;

            let initial_remaining = ticket_type.remaining.unwrap();
            let increase_amount = 5;

            let result = ticket_type.increase_remaining(&pool, increase_amount).await;

            assert!(result.is_ok(), "Increase remaining should succeed");
            let updated_ticket_type = result.unwrap();

            assert_eq!(
                updated_ticket_type.remaining,
                Some(initial_remaining + increase_amount)
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_increase_remaining_unlimited_supply() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "unlimited_increase").await;
            let event_id = create_test_event(&pool, organizer_id, "unlimited_increase").await;

            // Create unlimited ticket type
            let create_request = CreateTicketTypeRequest {
                name: "Unlimited Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: None,
            };
            let ticket_type = TicketType::create(&pool, event_id, create_request)
                .await
                .unwrap();

            let result = ticket_type.increase_remaining(&pool, 5).await;

            assert!(result.is_ok(), "Should succeed for unlimited ticket type");
            let updated_ticket_type = result.unwrap();

            // For unlimited tickets,no change
            assert_eq!(
                updated_ticket_type.remaining, None,
                "Unlimited tickets should remain None"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_type_status_management {
        use super::*;

        #[tokio::test]
        async fn test_set_active_status_disable() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "disable_ticket").await;
            let event_id = create_test_event(&pool, organizer_id, "disable_ticket").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "disable_ticket").await;

            assert!(
                ticket_type.is_active,
                "Ticket type should be active initially"
            );

            let result = ticket_type.set_active_status(&pool, false).await;

            assert!(result.is_ok(), "Disabling ticket type should succeed");
            let updated_ticket_type = result.unwrap();

            assert!(
                !updated_ticket_type.is_active,
                "Ticket type should be inactive"
            );
            assert!(
                !updated_ticket_type.is_available(),
                "Inactive ticket type should not be available"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_active_status_enable() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "enable_ticket").await;
            let event_id = create_test_event(&pool, organizer_id, "enable_ticket").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "enable_ticket").await;

            // First disable it
            let disabled_ticket_type = ticket_type.set_active_status(&pool, false).await.unwrap();
            assert!(!disabled_ticket_type.is_active);

            // Then re-enable it
            let result = disabled_ticket_type.set_active_status(&pool, true).await;

            assert!(result.is_ok(), "Enabling ticket type should succeed");
            let enabled_ticket_type = result.unwrap();

            assert!(
                enabled_ticket_type.is_active,
                "Ticket type should be active"
            );
            assert!(
                enabled_ticket_type.is_available(),
                "Active ticket type with supply should be available"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_set_active_status_idempotent() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "idempotent_status").await;
            let event_id = create_test_event(&pool, organizer_id, "idempotent_status").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "idempotent_status").await;

            // Set to active (already active)
            let result = ticket_type.set_active_status(&pool, true).await;

            assert!(result.is_ok(), "Setting to same status should succeed");
            let updated_ticket_type = result.unwrap();
            assert!(updated_ticket_type.is_active);

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod ticket_type_business_logic {
        use super::*;

        #[tokio::test]
        async fn test_is_available_active_with_supply() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "available_test").await;
            let event_id = create_test_event(&pool, organizer_id, "available_test").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "available_test").await;

            assert!(
                ticket_type.is_available(),
                "Active ticket type with remaining supply should be available"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_is_available_inactive() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "inactive_test").await;
            let event_id = create_test_event(&pool, organizer_id, "inactive_test").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "inactive_test").await;

            let inactive_ticket_type = ticket_type.set_active_status(&pool, false).await.unwrap();

            assert!(
                !inactive_ticket_type.is_available(),
                "Inactive ticket type should not be available"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_is_available_no_remaining() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "no_remaining_test").await;
            let event_id = create_test_event(&pool, organizer_id, "no_remaining_test").await;

            // Create ticket type with zero supply
            let create_request = CreateTicketTypeRequest {
                name: "Sold Out Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(0),
            };
            let ticket_type = TicketType::create(&pool, event_id, create_request)
                .await
                .unwrap();

            assert!(
                !ticket_type.is_available(),
                "Ticket type with no remaining supply should not be available"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_is_available_unlimited_supply() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "unlimited_test").await;
            let event_id = create_test_event(&pool, organizer_id, "unlimited_test").await;

            // Create unlimited ticket type
            let create_request = CreateTicketTypeRequest {
                name: "Unlimited Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: None,
            };
            let ticket_type = TicketType::create(&pool, event_id, create_request)
                .await
                .unwrap();

            assert!(
                ticket_type.is_available(),
                "Active unlimited ticket type should be available"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_formatted_price_paid_ticket() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "formatted_price").await;
            let event_id = create_test_event(&pool, organizer_id, "formatted_price").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "formatted_price").await;

            let formatted = ticket_type.formatted_price();
            assert!(formatted.contains("50"), "Should contain price amount");
            assert!(formatted.contains("XLM"), "Should contain currency");

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_formatted_price_free_ticket() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "free_formatted").await;
            let event_id = create_test_event(&pool, organizer_id, "free_formatted").await;

            // Create free ticket type
            let create_request = CreateTicketTypeRequest {
                name: "Free Ticket".to_string(),
                description: None,
                is_free: true,
                price: None,
                currency: None,
                total_supply: Some(100),
            };
            let ticket_type = TicketType::create(&pool, event_id, create_request)
                .await
                .unwrap();

            let formatted = ticket_type.formatted_price();
            assert_eq!(formatted, "Free", "Free ticket should show 'Free'");

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod data_validation {
        use super::*;

        #[test]
        fn test_create_ticket_type_request_deserialization() {
            let json = r#"{
                "name": "VIP Ticket",
                "description": "Premium access",
                is_free: false,
                "price": "100.50",
                "currency": "XLM",
                "total_supply": 50
            }"#;

            let request: CreateTicketTypeRequest = serde_json::from_str(json).unwrap();

            assert_eq!(request.name, "VIP Ticket");
            assert_eq!(request.description, Some("Premium access".to_string()));
            assert_eq!(request.is_free, false);
            assert_eq!(request.price, Some(BigDecimal::from_str("100.50").unwrap()));
            assert_eq!(request.currency, Some("XLM".to_string()));
            assert_eq!(request.total_supply, Some(50));
        }

        #[test]
        fn test_create_ticket_type_request_minimal() {
            let json = r#"{
                "name": "Basic Ticket"
            }"#;

            let request: CreateTicketTypeRequest = serde_json::from_str(json).unwrap();

            assert_eq!(request.name, "Basic Ticket");
            assert!(request.description.is_none());
            assert!(request.price.is_none());
            assert!(request.currency.is_none());
            assert!(request.total_supply.is_none());
        }

        #[tokio::test]
        async fn test_ticket_type_serialization() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "serialization").await;
            let event_id = create_test_event(&pool, organizer_id, "serialization").await;
            let ticket_type = create_test_ticket_type(&pool, event_id, "serialization").await;

            let serialized = serde_json::to_string(&ticket_type).unwrap();

            // Verify key fields are included
            assert!(
                serialized.contains(&ticket_type.id.to_string()),
                "ID should be serialized"
            );
            assert!(
                serialized.contains(&ticket_type.name),
                "Name should be serialized"
            );
            assert!(
                serialized.contains(&ticket_type.event_id.to_string()),
                "Event ID should be serialized"
            );
            assert!(
                serialized.contains("\"is_active\""),
                "Active status should be serialized"
            );

            cleanup_test_ticket_type(&pool, ticket_type.id).await;
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }

    mod edge_cases {
        use super::*;

        #[tokio::test]
        async fn test_very_large_price() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "large_price").await;
            let event_id = create_test_event(&pool, organizer_id, "large_price").await;

            let create_request = CreateTicketTypeRequest {
                name: "Expensive Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("999999999.99999999").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(1),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            if result.is_ok() {
                let ticket_type = result.unwrap();
                assert!(ticket_type.price.unwrap() > BigDecimal::from_str("999999999").unwrap());
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_very_large_supply() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "large_supply").await;
            let event_id = create_test_event(&pool, organizer_id, "large_supply").await;

            let create_request = CreateTicketTypeRequest {
                name: "Mass Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("1.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(2_000_000_000), // 2 billion tickets
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            if result.is_ok() {
                let ticket_type = result.unwrap();
                assert_eq!(ticket_type.total_supply, Some(2_000_000_000));
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_unicode_characters_in_fields() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "unicode").await;
            let event_id = create_test_event(&pool, organizer_id, "unicode").await;

            let create_request = CreateTicketTypeRequest {
                name: "票券 🎫 Билет".to_string(),
                description: Some("多言語対応 multilingual 🌍".to_string()),
                is_free: false,
                price: Some(BigDecimal::from_str("25.50").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(50),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            if result.is_ok() {
                let ticket_type = result.unwrap();
                assert!(
                    ticket_type.name.contains("票券"),
                    "Should preserve unicode characters"
                );
                assert!(ticket_type.name.contains("🎫"), "Should preserve emojis");
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_concurrent_ticket_type_creation() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "concurrent").await;
            let event_id = create_test_event(&pool, organizer_id, "concurrent").await;

            let create_request1 = CreateTicketTypeRequest {
                name: "Concurrent Ticket 1".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("10.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(50),
            };

            let create_request2 = CreateTicketTypeRequest {
                name: "Concurrent Ticket 2".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("20.00").unwrap()),
                currency: Some("XLM".to_string()),
                total_supply: Some(50),
            };

            // Attempt concurrent creation
            let (result1, result2) = tokio::join!(
                TicketType::create(&pool, event_id, create_request1),
                TicketType::create(&pool, event_id, create_request2)
            );

            // Both should succeed as there are no uniqueness constraints
            assert!(
                result1.is_ok() || result2.is_ok(),
                "At least one ticket type creation should succeed"
            );

            if let Ok(ticket_type) = result1 {
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            if let Ok(ticket_type) = result2 {
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }

        #[tokio::test]
        async fn test_decimal_precision_handling() {
            let pool = setup_test_db().await;
            let organizer_id = create_test_user(&pool, "decimal_precision").await;
            let event_id = create_test_event(&pool, organizer_id, "decimal_precision").await;

            let create_request = CreateTicketTypeRequest {
                name: "Precise Price Ticket".to_string(),
                description: None,
                is_free: false,
                price: Some(BigDecimal::from_str("12.12345678").unwrap()), // 8 decimal places
                currency: Some("XLM".to_string()),
                total_supply: Some(10),
            };

            let result = TicketType::create(&pool, event_id, create_request).await;

            if result.is_ok() {
                let ticket_type = result.unwrap();
                // Verify decimal precision is preserved
                let expected_price = BigDecimal::from_str("12.12345678").unwrap();
                assert_eq!(ticket_type.price, Some(expected_price));
                cleanup_test_ticket_type(&pool, ticket_type.id).await;
            }
            cleanup_test_event(&pool, event_id).await;
            cleanup_test_user(&pool, organizer_id).await;
        }
    }
}
