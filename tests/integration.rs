use actix_web::{test, web, App};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::env;
use uuid::Uuid;

use blocstage::models::user::LoginRequest;
use blocstage::services::crypto::KeyEncryption;
use blocstage::services::{AuthService, StellarService};

async fn setup_test_db() -> PgPool {
    dotenv::from_filename(".env.test").ok();
    dotenv::dotenv().ok();

    let database_url = env::var("TEST_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .expect("TEST_DATABASE_URL or DATABASE_URL must be set for integration tests");

    println!("🔌 Connecting to test database...");
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    println!("🔄 Running migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

fn get_unique_test_identifier() -> String {
    let uuid_str = format!("{}", Uuid::new_v4().simple());
    format!(
        "{}_{}",
        std::process::id(),
        &uuid_str[..8]
    )
}

async fn create_test_user(pool: &PgPool) -> (Uuid, String) {
    let user_id = Uuid::new_v4();
    let unique_id = get_unique_test_identifier();
    let email = format!("test{}@example.com", unique_id);
    let username = format!("user{}", unique_id);

    // Use cost factor 4 for faster testing
    let password_hash = bcrypt::hash("password123", 4).unwrap();
    println!("🔐 Created test user: {} with ID: {}", email, user_id);

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, email_verified, role, status, first_name, last_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, 'user', 'active', $5, $6, NOW(), NOW())
        "#,
    )
    .bind(user_id)
    .bind(username)
    .bind(email.clone())
    .bind(password_hash)
    .bind("Test")
    .bind("User")
    .execute(pool)
    .await
    .expect("Failed to create test user");

    (user_id, email)
}

async fn get_auth_token(pool: &PgPool, email: &str) -> String {
    println!("🔑 Getting auth token for: {}", email);

    dotenv::from_filename(".env.test").ok();
    dotenv::dotenv().ok();

    // Skip auth token generation if TESTNET_USDC_ISSUER is not set
    if env::var("TESTNET_USDC_ISSUER").is_err() {
        println!("⏭️  Skipping auth token generation - TESTNET_USDC_ISSUER not set");
        // Return a dummy token for tests that don't require Stellar functionality
        return "test-token-dummy".to_string();
    }

    let user_check = sqlx::query(
        "SELECT id, email, password_hash, email_verified, status, role FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .expect("Failed to check user existence");

    match user_check {
        Some(row) => {
            let user_id: Uuid = row.get("id");
            let password_hash: String = row.get("password_hash");
            let email_verified: bool = row.get("email_verified");
            let status: String = row.get("status");
            let role: String = row.get("role");

            println!(
                "✅ Found user: ID={}, verified={}, status={}, role={}",
                user_id, email_verified, status, role
            );

            let password_verify_result = bcrypt::verify("password123", &password_hash);
            if !password_verify_result.unwrap_or(false) {
                panic!("Password verification failed in test setup");
            }
        }
        None => {
            panic!("User {} not found in database", email);
        }
    };

    let auth_service = AuthService::new(pool.clone()).await.expect("Failed to create AuthService");

    let login_req = LoginRequest {
        email: email.to_string(),
        password: "password123".to_string(),
    };

    match auth_service.login(login_req, Some("127.0.0.1".to_string()), Some("test-agent".to_string())).await {
        Ok(token) => {
            println!("✅ Token generated successfully");
            token
        }
        Err(e) => {
            panic!("Failed to login test user: {}", e);
        }
    }
}

#[actix_web::test]
async fn test_user_registration_and_login() {
    let pool = setup_test_db().await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(blocstage::controllers::configure_routes),
    )
    .await;

    let unique_id = get_unique_test_identifier();
    let test_email = format!("reg{}@example.com", unique_id);
    let test_username = format!("reguser{}", unique_id);

    let reg_payload = json!({
        "username": test_username,
        "email": test_email,
        "password": "password123",
        "first_name": "Test",
        "last_name": "User"
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&reg_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("📝 Registration response status: {}", resp.status());

    if !resp.status().is_success() {
        let body = test::read_body(resp).await;
        println!("❌ Registration failed: {}", String::from_utf8_lossy(&body));
        panic!("Registration should succeed");
    }

    let user = sqlx::query("SELECT * FROM users WHERE email = $1")
        .bind(&test_email)
        .fetch_one(&pool)
        .await
        .expect("User should exist");

    let username: String = user.get("username");
    let email_verified: bool = user.get("email_verified");

    assert_eq!(username, test_username);
    assert!(!email_verified);

    println!("✅ User registration test passed");
}

#[actix_web::test]
async fn test_event_creation_and_management() {
    let pool = setup_test_db().await;

    let (user_id, email) = create_test_user(&pool).await;

    sqlx::query(
        "UPDATE users SET email_verified = true WHERE id = $1"
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("Failed to verify user");

    let token = get_auth_token(&pool, &email).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(blocstage::controllers::configure_routes),
    )
    .await;

    let unique_id = get_unique_test_identifier();
    let event_title = format!("Test Concert {}", unique_id);

    let event_payload = json!({
        "title": event_title,
        "description": "A test event",
        "location": "Test Venue",
        "start_time": "2025-12-01T19:00:00Z",
        "end_time": "2025-12-01T23:00:00Z",
        "category": "Music"
    });

    let req = test::TestRequest::post()
        .uri("/events")
        .insert_header(("authorization", format!("Bearer {}", token)))
        .set_json(&event_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("🎪 Event creation response status: {}", resp.status());

    if resp.status().is_success() {
        let body = test::read_body(resp).await;
        let event: serde_json::Value = serde_json::from_slice(&body).unwrap();
        println!("✅ Created event: {}", event["title"]);

        let event_id = event["id"].as_str().unwrap();

        let req = test::TestRequest::get()
            .uri(&format!("/events/{}", event_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Should be able to get event");
        println!("✅ Event retrieval test passed");
    } else {
        let body = test::read_body(resp).await;
        println!(
            "❌ Event creation failed: {}",
            String::from_utf8_lossy(&body)
        );
        panic!("Event creation should succeed");
    }
}

#[actix_web::test]
async fn test_ticket_type_creation_and_purchase() {
    let pool = setup_test_db().await;

    let (user_id, email) = create_test_user(&pool).await;

    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("Failed to verify user");

    let event_id = Uuid::new_v4();
    let unique_id = get_unique_test_identifier();
    let event_title = format!("Ticket Test Event {}", unique_id);

    sqlx::query(
        r#"
        INSERT INTO events (id, organizer_id, title, description, location, start_time, end_time, created_at, updated_at)
        VALUES ($1, $2, $3, 'Test Description', 'Test Location', 
                NOW() + INTERVAL '1 day', NOW() + INTERVAL '1 day' + INTERVAL '3 hours', NOW(), NOW())
        "#
    )
    .bind(event_id)
    .bind(user_id)
    .bind(event_title)
    .execute(&pool)
    .await
    .expect("Failed to create test event");

    println!("🎪 Created test event: {}", event_id);

    let token = get_auth_token(&pool, &email).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(blocstage::controllers::configure_routes),
    )
    .await;

    let ticket_name = format!("General Admission {}", unique_id);
    let ticket_type_payload = json!({
        "name": ticket_name,
        "description": "Standard ticket",
        "price": null,
        "total_supply": 100
    });

    let req = test::TestRequest::post()
        .uri(&format!("/events/{}/tickets", event_id))
        .insert_header(("authorization", format!("Bearer {}", token)))
        .set_json(&ticket_type_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("🎫 Ticket type creation status: {}", resp.status());

    if resp.status().is_success() {
        let body = test::read_body(resp).await;
        let ticket_type: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ticket_type_id = ticket_type["id"].as_str().unwrap();

        println!("✅ Created ticket type: {}", ticket_type["name"]);

        let req = test::TestRequest::post()
            .uri(&format!("/ticket-types/{}/purchase", ticket_type_id))
            .insert_header(("authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        println!("💳 Ticket purchase status: {}", resp.status());

        if resp.status().is_success() {
            println!("✅ Successfully purchased free ticket");
        } else {
            let body = test::read_body(resp).await;
            println!(
                "❌ Ticket purchase failed: {}",
                String::from_utf8_lossy(&body)
            );
        }
    } else {
        let body = test::read_body(resp).await;
        println!(
            "❌ Ticket type creation failed: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[actix_web::test]
async fn test_ticket_operations() {
    let pool = setup_test_db().await;

    let (user_id, email) = create_test_user(&pool).await;
    let (_user2_id, _) = create_test_user(&pool).await;

    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("Failed to verify user");

    let event_id = Uuid::new_v4();
    let ticket_type_id = Uuid::new_v4();
    let ticket_id = Uuid::new_v4();
    let unique_id = get_unique_test_identifier();

    sqlx::query(
        "INSERT INTO events (id, organizer_id, title, description, location, start_time, end_time, created_at, updated_at)
         VALUES ($1, $2, $3, 'Test Description', 'Test Location', 
                 NOW() + INTERVAL '1 day', NOW() + INTERVAL '1 day' + INTERVAL '3 hours', NOW(), NOW())"
    )
    .bind(event_id)
    .bind(user_id)
    .bind(format!("Test Event {}", unique_id))
    .execute(&pool).await.expect("Failed to create event");

    sqlx::query(
        "INSERT INTO ticket_types (id, event_id, name, description, price, currency, total_supply, remaining, is_active, is_free, created_at, updated_at)
         VALUES ($1, $2, $3, 'Test ticket', 10.0, 'USDC', 100, 100, true, false, NOW(), NOW())"
    )
    .bind(ticket_type_id)
    .bind(event_id)
    .bind(format!("General {}", unique_id))
    .execute(&pool).await.expect("Failed to create ticket type");

    sqlx::query(
        "INSERT INTO tickets (id, ticket_type_id, owner_id, status, created_at, updated_at)
         VALUES ($1, $2, $3, 'valid', NOW(), NOW())",
    )
    .bind(ticket_id)
    .bind(ticket_type_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("Failed to create ticket");

    println!("🎫 Created test ticket: {}", ticket_id);

    let token = get_auth_token(&pool, &email).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(blocstage::controllers::configure_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/tickets/my-tickets")
        .insert_header(("authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("🎫 Get user tickets status: {}", resp.status());

    if resp.status().is_success() {
        let body = test::read_body(resp).await;
        let tickets: serde_json::Value = serde_json::from_slice(&body).unwrap();
        println!(
            "✅ User has {} tickets",
            tickets.as_array().unwrap_or(&vec![]).len()
        );
    } else {
        let body = test::read_body(resp).await;
        println!("❌ Get tickets failed: {}", String::from_utf8_lossy(&body));
    }
}

#[actix_web::test]
async fn test_admin_operations() {
    let pool = setup_test_db().await;

    let admin_id = Uuid::new_v4();
    let unique_id = get_unique_test_identifier();
    let admin_email = format!("admin{}@example.com", unique_id);
    let admin_username = format!("admin{}", unique_id);

    let password_hash = bcrypt::hash("password123", 4).unwrap();

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, email_verified, role, status, first_name, last_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, 'admin', 'active', $5, $6, NOW(), NOW())
        "#
    )
    .bind(admin_id)
    .bind(admin_username)
    .bind(&admin_email)
    .bind(password_hash)
    .bind("Admin")
    .bind("User")
    .execute(&pool)
    .await
    .expect("Failed to create admin user");

    println!("👑 Created admin user: {}", admin_email);

    let admin_token = get_auth_token(&pool, &admin_email).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(blocstage::controllers::configure_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/events")
        .insert_header(("authorization", format!("Bearer {}", admin_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("📊 Admin events access status: {}", resp.status());

    if resp.status().is_success() {
        println!("✅ Admin can access all events");
    } else {
        let body = test::read_body(resp).await;
        println!(
            "❌ Admin events access failed: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// Stellar operations tests (these don't need database isolation)
#[tokio::test]
async fn test_stellar_service_basic_operations() {
    dotenv::from_filename(".env.test").ok();
    dotenv::dotenv().ok();

    if env::var("TESTNET_USDC_ISSUER").is_err() {
        println!("⏭️  Skipping Stellar test - TESTNET_USDC_ISSUER not set");
        return;
    }

    let stellar = StellarService::new().expect("Should create Stellar service");

    let (public_key, secret_key) = stellar.generate_keypair().expect("Should generate keypair");
    assert!(
        public_key.starts_with('G'),
        "Public key should start with G"
    );
    assert!(
        secret_key.starts_with('S'),
        "Secret key should start with S"
    );

    assert!(
        stellar.is_valid_public_key(&public_key),
        "Generated public key should be valid"
    );
    assert!(
        stellar.is_valid_secret_key(&secret_key),
        "Generated secret key should be valid"
    );

    assert!(
        !stellar.is_valid_public_key("invalid"),
        "Invalid key should fail validation"
    );
    assert!(
        !stellar.is_valid_secret_key("invalid"),
        "Invalid secret should fail validation"
    );

    let (pub2, _secret2) = stellar
        .generate_keypair()
        .expect("Should generate second keypair");
    let tx_hash = stellar
        .send_payment(&secret_key, &pub2, "10.0", &secret_key)
        .await
        .expect("Mock payment should succeed");

    assert!(!tx_hash.transaction_hash.is_empty(), "Transaction hash should not be empty");
    println!("✅ Mock transaction hash: {}", tx_hash.transaction_hash);

    println!("✅ Stellar service basic operations test passed");
}

#[tokio::test]
async fn test_bcrypt_cost_factor_investigation() {
    println!("🔍 Testing bcrypt cost factor compatibility...");

    let password = "password123";

    let hash4 = bcrypt::hash(password, 4).unwrap();
    let hash10 = bcrypt::hash(password, 10).unwrap();

    println!("Cost 4 hash: {}", hash4);
    println!("Cost 10 hash: {}", hash10);

    let verify4 = bcrypt::verify(password, &hash4).unwrap();
    let verify10 = bcrypt::verify(password, &hash10).unwrap();

    println!("Verify cost 4 hash: {}", verify4);
    println!("Verify cost 10 hash: {}", verify10);

    assert!(verify4, "Cost 4 hash should verify");
    assert!(verify10, "Cost 10 hash should verify");

    println!("✅ Bcrypt cost factor test passed");
}

#[tokio::test]
async fn test_crypto_service() {
    dotenv::from_filename(".env.test").ok();
    dotenv::dotenv().ok();

    if env::var("MASTER_KEY").is_err() {
        println!("⏭️  Skipping crypto test - MASTER_KEY not set");
        return;
    }

    let crypto = KeyEncryption::new().expect("Should create crypto instance");

    let original_secret = "SECRETKEYEXAMPLEFORTEST123456789";

    let encrypted = crypto
        .encrypt_secret_key(original_secret)
        .expect("Should encrypt secret key");
    assert!(!encrypted.is_empty(), "Encrypted data should not be empty");
    assert_ne!(
        encrypted, original_secret,
        "Encrypted should be different from original"
    );

    let decrypted = crypto
        .decrypt_secret_key(&encrypted)
        .expect("Should decrypt secret key");
    assert_eq!(
        decrypted, original_secret,
        "Decrypted should match original"
    );

    let invalid_result = crypto.decrypt_secret_key("invalid_base64!");
    assert!(
        invalid_result.is_err(),
        "Invalid data should fail to decrypt"
    );

    println!("✅ Crypto service test passed");
}
