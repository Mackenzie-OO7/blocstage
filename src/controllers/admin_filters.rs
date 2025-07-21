use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AdminTicketFilters {
    pub status: Option<String>,
    
    // Entity filtering
    pub event_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub organizer_id: Option<Uuid>,
    
    // Date filtering
    pub purchased_after: Option<DateTime<Utc>>,
    pub purchased_before: Option<DateTime<Utc>>,
    pub event_start_after: Option<DateTime<Utc>>,
    pub event_start_before: Option<DateTime<Utc>>,
    
    // Search
    pub search: Option<String>, // Search in event title, user email, ticket type name
    
    // Ticket type filtering
    pub is_free: Option<bool>,
    pub currency: Option<String>, // Filter by currency (XLM, USD, etc.)
    
    // Pagination
    pub limit: Option<i64>, // Default: 50, Max: 500
    pub offset: Option<i64>,
    
    // Sorting
    pub sort_by: Option<String>, // "created_at", "updated_at", "event_start", "amount"
    pub sort_order: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminEventFilters {
    // Status filtering
    pub status: Option<String>,
    pub effective_status: Option<String>,
    
    // Category filtering
    pub category: Option<String>,
    pub location: Option<String>, //(partial match)
    
    // Date filtering
    pub start_after: Option<DateTime<Utc>>,
    pub start_before: Option<DateTime<Utc>>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    
    // Search
    pub search: Option<String>,
    pub organizer_email: Option<String>,
    
    // Organizer filtering
    pub organizer_id: Option<Uuid>,

    // Tags filtering
    pub tags: Option<Vec<String>>,
    
    // Pagination
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    
    // Sorting
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

impl AdminTicketFilters {
    pub fn validate(&mut self) {
        self.limit = Some(self.limit.unwrap_or(50).min(500).max(1));
        self.offset = Some(self.offset.unwrap_or(0).max(0));
        self.sort_by = Some(self.sort_by.clone().unwrap_or_else(|| "created_at".to_string()));
        self.sort_order = Some(self.sort_order.clone().unwrap_or_else(|| "desc".to_string()));
    }
    
    pub fn build_where_clause(&self) -> (String, Vec<Box<dyn std::fmt::Display + Send>>) {
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn std::fmt::Display + Send>> = Vec::new();
        let mut param_count = 1;

        if let Some(status) = &self.status {
            conditions.push(format!("t.status = ${}", param_count));
            params.push(Box::new(status.clone()));
            param_count += 1;
        }

        if let Some(event_id) = &self.event_id {
            conditions.push(format!("tt.event_id = ${}", param_count));
            params.push(Box::new(*event_id));
            param_count += 1;
        }

        if let Some(user_id) = &self.user_id {
            conditions.push(format!("t.owner_id = ${}", param_count));
            params.push(Box::new(*user_id));
            param_count += 1;
        }

        if let Some(is_free) = &self.is_free {
            conditions.push(format!("tt.is_free = ${}", param_count));
            params.push(Box::new(*is_free));
            param_count += 1;
        }

        if let Some(search) = &self.search {
            conditions.push(format!(
                "(e.title ILIKE ${} OR u.email ILIKE ${} OR tt.name ILIKE ${})",
                param_count, param_count, param_count
            ));
            let search_pattern = format!("%{}%", search);
            params.push(Box::new(search_pattern));
            param_count += 1;
        }

        if let Some(purchased_after) = &self.purchased_after {
            conditions.push(format!("t.created_at >= ${}", param_count));
            params.push(Box::new(*purchased_after));
            param_count += 1;
        }

        if let Some(purchased_before) = &self.purchased_before {
            conditions.push(format!("t.created_at <= ${}", param_count));
            params.push(Box::new(*purchased_before));
            param_count += 1;
        }

        let where_clause = if conditions.is_empty() {
            "".to_string()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }
}

impl AdminEventFilters {
    pub fn validate(&mut self) {
        self.limit = Some(self.limit.unwrap_or(50).min(500).max(1));
        self.offset = Some(self.offset.unwrap_or(0).max(0));
        self.sort_by = Some(self.sort_by.clone().unwrap_or_else(|| "created_at".to_string()));
        self.sort_order = Some(self.sort_order.clone().unwrap_or_else(|| "desc".to_string()));
    }
}

// Response structures for paginated results
#[derive(Debug, serde::Serialize)]
pub struct PaginatedTicketsResponse {
    pub tickets: Vec<AdminTicketView>,
    pub total_count: i64,
    pub page_info: PageInfo,
}

#[derive(Debug, serde::Serialize)]
pub struct PaginatedEventsResponse {
    pub events: Vec<AdminEventView>,
    pub total_count: i64,
    pub page_info: PageInfo,
}

#[derive(Debug, serde::Serialize)]
pub struct PageInfo {
    pub limit: i64,
    pub offset: i64,
    pub total_pages: i64,
    pub current_page: i64,
    pub has_next: bool,
    pub has_previous: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct AdminTicketView {
    pub ticket_id: Uuid,
    pub ticket_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    
    // Event info
    pub event_id: Uuid,
    pub event_title: String,
    pub event_start_time: DateTime<Utc>,
    pub event_status: String,
    
    // Ticket type info
    pub ticket_type_name: String,
    pub is_free: bool,
    pub price: Option<String>,
    pub currency: Option<String>,
    
    // User info
    pub owner_id: Uuid,
    pub owner_email: String,
    pub owner_username: String,
    
    // Tx info
    pub transaction_id: Option<Uuid>,
    pub transaction_status: Option<String>,
    pub amount_paid: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct AdminEventView {
    pub event_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub category: Option<String>,
    pub status: String,
    pub effective_status: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    
    // Organizer info
    pub organizer_id: Uuid,
    pub organizer_email: String,
    pub organizer_username: String,
    
    // Statistics
    pub total_ticket_types: i64,
    pub total_tickets_sold: i64,
    pub total_revenue: Option<String>,
    pub tickets_remaining: Option<i64>,
}