use anyhow::Result;
use bigdecimal::{BigDecimal, Signed, Zero};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize)]
pub struct TicketTypeWithFeePreview {
    pub ticket_type: TicketType,
    pub fee_preview: Option<FeePreview>,
}

#[derive(Debug, Serialize)]
pub struct FeePreview {
    pub ticket_price: String,
    pub sponsorship_fee: String,
    pub total_cost: String,
    pub currency: String,
    pub fee_explanation: String,
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
            let price = ticket_type.price.as_ref().unwrap();
            if price.is_negative() || price.is_zero() {
                return Err(anyhow::anyhow!(
                    "Price must be greater than 0 for paid tickets"
                ));
            }

            if let Some(ref currency) = ticket_type.currency {
                if currency != "USDC" {
                    return Err(anyhow::anyhow!("Only USDC is supported for paid tickets"));
                }
            }
        }

        let (final_price, final_currency) = if ticket_type.is_free {
            (None, None)
        } else {
            // For paid tickets, default currency to USDC if not provided
            let currency = ticket_type.currency.unwrap_or_else(|| "USDC".to_string());
            if currency != "USDC" {
                return Err(anyhow::anyhow!(
                    "Only USDC is supported. Provided currency: {}",
                    currency
                ));
            }
            (ticket_type.price, Some(currency))
        };

        let result = sqlx::query_as!(
            TicketType,
            r#"
            INSERT INTO ticket_types (
                id, event_id, name, description, is_free, price, currency, 
                total_supply, remaining, is_active, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
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

        Ok(result)
    }

    pub fn is_claimable(&self) -> bool {
        self.is_free && self.is_active
    }

    pub fn is_purchasable(&self) -> bool {
        !self.is_free && self.is_active && self.price.is_some() && self.currency.is_some()
    }

    pub async fn find_by_event(pool: &PgPool, event_id: Uuid) -> Result<Vec<Self>> {
        let ticket_types = sqlx::query_as!(
            TicketType,
            r#"
            SELECT * FROM ticket_types 
            WHERE event_id = $1 AND is_active = true
            ORDER BY is_free DESC, price ASC
            "#,
            event_id
        )
        .fetch_all(pool)
        .await?;

        Ok(ticket_types)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>> {
        let ticket_type = sqlx::query_as!(
            TicketType,
            r#"
            SELECT * FROM ticket_types WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await?;

        Ok(ticket_type)
    }

    pub async fn get_with_fee_preview(&self, pool: &PgPool) -> Result<TicketTypeWithFeePreview> {
        let fee_preview = if !self.is_free && self.price.is_some() {

            let fee_calculator = crate::services::fee_calculator::FeeCalculator::new(pool.clone())?;
            let ticket_price = self.price.as_ref().unwrap().to_string().parse::<f64>()?;

            match fee_calculator.get_fee_breakdown(ticket_price).await {
                Ok(breakdown) => Some(FeePreview {
                    ticket_price: breakdown.ticket_price,
                    sponsorship_fee: breakdown.sponsorship_fee,
                    total_cost: breakdown.total_amount,
                    currency: breakdown.currency,
                    fee_explanation:
                        "Sponsorship fee covers transaction costs - no gas fees for you!"
                            .to_string(),
                }),
                Err(_) => None,
            }
        } else {
            None
        };

        Ok(TicketTypeWithFeePreview {
            ticket_type: self.clone(),
            fee_preview,
        })
    }

    pub async fn update_price(
        &self,
        pool: &PgPool,
        new_price: Option<BigDecimal>,
        currency: Option<String>,
    ) -> Result<Self> {
        
        if let Some(price) = &new_price {
            if !price.is_zero() && !price.is_negative() {
                let final_currency = currency
                    .as_ref()
                    .map(|c| c.clone())
                    .unwrap_or_else(|| "USDC".to_string());
                if final_currency != "USDC" {
                    return Err(anyhow::anyhow!("Only USDC is supported for paid tickets"));
                }
            }
        }

        let is_free =
            new_price.is_none() || new_price.as_ref().map(|p| p.is_zero()).unwrap_or(true);

        let result = sqlx::query_as!(
            TicketType,
            r#"
        UPDATE ticket_types
        SET price = $1, currency = $2, updated_at = $3, is_free = $4
        WHERE id = $5
        RETURNING *
        "#,
            new_price,
            currency,
            Utc::now(),
            is_free,
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    pub async fn decrease_remaining(&self, pool: &PgPool) -> Result<Self> {
        if let Some(remaining) = self.remaining {
            if remaining > 0 {
                let result = sqlx::query_as!(
                    TicketType,
                    r#"
                    UPDATE ticket_types
                    SET remaining = remaining - 1, updated_at = $1
                    WHERE id = $2
                    RETURNING *
                    "#,
                    Utc::now(),
                    self.id
                )
                .fetch_one(pool)
                .await?;

                return Ok(result);
            }
        }

        anyhow::bail!("No tickets remaining")
    }

    // for cancellations
    pub async fn increase_remaining(&self, pool: &PgPool, amount: i32) -> Result<Self> {
        // only increase if there's a limit on tickets
        if self.total_supply.is_some() {
            let result = sqlx::query_as!(
                TicketType,
                r#"
                UPDATE ticket_types
                SET remaining = remaining + $1, updated_at = $2
                WHERE id = $3
                RETURNING *
                "#,
                amount,
                Utc::now(),
                self.id
            )
            .fetch_one(pool)
            .await?;

            return Ok(result);
        }

        Ok(self.clone())
    }

    // activate/deactivate ticket sales
    pub async fn set_active_status(&self, pool: &PgPool, is_active: bool) -> Result<Self> {
        let result = sqlx::query_as!(
            TicketType,
            r#"
            UPDATE ticket_types
            SET is_active = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            is_active,
            Utc::now(),
            self.id
        )
        .fetch_one(pool)
        .await?;

        Ok(result)
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

    pub async fn formatted_price_with_fees(&self, pool: &PgPool) -> Result<String> {
        if self.is_free {
            return Ok("Free".to_string());
        }

        let price = match &self.price {
            Some(p) => p,
            None => return Ok("Free".to_string()),
        };

        // Calculate total cost including fees
        let fee_calculator = crate::services::fee_calculator::FeeCalculator::new(pool.clone())?;
        let ticket_price = price.to_string().parse::<f64>()?;

        match fee_calculator.get_fee_breakdown(ticket_price).await {
            Ok(breakdown) => Ok(format!(
                "{} USDC (+ {} fee = {} total)",
                breakdown.ticket_price, breakdown.sponsorship_fee, breakdown.total_amount
            )),
            Err(_) => {
                // Fallback to basic price display
                Ok(format!("{} USDC", price))
            }
        }
    }

    pub async fn get_statistics(&self, pool: &PgPool) -> Result<serde_json::Value> {
        let sold_count = if let Some(total) = self.total_supply {
            if let Some(remaining) = self.remaining {
                total - remaining
            } else {
                0
            }
        } else {
            // For unlimited tickets, count actual sales
            let count = sqlx::query!(
                r#"
                SELECT COUNT(*) as count
                FROM tickets t
                JOIN transactions tr ON t.id = tr.ticket_id
                WHERE t.ticket_type_id = $1 AND tr.status = 'completed'
                "#,
                self.id
            )
            .fetch_one(pool)
            .await?;

            count.count.unwrap_or(0) as i32
        };

        let revenue = if !self.is_free {
            let result = sqlx::query!(
                r#"
                SELECT COALESCE(SUM(
                    CASE 
                        WHEN tr.transaction_sponsorship_fee IS NOT NULL 
                        THEN tr.amount - tr.transaction_sponsorship_fee
                        ELSE tr.amount
                    END
                ), 0) as revenue
                FROM tickets t
                JOIN transactions tr ON t.id = tr.ticket_id
                WHERE t.ticket_type_id = $1 AND tr.status = 'completed'
                "#,
                self.id
            )
            .fetch_one(pool)
            .await?;

            result
                .revenue
                .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
                .unwrap_or(0.0)
        } else {
            0.0
        };

        Ok(serde_json::json!({
            "ticket_type_id": self.id,
            "name": self.name,
            "is_free": self.is_free,
            "price": self.formatted_price(),
            "total_supply": self.total_supply,
            "remaining": self.remaining,
            "sold": sold_count,
            "revenue": format!("{:.2}", revenue),
            "currency": self.currency,
            "is_active": self.is_active,
            "availability_status": if self.is_available() { "Available" } else { "Unavailable" }
        }))
    }
}
