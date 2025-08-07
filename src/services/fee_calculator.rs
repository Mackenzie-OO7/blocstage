use anyhow::{anyhow, Result};
use bigdecimal::{BigDecimal, FromPrimitive};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction as SqlxTransaction};
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct FeeCalculation {
    pub ticket_price: f64,
    pub base_sponsorship_fee: f64,
    pub gas_cost_usdc: f64,
    pub xlm_to_usdc_rate: f64,
    pub margin_percentage: f64,
    pub final_sponsorship_fee: f64,
    pub total_user_pays: f64,
    pub calculation_method: String, // "percentage" or "gas_based"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeeBreakdown {
    pub ticket_price: String,
    pub sponsorship_fee: String,
    pub total_amount: String,
    pub currency: String,
    pub breakdown_text: String,
}


#[derive(Debug, Clone)]
pub struct FeeCalculator {
    pool: PgPool,
    stellar_service: crate::services::stellar::StellarService,
    sponsorship_fee_percentage: f64,
    gas_margin_percentage: f64,
}

impl FeeCalculator {
    pub fn new(pool: PgPool) -> Result<Self> {
        let stellar_service = crate::services::stellar::StellarService::new()?;

        let sponsorship_fee_percentage = env::var("TRANSACTION_SPONSORSHIP_FEE_PERCENTAGE")
            .unwrap_or_else(|_| "2.5".to_string())
            .parse::<f64>()?;

        let gas_margin_percentage = env::var("GAS_FEE_MARGIN_PERCENTAGE")
            .unwrap_or_else(|_| "20".to_string())
            .parse::<f64>()?;

        Ok(Self {
            pool,
            stellar_service,
            sponsorship_fee_percentage,
            gas_margin_percentage,
        })
    }

    /// Calculate the sponsorship fee for a ticket purchase
    pub async fn calculate_sponsorship_fee(&self, ticket_price: f64) -> Result<FeeCalculation> {
        info!(
            "💰 Calculating sponsorship fee for ticket price: {} USDC",
            ticket_price
        );

        // Step 1: Calculate base percentage fee
        let base_sponsorship_fee = ticket_price * (self.sponsorship_fee_percentage / 100.0);

        // Step 2: Get current network gas cost
        let gas_cost_xlm = self.estimate_transaction_gas_cost().await?;

        // Step 3: Get XLM to USDC exchange rate
        let xlm_to_usdc_rate = self.get_xlm_to_usdc_rate().await?;

        // Step 4: Convert gas cost to USDC with margin
        let gas_cost_usdc = gas_cost_xlm * xlm_to_usdc_rate;
        let buffered_gas_cost = gas_cost_usdc * (1.0 + self.gas_margin_percentage / 100.0);

        // Step 5: Use the higher of percentage fee or buffered gas cost
        let (final_sponsorship_fee, calculation_method) =
            if base_sponsorship_fee >= buffered_gas_cost {
                (base_sponsorship_fee, "percentage".to_string())
            } else {
                (buffered_gas_cost, "gas_based".to_string())
            };

        let calculation = FeeCalculation {
            ticket_price,
            base_sponsorship_fee,
            gas_cost_usdc,
            xlm_to_usdc_rate,
            margin_percentage: self.gas_margin_percentage,
            final_sponsorship_fee,
            total_user_pays: ticket_price + final_sponsorship_fee,
            calculation_method: calculation_method.clone(),
        };

        info!(
            "✅ Fee calculation complete: {} USDC ticket + {} USDC fee = {} USDC total (method: {})",
            ticket_price, final_sponsorship_fee, calculation.total_user_pays, calculation_method
        );

        Ok(calculation)
    }

    /// Get user-friendly fee breakdown for display
    pub async fn get_fee_breakdown(&self, ticket_price: f64) -> Result<FeeBreakdown> {
        let calculation = self.calculate_sponsorship_fee(ticket_price).await?;

        let breakdown_text = format!(
            "Ticket: {} USDC + Platform Fee: {} USDC (covers transaction costs)",
            format!("{:.2}", calculation.ticket_price),
            format!("{:.2}", calculation.final_sponsorship_fee)
        );

        Ok(FeeBreakdown {
            ticket_price: format!("{:.2}", calculation.ticket_price),
            sponsorship_fee: format!("{:.2}", calculation.final_sponsorship_fee),
            total_amount: format!("{:.2}", calculation.total_user_pays),
            currency: "USDC".to_string(),
            breakdown_text,
        })
    }

    /// Record fee calculation in database for transparency and auditing
    pub async fn record_fee_calculation(
        &self,
        transaction_id: Uuid,
        calculation: &FeeCalculation,
    ) -> Result<()> {
        sqlx::query!(
            r#"
        INSERT INTO platform_fee_calculations (
            transaction_id, ticket_price, base_sponsorship_fee, gas_cost_usdc,
            xlm_to_usdc_rate, margin_percentage, final_sponsorship_fee, calculation_method
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
            transaction_id,
            BigDecimal::from_f64(calculation.ticket_price)
                .ok_or_else(|| anyhow!("Invalid ticket price"))?,
            BigDecimal::from_f64(calculation.base_sponsorship_fee)
                .ok_or_else(|| anyhow!("Invalid base sponsorship fee"))?,
            BigDecimal::from_f64(calculation.gas_cost_usdc)
                .ok_or_else(|| anyhow!("Invalid gas cost"))?,
            BigDecimal::from_f64(calculation.xlm_to_usdc_rate)
                .ok_or_else(|| anyhow!("Invalid exchange rate"))?,
            BigDecimal::from_f64(calculation.margin_percentage)
                .ok_or_else(|| anyhow!("Invalid margin percentage"))?,
            BigDecimal::from_f64(calculation.final_sponsorship_fee)
                .ok_or_else(|| anyhow!("Invalid final sponsorship fee"))?,
            calculation.calculation_method
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // in db within a tx context
    pub async fn record_fee_calculation_in_tx<'a>(
    &self,
    tx: &mut SqlxTransaction<'a, Postgres>,
    transaction_id: Uuid,
    calculation: &FeeCalculation,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO platform_fee_calculations (
            transaction_id, ticket_price, base_sponsorship_fee, gas_cost_usdc,
            xlm_to_usdc_rate, margin_percentage, final_sponsorship_fee, calculation_method
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        transaction_id,
        BigDecimal::from_f64(calculation.ticket_price)
            .ok_or_else(|| anyhow!("Invalid ticket price"))?,
        BigDecimal::from_f64(calculation.base_sponsorship_fee)
            .ok_or_else(|| anyhow!("Invalid base sponsorship fee"))?,
        BigDecimal::from_f64(calculation.gas_cost_usdc)
            .ok_or_else(|| anyhow!("Invalid gas cost"))?,
        BigDecimal::from_f64(calculation.xlm_to_usdc_rate)
            .ok_or_else(|| anyhow!("Invalid exchange rate"))?,
        BigDecimal::from_f64(calculation.margin_percentage)
            .ok_or_else(|| anyhow!("Invalid margin percentage"))?,
        BigDecimal::from_f64(calculation.final_sponsorship_fee)
            .ok_or_else(|| anyhow!("Invalid final sponsorship fee"))?,
        calculation.calculation_method
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}

    /// Estimate current Stellar network gas cost for a sponsored payment transaction
    async fn estimate_transaction_gas_cost(&self) -> Result<f64> {
        // A sponsored USDC payment typically involves:
        // 1. Payment operation (user pays USDC)
        // 2. Fee sponsorship (sponsor pays XLM fees)
        // Base fee is per operation, and we'll have 1 operation but with sponsorship overhead

        let base_fee = self
            .stellar_service
            .get_current_base_fee()
            .await
            .unwrap_or(100_000); // Fallback to 100,000 stroops if network query fails

        // Convert stroops to XLM (1 XLM = 10,000,000 stroops)
        let base_fee_xlm = base_fee as f64 / 10_000_000.0;

        // For sponsored transactions, we typically need slightly higher fees
        let sponsored_fee_multiplier = 1.2; // 20% overhead for sponsorship
        let estimated_gas_xlm = base_fee_xlm * sponsored_fee_multiplier;

        info!(
            "⛽ Estimated gas cost: {} XLM (base: {} stroops)",
            estimated_gas_xlm, base_fee
        );

        Ok(estimated_gas_xlm)
    }

    /// Get current XLM to USDC exchange rate
    async fn get_xlm_to_usdc_rate(&self) -> Result<f64> {
        // TODO: Implement actual exchange rate fetching from Stellar DEX or external API
        // For now, use a reasonable mock rate
        // In production, you'd query Stellar's orderbook or use a price API

        match self.fetch_xlm_usdc_rate_from_api().await {
            Ok(rate) => {
                info!("📈 XLM/USDC rate: {}", rate);
                Ok(rate)
            }
            Err(e) => {
                warn!(
                    "Failed to fetch live XLM/USDC rate: {}. Using fallback rate.",
                    e
                );
                // Fallback rate (update this based on recent market conditions)
                let fallback_rate = 0.10; // 1 XLM = 0.10 USDC (update as needed)
                Ok(fallback_rate)
            }
        }
    }

    /// Fetch live XLM/USDC rate from external API or Stellar DEX
    async fn fetch_xlm_usdc_rate_from_api(&self) -> Result<f64> {
        // Option 1: CoinGecko API (free tier available)
        let coingecko_url =
            "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=usd";

        match reqwest::get(coingecko_url).await {
            Ok(response) => {
                if response.status().is_success() {
                    let json: serde_json::Value = response.json().await?;

                    if let Some(xlm_price) = json["stellar"]["usd"].as_f64() {
                        // Assuming USDC ≈ $1 USD, XLM/USDC rate ≈ XLM/USD rate
                        return Ok(xlm_price);
                    }
                }
            }
            Err(e) => {
                warn!("CoinGecko API error: {}", e);
            }
        }

        // Option 2: Query Stellar DEX for XLM/USDC orderbook
        // This would be more accurate but requires more complex implementation
        // TODO: Implement Stellar DEX querying

        Err(anyhow!("Unable to fetch live exchange rate"))
    }

    /// Get configuration settings for fee calculation
    pub fn get_fee_configuration(&self) -> serde_json::Value {
        serde_json::json!({
            "sponsorship_fee_percentage": self.sponsorship_fee_percentage,
            "gas_margin_percentage": self.gas_margin_percentage,
            "calculation_info": {
                "method": "Dynamic fee calculation based on network conditions",
                "base_fee": format!("{}% of ticket price", self.sponsorship_fee_percentage),
                "gas_protection": format!("{}% margin for XLM volatility", self.gas_margin_percentage),
                "selection": "Higher of percentage fee or buffered gas cost"
            }
        })
    }

    /// Update fee configuration (for admin use)
    pub async fn update_sponsorship_fee_percentage(&mut self, new_percentage: f64) -> Result<()> {
        if new_percentage < 0.0 || new_percentage > 50.0 {
            return Err(anyhow!(
                "Sponsorship fee percentage must be between 0% and 50%"
            ));
        }

        self.sponsorship_fee_percentage = new_percentage;
        info!(
            "📊 Updated sponsorship fee percentage to: {}%",
            new_percentage
        );

        // TODO: Update environment variable or database configuration
        // For now, this only affects the current instance

        Ok(())
    }

    /// Calculate total platform revenue from fees for a given period
    pub async fn calculate_fee_revenue(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<f64> {
        let result = sqlx::query!(
            r#"
            SELECT COALESCE(SUM(t.transaction_sponsorship_fee), 0) as total_revenue
            FROM transactions t
            WHERE t.created_at BETWEEN $1 AND $2
            AND t.status = 'completed'
            AND t.transaction_sponsorship_fee IS NOT NULL
            "#,
            start_date,
            end_date
        )
        .fetch_one(&self.pool)
        .await?;

        let total_revenue = result
            .total_revenue
            .map(|amount| amount.to_string().parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        Ok(total_revenue)
    }
}
