ALTER TABLE transactions 
ADD COLUMN IF NOT EXISTS transaction_sponsorship_fee DECIMAL(19, 8) DEFAULT 0,
ADD COLUMN IF NOT EXISTS gas_fee_xlm DECIMAL(19, 8) DEFAULT 0,
ADD COLUMN IF NOT EXISTS sponsor_account_used VARCHAR(255);

-- Update default currency from XLM to USDC
ALTER TABLE ticket_types 
ALTER COLUMN currency SET DEFAULT 'USDC';

-- Update existing ticket types to use USDC
UPDATE ticket_types 
SET currency = 'USDC' 
WHERE (currency = 'XLM' OR currency IS NULL) AND is_free = false;

-- Update default currency in transactions table
ALTER TABLE transactions 
ALTER COLUMN currency SET DEFAULT 'USDC';

-- Create sponsor accounts tracking table
CREATE TABLE IF NOT EXISTS sponsor_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_name VARCHAR(255) NOT NULL,
    public_key VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    minimum_balance DECIMAL(19, 8) NOT NULL DEFAULT 200.0,
    current_balance DECIMAL(19, 8),
    last_balance_check TIMESTAMP WITH TIME ZONE,
    transactions_sponsored INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create platform fees tracking table
CREATE TABLE IF NOT EXISTS platform_fee_calculations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES transactions(id),
    ticket_price DECIMAL(19, 8) NOT NULL,
    base_sponsorship_fee DECIMAL(19, 8) NOT NULL,
    gas_cost_usdc DECIMAL(19, 8) NOT NULL,
    xlm_to_usdc_rate DECIMAL(19, 8) NOT NULL,
    margin_percentage DECIMAL(5, 2) NOT NULL,
    final_sponsorship_fee DECIMAL(19, 8) NOT NULL,
    calculation_method VARCHAR(50), -- 'percentage' or 'gas_based'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_sponsor_accounts_active ON sponsor_accounts(is_active, current_balance);
CREATE INDEX IF NOT EXISTS idx_transactions_currency ON transactions(currency);
CREATE INDEX IF NOT EXISTS idx_platform_fee_calculations_transaction ON platform_fee_calculations(transaction_id);

COMMENT ON COLUMN transactions.transaction_sponsorship_fee IS 'Fee charged to user in USDC for transaction sponsorship';
COMMENT ON COLUMN transactions.gas_fee_xlm IS 'Actual gas fee paid in XLM by sponsor account';
COMMENT ON COLUMN transactions.sponsor_account_used IS 'Public key of sponsor account that paid gas fees';
COMMENT ON TABLE sponsor_accounts IS 'Tracks platform sponsor accounts that pay gas fees for users';
COMMENT ON TABLE platform_fee_calculations IS 'Logs how sponsorship fees were calculated';