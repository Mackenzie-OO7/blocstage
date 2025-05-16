-- Add migration script here
ALTER TABLE transactions 
ADD COLUMN IF NOT EXISTS receipt_number VARCHAR(255),
ADD COLUMN IF NOT EXISTS refund_amount NUMERIC(19,8),
ADD COLUMN IF NOT EXISTS refund_transaction_hash VARCHAR(255),
ADD COLUMN IF NOT EXISTS refund_reason TEXT,
ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ;
