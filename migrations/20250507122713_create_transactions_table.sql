-- Add migration script here
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY,
    ticket_id UUID NOT NULL REFERENCES tickets(id),
    user_id UUID NOT NULL REFERENCES users(id),
    amount DECIMAL(19, 8) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'XLM',
    stellar_transaction_hash VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);