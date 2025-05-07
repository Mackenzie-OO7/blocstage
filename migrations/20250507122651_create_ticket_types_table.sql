-- Add migration script here
CREATE TABLE IF NOT EXISTS ticket_types (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES events(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(19, 8), -- NULL means free ticket
    currency VARCHAR(10) DEFAULT 'XLM',
    total_supply INTEGER,
    remaining INTEGER,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);