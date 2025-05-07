-- Add migration script here
CREATE TABLE IF NOT EXISTS tickets (
    id UUID PRIMARY KEY,
    ticket_type_id UUID NOT NULL REFERENCES ticket_types(id),
    owner_id UUID NOT NULL REFERENCES users(id),
    status VARCHAR(50) NOT NULL DEFAULT 'valid', -- valid, used, cancelled, transferred
    qr_code TEXT,
    nft_identifier TEXT, -- For future NFT implementation
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);