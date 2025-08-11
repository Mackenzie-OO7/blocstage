CREATE TABLE encrypted_sponsor_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_name VARCHAR(100) NOT NULL UNIQUE,
    public_key VARCHAR(56) NOT NULL UNIQUE,
    encrypted_secret_key TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id) -- Track which admin added this key
);

CREATE INDEX idx_encrypted_sponsor_keys_active ON encrypted_sponsor_keys (is_active);
CREATE INDEX idx_encrypted_sponsor_keys_public_key ON encrypted_sponsor_keys (public_key);
CREATE INDEX idx_encrypted_sponsor_keys_account_name ON encrypted_sponsor_keys (account_name);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_encrypted_sponsor_keys_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_encrypted_sponsor_keys_updated_at
    BEFORE UPDATE ON encrypted_sponsor_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_encrypted_sponsor_keys_updated_at();