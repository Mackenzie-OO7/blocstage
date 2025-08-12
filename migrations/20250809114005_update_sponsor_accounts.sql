ALTER TABLE sponsor_accounts 
ADD COLUMN IF NOT EXISTS encrypted_secret_key TEXT,
ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_sponsor_accounts_encrypted_key ON sponsor_accounts (encrypted_secret_key);

CREATE OR REPLACE FUNCTION update_sponsor_accounts_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'trigger_update_sponsor_accounts_updated_at'
    ) THEN
        CREATE TRIGGER trigger_update_sponsor_accounts_updated_at
            BEFORE UPDATE ON sponsor_accounts
            FOR EACH ROW
            EXECUTE FUNCTION update_sponsor_accounts_updated_at();
    END IF;
END $$