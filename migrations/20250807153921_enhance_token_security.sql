CREATE UNIQUE INDEX IF NOT EXISTS idx_users_verification_token_unique 
ON users (verification_token) 
WHERE verification_token IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_reset_token_unique 
ON users (reset_token) 
WHERE reset_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_verification_token 
ON users (verification_token) 
WHERE verification_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_reset_token 
ON users (reset_token) 
WHERE reset_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_status 
ON users (status);