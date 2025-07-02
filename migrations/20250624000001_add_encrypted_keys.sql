-- Add migration script here
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS stellar_secret_key_encrypted TEXT;