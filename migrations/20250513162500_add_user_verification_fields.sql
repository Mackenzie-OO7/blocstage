-- Add migration script here
ALTER TABLE users 
ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN verification_token VARCHAR(255),
ADD COLUMN reset_token VARCHAR(255),
ADD COLUMN reset_token_expires TIMESTAMP WITH TIME ZONE,
ADD COLUMN status VARCHAR(50) NOT NULL DEFAULT 'active';