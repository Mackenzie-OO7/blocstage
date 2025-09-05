-- Add profile picture URL column to users table

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS profile_picture_url VARCHAR(512);

CREATE INDEX IF NOT EXISTS idx_users_profile_picture 
ON users(profile_picture_url) 
WHERE profile_picture_url IS NOT NULL;
