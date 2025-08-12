ALTER TABLE users 
ADD COLUMN first_name VARCHAR(100) NOT NULL DEFAULT '',
ADD COLUMN last_name VARCHAR(100) NOT NULL DEFAULT '';

-- Remove default after adding (for future users)
ALTER TABLE users 
ALTER COLUMN first_name DROP DEFAULT,
ALTER COLUMN last_name DROP DEFAULT;