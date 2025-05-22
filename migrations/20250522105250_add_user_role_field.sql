-- Add migration script here
ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';
UPDATE users SET role = 'admin' WHERE email = 'levaiagbara@gmail.com';