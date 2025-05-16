-- Add migration script here
ALTER TABLE tickets 
ADD COLUMN IF NOT EXISTS checked_in_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS checked_in_by UUID,
ADD COLUMN IF NOT EXISTS pdf_url TEXT;