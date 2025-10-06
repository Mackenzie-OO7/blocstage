-- Add short_code column to events table for shortened URLs
-- Migration: Add event short codes
-- Created: 2025-10-06

-- Add short_code column (nullable first to handle existing data)
ALTER TABLE events ADD COLUMN short_code VARCHAR(8);

-- Create sequence for generating sequential short codes (optional approach)
CREATE SEQUENCE IF NOT EXISTS event_short_code_seq START WITH 100000;

-- Add unique constraint
ALTER TABLE events ADD CONSTRAINT events_short_code_unique UNIQUE (short_code);

-- Add index for fast lookups by short code
CREATE INDEX idx_events_short_code ON events(short_code);

-- Note: Existing events will need short codes generated via a backfill script
-- After backfill is complete, run: ALTER TABLE events ALTER COLUMN short_code SET NOT NULL;
