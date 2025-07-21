ALTER TABLE ticket_types 
ADD COLUMN is_free BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE ticket_types 
SET is_free = TRUE, currency = NULL 
WHERE price IS NULL OR price = 0;

UPDATE ticket_types 
SET price = NULL 
WHERE is_free = TRUE;

ALTER TABLE ticket_types 
ALTER COLUMN currency DROP NOT NULL;

-- Add check constraint to ensure data consistency
ALTER TABLE ticket_types 
ADD CONSTRAINT check_free_ticket_consistency 
CHECK (
    (is_free = TRUE AND price IS NULL AND currency IS NULL) OR
    (is_free = FALSE AND price IS NOT NULL AND currency IS NOT NULL)
);

CREATE INDEX idx_ticket_types_is_free ON ticket_types(is_free);