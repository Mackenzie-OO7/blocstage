UPDATE event_organizers 
SET added_at = NOW() 
WHERE added_at IS NULL;

UPDATE event_organizers 
SET permissions = '{
    "edit_event": true,
    "manage_tickets": true,
    "check_in_guests": true,
    "view_analytics": true,
    "manage_organizers": false,
    "cancel_event": false
}'::jsonb
WHERE permissions IS NULL;

ALTER TABLE event_organizers 
ALTER COLUMN added_at SET NOT NULL;

ALTER TABLE event_organizers 
ALTER COLUMN permissions SET NOT NULL;