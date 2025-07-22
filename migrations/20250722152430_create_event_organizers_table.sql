CREATE TABLE event_organizers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL DEFAULT 'organizer', -- 'owner' or 'organizer'
    permissions JSONB DEFAULT '{
        "edit_event": true,
        "manage_tickets": true,
        "check_in_guests": true,
        "view_analytics": true,
        "manage_organizers": false,
        "cancel_event": false
    }'::jsonb,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    added_by UUID REFERENCES users(id),
    UNIQUE(event_id, user_id)
);

-- Migrate existing event organizers to new table
INSERT INTO event_organizers (event_id, user_id, role, permissions, added_at, added_by)
SELECT 
    id as event_id,
    organizer_id as user_id,
    'owner' as role,
    '{
        "edit_event": true,
        "manage_tickets": true,  
        "check_in_guests": true,
        "view_analytics": true,
        "manage_organizers": true,
        "cancel_event": true
    }'::jsonb as permissions,
    created_at as added_at,
    organizer_id as added_by -- Owner added themselves
FROM events;

CREATE INDEX idx_event_organizers_event_id ON event_organizers(event_id);
CREATE INDEX idx_event_organizers_user_id ON event_organizers(user_id);
CREATE INDEX idx_event_organizers_role ON event_organizers(role);

--  max 4 organizers per event
CREATE OR REPLACE FUNCTION check_max_organizers()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM event_organizers WHERE event_id = NEW.event_id) >= 4 THEN
        RAISE EXCEPTION 'Maximum 4 organizers allowed per event';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_check_max_organizers
    BEFORE INSERT ON event_organizers
    FOR EACH ROW
    EXECUTE FUNCTION check_max_organizers();
