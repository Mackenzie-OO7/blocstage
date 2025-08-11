CREATE TABLE IF NOT EXISTS event_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    speaker_name VARCHAR(255),
    speaker_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    file_url VARCHAR(500),
    session_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_event_sessions_event_id ON event_sessions(event_id);
CREATE INDEX idx_event_sessions_start_time ON event_sessions(start_time);
CREATE INDEX idx_event_sessions_session_order ON event_sessions(event_id, session_order);
CREATE INDEX idx_event_sessions_speaker_user_id ON event_sessions(speaker_user_id);

ALTER TABLE event_sessions 
ADD CONSTRAINT check_session_timing 
CHECK (end_time > start_time);

CREATE UNIQUE INDEX idx_event_sessions_unique_order 
ON event_sessions(event_id, session_order);