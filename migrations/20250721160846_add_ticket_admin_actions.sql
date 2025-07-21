CREATE TABLE ticket_admin_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    admin_id UUID NOT NULL REFERENCES users(id),
    action_type VARCHAR(50) NOT NULL,
    reason TEXT NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_ticket_admin_actions_ticket_id ON ticket_admin_actions(ticket_id);
CREATE INDEX idx_ticket_admin_actions_admin_id ON ticket_admin_actions(admin_id);
CREATE INDEX idx_ticket_admin_actions_created_at ON ticket_admin_actions(created_at);
CREATE INDEX idx_ticket_admin_actions_action_type ON ticket_admin_actions(action_type);