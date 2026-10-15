-- AI7-T1: the hand-off ledger. Who handed a ticket to whom (an agent, a
-- person or a queue), with the summary and the reasoning, and what became
-- of it. A ticket has at most one hand-off waiting. Tickets are a
-- metadata-defined entity, so ticket_id carries no foreign key.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS service_handoff (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ticket_id uuid NOT NULL,
    from_kind text NOT NULL CHECK (from_kind IN ('agent', 'user')),
    from_ref uuid NOT NULL,
    to_kind text NOT NULL CHECK (to_kind IN ('agent', 'user', 'queue')),
    to_ref uuid NOT NULL,
    summary text NOT NULL,
    reasoning text NOT NULL,
    agent_session_ref uuid,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'returned', 'cancelled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz,
    returned_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS service_handoff_one_pending ON service_handoff (ticket_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS service_handoff_to_idx ON service_handoff (to_kind, to_ref, status);

GRANT SELECT, INSERT, UPDATE ON service_handoff TO attome_runtime;
GRANT SELECT ON service_handoff TO attome_readonly;
