-- E24-T1: which contact an identifier (email, tracking visitor, portal user,
-- phone) belongs to, linked only by deterministic events (a sign-in, a form
-- with an email, a tracked email click). An identifier has at most one live
-- link; a second contact claiming it is kept as a conflict for review.
CREATE TABLE IF NOT EXISTS marketing_identity_link (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    identifier_type text NOT NULL
        CHECK (identifier_type IN ('email', 'visitor', 'portal_user', 'phone')),
    identifier_value text NOT NULL,
    contact_id uuid NOT NULL,
    source text NOT NULL,
    status text NOT NULL DEFAULT 'linked'
        CHECK (status IN ('linked', 'conflict', 'dismissed')),
    conflict_with uuid,
    linked_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (identifier_type, identifier_value, contact_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS marketing_identity_link_live
    ON marketing_identity_link (identifier_type, identifier_value)
    WHERE status = 'linked';
CREATE INDEX IF NOT EXISTS marketing_identity_link_contact
    ON marketing_identity_link (contact_id);
CREATE INDEX IF NOT EXISTS marketing_identity_link_conflicts
    ON marketing_identity_link (linked_at DESC)
    WHERE status = 'conflict';

GRANT SELECT, INSERT, UPDATE ON marketing_identity_link TO attome_runtime;
GRANT SELECT ON marketing_identity_link TO attome_readonly;
