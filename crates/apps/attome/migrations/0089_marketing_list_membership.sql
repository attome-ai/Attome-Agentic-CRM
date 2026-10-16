-- E7-T2: list members, and the append-only history of people entering and
-- leaving a list (the trigger source for journeys and the list's audit).
CREATE TABLE IF NOT EXISTS marketing_list_member (
    list_id uuid NOT NULL,
    person_id uuid NOT NULL,
    person_entity text NOT NULL,
    source text NOT NULL CHECK (source IN ('segment', 'manual', 'import', 'form', 'flow')),
    import_job_id uuid,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (list_id, person_id)
);
CREATE INDEX IF NOT EXISTS marketing_list_member_person_idx ON marketing_list_member (person_id);
CREATE INDEX IF NOT EXISTS marketing_list_member_import_idx
    ON marketing_list_member (list_id, import_job_id) WHERE import_job_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS marketing_list_membership_event (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    list_id uuid NOT NULL,
    person_id uuid NOT NULL,
    change text NOT NULL CHECK (change IN ('entered', 'left')),
    reason text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS marketing_list_membership_event_list_idx
    ON marketing_list_membership_event (list_id, at);
CREATE INDEX IF NOT EXISTS marketing_list_membership_event_person_idx
    ON marketing_list_membership_event (list_id, person_id, at);

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_list_member TO attome_runtime;
-- Append-only: the application adds events and never rewrites them.
GRANT SELECT, INSERT ON marketing_list_membership_event TO attome_runtime;
GRANT SELECT ON marketing_list_member, marketing_list_membership_event TO attome_readonly;
