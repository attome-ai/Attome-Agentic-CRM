-- D3-T2: each lead conversion, so it can be undone within a day while the
-- records it made are unchanged. One live conversion per lead (a second
-- request, or a concurrent one, is refused).
CREATE TABLE IF NOT EXISTS lead_conversion (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    lead_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'undone')),
    account_id uuid,
    account_created boolean NOT NULL DEFAULT false,
    account_version bigint,
    contact_id uuid,
    contact_created boolean NOT NULL DEFAULT false,
    contact_version bigint,
    opportunity_id uuid,
    opportunity_created boolean NOT NULL DEFAULT false,
    opportunity_version bigint,
    moved jsonb NOT NULL DEFAULT '[]'::jsonb,
    previous_status text,
    converted_by uuid NOT NULL,
    converted_at timestamptz NOT NULL DEFAULT now(),
    undone_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS lead_conversion_live_uidx
    ON lead_conversion (lead_id) WHERE status <> 'undone';

GRANT SELECT, INSERT, UPDATE, DELETE ON lead_conversion TO attome_runtime;
GRANT SELECT ON lead_conversion TO attome_readonly;
