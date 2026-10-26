-- E15-T1: attribution credit for won opportunities, per model and
-- touchpoint, computed nightly; and when each opportunity was computed.
CREATE TABLE IF NOT EXISTS marketing_attribution_credit (
    opportunity_id uuid NOT NULL,
    model text NOT NULL,
    touchpoint_id uuid NOT NULL,
    touchpoint_kind text NOT NULL,
    campaign_id uuid,
    channel text NOT NULL,
    touched_at timestamptz NOT NULL,
    share double precision NOT NULL,
    amount double precision,
    PRIMARY KEY (opportunity_id, model, touchpoint_id)
);

CREATE INDEX IF NOT EXISTS marketing_attribution_credit_campaign
    ON marketing_attribution_credit (campaign_id, model)
    WHERE campaign_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS marketing_attribution_run (
    opportunity_id uuid PRIMARY KEY,
    computed_at timestamptz NOT NULL DEFAULT now(),
    touchpoints integer NOT NULL DEFAULT 0
);

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_attribution_credit TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON marketing_attribution_run TO attome_runtime;
GRANT SELECT ON marketing_attribution_credit, marketing_attribution_run TO attome_readonly;
