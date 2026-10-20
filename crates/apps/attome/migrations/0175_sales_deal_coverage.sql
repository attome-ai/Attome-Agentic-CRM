-- D23-T7: each deal's buying-committee coverage gaps, recomputed when its
-- contact roles or the deal change, so a read of the deal map does not
-- compute them again. One row per opportunity.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS sales_deal_coverage (
    opportunity_id uuid        PRIMARY KEY,
    gaps           jsonb       NOT NULL DEFAULT '[]'::jsonb,
    computed_at    timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON sales_deal_coverage TO attome_runtime;
GRANT SELECT ON sales_deal_coverage TO attome_readonly;
