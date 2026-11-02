-- F11-T6 (V2-D1588 (4)): a revenue contract change, previewed before it
-- moves any schedule line: its IFRS 15 treatment, whether the revenue
-- accountant overrode the rule, the planned lines' amounts before and after,
-- and whether it was applied or discarded.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS revenue_contract_change (
    id uuid PRIMARY KEY,
    contract_id uuid NOT NULL,
    -- amendment, change_order, credit_note
    change_kind text NOT NULL,
    source_ref text,
    -- separate_contract, prospective, cumulative_catch_up
    treatment text NOT NULL,
    overridden boolean NOT NULL DEFAULT false,
    preview jsonb NOT NULL,
    -- previewed, applied, discarded
    status text NOT NULL DEFAULT 'previewed',
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_by uuid,
    decided_at timestamptz
);

CREATE INDEX IF NOT EXISTS revenue_contract_change_contract_idx
    ON revenue_contract_change (contract_id, created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON revenue_contract_change TO attome_runtime;
GRANT SELECT ON revenue_contract_change TO attome_readonly;
