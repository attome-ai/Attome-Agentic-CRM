-- E20-T1: target account lists. An account on a list has a stage, an
-- engagement score from its contacts' recent activity, and which buying
-- roles it has covered among its contacts, rescored nightly.
CREATE TABLE IF NOT EXISTS marketing_target_account (
    list_id uuid NOT NULL,
    account_id uuid NOT NULL,
    stage text NOT NULL DEFAULT 'identified'
        CHECK (stage IN ('identified', 'aware', 'engaged', 'opportunity', 'customer')),
    score numeric NOT NULL DEFAULT 0,
    engaged_contacts integer NOT NULL DEFAULT 0,
    roles_covered text[] NOT NULL DEFAULT '{}',
    roles_missing text[] NOT NULL DEFAULT '{}',
    scored_at timestamptz,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (list_id, account_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_target_account TO attome_runtime;
GRANT SELECT ON marketing_target_account TO attome_readonly;
