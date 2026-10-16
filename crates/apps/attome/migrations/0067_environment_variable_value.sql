-- A30-T1: the values of environment variables. The definitions are
-- metadata (the environment_variable kind) and travel with configuration;
-- these values belong to one deployment and never leave it. A secret's value
-- is kept only encrypted (value_encrypted) and is never read back through
-- the API. Every change is kept in the history, without secret values.

CREATE TABLE IF NOT EXISTS environment_variable_value (
    name text NOT NULL PRIMARY KEY,
    value jsonb,
    value_encrypted text,
    row_version bigint NOT NULL DEFAULT 1,
    updated_by uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT environment_variable_value_one_form CHECK ((value IS NULL) <> (value_encrypted IS NULL))
);

CREATE TABLE IF NOT EXISTS environment_variable_history (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    name text NOT NULL,
    change text NOT NULL,
    value jsonb,
    is_secret boolean NOT NULL DEFAULT false,
    changed_by uuid NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT environment_variable_history_change CHECK (change IN ('set', 'cleared'))
);
CREATE INDEX IF NOT EXISTS ix_environment_variable_history_name
    ON environment_variable_history (name, changed_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON environment_variable_value TO attome_runtime;
GRANT SELECT, INSERT ON environment_variable_history TO attome_runtime;
