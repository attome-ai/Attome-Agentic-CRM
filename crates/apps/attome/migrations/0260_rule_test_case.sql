-- A11-T4: a business rule's test cases: an example record and whether the
-- rule must let its save pass or refuse it, with the values its set_value
-- policies must produce. Publishing the rule runs them and refuses on a case
-- that does not hold. A rule carries at most 100 (checked by the route).
CREATE TABLE IF NOT EXISTS rule_test_case (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    rule_ref uuid NOT NULL REFERENCES rule (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    record jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(record) = 'object'),
    expect text NOT NULL CHECK (expect IN ('pass', 'fail')),
    set_values jsonb CHECK (set_values IS NULL OR jsonb_typeof(set_values) = 'object'),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (rule_ref, name)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON rule_test_case TO attome_runtime;
GRANT SELECT ON rule_test_case TO attome_readonly;
