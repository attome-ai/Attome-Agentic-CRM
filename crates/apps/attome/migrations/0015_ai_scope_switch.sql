-- N31-T1: scoped AI switches. A row turns one agent, model, provider, tool or
-- channel off (or back on), with the cause (an administrator or an automatic
-- trip) and who changed it. Absent row: the scope is on.
CREATE TABLE IF NOT EXISTS ai_scope_switch (
    scope_kind text NOT NULL CHECK (scope_kind IN ('agent', 'model', 'provider', 'tool', 'channel')),
    scope_key  text NOT NULL CHECK (char_length(scope_key) BETWEEN 1 AND 200),
    enabled    boolean NOT NULL,
    cause      text NOT NULL CHECK (cause IN ('manual', 'budget', 'quality', 'injection', 'departure')),
    reason     text CHECK (reason IS NULL OR char_length(reason) <= 500),
    changed_by uuid,
    changed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, scope_key)
);
GRANT SELECT, INSERT, UPDATE ON ai_scope_switch TO attome_runtime;
