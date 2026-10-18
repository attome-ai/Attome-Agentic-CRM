-- Y12-T8: after a rename, the old attribute name keeps working in the record
-- API until expires_at; the registry maps it to the attribute's current name.
CREATE TABLE IF NOT EXISTS attribute_alias (
    entity       text        NOT NULL,
    old_name     text        NOT NULL,
    attribute_id uuid        NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity, old_name)
);

CREATE INDEX IF NOT EXISTS idx_attribute_alias_expires ON attribute_alias (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON attribute_alias TO attome_runtime;
GRANT SELECT ON attribute_alias TO attome_readonly;
