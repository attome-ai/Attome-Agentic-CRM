-- Z1-T8: every secret the configuration holds, by its configuration path
-- and key id, with when each key was first and last seen at a start and
-- since when it has been the active one. Never a value, a hash or any part
-- of one (see attome_compliance::secret_inventory). A plain secret, which
-- has no key ids, is recorded under the empty key id. `reminded_at` is the
-- last age reminder sent for it.
CREATE TABLE IF NOT EXISTS secret_inventory (
    name           text        NOT NULL,
    key_id         text        NOT NULL,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    active_since   timestamptz,
    reminded_at    timestamptz,
    PRIMARY KEY (name, key_id)
);

GRANT SELECT, INSERT, UPDATE ON secret_inventory TO attome_runtime;
GRANT SELECT ON secret_inventory TO attome_readonly;
