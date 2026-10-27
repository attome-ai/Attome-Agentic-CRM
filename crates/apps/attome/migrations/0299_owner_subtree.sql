-- A17-T3: a role's entity access may reach the records owned by the person and
-- by everyone under them in the position hierarchy, per operation. Off for
-- every existing row, so no one's access changes.
SET LOCAL lock_timeout = '5s';

ALTER TABLE role_mm_entity_access
    ADD COLUMN IF NOT EXISTS read_owner_subtree boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS write_owner_subtree boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS delete_owner_subtree boolean NOT NULL DEFAULT false;
