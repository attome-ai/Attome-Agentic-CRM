-- A1-T4: entity inheritance by copy-down. An entity may extend one base
-- entity; its table holds copies of the base's columns, and each copied
-- attribute row names the base attribute it was copied from, so a change
-- to the base is applied to every copy. No Postgres table inheritance: a
-- child's reads never join the base table.
ALTER TABLE entity_info
    ADD COLUMN IF NOT EXISTS extends_entity_id uuid NULL REFERENCES entity_info (id) ON DELETE SET NULL;

ALTER TABLE attribute_info
    ADD COLUMN IF NOT EXISTS inherited_from_attribute_id uuid NULL REFERENCES attribute_info (id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS entity_info_extends_idx
    ON entity_info (extends_entity_id) WHERE extends_entity_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS attribute_info_inherited_from_idx
    ON attribute_info (inherited_from_attribute_id) WHERE inherited_from_attribute_id IS NOT NULL;
