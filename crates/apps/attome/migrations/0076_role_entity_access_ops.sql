-- Q10-T1: per-operation access levels on a role's entity grant, and whether
-- each business-unit level reaches child units. NULL create/assign/share
-- levels mean "same as write"; export and bulk default to denied (D-589).
-- Every existing row keeps its behaviour: child units stay included.
ALTER TABLE role_mm_entity_access
    ADD COLUMN IF NOT EXISTS create_access_level smallint
        CHECK (create_access_level BETWEEN 0 AND 3),
    ADD COLUMN IF NOT EXISTS assign_access_level smallint
        CHECK (assign_access_level BETWEEN 0 AND 3),
    ADD COLUMN IF NOT EXISTS share_access_level smallint
        CHECK (share_access_level BETWEEN 0 AND 3),
    ADD COLUMN IF NOT EXISTS export_access_level smallint NOT NULL DEFAULT 0
        CHECK (export_access_level BETWEEN 0 AND 3),
    ADD COLUMN IF NOT EXISTS bulk_access_level smallint NOT NULL DEFAULT 0
        CHECK (bulk_access_level BETWEEN 0 AND 3),
    ADD COLUMN IF NOT EXISTS read_bu_children boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS write_bu_children boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS delete_bu_children boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS assign_bu_children boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS share_bu_children boolean NOT NULL DEFAULT true;
