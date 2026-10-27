-- Q10-T3: each business unit's materialised path, "/<root id>/.../<id>/", so
-- "this unit and everything under it" is one indexed prefix comparison
-- instead of a recursive walk. A trigger keeps it right on every write path
-- (the entity API, the admin screens, bundles, imports): a new unit takes its
-- parent's path, and moving a unit rewrites the paths of its whole subtree in
-- the same statement. A move that would put a unit under its own descendant
-- is refused.

ALTER TABLE organization ADD COLUMN IF NOT EXISTS unit_path text;

WITH RECURSIVE tree AS (
    SELECT o.id, '/' || o.id::text || '/' AS path
      FROM organization o
     WHERE o.organization_ref IS NULL
        OR NOT EXISTS (SELECT 1 FROM organization p WHERE p.id = o.organization_ref)
    UNION ALL
    SELECT c.id, t.path || c.id::text || '/'
      FROM organization c
      JOIN tree t ON c.organization_ref = t.id
)
UPDATE organization o
   SET unit_path = t.path
  FROM tree t
 WHERE o.id = t.id
   AND o.unit_path IS DISTINCT FROM t.path;

CREATE INDEX IF NOT EXISTS organization_unit_path_idx
    ON organization (unit_path text_pattern_ops);

CREATE OR REPLACE FUNCTION organization_unit_path() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    parent_path text;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.organization_ref IS NOT DISTINCT FROM OLD.organization_ref
       AND OLD.unit_path IS NOT NULL THEN
        NEW.unit_path := OLD.unit_path;
        RETURN NEW;
    END IF;
    -- Serialises path changes, so a unit added under a unit being moved
    -- cannot keep the old path. 23 is attome_security::ADVISORY_LOCK_NAMESPACE
    -- (D-351's two-argument form).
    IF NOT pg_try_advisory_xact_lock(23, hashtext('attome-security/unit-path:all')) THEN
        RAISE EXCEPTION 'another business unit change is in progress; retry'
            USING ERRCODE = '40001';
    END IF;
    SELECT p.unit_path INTO parent_path
      FROM organization p
     WHERE p.id = NEW.organization_ref;
    IF TG_OP = 'UPDATE' AND OLD.unit_path IS NOT NULL
       AND parent_path LIKE OLD.unit_path || '%' THEN
        RAISE EXCEPTION 'a business unit cannot be moved under itself or its own unit'
            USING ERRCODE = '23514';
    END IF;
    NEW.unit_path := COALESCE(parent_path, '/') || NEW.id::text || '/';
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION organization_unit_path_subtree() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.unit_path IS NOT NULL AND NEW.unit_path IS DISTINCT FROM OLD.unit_path THEN
        UPDATE organization
           SET unit_path = NEW.unit_path || substr(unit_path, length(OLD.unit_path) + 1)
         WHERE unit_path LIKE OLD.unit_path || '%'
           AND id <> NEW.id;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS organization_unit_path ON organization;
CREATE TRIGGER organization_unit_path BEFORE INSERT OR UPDATE OF organization_ref ON organization
    FOR EACH ROW EXECUTE FUNCTION organization_unit_path();

DROP TRIGGER IF EXISTS organization_unit_path_subtree ON organization;
CREATE TRIGGER organization_unit_path_subtree AFTER UPDATE OF organization_ref ON organization
    FOR EACH ROW EXECUTE FUNCTION organization_unit_path_subtree();
