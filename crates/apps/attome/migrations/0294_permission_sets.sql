-- Q10-T4: permission sets, additive bundles of entity operations and
-- privileges assigned to a user or a team, optionally until an end date.
-- A set adds to what a person's roles give, exactly like one more role; it
-- never takes anything away (no deny) and never carries system
-- administration (refused at write time, Q10-T5).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS permission_set (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    name text NOT NULL,
    name_ar text,
    description text,
    owner_layer text NOT NULL DEFAULT 'customer'
        CHECK (owner_layer IN ('platform', 'product', 'project', 'customer')),
    is_customized boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 0,
    is_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS permission_set_name_live
    ON permission_set (lower(name)) WHERE is_deleted = false;

-- The same level columns as role_mm_entity_access (0006, 0076).
CREATE TABLE IF NOT EXISTS permission_set_entity_access (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    set_ref uuid NOT NULL REFERENCES permission_set (id),
    entity_ref uuid NOT NULL,
    read_access_level smallint NOT NULL DEFAULT 3 CHECK (read_access_level BETWEEN 0 AND 3),
    write_access_level smallint NOT NULL DEFAULT 3 CHECK (write_access_level BETWEEN 0 AND 3),
    delete_access_level smallint NOT NULL DEFAULT 3 CHECK (delete_access_level BETWEEN 0 AND 3),
    create_access_level smallint CHECK (create_access_level BETWEEN 0 AND 3),
    assign_access_level smallint CHECK (assign_access_level BETWEEN 0 AND 3),
    share_access_level smallint CHECK (share_access_level BETWEEN 0 AND 3),
    export_access_level smallint NOT NULL DEFAULT 0 CHECK (export_access_level BETWEEN 0 AND 3),
    bulk_access_level smallint NOT NULL DEFAULT 0 CHECK (bulk_access_level BETWEEN 0 AND 3),
    read_bu_children boolean NOT NULL DEFAULT true,
    write_bu_children boolean NOT NULL DEFAULT true,
    delete_bu_children boolean NOT NULL DEFAULT true,
    assign_bu_children boolean NOT NULL DEFAULT true,
    share_bu_children boolean NOT NULL DEFAULT true,
    owner_layer text NOT NULL DEFAULT 'customer'
        CHECK (owner_layer IN ('platform', 'product', 'project', 'customer')),
    row_version bigint NOT NULL DEFAULT 0,
    is_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS permission_set_entity_access_one
    ON permission_set_entity_access (set_ref, entity_ref);

CREATE TABLE IF NOT EXISTS permission_set_privilege (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    set_ref uuid NOT NULL REFERENCES permission_set (id),
    privilege_ref uuid NOT NULL REFERENCES privilege (id),
    owner_layer text NOT NULL DEFAULT 'customer'
        CHECK (owner_layer IN ('platform', 'product', 'project', 'customer')),
    is_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS permission_set_privilege_one
    ON permission_set_privilege (set_ref, privilege_ref);

CREATE TABLE IF NOT EXISTS permission_set_assignment (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    set_ref uuid NOT NULL REFERENCES permission_set (id),
    user_ref uuid REFERENCES user_account (id),
    team_ref uuid,
    ends_at timestamptz,
    reason text,
    granted_by uuid,
    is_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((user_ref IS NULL) <> (team_ref IS NULL))
);
CREATE INDEX IF NOT EXISTS permission_set_assignment_user
    ON permission_set_assignment (user_ref) WHERE is_deleted = false;
CREATE INDEX IF NOT EXISTS permission_set_assignment_team
    ON permission_set_assignment (team_ref) WHERE is_deleted = false;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    permission_set, permission_set_entity_access, permission_set_privilege,
    permission_set_assignment
    TO attome_runtime;
