-- The metadata model's one versioned object store (roadmap Y1-T2, V2-D454):
-- every kind of metadata object (forms first) in one table, its versions in a
-- second, and the content-hashed artefacts the cooker produces in a third.
-- Definitions only: records never live here (one physical table per entity).

CREATE TABLE IF NOT EXISTS metadata_object (
    id          uuid PRIMARY KEY,
    kind        text NOT NULL,
    name        text NOT NULL,
    app         text NOT NULL DEFAULT 'customer',
    owner_layer text NOT NULL CHECK (owner_layer IN ('platform', 'app', 'customer')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    is_active   boolean NOT NULL DEFAULT true,
    CONSTRAINT metadata_object_kind_app_name_unique UNIQUE (kind, app, name)
);

CREATE INDEX IF NOT EXISTS metadata_object_kind_id_idx ON metadata_object (kind, id);

CREATE TABLE IF NOT EXISTS metadata_object_version (
    object_id           uuid NOT NULL REFERENCES metadata_object (id),
    version_no          bigint NOT NULL,
    kind_schema_version integer NOT NULL,
    doc                 jsonb NOT NULL,
    content_hash        text NOT NULL,
    state               text NOT NULL CHECK (state IN ('draft', 'published')),
    created_by          uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (object_id, version_no)
);

-- At most one open draft per object.
CREATE UNIQUE INDEX IF NOT EXISTS metadata_object_version_one_draft
    ON metadata_object_version (object_id) WHERE state = 'draft';

CREATE TABLE IF NOT EXISTS metadata_artefact (
    content_hash text PRIMARY KEY,
    kind         text NOT NULL,
    payload      bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Owned by the migrator like every table 0009 handed over; the runtime role
-- reads and writes, the read-only role reads.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_migrator') THEN
        ALTER TABLE metadata_object OWNER TO attome_migrator;
        ALTER TABLE metadata_object_version OWNER TO attome_migrator;
        ALTER TABLE metadata_artefact OWNER TO attome_migrator;
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_runtime') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON metadata_object, metadata_object_version, metadata_artefact TO attome_runtime;
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_readonly') THEN
        GRANT SELECT ON metadata_object, metadata_object_version, metadata_artefact TO attome_readonly;
    END IF;
END
$$;
