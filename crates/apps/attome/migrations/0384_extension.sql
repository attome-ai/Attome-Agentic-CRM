-- Y10-T5: published extensions. Each row is one version of one extension:
-- its WebAssembly module (in the file store at module_key, with its
-- SHA-256), its manifest (the grants an administrator approved) and its
-- status. At most one version of a name is published; switching an
-- extension off sets every version off at once, and the runtime reads the
-- status from here on every call, so it takes effect on every node.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS extension (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,62}$'),
    version integer NOT NULL CHECK (version > 0),
    module_key text NOT NULL,
    module_sha256 text NOT NULL,
    manifest jsonb NOT NULL,
    status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'published', 'superseded', 'off')),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    UNIQUE (name, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS extension_one_published
    ON extension (name) WHERE status = 'published';

GRANT SELECT, INSERT, UPDATE ON extension TO attome_runtime;
