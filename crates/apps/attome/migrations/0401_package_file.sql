-- T3-T2: a package's static files (a custom component's module), staged
-- with the metadata plan that installs it. The newest applied plan's files
-- of a package are what `GET /api/v1/packages/{id}/files/{path}` serves,
-- with the SHA-256 the package's signature covered and the Subresource
-- Integrity value a browser checks the module against.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS package_file (
    plan_ref     uuid NOT NULL REFERENCES metadata_bundle_plan (id) ON DELETE CASCADE,
    package_id   text NOT NULL,
    version      text NOT NULL,
    path         text NOT NULL,
    content_type text NOT NULL,
    sha256       text NOT NULL,
    integrity    text NOT NULL,
    size_bytes   integer NOT NULL CHECK (size_bytes >= 0),
    body         bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (plan_ref, path)
);

CREATE INDEX IF NOT EXISTS package_file_package_path ON package_file (package_id, path);

GRANT SELECT, INSERT, DELETE ON package_file TO attome_runtime;
