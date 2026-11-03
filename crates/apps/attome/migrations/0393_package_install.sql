-- T8-T2: a package's install, keyed by the metadata plan that installs it.
-- The preview records what a managed package locks; a successful apply of
-- that plan writes the locks to `metadata_lock` and stamps `installed_at`.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS package_install (
    plan_ref     uuid PRIMARY KEY,
    package_id   text NOT NULL,
    version      text NOT NULL,
    mode         text NOT NULL CHECK (mode IN ('managed', 'unmanaged')),
    locks        jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    installed_at timestamptz
);

GRANT SELECT, INSERT, UPDATE ON package_install TO attome_runtime;
GRANT SELECT ON package_install TO attome_readonly;
