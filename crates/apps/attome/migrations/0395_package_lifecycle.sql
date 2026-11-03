-- T8-T3: a package's lifecycle after install. `manifest` is what an upgrade,
-- drift and uninstall read back (namespace, extension points);
-- `uninstalled_at` and `data_choice` close an install: uninstalled with its
-- data kept, exported then retired, or retired, or replaced by an upgrade.
SET LOCAL lock_timeout = '5s';

ALTER TABLE package_install
    ADD COLUMN IF NOT EXISTS manifest jsonb,
    ADD COLUMN IF NOT EXISTS uninstalled_at timestamptz,
    ADD COLUMN IF NOT EXISTS data_choice text
        CHECK (data_choice IN ('keep', 'export', 'delete', 'upgraded'));

CREATE INDEX IF NOT EXISTS package_install_current_idx
    ON package_install (package_id, installed_at DESC)
    WHERE installed_at IS NOT NULL AND uninstalled_at IS NULL;
