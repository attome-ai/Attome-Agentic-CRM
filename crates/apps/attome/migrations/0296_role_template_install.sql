-- Q10-T7: which module template a role was installed from. A separate table,
-- not a column on `role`, which is also a metadata entity. The installed role
-- is an ordinary role its administrators own: nothing re-syncs it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS role_template_install (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    role_ref uuid NOT NULL UNIQUE REFERENCES role (id),
    template_key text NOT NULL,
    installed_by uuid,
    installed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS role_template_install_key ON role_template_install (template_key);

GRANT SELECT, INSERT ON role_template_install TO attome_runtime;
