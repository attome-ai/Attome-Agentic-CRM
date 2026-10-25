-- Q9-T1: sign-in hours and countries per role. A role's network allow-list
-- stays `role.ip_allowlist`. `login_calendar_ref` is a Z12 business calendar
-- whose working time is when holders may sign in (NULL: any time);
-- `allowed_countries` holds ISO 3166 alpha-2 codes (NULL or empty: anywhere).
ALTER TABLE role_auth_policy
    ADD COLUMN IF NOT EXISTS login_calendar_ref uuid REFERENCES calendar (id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS allowed_countries text[];
