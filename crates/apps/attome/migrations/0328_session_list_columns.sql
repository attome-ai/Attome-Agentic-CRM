-- Q8-T4: the session family a browser was remembered in, so ending that
-- session from the person's own session list forgets the browser too, and
-- the country a session signed in from, for that list. NULL for a device
-- remembered, or a session started, before these columns existed, and for a
-- country with no `auth.geoip_database`. A country code, never an address.
ALTER TABLE remembered_device ADD COLUMN IF NOT EXISTS family_ref uuid;

CREATE INDEX IF NOT EXISTS remembered_device_family_live_idx
    ON remembered_device (family_ref) WHERE revoked_at IS NULL AND family_ref IS NOT NULL;

ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS sign_in_country text;
