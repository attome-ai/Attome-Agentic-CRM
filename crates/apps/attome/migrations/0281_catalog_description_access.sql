-- L4-T4: catalog descriptions are edited with If-Match and approved by a
-- builder, and an access request names the role it asks for and, once
-- decided, the approval request a gated grant waits on.
SET LOCAL lock_timeout = '5s';

ALTER TABLE catalog_asset ADD COLUMN IF NOT EXISTS row_version bigint NOT NULL DEFAULT 0;
ALTER TABLE catalog_asset ADD COLUMN IF NOT EXISTS description_by uuid;
ALTER TABLE catalog_asset ADD COLUMN IF NOT EXISTS description_reviewed_by uuid;

ALTER TABLE catalog_access_request ADD COLUMN IF NOT EXISTS role_ref uuid;
ALTER TABLE catalog_access_request ADD COLUMN IF NOT EXISTS approval_request_id uuid;
ALTER TABLE catalog_access_request ADD COLUMN IF NOT EXISTS row_version bigint NOT NULL DEFAULT 0;
