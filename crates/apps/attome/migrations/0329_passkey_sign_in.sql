-- Q6-T1: a role may let its holders sign in with a passkey alone (no
-- password). Off by default; a person may when any role they hold allows it.
ALTER TABLE role_auth_policy ADD COLUMN IF NOT EXISTS passkey_sign_in boolean NOT NULL DEFAULT false;
