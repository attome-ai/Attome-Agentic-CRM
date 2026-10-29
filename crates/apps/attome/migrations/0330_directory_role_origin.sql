-- Q4-T1: a role membership the LDAP directory's group mappings gave. The
-- directory removes only the memberships it gave (this column is true); one an
-- administrator gave is false and never touched, and an administrator's grant
-- of the same role clears the column and takes the membership over.
ALTER TABLE user_account_mm_role ADD COLUMN IF NOT EXISTS source_directory boolean NOT NULL DEFAULT false;
