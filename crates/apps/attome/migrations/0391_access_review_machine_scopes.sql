-- Q11-T2: an access review campaign may also re-certify S2S clients and
-- agent principals (`attome_security::access_review_populations`).
SET LOCAL lock_timeout = '5s';

ALTER TABLE access_review DROP CONSTRAINT IF EXISTS access_review_scope_check;
ALTER TABLE access_review ADD CONSTRAINT access_review_scope_check
    CHECK (scope IN ('role', 'team', 'entity_share', 's2s_client', 'agent'));
