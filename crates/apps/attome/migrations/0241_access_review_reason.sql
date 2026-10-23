-- Q11-T1: why a reviewer kept or revoked an access, shown in the review
-- screen and its evidence export.
SET LOCAL lock_timeout = '5s';

ALTER TABLE access_review_item ADD COLUMN IF NOT EXISTS decision_reason text;
