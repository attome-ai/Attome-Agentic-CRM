-- T1-T3: Develop workspaces shared with a team, and a builder's publish
-- waiting for the owner's review (status in_review, the approval request).
SET LOCAL lock_timeout = '5s';

ALTER TABLE develop_workspace ADD COLUMN IF NOT EXISTS team_ref uuid;
ALTER TABLE develop_workspace ADD COLUMN IF NOT EXISTS review_request_ref uuid;

ALTER TABLE develop_workspace DROP CONSTRAINT IF EXISTS develop_workspace_status_check;
ALTER TABLE develop_workspace ADD CONSTRAINT develop_workspace_status_check
    CHECK (status IN ('open', 'in_review', 'publishing', 'published', 'discarded'));

CREATE INDEX IF NOT EXISTS develop_workspace_by_team
    ON develop_workspace (team_ref) WHERE team_ref IS NOT NULL;
