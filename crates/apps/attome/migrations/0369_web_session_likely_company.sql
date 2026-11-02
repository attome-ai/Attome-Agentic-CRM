-- E14-T10: the company a session's visitor likely works for, from the
-- truncated IP through the customer's provider; never on a person.
ALTER TABLE marketing_web_session ADD COLUMN IF NOT EXISTS likely_company text;
ALTER TABLE marketing_web_session ADD COLUMN IF NOT EXISTS likely_account_ref uuid;
