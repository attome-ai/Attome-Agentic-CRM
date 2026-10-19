-- D21-T6: the caller id a call shows the customer, chosen by country from
-- the numbers the voice system owns (the dialer's caller id rules); none
-- means the system's own number.
SET LOCAL lock_timeout = '5s';

ALTER TABLE voice_call ADD COLUMN IF NOT EXISTS caller_id text;
