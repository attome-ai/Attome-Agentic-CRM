-- E31-T1: referral codes and the referrals they bring. A contact has one
-- code; a lead attributed to a code is a referral, at most once per lead;
-- when the lead converts, the referral is rewarded once.
CREATE TABLE IF NOT EXISTS referral_code (
    code text NOT NULL PRIMARY KEY,
    contact_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS referral (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    code text NOT NULL REFERENCES referral_code (code),
    lead_id uuid NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'attributed' CHECK (status IN ('attributed', 'rewarded')),
    attributed_at timestamptz NOT NULL DEFAULT now(),
    rewarded_at timestamptz
);

GRANT SELECT, INSERT, UPDATE ON referral_code, referral TO attome_runtime;
GRANT SELECT ON referral_code, referral TO attome_readonly;
