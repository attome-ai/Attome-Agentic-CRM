-- R4-T1: the people a legal hold asks to keep what they hold, when they
-- were told and when they acknowledged it.
CREATE TABLE IF NOT EXISTS legal_hold_custodian (
    hold_ref uuid NOT NULL REFERENCES legal_hold (id),
    user_ref uuid NOT NULL REFERENCES user_account (id),
    notified_at timestamptz NOT NULL DEFAULT now(),
    notified_by uuid NOT NULL,
    acknowledged_at timestamptz,
    PRIMARY KEY (hold_ref, user_ref)
);

CREATE INDEX IF NOT EXISTS legal_hold_custodian_user_idx ON legal_hold_custodian (user_ref);

GRANT SELECT, INSERT, UPDATE ON legal_hold_custodian TO attome_runtime;
GRANT SELECT ON legal_hold_custodian TO attome_readonly;
