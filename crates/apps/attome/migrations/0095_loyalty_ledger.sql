-- E30-T1: loyalty points. The ledger is insert-only: earning adds points,
-- redeeming and expiring take them away, an adjustment does either. Each
-- entry's reference is unique within its kind, so the same order or
-- redemption is never counted twice. The balance is the sum of a member's
-- entries; points expire first in, first out.
CREATE TABLE IF NOT EXISTS loyalty_ledger (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    member_entity text NOT NULL,
    member_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('earn', 'redeem', 'expire', 'adjust')),
    points bigint NOT NULL,
    reference text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    UNIQUE (kind, reference)
);

CREATE INDEX IF NOT EXISTS loyalty_ledger_member_idx
    ON loyalty_ledger (member_entity, member_id, occurred_at);

GRANT SELECT, INSERT ON loyalty_ledger TO attome_runtime;
GRANT SELECT ON loyalty_ledger TO attome_readonly;
