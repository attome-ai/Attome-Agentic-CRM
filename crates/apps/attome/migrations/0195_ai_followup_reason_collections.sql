-- AI5-T2: the follow-up ledger also records collections: invoices coming due,
-- overdue invoices and subscriptions coming up for renewal, written by the
-- collections detector under an `ai_collection_rule`. The reason check is
-- widened; the existing reasons keep their meaning.
SET LOCAL lock_timeout = '5s';

ALTER TABLE ai_followup_item DROP CONSTRAINT IF EXISTS ai_followup_item_reason_check;
ALTER TABLE ai_followup_item ADD CONSTRAINT ai_followup_item_reason_check CHECK (
    reason IN ('stalled_deal', 'overdue_task', 'unanswered_customer',
               'invoice_due', 'invoice_overdue', 'renewal_due')
);
