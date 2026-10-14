-- The runtime records a decision's digest on its own grant row
-- (attome_audit::signoff::record_decision_digest) and may change nothing else:
-- approval_grant stays append-only for every other column.
GRANT UPDATE (signature) ON approval_grant TO attome_runtime;
