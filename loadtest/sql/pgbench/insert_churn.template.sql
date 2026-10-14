-- pgbench custom script — sustained INSERT-only churn against an
-- append-only-class table (audit-family shape: never UPDATEd after insert).
-- __TABLE__ is substituted by bloat-measurement.ps1 before use.
INSERT INTO bloat_test.__TABLE__ (seq_id, organization_ref, payload)
VALUES (nextval('bloat_test.__TABLE___seq'), uuidv7(), repeat('x', 200));
