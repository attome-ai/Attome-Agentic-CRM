-- F5-T7 follow-up: billing_gateway_event's grants, explicit like every
-- other billing table's (0106 relied on the migrator's default privileges,
-- which do not apply when migrations run as another owner).

GRANT SELECT, INSERT, UPDATE ON billing_gateway_event TO attome_runtime;
GRANT SELECT ON billing_gateway_event TO attome_readonly;
