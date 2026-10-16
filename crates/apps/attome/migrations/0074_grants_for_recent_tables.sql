-- The tables and the sequence migrations 0068, 0072 and 0073 created, made
-- usable by the application roles: migrations run as the bootstrap role, so
-- the migrator's default privileges do not cover them.
GRANT SELECT, INSERT, UPDATE, DELETE ON workflow_schedule_slot TO attome_runtime;
GRANT SELECT ON workflow_schedule_slot TO attome_readonly;

GRANT SELECT, INSERT, UPDATE, DELETE ON change_consumer_applied TO attome_runtime;
GRANT SELECT ON change_consumer_applied TO attome_readonly;

-- Every outbox insert draws `seq` from it.
GRANT USAGE, SELECT ON SEQUENCE entity_change_event_seq TO attome_runtime;
