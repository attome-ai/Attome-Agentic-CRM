-- O13-T1: a digital worker. An agent principal (AH3) that works a service
-- queue: it is a member of the queue (`service_work_queue_member`) with
-- per-channel capacity (`agent_channel_capacity`) as a person is; here it
-- names the agent definition it runs on each item, the person its items
-- escalate to, and its working hours (ISO weekdays and minutes of the day in
-- its time zone), which stand in for a person's presence.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS digital_worker (
    user_ref             uuid PRIMARY KEY REFERENCES agent_principal (user_ref),
    agent_definition_ref uuid NOT NULL,
    supervisor_ref       uuid NOT NULL REFERENCES user_account (id),
    working_days         smallint[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
    start_minute         integer NOT NULL DEFAULT 0 CHECK (start_minute BETWEEN 0 AND 1440),
    end_minute           integer NOT NULL DEFAULT 1440 CHECK (end_minute BETWEEN 0 AND 1440),
    time_zone            text NOT NULL DEFAULT 'UTC',
    is_active            boolean NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now(),
    created_by           uuid NOT NULL,
    row_version          bigint NOT NULL DEFAULT 1
);

GRANT SELECT, INSERT, UPDATE ON digital_worker TO attome_runtime;
GRANT SELECT ON digital_worker TO attome_readonly;
