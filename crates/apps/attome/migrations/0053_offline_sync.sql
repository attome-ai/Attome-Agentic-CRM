-- B18-T3: offline sync. Per device: its sync state (the pull cursor, when it
-- last pulled and pushed, its queue and storage use, and whether the server
-- wants a full refresh), the records it holds (the manifest), and the
-- operations it pushed, kept by the client's own id so a retried push
-- answers with the first result instead of applying twice.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS offline_device_state (
    device_id uuid PRIMARY KEY REFERENCES user_device (id) ON DELETE CASCADE,
    profile_id uuid NOT NULL,
    cursor jsonb NOT NULL DEFAULT '{}',
    last_pull_at timestamptz,
    last_push_at timestamptz,
    queue_size integer NOT NULL DEFAULT 0,
    bytes_used bigint NOT NULL DEFAULT 0,
    last_error text,
    force_refresh boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS offline_manifest (
    device_id uuid NOT NULL,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    PRIMARY KEY (device_id, entity, record_id)
);
CREATE INDEX IF NOT EXISTS offline_manifest_record_idx ON offline_manifest (entity, record_id);

CREATE TABLE IF NOT EXISTS offline_op (
    device_id uuid NOT NULL,
    client_op_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('applied', 'merged', 'conflict', 'rejected')),
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, client_op_id)
);
-- For pruning old operations.
CREATE INDEX IF NOT EXISTS offline_op_created_idx ON offline_op (created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON offline_device_state, offline_manifest, offline_op
    TO attome_runtime;
GRANT SELECT ON offline_device_state, offline_manifest, offline_op TO attome_readonly;
