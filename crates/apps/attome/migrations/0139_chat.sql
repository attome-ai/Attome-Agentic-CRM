-- C9-T1: internal chat. Channels (direct between two people, a named group,
-- or one linked to a record), their members, and messages with one level of
-- threads and an optional attached document. Membership is the read gate, so
-- these are infrastructure tables served by attome-chat's own routes, not
-- metadata entities the generic record API would expose. A channel may keep
-- its messages for `retention_days`; legal holds suspend the purge.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS chat_channel (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    kind text NOT NULL CHECK (kind IN ('direct', 'group', 'record')),
    name text CHECK (char_length(name) <= 200),
    -- The two members of a direct channel, sorted: one channel per pair.
    direct_key text,
    entity_name text,
    record_id uuid,
    retention_days integer CHECK (retention_days BETWEEN 1 AND 3650),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CHECK ((kind = 'direct') = (direct_key IS NOT NULL)),
    CHECK ((kind = 'record') = (entity_name IS NOT NULL AND record_id IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS chat_channel_direct_key_uq
    ON chat_channel (direct_key) WHERE kind = 'direct';
CREATE INDEX IF NOT EXISTS chat_channel_record_idx
    ON chat_channel (entity_name, record_id) WHERE kind = 'record';

CREATE TABLE IF NOT EXISTS chat_member (
    channel_id uuid NOT NULL REFERENCES chat_channel (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    role text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    joined_at timestamptz NOT NULL DEFAULT now(),
    last_read_at timestamptz,
    PRIMARY KEY (channel_id, user_id)
);
CREATE INDEX IF NOT EXISTS chat_member_user_idx ON chat_member (user_id);

CREATE TABLE IF NOT EXISTS chat_message (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    channel_id uuid NOT NULL REFERENCES chat_channel (id) ON DELETE CASCADE,
    -- A reply names the top-level message it answers; when that expires the
    -- reply stays, as a top-level message.
    thread_root_id uuid REFERENCES chat_message (id) ON DELETE SET NULL,
    author_id uuid NOT NULL,
    body text NOT NULL,
    file_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    CHECK (deleted_at IS NOT NULL OR char_length(body) BETWEEN 1 AND 8000)
);
CREATE INDEX IF NOT EXISTS chat_message_channel_idx
    ON chat_message (channel_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS chat_message_thread_idx
    ON chat_message (thread_root_id, created_at, id) WHERE thread_root_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON chat_channel, chat_member, chat_message
    TO attome_runtime;
GRANT SELECT ON chat_channel, chat_member, chat_message TO attome_readonly;
