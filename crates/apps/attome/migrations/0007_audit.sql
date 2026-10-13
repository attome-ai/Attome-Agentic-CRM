-- The audit log (attome-audit), from v1's final schema renamed by V2-D483.
--
-- `audit_header`, `audit_detail` and `audit_snapshot` are range-partitioned
-- by month on `created_at`. Partition maintenance creates months ahead at
-- runtime (`attome_core::partition_maintenance`); this migration creates the
-- historical bucket (everything before the current month) and the current
-- month plus two ahead, named `{table}_p{YYYY_MM}` like the ones maintenance
-- creates, so a fresh database can write audit rows before the first
-- maintenance run.

CREATE TABLE IF NOT EXISTS audit_chain_batch (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_chain_batch_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_chain_batch_created_at_not_null NOT NULL,
    organization_ref uuid CONSTRAINT audit_chain_batch_organization_ref_not_null NOT NULL,
    first_ingest_id uuid CONSTRAINT audit_chain_batch_first_ingest_id_not_null NOT NULL,
    last_ingest_id uuid CONSTRAINT audit_chain_batch_last_ingest_id_not_null NOT NULL,
    event_count integer CONSTRAINT audit_chain_batch_event_count_not_null NOT NULL,
    prev_batch_hash character varying DEFAULT ''::character varying CONSTRAINT audit_chain_batch_prev_batch_hash_not_null NOT NULL,
    merkle_root character varying CONSTRAINT audit_chain_batch_merkle_root_not_null NOT NULL,
    signing_key_id character varying,
    signature character varying,
    epoch_period date DEFAULT (date_trunc('month'::text, now()))::date NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_config (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_config_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_config_createdon_not_null NOT NULL,
    created_by uuid,
    organization_ref uuid,
    is_active boolean DEFAULT true CONSTRAINT audit_config_is_active_not_null NOT NULL,
    entity_name character varying(128),
    field_name character varying(128),
    operation_mask integer DEFAULT 2147483647 CONSTRAINT audit_config_operation_mask_not_null NOT NULL,
    is_audited boolean DEFAULT true CONSTRAINT audit_config_is_audited_not_null NOT NULL,
    capture_snapshot boolean DEFAULT false CONSTRAINT audit_config_capture_snapshot_not_null NOT NULL,
    sensitive_fields jsonb,
    environment_mask integer DEFAULT 7 CONSTRAINT audit_config_environment_mask_not_null NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_detail (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_detail_id_not_null1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_detail_createdon_not_null1 NOT NULL,
    organization_ref uuid,
    is_active boolean DEFAULT true CONSTRAINT audit_detail_is_active_not_null1 NOT NULL,
    audit_ref uuid,
    field_name character varying(128),
    display_name character varying(256),
    data_type integer,
    old_value text,
    new_value text,
    old_display_value text,
    new_display_value text,
    old_lookup_entity character varying(128),
    old_lookup_name text,
    new_lookup_entity character varying(128),
    new_lookup_name text,
    is_sensitive boolean DEFAULT false CONSTRAINT audit_detail_is_sensitive_not_null1 NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT audit_detail_row_version_not_null NOT NULL,
    created_by uuid,
    value_mode smallint
)
PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS audit_erasure_key (
    record_id uuid CONSTRAINT erasure_key_record_id_not_null NOT NULL,
    wrapped_dek bytea,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT erasure_key_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT erasure_key_updated_at_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT erasure_key_row_version_not_null NOT NULL,
    destroyed_at timestamp with time zone,
    destroyed_by uuid,
    CONSTRAINT audit_erasure_key_wrapped_or_destroyed CHECK (((wrapped_dek IS NOT NULL) OR (destroyed_at IS NOT NULL)))
);

CREATE TABLE IF NOT EXISTS audit_header (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_header_id_not_null1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_header_createdon_not_null1 NOT NULL,
    organization_ref uuid,
    is_active boolean DEFAULT true CONSTRAINT audit_header_is_active_not_null1 NOT NULL,
    category integer,
    entity_name character varying(128),
    record_id uuid,
    operation integer,
    version_before bigint,
    version_after bigint,
    user_id uuid,
    user_name character varying(256),
    user_display_name character varying(256),
    user_email character varying(256),
    user_job_ref uuid,
    user_job_name character varying(256),
    changed_on timestamp with time zone,
    source integer,
    ip_address text,
    browser text,
    device_type integer,
    correlation_id uuid,
    batch_id uuid,
    event_name character varying(256),
    event_comment text,
    event_index bigint,
    prev_hash character varying,
    event_hash character varying DEFAULT ''::character varying CONSTRAINT audit_header_event_hash_not_null1 NOT NULL,
    signing_key_id character varying,
    signature character varying,
    chain_batch_ref uuid,
    row_version bigint DEFAULT 0 CONSTRAINT audit_header_row_version_not_null NOT NULL,
    created_by uuid,
    initiator smallint DEFAULT 0 NOT NULL,
    agent_session_id uuid,
    agent_action_id character varying(128),
    hash_version smallint DEFAULT 1 NOT NULL,
    content_digest character varying(64),
    request_id text,
    session_id uuid,
    ai_model_id text,
    approval_request_ref uuid,
    outcome smallint,
    requested_count integer,
    affected_count integer,
    failed_count integer,
    occurrence_count integer,
    CONSTRAINT audit_header_agent_needs_session CHECK (((initiator = ANY (ARRAY[0, 2])) OR (agent_session_id IS NOT NULL))),
    CONSTRAINT audit_header_initiator_range CHECK (((initiator >= 0) AND (initiator <= 2)))
)
PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS audit_ingest (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_ingest_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_ingest_created_at_not_null NOT NULL,
    organization_ref uuid CONSTRAINT audit_ingest_organization_ref_not_null NOT NULL,
    payload jsonb CONSTRAINT audit_ingest_payload_not_null NOT NULL,
    xact_id xid8 DEFAULT pg_current_xact_id()
);

CREATE TABLE IF NOT EXISTS audit_ingest_prune (
    id uuid DEFAULT uuidv7() NOT NULL,
    organization_ref uuid NOT NULL,
    through_batch_id uuid NOT NULL,
    through_ingest_id uuid NOT NULL,
    rows_deleted bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_snapshot (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_snapshot_id_not_null1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_snapshot_createdon_not_null1 NOT NULL,
    organization_ref uuid,
    audit_ref uuid,
    entity_name character varying(128),
    record_id uuid,
    version bigint,
    snapshot_json jsonb,
    trigger integer,
    row_version bigint DEFAULT 0 CONSTRAINT audit_snapshot_row_version_not_null NOT NULL,
    created_by uuid,
    is_active boolean DEFAULT true CONSTRAINT audit_snapshot_is_active_not_null NOT NULL
)
PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS audit_v1_checkpoint (
    organization_ref uuid NOT NULL,
    last_v1_header_id uuid NOT NULL,
    record text NOT NULL,
    record_sha256 character varying(64) NOT NULL,
    signing_key_id text,
    signature text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY audit_config
    ADD CONSTRAINT uq_audit_config UNIQUE (organization_ref, entity_name, field_name);

ALTER TABLE ONLY audit_ingest_prune
    ADD CONSTRAINT audit_ingest_prune_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_v1_checkpoint
    ADD CONSTRAINT audit_v1_checkpoint_pkey PRIMARY KEY (organization_ref);

ALTER TABLE ONLY audit_chain_batch
    ADD CONSTRAINT audit_chain_batch_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_config
    ADD CONSTRAINT audit_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_detail
    ADD CONSTRAINT audit_detail_pkey PRIMARY KEY (id, created_at);

ALTER TABLE ONLY audit_header
    ADD CONSTRAINT audit_header_pkey PRIMARY KEY (id, created_at);

ALTER TABLE ONLY audit_ingest
    ADD CONSTRAINT audit_ingest_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_snapshot
    ADD CONSTRAINT audit_snapshot_pkey PRIMARY KEY (id, created_at);

ALTER TABLE ONLY audit_erasure_key
    ADD CONSTRAINT erasure_key_pkey PRIMARY KEY (record_id);

CREATE INDEX IF NOT EXISTS audit_header_agent_session_idx ON audit_header USING btree (agent_session_id, created_at DESC) WHERE (initiator = 1);

CREATE INDEX IF NOT EXISTS idx_audit_chain_batch_epoch ON audit_chain_batch USING btree (organization_ref, epoch_period);

CREATE INDEX IF NOT EXISTS idx_audit_chain_batch_org ON audit_chain_batch USING btree (organization_ref, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_config_entity ON audit_config USING btree (organization_ref, entity_name, is_active);

CREATE INDEX IF NOT EXISTS idx_audit_detail_audit_ref ON audit_detail USING btree (audit_ref);

CREATE INDEX IF NOT EXISTS idx_audit_detail_field ON audit_detail USING btree (organization_ref, field_name);

CREATE INDEX IF NOT EXISTS idx_audit_header_batch ON audit_header USING btree (batch_id) WHERE (batch_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_audit_header_chain_batch_ref ON audit_header USING btree (chain_batch_ref) WHERE (chain_batch_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_audit_header_change_feed_entity ON audit_header USING btree (entity_name, changed_on DESC, id DESC) WHERE (((entity_name)::text = ANY ((ARRAY['ai_model'::character varying, 'setting'::character varying])::text[])) AND (changed_on IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_audit_header_change_feed_security ON audit_header USING btree (changed_on DESC, id DESC) WHERE ((category = 1) AND (operation = ANY (ARRAY[12, 13, 14])) AND (changed_on IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_audit_header_correlation ON audit_header USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_audit_header_entity_record ON audit_header USING btree (organization_ref, entity_name, record_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_header_operation ON audit_header USING btree (organization_ref, entity_name, operation, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_header_org_createdon ON audit_header USING btree (organization_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_header_user ON audit_header USING btree (organization_ref, user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_snapshot_json ON audit_snapshot USING gin (snapshot_json);

CREATE INDEX IF NOT EXISTS idx_audit_snapshot_record ON audit_snapshot USING btree (organization_ref, entity_name, record_id, version DESC);

CREATE INDEX IF NOT EXISTS audit_ingest_prune_org_through_idx ON audit_ingest_prune USING btree (organization_ref, through_ingest_id DESC);


-- Partitions for a fresh database, relative to the day it is installed.
DO $$
DECLARE
    parent TEXT;
    month_start TIMESTAMPTZ := date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    i INTEGER;
    part_from TIMESTAMPTZ;
    part_to TIMESTAMPTZ;
BEGIN
    FOREACH parent IN ARRAY ARRAY['audit_header', 'audit_detail', 'audit_snapshot'] LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (MINVALUE) TO (%L)',
            parent || '_pre_partition', parent, month_start);
        FOR i IN 0..2 LOOP
            part_from := month_start + make_interval(months => i);
            part_to := month_start + make_interval(months => i + 1);
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                parent || '_p' || to_char(part_from AT TIME ZONE 'UTC', 'YYYY_MM'), parent,
                part_from, part_to);
        END LOOP;
    END LOOP;
END
$$;
