-- The modules' tables: AI conversations, automation (bulk operations and
-- staged imports), content, docgen, the developer fleet console, integration
-- credentials, metrics, data migration, notifications, predictions, process
-- mining, reports, server-to-server clients, web crawling, portals and
-- workflows. From v1's final schema, renamed by V2-D483.
--
-- They arrive in one migration because they reference each other and the
-- engine tables; a module that is switched off (attome-modules) keeps its
-- empty tables, which cost nothing.

CREATE TABLE IF NOT EXISTS ai_conversation (
    id uuid DEFAULT uuidv7() NOT NULL,
    agent_session_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    agent_definition_ref uuid,
    surface text NOT NULL,
    title text,
    last_ordinal bigint DEFAULT 0 NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    last_message_at timestamp with time zone,
    ended_at timestamp with time zone,
    row_version bigint DEFAULT 1 NOT NULL,
    last_event_ordinal bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ai_conversation_last_event_ordinal_nonnegative CHECK ((last_event_ordinal >= 0)),
    CONSTRAINT ai_conversation_ordinal_non_negative CHECK ((last_ordinal >= 0)),
    CONSTRAINT ai_conversation_surface_known CHECK ((surface = ANY (ARRAY['internal'::text, 'webchat'::text, 'mcp'::text, 'workflow'::text])))
);

CREATE TABLE IF NOT EXISTS ai_conversation_event (
    id uuid DEFAULT uuidv7() NOT NULL,
    conversation_id uuid NOT NULL,
    ordinal bigint NOT NULL,
    turn_id uuid,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_conversation_event_ordinal_positive CHECK ((ordinal > 0)),
    CONSTRAINT ai_conversation_event_type_known CHECK ((event_type = ANY (ARRAY['turn.started'::text, 'tool.call.proposed'::text, 'tool.call.started'::text, 'tool.call.completed'::text, 'tool.call.failed'::text, 'approval.required'::text, 'approval.resolved'::text, 'message.completed'::text, 'turn.completed'::text])))
);

CREATE TABLE IF NOT EXISTS ai_message (
    id uuid DEFAULT uuidv7() NOT NULL,
    conversation_id uuid NOT NULL,
    ordinal bigint NOT NULL,
    role text NOT NULL,
    content text DEFAULT ''::text NOT NULL,
    turn_id uuid NOT NULL,
    terminal_state text,
    model_id text,
    prompt_version text,
    input_tokens integer,
    output_tokens integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tool_calls jsonb,
    tool_call_id text,
    persona_sha256 text,
    CONSTRAINT ai_message_ordinal_positive CHECK ((ordinal > 0)),
    CONSTRAINT ai_message_role_known CHECK ((role = ANY (ARRAY['user'::text, 'assistant'::text, 'tool'::text]))),
    CONSTRAINT ai_message_terminal_state_known CHECK (((terminal_state IS NULL) OR (terminal_state = ANY (ARRAY['completed'::text, 'max_steps'::text, 'budget_exceeded'::text, 'session_revoked'::text, 'kill_switch'::text, 'privilege_revoked'::text, 'awaiting_confirmation'::text, 'awaiting_approval'::text, 'invalid_tool_call'::text, 'model_failure'::text, 'tool_failure'::text, 'protocol_error'::text, 'cancelled'::text])))),
    CONSTRAINT ai_message_tool_links_by_role CHECK ((((tool_calls IS NULL) OR ((role = 'assistant'::text) AND (jsonb_typeof(tool_calls) = 'array'::text))) AND ((tool_call_id IS NULL) OR (role = 'tool'::text))))
);

CREATE TABLE IF NOT EXISTS ai_message_feedback (
    id uuid DEFAULT uuidv7() NOT NULL,
    message_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    user_id uuid NOT NULL,
    vote text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT ai_message_feedback_vote_known CHECK ((vote = ANY (ARRAY['up'::text, 'down'::text])))
);

CREATE TABLE IF NOT EXISTS ai_provider_credential (
    id uuid DEFAULT uuidv7() NOT NULL,
    provider_ref uuid NOT NULL,
    secret_encrypted text NOT NULL,
    secret_last4 text,
    rotated_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_suggestion_outcome (
    id uuid DEFAULT uuidv7() NOT NULL,
    model_id text NOT NULL,
    prompt_version text NOT NULL,
    action_id text NOT NULL,
    entity_logicalname text NOT NULL,
    field_ref text,
    record_id uuid,
    outcome text DEFAULT 'pending'::text NOT NULL,
    edit_distance integer,
    latency_ms integer,
    prompt_tokens integer,
    completion_tokens integer,
    user_ref uuid,
    organization_ref uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    agent_session_ref uuid,
    CONSTRAINT ai_suggestion_outcome_decided_at_chk CHECK (((outcome = 'pending'::text) = (decided_at IS NULL))),
    CONSTRAINT ai_suggestion_outcome_edit_distance_chk CHECK (((outcome = 'edited'::text) = (edit_distance IS NOT NULL))),
    CONSTRAINT ai_suggestion_outcome_outcome_chk CHECK ((outcome = ANY (ARRAY['pending'::text, 'accepted'::text, 'edited'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS ai_tool_call (
    id uuid DEFAULT uuidv7() NOT NULL,
    conversation_id uuid NOT NULL,
    message_id uuid,
    turn_id uuid NOT NULL,
    tool_call_id text NOT NULL,
    action_id text NOT NULL,
    arguments jsonb NOT NULL,
    arguments_hash text NOT NULL,
    status text DEFAULT 'proposed'::text NOT NULL,
    claimed_at timestamp with time zone,
    approval_request_id uuid,
    initiator smallint DEFAULT 1 NOT NULL,
    gate_decision text,
    outcome jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT ai_tool_call_initiator_range CHECK (((initiator >= 0) AND (initiator <= 1))),
    CONSTRAINT ai_tool_call_lease_matches_status CHECK (((status = 'executing'::text) = (claimed_at IS NOT NULL))),
    CONSTRAINT ai_tool_call_status_known CHECK ((status = ANY (ARRAY['proposed'::text, 'executing'::text, 'executed'::text, 'rejected'::text, 'expired'::text, 'invalidated'::text, 'approval_pending'::text])))
);

CREATE TABLE IF NOT EXISTS ai_turn_cancel (
    turn_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS automation_bulk_operation (
    id uuid DEFAULT uuidv7() CONSTRAINT bulk_operation_id_not_null NOT NULL,
    entity_logicalname text CONSTRAINT bulk_operation_entity_logicalname_not_null NOT NULL,
    operation text CONSTRAINT bulk_operation_operation_not_null NOT NULL,
    status text DEFAULT 'pending'::text CONSTRAINT bulk_operation_status_not_null NOT NULL,
    total integer CONSTRAINT bulk_operation_total_not_null NOT NULL,
    succeeded integer DEFAULT 0 CONSTRAINT bulk_operation_succeeded_not_null NOT NULL,
    failed integer DEFAULT 0 CONSTRAINT bulk_operation_failed_not_null NOT NULL,
    errors jsonb DEFAULT '[]'::jsonb CONSTRAINT bulk_operation_errors_not_null NOT NULL,
    created_by uuid CONSTRAINT bulk_operation_created_by_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT bulk_operation_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT bulk_operation_updated_at_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT bulk_operation_row_version_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT bulk_operation_is_deleted_not_null NOT NULL,
    batch_mode text DEFAULT 'partial'::text CONSTRAINT bulk_operation_batch_mode_not_null NOT NULL,
    rejected integer DEFAULT 0 CONSTRAINT bulk_operation_rejected_not_null NOT NULL,
    CONSTRAINT bulk_operation_batch_mode_check CHECK ((batch_mode = ANY (ARRAY['partial'::text, 'atomic'::text]))),
    CONSTRAINT bulk_operation_operation_check CHECK ((operation = ANY (ARRAY['create'::text, 'update'::text, 'delete'::text]))),
    CONSTRAINT bulk_operation_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS automation_bulk_operation_item (
    id uuid DEFAULT uuidv7() CONSTRAINT bulk_operation_item_id_not_null NOT NULL,
    bulk_operation_id uuid CONSTRAINT bulk_operation_item_bulk_operation_id_not_null NOT NULL,
    item_index integer CONSTRAINT bulk_operation_item_item_index_not_null NOT NULL,
    record_id uuid,
    payload jsonb CONSTRAINT bulk_operation_item_payload_not_null NOT NULL,
    status text DEFAULT 'pending'::text CONSTRAINT bulk_operation_item_status_not_null NOT NULL,
    error text,
    attempts integer DEFAULT 0 CONSTRAINT bulk_operation_item_attempts_not_null NOT NULL,
    claimed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT bulk_operation_item_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT bulk_operation_item_updated_at_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT bulk_operation_item_row_version_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT bulk_operation_item_is_deleted_not_null NOT NULL,
    CONSTRAINT automation_bulk_operation_item_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS automation_staged_import (
    id uuid DEFAULT uuidv7() CONSTRAINT staged_import_id_not_null NOT NULL,
    entity_logicalname text CONSTRAINT staged_import_entity_logicalname_not_null NOT NULL,
    operation text CONSTRAINT staged_import_operation_not_null NOT NULL,
    raw_records jsonb CONSTRAINT staged_import_raw_records_not_null NOT NULL,
    validation_report jsonb DEFAULT '[]'::jsonb CONSTRAINT staged_import_validation_report_not_null NOT NULL,
    status text DEFAULT 'pending_review'::text CONSTRAINT staged_import_status_not_null NOT NULL,
    created_by uuid CONSTRAINT staged_import_created_by_not_null NOT NULL,
    approved_by uuid,
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT staged_import_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT staged_import_updated_at_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT staged_import_row_version_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT staged_import_is_deleted_not_null NOT NULL,
    batch_mode text DEFAULT 'partial'::text CONSTRAINT staged_import_batch_mode_not_null NOT NULL,
    rejected integer DEFAULT 0 CONSTRAINT staged_import_rejected_not_null NOT NULL,
    mapping_ref uuid,
    migration_run_id uuid,
    mode text DEFAULT 'stage'::text NOT NULL,
    CONSTRAINT automation_staged_import_mode_check CHECK ((mode = ANY (ARRAY['stage'::text, 'dry_run'::text]))),
    CONSTRAINT staged_import_batch_mode_check CHECK ((batch_mode = ANY (ARRAY['partial'::text, 'atomic'::text]))),
    CONSTRAINT staged_import_operation_check CHECK ((operation = ANY (ARRAY['create'::text, 'update'::text, 'delete'::text]))),
    CONSTRAINT staged_import_status_check CHECK ((status = ANY (ARRAY['pending_review'::text, 'approving'::text, 'approved'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS automation_staged_import_item (
    id uuid DEFAULT uuidv7() CONSTRAINT staged_import_item_id_not_null NOT NULL,
    staged_import_id uuid CONSTRAINT staged_import_item_staged_import_id_not_null NOT NULL,
    item_index integer CONSTRAINT staged_import_item_item_index_not_null NOT NULL,
    record_id uuid,
    payload jsonb CONSTRAINT staged_import_item_payload_not_null NOT NULL,
    status text DEFAULT 'pending'::text CONSTRAINT staged_import_item_status_not_null NOT NULL,
    error text,
    attempts integer DEFAULT 0 CONSTRAINT staged_import_item_attempts_not_null NOT NULL,
    claimed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT staged_import_item_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT staged_import_item_updated_at_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT staged_import_item_row_version_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT staged_import_item_is_deleted_not_null NOT NULL,
    CONSTRAINT automation_staged_import_item_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS content_page (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    parent_page_id uuid,
    title text NOT NULL,
    url_path text NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    blocks_draft jsonb DEFAULT '[]'::jsonb NOT NULL,
    blocks_published jsonb,
    seo_title text,
    seo_description text,
    published_at timestamp with time zone,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    content_space_id uuid NOT NULL,
    template_id uuid,
    publish_at timestamp with time zone,
    unpublish_at timestamp with time zone,
    review_by date
);

CREATE TABLE IF NOT EXISTS content_page_related (
    page_id uuid NOT NULL,
    related_page_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_content_page_related_not_self CHECK ((page_id <> related_page_id))
);

CREATE TABLE IF NOT EXISTS content_page_stats (
    page_ref uuid NOT NULL,
    views bigint DEFAULT 0 NOT NULL,
    retrievals bigint DEFAULT 0 NOT NULL,
    helpfulness_up bigint DEFAULT 0 NOT NULL,
    helpfulness_down bigint DEFAULT 0 NOT NULL,
    last_useful_at timestamp with time zone,
    rolled_up_through timestamp with time zone DEFAULT '-infinity'::timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS content_page_view (
    id uuid DEFAULT uuidv7() NOT NULL,
    page_ref uuid NOT NULL,
    viewed_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS content_page_vote (
    id uuid DEFAULT uuidv7() NOT NULL,
    page_ref uuid NOT NULL,
    useful boolean NOT NULL,
    voted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS content_space (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    name text NOT NULL,
    description text,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_content_space_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS content_space_template (
    content_space_id uuid NOT NULL,
    template_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS content_template (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    name text NOT NULL,
    description text,
    blocks jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_content_template_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS s2s_access_log (
    id uuid DEFAULT uuidv7() CONSTRAINT s2s_access_log_id_not_null1 NOT NULL,
    client_ref uuid,
    client_name text,
    method text CONSTRAINT s2s_access_log_method_not_null1 NOT NULL,
    path text CONSTRAINT s2s_access_log_path_not_null1 NOT NULL,
    status_code smallint,
    response_time_ms integer,
    bytes_received integer,
    bytes_sent integer,
    correlation_id text,
    ip_address text,
    nonce text,
    error_code text,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT s2s_access_log_created_at_not_null1 NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT s2s_access_log_row_version_not_null NOT NULL
)
PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS docgen_render (
    id uuid DEFAULT uuidv7() NOT NULL,
    template_ref uuid NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    format text DEFAULT 'pdf'::text NOT NULL,
    object_key text,
    checksum text,
    size_bytes bigint,
    duration_ms bigint,
    error text,
    attached boolean DEFAULT false NOT NULL,
    attach_error text,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS fleet_action (
    id uuid DEFAULT uuidv7() NOT NULL,
    actor_ref uuid NOT NULL,
    deployment_ref uuid,
    rollout_ref uuid,
    action text NOT NULL,
    remote_method text,
    remote_path text,
    remote_status integer,
    outcome text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_fleet_action_outcome CHECK ((outcome = ANY (ARRAY['ok'::text, 'refused'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS fleet_deployment (
    id uuid DEFAULT uuidv7() NOT NULL,
    project_code text NOT NULL,
    label text NOT NULL,
    environment text DEFAULT 'prod'::text NOT NULL,
    ring text DEFAULT 'broad'::text NOT NULL,
    base_url text NOT NULL,
    s2s_client_id text,
    s2s_key_id text,
    secret_enc bytea,
    secret_last4 text,
    secret_rotated_at timestamp with time zone,
    maintenance_window text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_fleet_deployment_credential CHECK ((((s2s_client_id IS NULL) = (secret_enc IS NULL)) AND ((s2s_key_id IS NULL) = (secret_enc IS NULL)))),
    CONSTRAINT ck_fleet_deployment_environment CHECK ((environment = ANY (ARRAY['dev'::text, 'test'::text, 'prod'::text]))),
    CONSTRAINT ck_fleet_deployment_ring CHECK ((ring = ANY (ARRAY['canary'::text, 'early'::text, 'broad'::text])))
);

CREATE TABLE IF NOT EXISTS fleet_observation (
    deployment_ref uuid NOT NULL,
    application_version text,
    git_revision text,
    schema_version bigint,
    schema_dirty boolean,
    configuration_version text,
    ready boolean,
    open_items integer,
    last_report_id uuid,
    last_release_at timestamp with time zone,
    ledger_head jsonb,
    pending_approvals integer,
    error_code text,
    observed_at timestamp with time zone NOT NULL,
    notified_report_id uuid
);

CREATE TABLE IF NOT EXISTS fleet_rollout (
    id uuid DEFAULT uuidv7() NOT NULL,
    title text NOT NULL,
    changesets jsonb NOT NULL,
    plan jsonb NOT NULL,
    status text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_fleet_rollout_status CHECK ((status = ANY (ARRAY['planned'::text, 'in_progress'::text, 'completed'::text, 'halted'::text, 'cancelled'::text])))
);

CREATE TABLE IF NOT EXISTS fleet_target (
    id uuid DEFAULT uuidv7() NOT NULL,
    rollout_ref uuid NOT NULL,
    deployment_ref uuid NOT NULL,
    wave integer NOT NULL,
    status text NOT NULL,
    remote_apply_ids uuid[],
    remote_approval_id uuid,
    backup_ref text,
    plan_summary jsonb,
    error_code text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_fleet_target_status CHECK ((status = ANY (ARRAY['pending'::text, 'planned'::text, 'approval_pending'::text, 'applying'::text, 'applied'::text, 'failed'::text, 'skipped'::text])))
);

CREATE TABLE IF NOT EXISTS integration_credential (
    id uuid DEFAULT uuidv7() NOT NULL,
    system_ref uuid NOT NULL,
    secret_encrypted text NOT NULL,
    secret_last4 text,
    rotated_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_gap_topic (
    id uuid DEFAULT uuidv7() NOT NULL,
    normalized_phrase text NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    hit_count bigint DEFAULT 1 NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    addressed_page_ref uuid,
    addressed_item_ref uuid,
    CONSTRAINT knowledge_gap_topic_status_check CHECK ((status = ANY (ARRAY['open'::text, 'addressed'::text, 'dismissed'::text])))
);

CREATE TABLE IF NOT EXISTS metric_snapshot (
    id uuid DEFAULT uuidv7() NOT NULL,
    metric_ref uuid NOT NULL,
    period_start date NOT NULL,
    actual double precision,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    source_version text,
    status text NOT NULL,
    superseded_ref uuid,
    evaluated_by uuid,
    error_message text
)
PARTITION BY RANGE (computed_at);

CREATE TABLE IF NOT EXISTS migration_project (
    id uuid DEFAULT uuidv7() NOT NULL,
    name text NOT NULL,
    description text,
    source_kind text NOT NULL,
    source_ref text,
    target_entity text NOT NULL,
    mapping_ref uuid,
    status text DEFAULT 'draft'::text NOT NULL,
    owner uuid NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT migration_project_source_kind_check CHECK ((source_kind = ANY (ARRAY['csv'::text, 'json'::text, 'connector'::text]))),
    CONSTRAINT migration_project_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'active'::text, 'completed'::text, 'archived'::text])))
);

CREATE TABLE IF NOT EXISTS migration_run (
    id uuid DEFAULT uuidv7() NOT NULL,
    project_id uuid NOT NULL,
    staged_import_id uuid NOT NULL,
    created_by uuid NOT NULL,
    rollback_status text DEFAULT 'none'::text NOT NULL,
    rollback_error text,
    rolled_back_by uuid,
    rolled_back_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT migration_run_rollback_status_check CHECK ((rollback_status = ANY (ARRAY['none'::text, 'requested'::text, 'running'::text, 'completed'::text, 'refused'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS migration_run_item (
    id uuid DEFAULT uuidv7() NOT NULL,
    migration_run_id uuid NOT NULL,
    item_index integer NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    operation text NOT NULL,
    prior_row_version bigint,
    applied_row_version bigint NOT NULL,
    prior_data jsonb,
    rollback_status text DEFAULT 'pending'::text NOT NULL,
    rollback_error text,
    claimed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT migration_run_item_operation_check CHECK ((operation = ANY (ARRAY['create'::text, 'update'::text]))),
    CONSTRAINT migration_run_item_rollback_status_check CHECK ((rollback_status = ANY (ARRAY['pending'::text, 'running'::text, 'rolled_back'::text, 'refused'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS notification_dispatch (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    organization_ref uuid,
    is_global boolean DEFAULT false NOT NULL,
    recipient_user_ref uuid,
    template_key text,
    locale text DEFAULT 'en'::text NOT NULL,
    subject text,
    body_html text,
    body_text text NOT NULL,
    route text,
    channels jsonb DEFAULT '[]'::jsonb NOT NULL,
    channels_sent jsonb DEFAULT '[]'::jsonb NOT NULL,
    priority text DEFAULT 'normal'::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    dispatched_at timestamp with time zone,
    notification_inbox_ref uuid,
    escalate_after_minutes integer,
    escalate_channels jsonb,
    escalated_at timestamp with time zone,
    escalation_channels_sent jsonb DEFAULT '[]'::jsonb NOT NULL,
    channel_outcomes jsonb DEFAULT '{}'::jsonb NOT NULL,
    preference_category text
);

CREATE TABLE IF NOT EXISTS notification_inbox (
    id uuid CONSTRAINT notification_id_not_null NOT NULL,
    created_on timestamp with time zone,
    title character varying,
    message character varying,
    type integer,
    is_read boolean,
    related_entity_reference uuid,
    related_record uuid,
    route character varying,
    is_active boolean DEFAULT true,
    organization_ref uuid,
    created_at timestamp with time zone,
    created_by uuid,
    is_global boolean DEFAULT false CONSTRAINT notification_is_global_not_null NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_preference (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    user_ref uuid NOT NULL,
    category text NOT NULL,
    channel text NOT NULL,
    enabled boolean NOT NULL,
    CONSTRAINT notification_preference_category_bounded CHECK (((char_length(category) >= 1) AND (char_length(category) <= 100))),
    CONSTRAINT notification_preference_channel_known CHECK ((channel = ANY (ARRAY['in_app'::text, 'email'::text, 'sms'::text, 'push'::text, 'chat'::text])))
);

CREATE TABLE IF NOT EXISTS notification_recipient (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    dispatch_ref uuid NOT NULL,
    user_ref uuid NOT NULL,
    title text,
    message text NOT NULL,
    notif_type integer DEFAULT 0 NOT NULL,
    route text,
    read_at timestamp with time zone,
    audience_kind text NOT NULL,
    CONSTRAINT notification_recipient_audience_kind_check CHECK ((audience_kind = ANY (ARRAY['direct'::text, 'organization'::text, 'global'::text])))
)
PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS prediction (
    id uuid DEFAULT uuidv7() NOT NULL,
    model_ref uuid NOT NULL,
    regarding_entity character varying NOT NULL,
    regarding_id uuid NOT NULL,
    score double precision NOT NULL,
    label character varying NOT NULL,
    explanation jsonb,
    predicted_at timestamp with time zone DEFAULT now() NOT NULL,
    horizon_at timestamp with time zone NOT NULL,
    outcome_ref uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT prediction_score_chk CHECK (((score >= (0)::double precision) AND (score <= (1)::double precision)))
);

CREATE TABLE IF NOT EXISTS prediction_model (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    target character varying NOT NULL,
    entity character varying NOT NULL,
    features jsonb DEFAULT '[]'::jsonb NOT NULL,
    algorithm character varying DEFAULT 'logistic_regression'::character varying NOT NULL,
    trained_version integer DEFAULT 0 NOT NULL,
    metrics jsonb,
    model_artifact jsonb,
    status character varying DEFAULT 'training'::character varying NOT NULL,
    created_by uuid,
    organization_ref uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT prediction_model_status_chk CHECK (((status)::text = ANY ((ARRAY['training'::character varying, 'active'::character varying, 'failed_holdout'::character varying, 'retired'::character varying])::text[]))),
    CONSTRAINT prediction_model_target_chk CHECK ((((target)::text = ANY ((ARRAY['sla_breach'::character varying, 'capacity_shortfall'::character varying, 'anomaly'::character varying])::text[])) OR ((target)::text ~~ 'custom_metric:%'::text)))
);

CREATE TABLE IF NOT EXISTS process_case_def (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    source character varying NOT NULL,
    activity_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    resource_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    visibility_privilege character varying,
    is_active boolean DEFAULT true NOT NULL,
    cursor_last_ts timestamp with time zone,
    cursor_last_id uuid,
    last_extracted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_process_case_def_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT process_case_def_source_chk CHECK (((source)::text ~ '^(workflow|entity):.+'::text))
);

CREATE TABLE IF NOT EXISTS process_dfg_snapshot (
    id uuid DEFAULT uuidv7() NOT NULL,
    case_def_ref uuid NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    graph_json jsonb NOT NULL,
    variants_json jsonb NOT NULL,
    cycle_time_json jsonb NOT NULL,
    case_count integer DEFAULT 0 NOT NULL,
    event_count integer DEFAULT 0 NOT NULL
);

CREATE TABLE IF NOT EXISTS process_event (
    id uuid DEFAULT uuidv7() NOT NULL,
    case_def_ref uuid NOT NULL,
    case_id uuid NOT NULL,
    activity text NOT NULL,
    ts_start timestamp with time zone NOT NULL,
    ts_end timestamp with time zone,
    resource_ref uuid,
    variant_hash text,
    source_kind text NOT NULL,
    source_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT process_event_source_kind_chk CHECK ((source_kind = ANY (ARRAY['workflow_node_run'::text, 'audit_detail'::text])))
)
PARTITION BY RANGE (ts_start);

CREATE TABLE IF NOT EXISTS report_run (
    id uuid DEFAULT uuidv7() NOT NULL,
    report_ref uuid NOT NULL,
    schedule_ref uuid,
    source text DEFAULT 'manual'::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    format text NOT NULL,
    params jsonb DEFAULT '[]'::jsonb NOT NULL,
    object_key text,
    checksum text,
    row_count bigint,
    duration_ms bigint,
    error text,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS s2s_client (
    id uuid DEFAULT uuidv7() CONSTRAINT s2s_client_id_not_null NOT NULL,
    name text CONSTRAINT s2s_client_name_not_null NOT NULL,
    client_id text CONSTRAINT s2s_client_client_id_not_null NOT NULL,
    description text,
    status text DEFAULT 'active'::text CONSTRAINT s2s_client_status_not_null NOT NULL,
    service_user_ref uuid,
    rate_limit_rpm integer DEFAULT 1000 CONSTRAINT s2s_client_rate_limit_rpm_not_null NOT NULL,
    max_concurrent integer DEFAULT 10 CONSTRAINT s2s_client_max_concurrent_not_null NOT NULL,
    allowed_cidrs text[],
    max_payload_bytes bigint DEFAULT 10485760 CONSTRAINT s2s_client_max_payload_bytes_not_null NOT NULL,
    auto_disable_days integer DEFAULT 90 CONSTRAINT s2s_client_auto_disable_days_not_null NOT NULL,
    last_used_at timestamp with time zone,
    row_version bigint DEFAULT 0 CONSTRAINT s2s_client_row_version_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT s2s_client_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT s2s_client_updated_at_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT s2s_client_is_deleted_not_null NOT NULL,
    CONSTRAINT s2s_client_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'revoked'::text])))
);

CREATE TABLE IF NOT EXISTS s2s_client_key (
    id uuid DEFAULT uuidv7() CONSTRAINT s2s_client_key_id_not_null NOT NULL,
    client_ref uuid CONSTRAINT s2s_client_key_client_ref_not_null NOT NULL,
    key_slot text DEFAULT 'primary'::text CONSTRAINT s2s_client_key_key_slot_not_null NOT NULL,
    public_id text CONSTRAINT s2s_client_key_public_id_not_null NOT NULL,
    secret_encrypted text CONSTRAINT s2s_client_key_secret_encrypted_not_null NOT NULL,
    secret_last4 text,
    status text DEFAULT 'active'::text CONSTRAINT s2s_client_key_status_not_null NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    row_version bigint DEFAULT 0 CONSTRAINT s2s_client_key_row_version_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT s2s_client_key_created_at_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT s2s_client_key_is_deleted_not_null NOT NULL,
    CONSTRAINT s2s_client_key_slot_chk CHECK ((key_slot = ANY (ARRAY['primary'::text, 'secondary'::text]))),
    CONSTRAINT s2s_client_key_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'revoked'::text])))
);

CREATE TABLE IF NOT EXISTS s2s_permission (
    id uuid DEFAULT uuidv7() CONSTRAINT s2s_permission_id_not_null NOT NULL,
    client_ref uuid CONSTRAINT s2s_permission_client_ref_not_null NOT NULL,
    entity_name text CONSTRAINT s2s_permission_entity_name_not_null NOT NULL,
    can_read boolean DEFAULT false CONSTRAINT s2s_permission_can_read_not_null NOT NULL,
    can_create boolean DEFAULT false CONSTRAINT s2s_permission_can_create_not_null NOT NULL,
    can_update boolean DEFAULT false CONSTRAINT s2s_permission_can_update_not_null NOT NULL,
    can_delete boolean DEFAULT false CONSTRAINT s2s_permission_can_delete_not_null NOT NULL,
    can_export boolean DEFAULT false CONSTRAINT s2s_permission_can_export_not_null NOT NULL,
    can_bulk boolean DEFAULT false CONSTRAINT s2s_permission_can_bulk_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT s2s_permission_row_version_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT s2s_permission_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT s2s_permission_updated_at_not_null NOT NULL,
    is_deleted boolean DEFAULT false CONSTRAINT s2s_permission_is_deleted_not_null NOT NULL
);

CREATE TABLE IF NOT EXISTS webcrawl_page (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    target_ref uuid NOT NULL,
    url_path text NOT NULL,
    parent_path text,
    depth integer DEFAULT 0 NOT NULL,
    size_bytes integer,
    status text DEFAULT 'pending'::text NOT NULL,
    content text,
    is_selected boolean DEFAULT false NOT NULL,
    imported_data_item_ref uuid
);

CREATE TABLE IF NOT EXISTS webcrawl_target (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    url text NOT NULL,
    data_source_ref uuid,
    status text DEFAULT 'pending'::text NOT NULL,
    pages_found integer DEFAULT 0 NOT NULL,
    pages_imported integer DEFAULT 0 NOT NULL,
    last_error text,
    created_by uuid NOT NULL,
    last_crawled_at timestamp with time zone,
    max_depth smallint DEFAULT 6 NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_auth_policy (
    webportal_id uuid NOT NULL,
    signup_mode text DEFAULT 'invite_only'::text NOT NULL,
    signup_domains text[] DEFAULT '{}'::text[] NOT NULL,
    signup_role_ref uuid,
    oidc_providers text[] DEFAULT '{}'::text[] NOT NULL,
    terms_version text,
    privacy_version text,
    editable_profile_fields text[] DEFAULT '{}'::text[] NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    page_size_cap smallint DEFAULT 100 NOT NULL,
    allowed_cidrs text[] DEFAULT '{}'::text[] NOT NULL,
    records_rpm integer DEFAULT 6000 NOT NULL,
    username_min_len smallint DEFAULT 3 NOT NULL,
    username_max_len smallint DEFAULT 12 NOT NULL,
    username_blocked_words text[] DEFAULT '{}'::text[] NOT NULL,
    username_reserved text[] DEFAULT '{}'::text[] NOT NULL,
    trusted_server_login boolean DEFAULT false NOT NULL,
    CONSTRAINT webportal_auth_policy_page_size_cap CHECK (((page_size_cap >= 1) AND (page_size_cap <= 100))),
    CONSTRAINT webportal_auth_policy_records_rpm CHECK (((records_rpm >= 60) AND (records_rpm <= 100000))),
    CONSTRAINT webportal_auth_policy_signup_mode_check CHECK ((signup_mode = ANY (ARRAY['invite_only'::text, 'self_service'::text, 'domain_allowlist'::text]))),
    CONSTRAINT webportal_auth_policy_username_max_len_check CHECK (((username_max_len >= 1) AND (username_max_len <= 64))),
    CONSTRAINT webportal_auth_policy_username_min_len_check CHECK (((username_min_len >= 1) AND (username_min_len <= 64)))
);

CREATE TABLE IF NOT EXISTS webportal_consent (
    id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    webportal_user_id uuid NOT NULL,
    terms_version text,
    privacy_version text,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_credential (
    webportal_user_id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    password_hash text,
    password_changed_at timestamp with time zone,
    email_verified boolean DEFAULT false NOT NULL,
    auth_epoch integer DEFAULT 0 NOT NULL,
    failed_login_count integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    mfa_enabled boolean DEFAULT false NOT NULL,
    mfa_secret_enc text,
    mfa_pending_secret_enc text,
    mfa_last_step bigint,
    mfa_reenroll_required boolean DEFAULT false NOT NULL,
    login_email_lower text,
    login_username_lower text,
    trusted_failed_count integer DEFAULT 0 NOT NULL,
    trusted_retry_after timestamp with time zone
);

CREATE TABLE IF NOT EXISTS webportal_entity (
    webportal_id uuid NOT NULL,
    entity_logicalname text NOT NULL,
    portal_user_field text
);

CREATE TABLE IF NOT EXISTS webportal_erasure_request (
    id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    webportal_user_id uuid NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    handled_by uuid,
    handled_at timestamp with time zone,
    CONSTRAINT webportal_erasure_request_status_check CHECK ((status = ANY (ARRAY['open'::text, 'completed'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS webportal_grant (
    id uuid DEFAULT uuidv7() NOT NULL,
    role_id uuid NOT NULL,
    entity_logicalname text NOT NULL,
    can_read boolean DEFAULT false NOT NULL,
    can_create boolean DEFAULT false NOT NULL,
    can_update boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_grant_condition (
    id uuid DEFAULT uuidv7() NOT NULL,
    grant_id uuid NOT NULL,
    ordinal smallint NOT NULL,
    field_logicalname text NOT NULL,
    operator smallint NOT NULL,
    value jsonb,
    value_ref text,
    CONSTRAINT webportal_grant_condition_one_value CHECK (((value IS NULL) <> (value_ref IS NULL))),
    CONSTRAINT webportal_grant_condition_operator_check CHECK (((operator >= 0) AND (operator <= 6)))
);

CREATE TABLE IF NOT EXISTS webportal_grant_field (
    grant_id uuid NOT NULL,
    field_logicalname text NOT NULL,
    can_read boolean DEFAULT false NOT NULL,
    can_write boolean DEFAULT false NOT NULL,
    can_filter boolean DEFAULT false NOT NULL,
    allow_sensitive boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_identity (
    id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    webportal_user_id uuid NOT NULL,
    provider_key text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_mfa_recovery_code (
    id uuid NOT NULL,
    webportal_user_id uuid NOT NULL,
    code_hash text NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_refresh_token (
    id uuid NOT NULL,
    family_id uuid NOT NULL,
    webportal_user_id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    secret_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    family_expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    revoked_at timestamp with time zone
);

CREATE TABLE IF NOT EXISTS webportal_role (
    id uuid DEFAULT uuidv7() NOT NULL,
    webportal_id uuid NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_signup (
    id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    email_lower text NOT NULL,
    name text NOT NULL,
    password_hash text NOT NULL,
    terms_version text,
    privacy_version text,
    secret_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS webportal_token (
    id uuid NOT NULL,
    kind text NOT NULL,
    webportal_user_id uuid NOT NULL,
    webportal_id uuid NOT NULL,
    secret_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    email text,
    CONSTRAINT webportal_token_kind_check CHECK ((kind = ANY (ARRAY['invitation'::text, 'reset'::text, 'email_add'::text])))
);

CREATE TABLE IF NOT EXISTS webportal_user_role (
    webportal_user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_definition (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    logicalname text NOT NULL,
    name text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    organization_ref uuid,
    owner_layer text NOT NULL,
    CONSTRAINT ck_workflow_definition_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS workflow_definition_version (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    definition_id uuid NOT NULL,
    version_number integer NOT NULL,
    graph jsonb DEFAULT '{"edges": [], "nodes": []}'::jsonb NOT NULL,
    node_schema_hash text,
    status text DEFAULT 'draft'::text NOT NULL,
    published_at timestamp with time zone,
    published_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT core_workflow_definition_version_status_chk CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'deprecated'::text])))
);

CREATE TABLE IF NOT EXISTS workflow_instance (
    id uuid DEFAULT uuidv7() NOT NULL,
    definition_version_id uuid NOT NULL,
    trigger_node_id text,
    correlation_entity_id uuid,
    status text DEFAULT 'running'::text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    started_by uuid,
    context jsonb DEFAULT '{}'::jsonb NOT NULL,
    node_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    fired_side_effects jsonb DEFAULT '[]'::jsonb NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    trigger_event_id uuid,
    CONSTRAINT core_workflow_instance_status_chk CHECK ((status = ANY (ARRAY['running'::text, 'waiting'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])))
);

CREATE TABLE IF NOT EXISTS workflow_node_run (
    id uuid DEFAULT uuidv7() NOT NULL,
    instance_id uuid NOT NULL,
    node_id text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    output_hash text,
    attempt_count integer DEFAULT 0 NOT NULL,
    last_error text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT core_workflow_node_run_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'waiting'::text, 'succeeded'::text, 'failed'::text, 'skipped'::text])))
);

CREATE TABLE IF NOT EXISTS workflow_trigger_failure (
    event_id uuid NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    operation text NOT NULL,
    attempts integer DEFAULT 1 NOT NULL,
    last_error text NOT NULL,
    first_failed_at timestamp with time zone DEFAULT now() NOT NULL,
    last_failed_at timestamp with time zone DEFAULT now() NOT NULL,
    dead_lettered_at timestamp with time zone,
    CONSTRAINT workflow_trigger_failure_attempts_positive CHECK ((attempts > 0))
);

CREATE TABLE IF NOT EXISTS workflow_trigger_index (
    id uuid DEFAULT uuidv7() NOT NULL,
    definition_version_id uuid NOT NULL,
    node_id text NOT NULL,
    role text NOT NULL,
    instance_id uuid,
    node_run_id uuid,
    match_type text NOT NULL,
    entity_logicalname text,
    condition jsonb,
    resume_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT core_workflow_trigger_index_entry_no_instance_chk CHECK (((role = 'wait'::text) OR ((instance_id IS NULL) AND (node_run_id IS NULL)))),
    CONSTRAINT core_workflow_trigger_index_role_chk CHECK ((role = ANY (ARRAY['entry'::text, 'wait'::text])))
);

ALTER TABLE ONLY workflow_definition
    ADD CONSTRAINT core_workflow_definition_logicalname_unique UNIQUE (logicalname);

ALTER TABLE ONLY workflow_definition_version
    ADD CONSTRAINT core_workflow_definition_version_unique UNIQUE (definition_id, version_number);

ALTER TABLE ONLY workflow_node_run
    ADD CONSTRAINT core_workflow_node_run_instance_node_unique UNIQUE (instance_id, node_id);

ALTER TABLE ONLY fleet_deployment
    ADD CONSTRAINT uq_fleet_deployment_code_env UNIQUE (project_code, environment);

ALTER TABLE ONLY fleet_target
    ADD CONSTRAINT uq_fleet_target_rollout_deployment UNIQUE (rollout_ref, deployment_ref);

ALTER TABLE ONLY knowledge_gap_topic
    ADD CONSTRAINT uq_knowledge_gap_topic_phrase UNIQUE (normalized_phrase);

ALTER TABLE ONLY notification_preference
    ADD CONSTRAINT uq_notification_preference_user_category_channel UNIQUE (user_ref, category, channel);

ALTER TABLE ONLY webportal_grant_condition
    ADD CONSTRAINT webportal_grant_condition_ordinal UNIQUE (grant_id, ordinal);

ALTER TABLE ONLY webportal_grant
    ADD CONSTRAINT webportal_grant_unique UNIQUE (role_id, entity_logicalname);

ALTER TABLE ONLY webportal_identity
    ADD CONSTRAINT webportal_identity_subject_uq UNIQUE (webportal_id, issuer, subject);

ALTER TABLE ONLY webportal_role
    ADD CONSTRAINT webportal_role_name_unique UNIQUE (webportal_id, name);

ALTER TABLE ONLY ai_conversation_event
    ADD CONSTRAINT ai_conversation_event_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_conversation
    ADD CONSTRAINT ai_conversation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_message_feedback
    ADD CONSTRAINT ai_message_feedback_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_message
    ADD CONSTRAINT ai_message_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_provider_credential
    ADD CONSTRAINT ai_provider_credential_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_suggestion_outcome
    ADD CONSTRAINT ai_suggestion_outcome_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_tool_call
    ADD CONSTRAINT ai_tool_call_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_turn_cancel
    ADD CONSTRAINT ai_turn_cancel_pkey PRIMARY KEY (turn_id);

ALTER TABLE ONLY content_page
    ADD CONSTRAINT content_page_pkey PRIMARY KEY (id);

ALTER TABLE ONLY content_page_related
    ADD CONSTRAINT content_page_related_pkey PRIMARY KEY (page_id, related_page_id);

ALTER TABLE ONLY content_page_stats
    ADD CONSTRAINT content_page_stats_pkey PRIMARY KEY (page_ref);

ALTER TABLE ONLY content_page_view
    ADD CONSTRAINT content_page_view_pkey PRIMARY KEY (id);

ALTER TABLE ONLY content_page_vote
    ADD CONSTRAINT content_page_vote_pkey PRIMARY KEY (id);

ALTER TABLE ONLY content_space
    ADD CONSTRAINT content_space_pkey PRIMARY KEY (id);

ALTER TABLE ONLY content_space_template
    ADD CONSTRAINT content_space_template_pkey PRIMARY KEY (content_space_id, template_id);

ALTER TABLE ONLY content_template
    ADD CONSTRAINT content_template_pkey PRIMARY KEY (id);

ALTER TABLE ONLY automation_bulk_operation_item
    ADD CONSTRAINT bulk_operation_item_bulk_operation_id_item_index_key UNIQUE (bulk_operation_id, item_index);

ALTER TABLE ONLY automation_bulk_operation_item
    ADD CONSTRAINT bulk_operation_item_pkey PRIMARY KEY (id);

ALTER TABLE ONLY automation_bulk_operation
    ADD CONSTRAINT bulk_operation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY notification_inbox
    ADD CONSTRAINT notification_pkey PRIMARY KEY (id);

ALTER TABLE ONLY s2s_access_log
    ADD CONSTRAINT s2s_access_log_pkey PRIMARY KEY (id, created_at);

ALTER TABLE ONLY s2s_client_key
    ADD CONSTRAINT s2s_client_key_pkey PRIMARY KEY (id);

ALTER TABLE ONLY s2s_client
    ADD CONSTRAINT s2s_client_pkey PRIMARY KEY (id);

ALTER TABLE ONLY s2s_permission
    ADD CONSTRAINT s2s_permission_pkey PRIMARY KEY (id);

ALTER TABLE ONLY automation_staged_import_item
    ADD CONSTRAINT staged_import_item_pkey PRIMARY KEY (id);

ALTER TABLE ONLY automation_staged_import_item
    ADD CONSTRAINT staged_import_item_staged_import_id_item_index_key UNIQUE (staged_import_id, item_index);

ALTER TABLE ONLY automation_staged_import
    ADD CONSTRAINT staged_import_pkey PRIMARY KEY (id);

ALTER TABLE ONLY docgen_render
    ADD CONSTRAINT docgen_render_pkey PRIMARY KEY (id);

ALTER TABLE ONLY fleet_action
    ADD CONSTRAINT fleet_action_pkey PRIMARY KEY (id);

ALTER TABLE ONLY fleet_deployment
    ADD CONSTRAINT fleet_deployment_pkey PRIMARY KEY (id);

ALTER TABLE ONLY fleet_observation
    ADD CONSTRAINT fleet_observation_pkey PRIMARY KEY (deployment_ref);

ALTER TABLE ONLY fleet_rollout
    ADD CONSTRAINT fleet_rollout_pkey PRIMARY KEY (id);

ALTER TABLE ONLY fleet_target
    ADD CONSTRAINT fleet_target_pkey PRIMARY KEY (id);

ALTER TABLE ONLY integration_credential
    ADD CONSTRAINT integration_credential_pkey PRIMARY KEY (id);

ALTER TABLE ONLY knowledge_gap_topic
    ADD CONSTRAINT knowledge_gap_topic_pkey PRIMARY KEY (id);

ALTER TABLE ONLY metric_snapshot
    ADD CONSTRAINT metric_snapshot_pkey PRIMARY KEY (id, computed_at);

ALTER TABLE ONLY migration_project
    ADD CONSTRAINT migration_project_pkey PRIMARY KEY (id);

ALTER TABLE ONLY migration_run_item
    ADD CONSTRAINT migration_run_item_migration_run_id_item_index_key UNIQUE (migration_run_id, item_index);

ALTER TABLE ONLY migration_run_item
    ADD CONSTRAINT migration_run_item_pkey PRIMARY KEY (id);

ALTER TABLE ONLY migration_run
    ADD CONSTRAINT migration_run_pkey PRIMARY KEY (id);

ALTER TABLE ONLY migration_run
    ADD CONSTRAINT migration_run_staged_import_id_key UNIQUE (staged_import_id);

ALTER TABLE ONLY notification_dispatch
    ADD CONSTRAINT notification_dispatch_pkey PRIMARY KEY (id);

ALTER TABLE ONLY notification_preference
    ADD CONSTRAINT notification_preference_pkey PRIMARY KEY (id);

ALTER TABLE ONLY notification_recipient
    ADD CONSTRAINT notification_recipient_pkey PRIMARY KEY (id, created_at);

ALTER TABLE ONLY prediction_model
    ADD CONSTRAINT prediction_model_pkey PRIMARY KEY (id);

ALTER TABLE ONLY prediction
    ADD CONSTRAINT prediction_pkey PRIMARY KEY (id);

ALTER TABLE ONLY process_case_def
    ADD CONSTRAINT process_case_def_pkey PRIMARY KEY (id);

ALTER TABLE ONLY process_dfg_snapshot
    ADD CONSTRAINT process_dfg_snapshot_pkey PRIMARY KEY (id);

ALTER TABLE ONLY process_event
    ADD CONSTRAINT process_event_pkey PRIMARY KEY (id, ts_start);

ALTER TABLE ONLY report_run
    ADD CONSTRAINT report_run_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webcrawl_page
    ADD CONSTRAINT webcrawl_page_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webcrawl_page
    ADD CONSTRAINT webcrawl_page_target_ref_url_path_key UNIQUE (target_ref, url_path);

ALTER TABLE ONLY webcrawl_target
    ADD CONSTRAINT webcrawl_target_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_auth_policy
    ADD CONSTRAINT webportal_auth_policy_pkey PRIMARY KEY (webportal_id);

ALTER TABLE ONLY webportal_consent
    ADD CONSTRAINT webportal_consent_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_credential
    ADD CONSTRAINT webportal_credential_pkey PRIMARY KEY (webportal_user_id);

ALTER TABLE ONLY webportal_entity
    ADD CONSTRAINT webportal_entity_pkey PRIMARY KEY (webportal_id, entity_logicalname);

ALTER TABLE ONLY webportal_erasure_request
    ADD CONSTRAINT webportal_erasure_request_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_grant_condition
    ADD CONSTRAINT webportal_grant_condition_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_grant_field
    ADD CONSTRAINT webportal_grant_field_pkey PRIMARY KEY (grant_id, field_logicalname);

ALTER TABLE ONLY webportal_grant
    ADD CONSTRAINT webportal_grant_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_identity
    ADD CONSTRAINT webportal_identity_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_mfa_recovery_code
    ADD CONSTRAINT webportal_mfa_recovery_code_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_refresh_token
    ADD CONSTRAINT webportal_refresh_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_role
    ADD CONSTRAINT webportal_role_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_signup
    ADD CONSTRAINT webportal_signup_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_token
    ADD CONSTRAINT webportal_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY webportal_user_role
    ADD CONSTRAINT webportal_user_role_pkey PRIMARY KEY (webportal_user_id);

ALTER TABLE ONLY workflow_definition
    ADD CONSTRAINT workflow_definition_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_definition_version
    ADD CONSTRAINT workflow_definition_version_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_instance
    ADD CONSTRAINT workflow_instance_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_node_run
    ADD CONSTRAINT workflow_node_run_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_trigger_failure
    ADD CONSTRAINT workflow_trigger_failure_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY workflow_trigger_index
    ADD CONSTRAINT workflow_trigger_index_pkey PRIMARY KEY (id);

CREATE INDEX IF NOT EXISTS ai_conversation_owner_idx ON ai_conversation USING btree (owner_user_id, started_at DESC);

CREATE INDEX IF NOT EXISTS ai_conversation_session_idx ON ai_conversation USING btree (agent_session_id);

CREATE INDEX IF NOT EXISTS ai_message_feedback_conversation_idx ON ai_message_feedback USING btree (conversation_id, user_id);

CREATE INDEX IF NOT EXISTS ai_provider_credential_provider_ref_idx ON ai_provider_credential USING btree (provider_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS ai_tool_call_conversation_idx ON ai_tool_call USING btree (conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ai_tool_call_live_idx ON ai_tool_call USING btree (status, created_at) WHERE (status = ANY (ARRAY['proposed'::text, 'executing'::text]));

CREATE INDEX IF NOT EXISTS ai_turn_cancel_conversation_idx ON ai_turn_cancel USING btree (conversation_id);

CREATE INDEX IF NOT EXISTS core_workflow_definition_active_idx ON workflow_definition USING btree (is_active) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_workflow_definition_version_definition_idx ON workflow_definition_version USING btree (definition_id, version_number DESC);

CREATE INDEX IF NOT EXISTS core_workflow_definition_version_published_idx ON workflow_definition_version USING btree (definition_id) WHERE (status = 'published'::text);

CREATE INDEX IF NOT EXISTS core_workflow_instance_correlation_idx ON workflow_instance USING btree (correlation_entity_id) WHERE (correlation_entity_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS core_workflow_instance_definition_version_idx ON workflow_instance USING btree (definition_version_id);

CREATE INDEX IF NOT EXISTS core_workflow_instance_status_idx ON workflow_instance USING btree (status, started_at DESC);

CREATE INDEX IF NOT EXISTS core_workflow_node_run_output_hash_idx ON workflow_node_run USING btree (output_hash) WHERE (output_hash IS NOT NULL);

CREATE INDEX IF NOT EXISTS core_workflow_node_run_stuck_idx ON workflow_node_run USING btree (status, started_at) WHERE (status = ANY (ARRAY['running'::text, 'waiting'::text]));

CREATE INDEX IF NOT EXISTS core_workflow_trigger_index_definition_version_idx ON workflow_trigger_index USING btree (definition_version_id);

CREATE INDEX IF NOT EXISTS core_workflow_trigger_index_entry_idx ON workflow_trigger_index USING btree (entity_logicalname, match_type) WHERE (role = 'entry'::text);

CREATE INDEX IF NOT EXISTS core_workflow_trigger_index_wait_entity_idx ON workflow_trigger_index USING btree (entity_logicalname, match_type) WHERE (role = 'wait'::text);

CREATE INDEX IF NOT EXISTS core_workflow_trigger_index_wait_schedule_idx ON workflow_trigger_index USING btree (resume_at) WHERE ((role = 'wait'::text) AND (match_type = 'schedule'::text));

CREATE INDEX IF NOT EXISTS idx_automation_bulk_operation_created_by ON automation_bulk_operation USING btree (created_by, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_automation_bulk_operation_item_status ON automation_bulk_operation_item USING btree (bulk_operation_id, status, item_index);

CREATE INDEX IF NOT EXISTS idx_automation_staged_import_entity_status ON automation_staged_import USING btree (entity_logicalname, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_automation_staged_import_item_status ON automation_staged_import_item USING btree (staged_import_id, status, item_index);

CREATE INDEX IF NOT EXISTS idx_fleet_action_deployment ON fleet_action USING btree (deployment_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_fleet_action_rollout ON fleet_action USING btree (rollout_ref, created_at DESC) WHERE (rollout_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_fleet_target_deployment ON fleet_target USING btree (deployment_ref);

CREATE INDEX IF NOT EXISTS idx_knowledge_gap_topic_open ON knowledge_gap_topic USING btree (last_seen_at DESC) WHERE (status = 'open'::text);

CREATE INDEX IF NOT EXISTS idx_metric_snapshot_metric_period ON metric_snapshot USING btree (metric_ref, period_start, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_migration_project_target_entity ON migration_project USING btree (target_entity) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_migration_run_item_status ON migration_run_item USING btree (migration_run_id, rollback_status);

CREATE INDEX IF NOT EXISTS idx_migration_run_project ON migration_run USING btree (project_id, created_at DESC) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_notification_inbox_org_global_created ON notification_inbox USING btree (organization_ref, is_global, created_on DESC);

CREATE INDEX IF NOT EXISTS idx_notification_preference_muted ON notification_preference USING btree (category, channel, user_ref) WHERE ((enabled = false) AND (is_deleted = false));

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_parent ON content_page USING btree (parent_page_id) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_publish_at ON content_page USING btree (publish_at) WHERE ((is_deleted = false) AND (status = 'draft'::text) AND (publish_at IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_published_path ON content_page USING btree (url_path) WHERE ((is_deleted = false) AND (status = 'published'::text));

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_review_by ON content_page USING btree (review_by) WHERE ((is_deleted = false) AND (review_by IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_space ON content_page USING btree (content_space_id) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_unpublish_at ON content_page USING btree (unpublish_at) WHERE ((is_deleted = false) AND (status = 'published'::text) AND (unpublish_at IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_view_page_time ON content_page_view USING btree (page_ref, viewed_at);

CREATE INDEX IF NOT EXISTS idx_xrm_content_page_vote_page_time ON content_page_vote USING btree (page_ref, voted_at);

CREATE INDEX IF NOT EXISTS idx_xrm_docgen_render_record ON docgen_render USING btree (entity_logicalname, record_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_xrm_docgen_render_requested_by ON docgen_render USING btree (requested_by, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_xrm_docgen_render_template_ref ON docgen_render USING btree (template_ref, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_xrm_notification_dispatch_escalation ON notification_dispatch USING btree (dispatched_at) WHERE ((is_deleted = false) AND (status = 'sent'::text) AND (escalated_at IS NULL));

CREATE INDEX IF NOT EXISTS idx_xrm_notification_dispatch_pending ON notification_dispatch USING btree (created_at) WHERE ((is_deleted = false) AND (status = ANY (ARRAY['pending'::text, 'processing'::text])));

CREATE INDEX IF NOT EXISTS idx_xrm_notification_recipient_user_feed ON notification_recipient USING btree (user_ref, created_at DESC) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_report_run_report_ref ON report_run USING btree (report_ref, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_xrm_report_run_requested_by ON report_run USING btree (requested_by, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_xrm_report_run_schedule_ref ON report_run USING btree (schedule_ref) WHERE (schedule_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_xrm_webcrawl_page_target ON webcrawl_page USING btree (target_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_webcrawl_target_list ON webcrawl_target USING btree (created_at DESC) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS integration_credential_system_ref_idx ON integration_credential USING btree (system_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS s2s_access_log_client_created_idx ON s2s_access_log USING btree (client_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS s2s_access_log_correlation_id_idx ON s2s_access_log USING btree (correlation_id);

CREATE INDEX IF NOT EXISTS s2s_access_log_created_at_idx ON s2s_access_log USING btree (created_at DESC);

CREATE INDEX IF NOT EXISTS s2s_client_client_id_idx ON s2s_client USING btree (client_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS s2s_client_id_unique ON s2s_client USING btree (client_id) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS s2s_client_key_client_ref_idx ON s2s_client_key USING btree (client_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS s2s_client_key_public_id_idx ON s2s_client_key USING btree (public_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS s2s_client_key_public_id_unique ON s2s_client_key USING btree (public_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS s2s_client_key_slot_unique ON s2s_client_key USING btree (client_ref, key_slot) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS s2s_client_status_idx ON s2s_client USING btree (status) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS s2s_permission_client_ref_idx ON s2s_permission USING btree (client_ref) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS s2s_permission_unique ON s2s_permission USING btree (client_ref, entity_name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_conversation_event_ordinal ON ai_conversation_event USING btree (conversation_id, ordinal);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_message_conversation_ordinal ON ai_message USING btree (conversation_id, ordinal);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_message_feedback_message_user ON ai_message_feedback USING btree (message_id, user_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_tool_call_conversation_call ON ai_tool_call USING btree (conversation_id, tool_call_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_migration_project_name ON migration_project USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS uq_xrm_content_page_url_path ON content_page USING btree (url_path) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS uq_xrm_content_space_name ON content_space USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS uq_xrm_content_template_name ON content_template USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS uq_xrm_notification_recipient_dispatch_user ON notification_recipient USING btree (dispatch_ref, user_ref, created_at);

CREATE INDEX IF NOT EXISTS webportal_consent_user_idx ON webportal_consent USING btree (webportal_user_id, accepted_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS webportal_credential_login_email_uq ON webportal_credential USING btree (webportal_id, login_email_lower) WHERE (login_email_lower IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS webportal_credential_login_username_uq ON webportal_credential USING btree (webportal_id, login_username_lower) WHERE (login_username_lower IS NOT NULL);

CREATE INDEX IF NOT EXISTS webportal_credential_portal_idx ON webportal_credential USING btree (webportal_id);

CREATE UNIQUE INDEX IF NOT EXISTS webportal_erasure_request_open_uq ON webportal_erasure_request USING btree (webportal_user_id) WHERE (status = 'open'::text);

CREATE INDEX IF NOT EXISTS webportal_identity_user_idx ON webportal_identity USING btree (webportal_user_id);

CREATE INDEX IF NOT EXISTS webportal_mfa_recovery_code_user_idx ON webportal_mfa_recovery_code USING btree (webportal_user_id) WHERE (used_at IS NULL);

CREATE INDEX IF NOT EXISTS webportal_refresh_family_idx ON webportal_refresh_token USING btree (family_id);

CREATE INDEX IF NOT EXISTS webportal_refresh_user_idx ON webportal_refresh_token USING btree (webportal_user_id);

CREATE INDEX IF NOT EXISTS webportal_signup_pending_idx ON webportal_signup USING btree (webportal_id, email_lower) WHERE (used_at IS NULL);

CREATE INDEX IF NOT EXISTS webportal_token_user_idx ON webportal_token USING btree (webportal_user_id, kind);

CREATE INDEX IF NOT EXISTS webportal_user_role_role_idx ON webportal_user_role USING btree (role_id);

CREATE UNIQUE INDEX IF NOT EXISTS workflow_instance_trigger_event_uidx ON workflow_instance USING btree (definition_version_id, trigger_node_id, trigger_event_id) WHERE (trigger_event_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS workflow_trigger_failure_dead_idx ON workflow_trigger_failure USING btree (dead_lettered_at DESC) WHERE (dead_lettered_at IS NOT NULL);

CREATE INDEX IF NOT EXISTS ai_suggestion_outcome_model_action_idx ON ai_suggestion_outcome USING btree (model_id, action_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ai_suggestion_outcome_pending_idx ON ai_suggestion_outcome USING btree (created_at) WHERE (outcome = 'pending'::text);

CREATE INDEX IF NOT EXISTS prediction_model_active_idx ON prediction_model USING btree (entity, target) WHERE ((is_deleted = false) AND ((status)::text = 'active'::text));

CREATE INDEX IF NOT EXISTS prediction_model_idx ON prediction USING btree (model_ref, predicted_at DESC) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS prediction_model_name_idx ON prediction_model USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS prediction_pending_horizon_idx ON prediction USING btree (horizon_at) WHERE ((is_deleted = false) AND (outcome_ref IS NULL));

CREATE INDEX IF NOT EXISTS prediction_regarding_idx ON prediction USING btree (regarding_entity, regarding_id, predicted_at DESC) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS process_case_def_active_idx ON process_case_def USING btree (is_active) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS process_case_def_name_idx ON process_case_def USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS process_dfg_snapshot_case_def_idx ON process_dfg_snapshot USING btree (case_def_ref, period_start DESC, computed_at DESC);

CREATE INDEX IF NOT EXISTS process_event_case_idx ON process_event USING btree (case_def_ref, case_id, ts_start);

CREATE UNIQUE INDEX IF NOT EXISTS process_event_source_idx ON process_event USING btree (case_def_ref, source_kind, source_ref, ts_start);

ALTER TABLE ONLY ai_conversation
    ADD CONSTRAINT ai_conversation_agent_session_id_fkey FOREIGN KEY (agent_session_id) REFERENCES agent_session(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai_conversation_event
    ADD CONSTRAINT ai_conversation_event_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES ai_conversation(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai_message
    ADD CONSTRAINT ai_message_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES ai_conversation(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai_message_feedback
    ADD CONSTRAINT ai_message_feedback_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES ai_conversation(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai_message_feedback
    ADD CONSTRAINT ai_message_feedback_message_id_fkey FOREIGN KEY (message_id) REFERENCES ai_message(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai_tool_call
    ADD CONSTRAINT ai_tool_call_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES ai_conversation(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai_tool_call
    ADD CONSTRAINT ai_tool_call_message_id_fkey FOREIGN KEY (message_id) REFERENCES ai_message(id) ON DELETE SET NULL;

ALTER TABLE ONLY ai_turn_cancel
    ADD CONSTRAINT ai_turn_cancel_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES ai_conversation(id) ON DELETE CASCADE;

ALTER TABLE ONLY automation_staged_import
    ADD CONSTRAINT automation_staged_import_mapping_ref_fkey FOREIGN KEY (mapping_ref) REFERENCES data_mapping(id);

ALTER TABLE ONLY automation_staged_import
    ADD CONSTRAINT automation_staged_import_migration_run_id_fkey FOREIGN KEY (migration_run_id) REFERENCES migration_run(id);

ALTER TABLE ONLY content_page
    ADD CONSTRAINT content_page_content_space_id_fkey FOREIGN KEY (content_space_id) REFERENCES content_space(id);

ALTER TABLE ONLY content_page
    ADD CONSTRAINT content_page_parent_page_id_fkey FOREIGN KEY (parent_page_id) REFERENCES content_page(id);

ALTER TABLE ONLY content_page_related
    ADD CONSTRAINT content_page_related_page_id_fkey FOREIGN KEY (page_id) REFERENCES content_page(id);

ALTER TABLE ONLY content_page_related
    ADD CONSTRAINT content_page_related_related_page_id_fkey FOREIGN KEY (related_page_id) REFERENCES content_page(id);

ALTER TABLE ONLY content_page_stats
    ADD CONSTRAINT content_page_stats_page_ref_fkey FOREIGN KEY (page_ref) REFERENCES content_page(id) ON DELETE CASCADE;

ALTER TABLE ONLY content_page
    ADD CONSTRAINT content_page_template_id_fkey FOREIGN KEY (template_id) REFERENCES content_template(id) ON DELETE SET NULL;

ALTER TABLE ONLY content_page_view
    ADD CONSTRAINT content_page_view_page_ref_fkey FOREIGN KEY (page_ref) REFERENCES content_page(id) ON DELETE CASCADE;

ALTER TABLE ONLY content_page_vote
    ADD CONSTRAINT content_page_vote_page_ref_fkey FOREIGN KEY (page_ref) REFERENCES content_page(id) ON DELETE CASCADE;

ALTER TABLE ONLY content_space_template
    ADD CONSTRAINT content_space_template_content_space_id_fkey FOREIGN KEY (content_space_id) REFERENCES content_space(id);

ALTER TABLE ONLY content_space_template
    ADD CONSTRAINT content_space_template_template_id_fkey FOREIGN KEY (template_id) REFERENCES content_template(id);

ALTER TABLE ONLY automation_bulk_operation_item
    ADD CONSTRAINT bulk_operation_item_bulk_operation_id_fkey FOREIGN KEY (bulk_operation_id) REFERENCES automation_bulk_operation(id);

ALTER TABLE s2s_access_log
    ADD CONSTRAINT s2s_access_log_client_ref_fkey1 FOREIGN KEY (client_ref) REFERENCES s2s_client(id);

ALTER TABLE ONLY s2s_client_key
    ADD CONSTRAINT s2s_client_key_client_ref_fkey FOREIGN KEY (client_ref) REFERENCES s2s_client(id) ON DELETE CASCADE;

ALTER TABLE ONLY s2s_client
    ADD CONSTRAINT s2s_client_service_user_ref_fkey FOREIGN KEY (service_user_ref) REFERENCES user_account(id);

ALTER TABLE ONLY s2s_permission
    ADD CONSTRAINT s2s_permission_client_ref_fkey FOREIGN KEY (client_ref) REFERENCES s2s_client(id) ON DELETE CASCADE;

ALTER TABLE ONLY automation_staged_import_item
    ADD CONSTRAINT staged_import_item_staged_import_id_fkey FOREIGN KEY (staged_import_id) REFERENCES automation_staged_import(id);

ALTER TABLE ONLY fleet_action
    ADD CONSTRAINT fleet_action_deployment_ref_fkey FOREIGN KEY (deployment_ref) REFERENCES fleet_deployment(id);

ALTER TABLE ONLY fleet_action
    ADD CONSTRAINT fleet_action_rollout_ref_fkey FOREIGN KEY (rollout_ref) REFERENCES fleet_rollout(id);

ALTER TABLE ONLY fleet_observation
    ADD CONSTRAINT fleet_observation_deployment_ref_fkey FOREIGN KEY (deployment_ref) REFERENCES fleet_deployment(id);

ALTER TABLE ONLY fleet_target
    ADD CONSTRAINT fleet_target_deployment_ref_fkey FOREIGN KEY (deployment_ref) REFERENCES fleet_deployment(id);

ALTER TABLE ONLY fleet_target
    ADD CONSTRAINT fleet_target_rollout_ref_fkey FOREIGN KEY (rollout_ref) REFERENCES fleet_rollout(id);

ALTER TABLE ONLY knowledge_gap_topic
    ADD CONSTRAINT knowledge_gap_topic_addressed_page_ref_fkey FOREIGN KEY (addressed_page_ref) REFERENCES content_page(id);

ALTER TABLE ONLY migration_project
    ADD CONSTRAINT migration_project_mapping_ref_fkey FOREIGN KEY (mapping_ref) REFERENCES data_mapping(id);

ALTER TABLE ONLY migration_run_item
    ADD CONSTRAINT migration_run_item_migration_run_id_fkey FOREIGN KEY (migration_run_id) REFERENCES migration_run(id);

ALTER TABLE ONLY migration_run
    ADD CONSTRAINT migration_run_project_id_fkey FOREIGN KEY (project_id) REFERENCES migration_project(id);

ALTER TABLE ONLY migration_run
    ADD CONSTRAINT migration_run_staged_import_id_fkey FOREIGN KEY (staged_import_id) REFERENCES automation_staged_import(id);

ALTER TABLE ONLY notification_preference
    ADD CONSTRAINT notification_preference_user_ref_fkey FOREIGN KEY (user_ref) REFERENCES user_account(id);

ALTER TABLE notification_recipient
    ADD CONSTRAINT notification_recipient_dispatch_ref_fkey FOREIGN KEY (dispatch_ref) REFERENCES notification_dispatch(id);

ALTER TABLE notification_recipient
    ADD CONSTRAINT notification_recipient_user_ref_fkey FOREIGN KEY (user_ref) REFERENCES user_account(id);

ALTER TABLE ONLY prediction
    ADD CONSTRAINT prediction_model_ref_fkey FOREIGN KEY (model_ref) REFERENCES prediction_model(id);

ALTER TABLE ONLY webcrawl_page
    ADD CONSTRAINT webcrawl_page_target_ref_fkey FOREIGN KEY (target_ref) REFERENCES webcrawl_target(id) ON DELETE CASCADE;

ALTER TABLE ONLY webportal_grant_condition
    ADD CONSTRAINT webportal_grant_condition_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES webportal_grant(id) ON DELETE CASCADE;

ALTER TABLE ONLY webportal_grant_field
    ADD CONSTRAINT webportal_grant_field_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES webportal_grant(id) ON DELETE CASCADE;

ALTER TABLE ONLY webportal_grant
    ADD CONSTRAINT webportal_grant_role_id_fkey FOREIGN KEY (role_id) REFERENCES webportal_role(id) ON DELETE CASCADE;

ALTER TABLE ONLY webportal_user_role
    ADD CONSTRAINT webportal_user_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES webportal_role(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_definition
    ADD CONSTRAINT workflow_definition_created_by_fkey FOREIGN KEY (created_by) REFERENCES user_account(id);

ALTER TABLE ONLY workflow_definition_version
    ADD CONSTRAINT workflow_definition_version_definition_id_fkey FOREIGN KEY (definition_id) REFERENCES workflow_definition(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_definition_version
    ADD CONSTRAINT workflow_definition_version_published_by_fkey FOREIGN KEY (published_by) REFERENCES user_account(id);

ALTER TABLE ONLY workflow_instance
    ADD CONSTRAINT workflow_instance_definition_version_id_fkey FOREIGN KEY (definition_version_id) REFERENCES workflow_definition_version(id);

ALTER TABLE ONLY workflow_instance
    ADD CONSTRAINT workflow_instance_started_by_fkey FOREIGN KEY (started_by) REFERENCES user_account(id);

ALTER TABLE ONLY workflow_node_run
    ADD CONSTRAINT workflow_node_run_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES workflow_instance(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_trigger_index
    ADD CONSTRAINT workflow_trigger_index_definition_version_id_fkey FOREIGN KEY (definition_version_id) REFERENCES workflow_definition_version(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_trigger_index
    ADD CONSTRAINT workflow_trigger_index_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES workflow_instance(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_trigger_index
    ADD CONSTRAINT workflow_trigger_index_node_run_id_fkey FOREIGN KEY (node_run_id) REFERENCES workflow_node_run(id) ON DELETE CASCADE;

-- 0006 left this out because portal roles live here.
ALTER TABLE ONLY rule_role
    ADD CONSTRAINT rule_role_portal_role_ref_fkey FOREIGN KEY (portal_role_ref) REFERENCES webportal_role(id) ON DELETE CASCADE;

-- Monthly partitions for a fresh database, relative to the day it is
-- installed: the historical bucket and the current month plus two ahead,
-- named `{table}_p{YYYY_MM}` like the ones partition maintenance creates.
DO $$
DECLARE
    parent TEXT;
    month_start TIMESTAMPTZ := date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    i INTEGER;
    part_from TIMESTAMPTZ;
BEGIN
    FOREACH parent IN ARRAY ARRAY['s2s_access_log', 'metric_snapshot', 'notification_recipient', 'process_event'] LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (MINVALUE) TO (%L)',
            parent || '_pre_partition', parent, month_start);
        FOR i IN 0..2 LOOP
            part_from := month_start + make_interval(months => i);
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                parent || '_p' || to_char(part_from AT TIME ZONE 'UTC', 'YYYY_MM'), parent,
                part_from, part_from + make_interval(months => 1));
        END LOOP;
    END LOOP;
END
$$;
