-- The engine's baseline schema: metadata (entities, attributes,
-- relationships, views, labels, references, change log), changesets and
-- releases, settings, rules, state models, calendars, the change feed,
-- security (roles, teams, positions, organizations, privileges, sharing,
-- field security), records' supporting tables (archives, baselines, bulk and
-- import operations, data quality, search index) and the sidebar.
--
-- Generated from v1's final schema (all 285 v1 migrations applied to an empty
-- PostgreSQL 18, then pg_dump --schema-only), renamed by V2-D483: `xrm_` and a
-- leading `core_` dropped, `xrm_core_systemuser` is `user_account`, and the
-- entity system columns are `created_at`/`created_by`/`modified_at`/
-- `modified_by`. Tables that moved earlier (approvals, API keys, federated
-- identities) are in 0003 and 0005; v1's licence tables are gone (V2-D473).
--
-- Entity record tables are not here: the record engine provisions them at
-- runtime from metadata.

-- The user entity is attome-auth's `user_account` (V2-D483): the profile
-- columns v1 kept on its user entity.
ALTER TABLE user_account
    ADD COLUMN IF NOT EXISTS auth_type        INTEGER,
    ADD COLUMN IF NOT EXISTS organization_ref UUID,
    ADD COLUMN IF NOT EXISTS language         INTEGER,
    ADD COLUMN IF NOT EXISTS max_page_size    INTEGER DEFAULT 25,
    ADD COLUMN IF NOT EXISTS currency         INTEGER,
    ADD COLUMN IF NOT EXISTS theme            TEXT DEFAULT 'system';

-- pg_trgm backs the fuzzy-match indexes; vector (pgvector) backs the
-- embedding columns of search and knowledge.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS vector;

-- Helper functions.

CREATE OR REPLACE FUNCTION normalize_ar(input text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$
    -- Read inside-out. The order is load-bearing; each step says why.
    SELECT btrim(
      -- 5. Collapse runs of whitespace, LAST — removing a tatweel or a harakat
      --    between two words can leave a doubled space behind, so this has to
      --    run after every removal below it.
      regexp_replace(
        -- 4b. Fold the Unicode spaces `\s` does NOT cover, to ASCII space.
        --
        --     **A real divergence, not a hypothetical one.** PostgreSQL's `\s`
        --     is `[[:space:]]`, ASCII-only under the usual ctype — it does not
        --     match U+00A0, the non-breaking space that arrives with text
        --     pasted from Word, a PDF, or a web page. Rust's
        --     `split_whitespace()` follows the Unicode White_Space property and
        --     does match it. So a name containing a non-breaking space
        --     normalized to two different strings on the two sides: the index
        --     would hold one, the query would produce the other, and NOTHING
        --     would error. `arabic_parity.rs` caught this on its first run,
        --     which is the entire argument for that test existing.
        --
        --     19 codepoints, 19 spaces — Unicode White_Space minus the ASCII
        --     range `\s` already handles.
        translate(
          -- 4a. Lowercase, for the Latin half. Arabic is unicameral, so this is
          --     a no-op there and the whole string can be lowered without
          --     segmenting it first.
          lower(
            translate(
              -- 1. Drop diacritics and tatweel — they carry no lexical meaning.
              --    The harakat block is contiguous by design; enumerating
              --    codepoints instead of using a range invites a missed one,
              --    which then breaks matching only for words containing it.
              regexp_replace(input, '[ً-ٰٟۖ-ۭـ]', '', 'g'),
              -- 2 & 3. Letter folds and digit folds, in one pass.
              --
              -- Letters: alef with any hamza/madda plus the Quranic wasla ->
              -- bare alef; alef maksura -> ya; taa marbuta -> haa; hamza
              -- carriers -> bare hamza. Each is a pair native typists
              -- interchange in practice, not a linguistic equivalence — folding
              -- them is what makes احمد find أحمد, the highest-value fold there
              -- is, because names are what people search for and names are
              -- exactly where the hamza gets dropped.
              --
              -- Digits: both the Arabic-Indic and Eastern Arabic-Indic ranges,
              -- because both are in live use across the GCC and an invoice
              -- number typed ١٢٣ must find a record storing 123.
              'آأإٱىةؤئ٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹',
              'اااايهءء01234567890123456789'
            )
          ),
          E'                 　',
          '                   '
        ),
        '\s+',
        ' ',
        'g'
      )
    );
$$;

CREATE OR REPLACE FUNCTION role_sync_lifecycle_flags() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.is_active := NOT NEW.is_deleted;
        RETURN NEW;
    END IF;

    IF NEW.is_deleted IS DISTINCT FROM OLD.is_deleted THEN
        NEW.is_active := NOT NEW.is_deleted;
    ELSIF NEW.is_active IS DISTINCT FROM OLD.is_active THEN
        NEW.is_deleted := NOT NEW.is_active;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION try_bool(v text, true_values text[], false_values text[]) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    t TEXT;
BEGIN
    IF v IS NULL OR btrim(v) = '' THEN
        RETURN NULL;
    END IF;
    t := lower(btrim(v));
    IF true_values IS NULL AND false_values IS NULL THEN
        RETURN t::boolean;
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(true_values) x WHERE lower(btrim(x)) = t) THEN
        RETURN true;
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(false_values) x WHERE lower(btrim(x)) = t) THEN
        RETURN false;
    END IF;
    RETURN NULL;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION try_numeric(v text) RETURNS numeric
    LANGUAGE plpgsql IMMUTABLE
    AS $$
BEGIN
    IF v IS NULL OR btrim(v) = '' THEN
        RETURN NULL;
    END IF;
    RETURN btrim(v)::numeric;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION try_timestamptz(v text, fmt text) RETURNS timestamp with time zone
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    IF v IS NULL OR btrim(v) = '' THEN
        RETURN NULL;
    END IF;
    CASE coalesce(fmt, 'iso8601')
        WHEN 'iso8601' THEN RETURN btrim(v)::timestamptz;
        WHEN 'dd/mm/yyyy' THEN RETURN to_timestamp(btrim(v), 'DD/MM/YYYY');
        WHEN 'mm/dd/yyyy' THEN RETURN to_timestamp(btrim(v), 'MM/DD/YYYY');
        WHEN 'dd.mm.yyyy' THEN RETURN to_timestamp(btrim(v), 'DD.MM.YYYY');
        ELSE RETURN NULL;
    END CASE;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

-- Tables, constraints, indexes and triggers.

CREATE SEQUENCE IF NOT EXISTS metadata_change_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE SEQUENCE IF NOT EXISTS metadata_label_change_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE SEQUENCE IF NOT EXISTS setting_change_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE IF NOT EXISTS ai_runtime_switch (
    surface text NOT NULL,
    enabled boolean NOT NULL,
    reason text,
    changed_by uuid NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT ai_runtime_switch_reason_bounded CHECK (((reason IS NULL) OR (char_length(reason) <= 500))),
    CONSTRAINT ai_runtime_switch_surface_known CHECK ((surface = ANY (ARRAY['all'::text, 'fields'::text, 'chat'::text, 'semantic_search'::text, 'workflow_nodes'::text, 'webchat'::text])))
);

CREATE TABLE IF NOT EXISTS audit_retention_action (
    id uuid DEFAULT uuidv7() NOT NULL,
    action_type text NOT NULL,
    target text NOT NULL,
    status text DEFAULT 'proposed'::text NOT NULL,
    proposed_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_by uuid,
    approved_at timestamp with time zone,
    executed_at timestamp with time zone,
    failure_reason text,
    evidence_ref text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT audit_retention_action_action_type_check CHECK ((action_type = ANY (ARRAY['partition_archive'::text, 'entity_purge'::text, 'archive'::text]))),
    CONSTRAINT audit_retention_action_status_check CHECK ((status = ANY (ARRAY['proposed'::text, 'approved'::text, 'executing'::text, 'completed'::text, 'failed'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS audit_signing_key (
    id uuid DEFAULT uuidv7() CONSTRAINT audit_signing_key_id_not_null NOT NULL,
    key_id text CONSTRAINT audit_signing_key_key_id_not_null NOT NULL,
    public_key text CONSTRAINT audit_signing_key_public_key_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT audit_signing_key_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT audit_signing_key_updated_at_not_null NOT NULL,
    row_version bigint DEFAULT 0 CONSTRAINT audit_signing_key_row_version_not_null NOT NULL,
    retired_at timestamp with time zone
);

CREATE TABLE IF NOT EXISTS access_review (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    scope text NOT NULL,
    scope_role_ref uuid,
    scope_team_ref uuid,
    scope_entity_ref uuid,
    due_date timestamp with time zone NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT access_review_scope_check CHECK ((scope = ANY (ARRAY['role'::text, 'team'::text, 'entity_share'::text]))),
    CONSTRAINT access_review_status_check CHECK ((status = ANY (ARRAY['active'::text, 'completed'::text, 'cancelled'::text])))
);

CREATE TABLE IF NOT EXISTS access_review_item (
    id uuid DEFAULT uuidv7() NOT NULL,
    review_ref uuid NOT NULL,
    subject_user_ref uuid NOT NULL,
    grant_ref uuid NOT NULL,
    reviewer_user_ref uuid,
    approval_request_ref uuid,
    decision text,
    decided_by uuid,
    decided_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT access_review_item_decision_check CHECK ((decision = ANY (ARRAY['keep'::text, 'revoke'::text])))
);

CREATE TABLE IF NOT EXISTS action_invocation (
    id uuid DEFAULT uuidv7() NOT NULL,
    agent_session_id uuid,
    tool_call_id text,
    action_id text NOT NULL,
    initiator smallint DEFAULT 0 NOT NULL,
    acting_user_id uuid NOT NULL,
    outcome text NOT NULL,
    result jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_invocation_agent_needs_session CHECK (((initiator = 0) OR (agent_session_id IS NOT NULL))),
    CONSTRAINT action_invocation_initiator_range CHECK (((initiator >= 0) AND (initiator <= 1)))
);

CREATE TABLE IF NOT EXISTS agent_session (
    id uuid DEFAULT uuidv7() NOT NULL,
    owner_user_id uuid NOT NULL,
    risk_ceiling smallint DEFAULT 0 NOT NULL,
    allowed_action_ids text[],
    surface text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    ended_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_by uuid,
    revoked_reason text,
    agent_definition_ref uuid,
    paused_at timestamp with time zone,
    paused_by uuid,
    paused_reason text,
    tainted boolean DEFAULT false NOT NULL,
    integration_system_id uuid,
    handed_off_at timestamp with time zone,
    work_request_ref uuid,
    policy_ref uuid,
    policy_row_version bigint,
    knowledge_source_refs uuid[],
    max_invocations_per_session integer,
    max_writes_per_day integer,
    max_tokens_per_session bigint,
    max_session_duration_minutes integer,
    invocations_used bigint DEFAULT 0 NOT NULL,
    capability_pack_refs jsonb,
    retrieval_mode text DEFAULT 'tool_invoked'::text NOT NULL,
    persona_snapshot text,
    CONSTRAINT agent_session_capability_pack_refs_is_an_array CHECK (((capability_pack_refs IS NULL) OR (jsonb_typeof(capability_pack_refs) = 'array'::text))),
    CONSTRAINT agent_session_capability_packs_need_policy CHECK (((capability_pack_refs IS NULL) OR (policy_ref IS NOT NULL))),
    CONSTRAINT agent_session_invocations_used_nonnegative CHECK ((invocations_used >= 0)),
    CONSTRAINT agent_session_limits_positive CHECK ((((max_invocations_per_session IS NULL) OR (max_invocations_per_session > 0)) AND ((max_writes_per_day IS NULL) OR (max_writes_per_day > 0)) AND ((max_tokens_per_session IS NULL) OR (max_tokens_per_session > 0)) AND ((max_session_duration_minutes IS NULL) OR (max_session_duration_minutes > 0)))),
    CONSTRAINT agent_session_pause_pair CHECK (((paused_at IS NULL) = (paused_by IS NULL))),
    CONSTRAINT agent_session_policy_needs_definition CHECK (((policy_ref IS NULL) OR (agent_definition_ref IS NOT NULL))),
    CONSTRAINT agent_session_policy_pair CHECK (((policy_ref IS NULL) = (policy_row_version IS NULL))),
    CONSTRAINT agent_session_retrieval_mode_known CHECK ((retrieval_mode = ANY (ARRAY['tool_invoked'::text, 'pre_retrieved'::text]))),
    CONSTRAINT agent_session_revocation_pair CHECK (((revoked_at IS NULL) = (revoked_by IS NULL))),
    CONSTRAINT agent_session_risk_ceiling_range CHECK (((risk_ceiling >= 0) AND (risk_ceiling <= 2)))
);

CREATE TABLE IF NOT EXISTS agent_session_token (
    id uuid DEFAULT uuidv7() CONSTRAINT webchat_session_id_not_null NOT NULL,
    secret_hash text CONSTRAINT webchat_session_secret_hash_not_null NOT NULL,
    agent_session_id uuid CONSTRAINT webchat_session_agent_session_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT webchat_session_created_at_not_null NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() CONSTRAINT webchat_session_last_seen_at_not_null NOT NULL
);

CREATE TABLE IF NOT EXISTS app (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying(128) NOT NULL,
    icon character varying DEFAULT 'las la-th-large'::character varying NOT NULL,
    sidebar_root_ref uuid,
    default_dashboard_ref uuid,
    entities jsonb DEFAULT '[]'::jsonb NOT NULL,
    roles jsonb DEFAULT '[]'::jsonb NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_app_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS approval_delegation (
    id uuid DEFAULT uuidv7() NOT NULL,
    from_user uuid NOT NULL,
    to_user uuid NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_to timestamp with time zone NOT NULL,
    scope text DEFAULT 'all'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT approval_delegation_check CHECK ((from_user <> to_user)),
    CONSTRAINT approval_delegation_check1 CHECK ((valid_to > valid_from))
);

CREATE TABLE IF NOT EXISTS approval_policy (
    id uuid DEFAULT uuidv7() NOT NULL,
    name text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    action_type text NOT NULL,
    condition text,
    plan jsonb NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_record (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    archive_ref text NOT NULL,
    manifest_ref text NOT NULL,
    checksum text NOT NULL,
    attachment_count integer DEFAULT 0 NOT NULL,
    retention_action_ref uuid,
    archived_by uuid NOT NULL,
    archived_at timestamp with time zone DEFAULT now() NOT NULL,
    restored_by uuid,
    restored_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS attribute_info (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone,
    created_by uuid,
    modified_at timestamp with time zone,
    modified_by uuid,
    logicalname character varying,
    name character varying,
    type integer,
    required boolean,
    max_length integer,
    default_value character varying,
    entity_ref uuid,
    lookup_entity_ref uuid,
    organization_ref uuid,
    is_active boolean DEFAULT true,
    is_sensitive boolean DEFAULT false NOT NULL,
    is_sortable boolean DEFAULT false NOT NULL,
    is_filterable boolean DEFAULT false NOT NULL,
    on_target_delete character varying(20) DEFAULT 'orphan'::character varying NOT NULL,
    options jsonb,
    data_classification character varying(30) DEFAULT 'general'::character varying NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    purpose text,
    sort_order integer DEFAULT 0 NOT NULL,
    is_write_restricted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_attribute_info_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT core_attribute_info_data_classification_check CHECK (((data_classification)::text = ANY ((ARRAY['general'::character varying, 'personal'::character varying, 'sensitive_special_category'::character varying])::text[]))),
    CONSTRAINT core_attribute_info_on_target_delete_check CHECK (((on_target_delete)::text = ANY ((ARRAY['restrict'::character varying, 'orphan'::character varying, 'cascade-deactivate'::character varying])::text[])))
);

CREATE TABLE IF NOT EXISTS bulk_transform_operation (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    field_logicalname text NOT NULL,
    transform text NOT NULL,
    transform_value text,
    status text DEFAULT 'pending'::text NOT NULL,
    total integer NOT NULL,
    succeeded integer DEFAULT 0 NOT NULL,
    failed integer DEFAULT 0 NOT NULL,
    errors jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT bulk_transform_operation_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT bulk_transform_operation_transform_check CHECK ((transform = ANY (ARRAY['trim'::text, 'upper'::text, 'lower'::text, 'set_to_value'::text])))
);

CREATE TABLE IF NOT EXISTS bulk_transform_operation_item (
    id uuid DEFAULT uuidv7() NOT NULL,
    operation_id uuid NOT NULL,
    item_index integer NOT NULL,
    record_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    error text,
    attempts integer DEFAULT 0 NOT NULL,
    claimed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT bulk_transform_operation_item_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS calendar (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    tz text NOT NULL,
    working_days text[] DEFAULT '{}'::text[] NOT NULL,
    hours jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_calendar_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS calendar_exception (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    calendar_id uuid NOT NULL,
    name text NOT NULL,
    exception_date date NOT NULL,
    ranges jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_calendar_exception_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT ck_core_calendar_exception_ranges_array CHECK ((jsonb_typeof(ranges) = 'array'::text))
);

CREATE TABLE IF NOT EXISTS calendar_holiday (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    calendar_id uuid NOT NULL,
    name text NOT NULL,
    holiday_date date NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_calendar_holiday_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS cascade_deactivation (
    id uuid DEFAULT uuidv7() NOT NULL,
    parent_entity text NOT NULL,
    parent_record_id uuid NOT NULL,
    dependent_entity text NOT NULL,
    dependent_field text NOT NULL,
    dependent_record_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS catalog_usage_rollup (
    entity_logicalname text NOT NULL,
    record_count bigint DEFAULT 0 NOT NULL,
    last_write_at timestamp with time zone,
    search_impressions_30d bigint DEFAULT 0 NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS change_consumer_cursor (
    consumer text NOT NULL,
    last_commit_xid xid8 DEFAULT '0'::xid8 NOT NULL,
    last_id uuid,
    last_created_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT core_change_consumer_cursor_consumer_chk CHECK (((consumer <> ''::text) AND (length(consumer) <= 128)))
);

CREATE TABLE IF NOT EXISTS changeset (
    id uuid DEFAULT uuidv7() NOT NULL,
    layer text NOT NULL,
    scope text NOT NULL,
    name text NOT NULL,
    title text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    origin text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    requires jsonb DEFAULT '{}'::jsonb NOT NULL,
    op_count integer DEFAULT 0 NOT NULL,
    opened_log_id bigint DEFAULT 0 NOT NULL,
    author_ref uuid,
    author_label text NOT NULL,
    opened_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    document jsonb,
    checksum text,
    ops_hash text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_core_changeset_checksum CHECK ((checksum ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_core_changeset_closed_at CHECK (((status = 'closed'::text) = (closed_at IS NOT NULL))),
    CONSTRAINT ck_core_changeset_closed_sealed CHECK (((status <> 'closed'::text) OR (origin = ANY (ARRAY['auto'::text, 'break_glass'::text])) OR (checksum IS NOT NULL))),
    CONSTRAINT ck_core_changeset_layer CHECK ((layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT ck_core_changeset_name CHECK (((name ~ '^[a-z0-9]+(-[a-z0-9]+)*$'::text) AND (length(name) <= 60))),
    CONSTRAINT ck_core_changeset_op_count CHECK ((op_count >= 0)),
    CONSTRAINT ck_core_changeset_origin CHECK ((origin = ANY (ARRAY['authored'::text, 'auto'::text, 'break_glass'::text]))),
    CONSTRAINT ck_core_changeset_scope CHECK ((scope ~ '^[a-z0-9]+([-_][a-z0-9]+)*$'::text)),
    CONSTRAINT ck_core_changeset_status CHECK ((status = ANY (ARRAY['open'::text, 'closed'::text, 'abandoned'::text]))),
    CONSTRAINT ck_core_changeset_title CHECK (((length(title) >= 1) AND (length(title) <= 200)))
);

CREATE TABLE IF NOT EXISTS changeset_apply (
    id uuid DEFAULT uuidv7() NOT NULL,
    changeset_id uuid NOT NULL,
    ref text NOT NULL,
    layer text NOT NULL,
    scope text NOT NULL,
    seq integer NOT NULL,
    phase text NOT NULL,
    checksum text NOT NULL,
    document jsonb NOT NULL,
    plan jsonb NOT NULL,
    status text DEFAULT 'planned'::text NOT NULL,
    source text NOT NULL,
    platform_version text NOT NULL,
    backup_ref text,
    requested_by uuid,
    approval_ref uuid,
    claimed_by text,
    claimed_at timestamp with time zone,
    cursor integer DEFAULT 0 NOT NULL,
    applied_count integer DEFAULT 0 NOT NULL,
    error_message text,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    risky boolean DEFAULT false NOT NULL,
    copy_test_ref text,
    backup_retain_until timestamp with time zone,
    report_ref uuid,
    health_checked_at timestamp with time zone,
    CONSTRAINT ck_core_changeset_apply_checksum CHECK ((checksum ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_core_changeset_apply_cursor CHECK (((cursor >= 0) AND (applied_count >= 0))),
    CONSTRAINT ck_core_changeset_apply_layer CHECK ((layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT ck_core_changeset_apply_phase CHECK ((phase = ANY (ARRAY['expand'::text, 'contract'::text]))),
    CONSTRAINT ck_core_changeset_apply_source CHECK ((source = ANY (ARRAY['boot'::text, 'admin'::text, 'adopt'::text, 'replay'::text]))),
    CONSTRAINT ck_core_changeset_apply_status CHECK ((status = ANY (ARRAY['planned'::text, 'queued'::text, 'claimed'::text, 'applying'::text, 'succeeded'::text, 'failed'::text, 'adopted'::text])))
);

CREATE TABLE IF NOT EXISTS changeset_operation (
    id uuid DEFAULT uuidv7() NOT NULL,
    changeset_ref uuid NOT NULL,
    seq integer NOT NULL,
    op text NOT NULL,
    phase text NOT NULL,
    object_kind text NOT NULL,
    object_ref uuid,
    target jsonb NOT NULL,
    snapshot jsonb NOT NULL,
    args jsonb,
    changed text[] DEFAULT '{}'::text[] NOT NULL,
    route text NOT NULL,
    request_id text,
    actor_ref uuid,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_core_changeset_operation_phase CHECK ((phase = ANY (ARRAY['expand'::text, 'contract'::text]))),
    CONSTRAINT ck_core_changeset_operation_seq CHECK ((seq >= 1))
);

CREATE TABLE IF NOT EXISTS data_domain (
    id uuid DEFAULT uuidv7() NOT NULL,
    name text NOT NULL,
    description text,
    steward_ref uuid,
    deputy_ref uuid,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_data_domain_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS data_export (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    format text NOT NULL,
    columns jsonb DEFAULT '[]'::jsonb NOT NULL,
    filters jsonb DEFAULT '[]'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    row_count bigint,
    object_key text,
    checksum text,
    error text,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT data_export_format_check CHECK ((format = ANY (ARRAY['csv'::text, 'xlsx'::text, 'json'::text]))),
    CONSTRAINT data_export_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS data_mapping (
    id uuid DEFAULT uuidv7() NOT NULL,
    name text NOT NULL,
    target_entity text NOT NULL,
    source_kind text NOT NULL,
    fields jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT data_mapping_source_kind_check CHECK ((source_kind = ANY (ARRAY['csv'::text, 'json'::text, 'connector'::text])))
);

CREATE TABLE IF NOT EXISTS data_profile (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    row_count bigint,
    fields jsonb DEFAULT '[]'::jsonb NOT NULL,
    error text,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT data_profile_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS data_step_run (
    id uuid DEFAULT uuidv7() NOT NULL,
    changeset_id uuid,
    op_seq integer,
    apply_ref uuid,
    source text NOT NULL,
    entity_logicalname text NOT NULL,
    kind text NOT NULL,
    spec jsonb NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    rows_estimate bigint,
    rows_scanned bigint DEFAULT 0 NOT NULL,
    rows_written bigint DEFAULT 0 NOT NULL,
    rows_nulled bigint DEFAULT 0 NOT NULL,
    cursor uuid,
    claimed_by text,
    claimed_at timestamp with time zone,
    error_message text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_core_data_step_run_kind CHECK ((kind = ANY (ARRAY['copy'::text, 'convert'::text, 'map_values'::text, 'set_default'::text, 'retype'::text, 'archive'::text]))),
    CONSTRAINT ck_core_data_step_run_op CHECK (((changeset_id IS NULL) = (op_seq IS NULL))),
    CONSTRAINT ck_core_data_step_run_source CHECK ((source = ANY (ARRAY['admin'::text, 'apply'::text, 'replay'::text]))),
    CONSTRAINT ck_core_data_step_run_status CHECK ((status = ANY (ARRAY['queued'::text, 'claimed'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'abandoned'::text])))
);

CREATE TABLE IF NOT EXISTS document_folder (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_name text NOT NULL,
    record_id uuid NOT NULL,
    folder text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT document_folder_normalized CHECK (((folder = btrim(folder)) AND (folder !~~ '/%'::text) AND (folder !~~ '%/'::text) AND (folder !~~ '%//%'::text) AND (POSITION((chr(92)) IN (folder)) = 0))),
    CONSTRAINT document_folder_folder_check CHECK (((length(folder) >= 1) AND (length(folder) <= 500)))
);

CREATE TABLE IF NOT EXISTS dsr_request (
    id uuid DEFAULT uuidv7() NOT NULL,
    subject_reference text NOT NULL,
    request_type text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    block_reason text,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    fulfilled_at timestamp with time zone,
    evidence_ref text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT dsr_request_request_type_check CHECK ((request_type = ANY (ARRAY['access'::text, 'erasure'::text, 'portability'::text, 'objection'::text]))),
    CONSTRAINT dsr_request_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'blocked'::text, 'fulfilled'::text, 'rejected'::text])))
);

CREATE TABLE IF NOT EXISTS duplicate_candidate (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    record_a uuid NOT NULL,
    record_b uuid NOT NULL,
    match_rule_id uuid NOT NULL,
    score real NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    auto_merge_eligible boolean DEFAULT false NOT NULL,
    approval_request_id uuid,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    resolution_note text,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT duplicate_candidate_order_chk CHECK ((record_a < record_b)),
    CONSTRAINT duplicate_candidate_status_chk CHECK ((status = ANY (ARRAY['open'::text, 'merged'::text, 'dismissed'::text])))
);

CREATE TABLE IF NOT EXISTS entity_change_event (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    operation text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    commit_xid xid8 DEFAULT pg_current_xact_id() NOT NULL,
    event_name text,
    CONSTRAINT core_entity_change_event_operation_chk CHECK ((operation = ANY (ARRAY['create'::text, 'update'::text, 'delete'::text, 'restore'::text, 'purge'::text])))
);

CREATE TABLE IF NOT EXISTS entity_default_share (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_ref uuid NOT NULL,
    principal_type smallint NOT NULL,
    principal_id uuid NOT NULL,
    capability smallint NOT NULL,
    granted_by uuid,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_entity_default_share_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT core_entity_default_share_capability_range CHECK (((capability >= 0) AND (capability <= 2))),
    CONSTRAINT core_entity_default_share_principal_type_range CHECK (((principal_type >= 0) AND (principal_type <= 1)))
);

CREATE TABLE IF NOT EXISTS entity_info (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone,
    created_by uuid,
    modified_at timestamp with time zone,
    modified_by uuid,
    logicalname character varying,
    name character varying,
    is_audited boolean DEFAULT false,
    primary_name_attribute character varying(128),
    organization_ref uuid,
    is_active boolean DEFAULT true,
    is_append_only boolean DEFAULT false NOT NULL,
    category character varying,
    is_customized boolean DEFAULT false NOT NULL,
    domain_ref uuid,
    owner_layer text NOT NULL,
    business_key text[],
    is_reference_data boolean DEFAULT false NOT NULL,
    CONSTRAINT ck_core_entity_info_business_key CHECK (((business_key IS NULL) OR ((cardinality(business_key) >= 1) AND (cardinality(business_key) <= 4)))),
    CONSTRAINT ck_core_entity_info_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT ck_core_entity_info_reference_key CHECK (((NOT is_reference_data) OR (business_key IS NOT NULL)))
);

CREATE TABLE IF NOT EXISTS event_delivery (
    id uuid DEFAULT uuidv7() NOT NULL,
    subscription_ref uuid NOT NULL,
    event_id uuid NOT NULL,
    event_entity_logicalname text NOT NULL,
    event_record_id uuid NOT NULL,
    event_operation text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    response_status integer,
    last_attempted_at timestamp with time zone,
    delivered_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT core_event_delivery_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'delivering'::text, 'delivered'::text, 'failed'::text, 'dead_letter'::text])))
);

CREATE TABLE IF NOT EXISTS event_subscription (
    id uuid DEFAULT uuidv7() NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    filter_entity_logicalnames text[],
    filter_operations text[],
    filter_expression text,
    target_url text,
    webhook_secret_encrypted text,
    target_workflow_definition_id uuid,
    target_internal_key text,
    retry_class text DEFAULT 'standard'::text NOT NULL,
    max_attempts integer DEFAULT 8 NOT NULL,
    owner_ref uuid NOT NULL,
    created_by uuid,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    target_integration_system_ref uuid,
    filter_event_names text[],
    CONSTRAINT core_event_subscription_kind_chk CHECK ((kind = ANY (ARRAY['webhook'::text, 'job'::text, 'workflow'::text, 'internal'::text, 'audit'::text]))),
    CONSTRAINT core_event_subscription_max_attempts_chk CHECK (((max_attempts >= 1) AND (max_attempts <= 50))),
    CONSTRAINT core_event_subscription_retry_class_chk CHECK ((retry_class = ANY (ARRAY['standard'::text, 'extended'::text]))),
    CONSTRAINT core_event_subscription_webhook_target_chk CHECK (((kind <> ALL (ARRAY['webhook'::text, 'audit'::text])) OR ((target_url IS NOT NULL) AND (webhook_secret_encrypted IS NOT NULL))))
);

CREATE TABLE IF NOT EXISTS field_security_profile (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    description character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_field_security_profile_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS field_security_profile_field (
    id uuid DEFAULT uuidv7() NOT NULL,
    profile_ref uuid NOT NULL,
    entity_logicalname character varying CONSTRAINT field_security_profile_fie_entity_logicalname_not_null NOT NULL,
    field_logicalname character varying CONSTRAINT field_security_profile_fiel_field_logicalname_not_null NOT NULL,
    can_read boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    can_update boolean DEFAULT true NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_field_security_profile_field_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS file_version (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    field text NOT NULL,
    version_no integer NOT NULL,
    object_key text NOT NULL,
    size bigint,
    hash text,
    content_type text,
    uploaded_by uuid,
    scan_status text DEFAULT 'clean'::text NOT NULL,
    is_current boolean DEFAULT false NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    retention_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    uploaded_by_portal_user uuid,
    CONSTRAINT core_file_version_one_uploader CHECK (((uploaded_by IS NULL) <> (uploaded_by_portal_user IS NULL)))
);

CREATE TABLE IF NOT EXISTS knowledge_chunk (
    id uuid DEFAULT uuidv7() NOT NULL,
    collection_ref uuid NOT NULL,
    source_type text NOT NULL,
    source_id uuid NOT NULL,
    parent_entity text,
    parent_record_id uuid,
    lifecycle text DEFAULT 'draft'::text NOT NULL,
    ordinal integer NOT NULL,
    heading_path text[] DEFAULT ARRAY[]::text[] NOT NULL,
    text_display text NOT NULL,
    text_indexed text NOT NULL,
    tsv tsvector NOT NULL,
    content_hash bytea,
    fetched_at timestamp with time zone,
    indexed_at timestamp with time zone DEFAULT now() NOT NULL,
    embedding halfvec(1024),
    embedding_model character varying(128),
    embedding_locality text,
    CONSTRAINT knowledge_chunk_fetched_at_is_web_only CHECK (((source_type = 'web'::text) OR (fetched_at IS NULL))),
    CONSTRAINT knowledge_chunk_lifecycle CHECK ((lifecycle = ANY (ARRAY['draft'::text, 'published'::text, 'expired'::text]))),
    CONSTRAINT knowledge_chunk_parent_pair CHECK (((parent_entity IS NULL) = (parent_record_id IS NULL))),
    CONSTRAINT knowledge_chunk_source_type CHECK ((source_type = ANY (ARRAY['article'::text, 'attachment'::text, 'web'::text])))
);

CREATE TABLE IF NOT EXISTS knowledge_chunk_retrieval (
    id uuid DEFAULT uuidv7() NOT NULL,
    chunk_ref uuid NOT NULL,
    retrieved_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS legal_hold (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid,
    matter_reference text NOT NULL,
    placed_by uuid NOT NULL,
    placed_at timestamp with time zone DEFAULT now() NOT NULL,
    released_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS match_rule (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    name text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    fields jsonb NOT NULL,
    threshold real NOT NULL,
    auto_merge boolean DEFAULT false NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT match_rule_fields_chk CHECK ((jsonb_typeof(fields) = 'array'::text)),
    CONSTRAINT match_rule_threshold_chk CHECK (((threshold > (0)::double precision) AND (threshold <= (1)::double precision)))
);

CREATE TABLE IF NOT EXISTS memory (
    id uuid DEFAULT uuidv7() NOT NULL,
    scope_kind text NOT NULL,
    scope_ref text NOT NULL,
    owner_principal uuid NOT NULL,
    parent_entity text,
    parent_record_id uuid,
    kind text NOT NULL,
    summary text NOT NULL,
    facts jsonb DEFAULT '[]'::jsonb NOT NULL,
    source_refs jsonb DEFAULT '[]'::jsonb NOT NULL,
    tsv tsvector GENERATED ALWAYS AS (to_tsvector('english'::regconfig, ((summary || ' '::text) || (facts)::text))) STORED,
    embedding halfvec(1024),
    embedding_model character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version integer DEFAULT 0 NOT NULL,
    embedding_locality text,
    CONSTRAINT memory_facts_shape CHECK (((jsonb_typeof(facts) = 'array'::text) AND (pg_column_size(facts) <= 8192))),
    CONSTRAINT memory_kind_length CHECK ((char_length(kind) <= 64)),
    CONSTRAINT memory_parent_only_for_entity_scope CHECK (((parent_record_id IS NULL) OR (scope_kind = 'entity'::text))),
    CONSTRAINT memory_parent_pair CHECK (((parent_entity IS NULL) = (parent_record_id IS NULL))),
    CONSTRAINT memory_scope_kind CHECK ((scope_kind = ANY (ARRAY['user'::text, 'organization'::text, 'entity'::text, 'conversation'::text, 'workflow'::text, 'decision'::text, 'agent'::text]))),
    CONSTRAINT memory_source_refs_shape CHECK (((jsonb_typeof(source_refs) = 'array'::text) AND (pg_column_size(source_refs) <= 8192))),
    CONSTRAINT memory_summary_length CHECK ((char_length(summary) <= 2000))
);

CREATE TABLE IF NOT EXISTS metadata_bundle_plan (
    id uuid DEFAULT uuidv7() NOT NULL,
    status text DEFAULT 'planned'::text NOT NULL,
    bundle jsonb NOT NULL,
    plan jsonb NOT NULL,
    bundle_hash text NOT NULL,
    basis_hash text NOT NULL,
    format_version text NOT NULL,
    platform_version text NOT NULL,
    allow_retire boolean DEFAULT false NOT NULL,
    requested_by uuid,
    approval_ref uuid,
    claimed_by text,
    claimed_at timestamp with time zone,
    cursor integer DEFAULT 0 NOT NULL,
    applied_count integer DEFAULT 0 NOT NULL,
    error_message text,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT metadata_bundle_plan_status_check CHECK ((status = ANY (ARRAY['planned'::text, 'queued'::text, 'claimed'::text, 'applying'::text, 'succeeded'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS metadata_change_log (
    id bigint NOT NULL,
    entity_ref uuid NOT NULL,
    logicalname character varying NOT NULL,
    change_kind character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT metadata_change_log_change_kind_check CHECK (((change_kind)::text = ANY ((ARRAY['upsert'::character varying, 'delete'::character varying])::text[])))
);

CREATE TABLE IF NOT EXISTS metadata_label (
    id uuid DEFAULT uuidv7() NOT NULL,
    object_kind text NOT NULL,
    object_ref text NOT NULL,
    locale text NOT NULL,
    display_name text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_metadata_label_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT metadata_label_object_kind_check CHECK ((object_kind = ANY (ARRAY['entity'::text, 'attribute'::text, 'choice_option'::text, 'view'::text, 'sidebar'::text, 'dashboard'::text])))
);

CREATE TABLE IF NOT EXISTS metadata_label_change_log (
    id bigint NOT NULL,
    object_kind text NOT NULL,
    object_ref text NOT NULL,
    locale text NOT NULL,
    change_kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT metadata_label_change_log_change_kind_check CHECK ((change_kind = ANY (ARRAY['upsert'::text, 'delete'::text])))
);

CREATE TABLE IF NOT EXISTS metadata_reference (
    id uuid DEFAULT uuidv7() NOT NULL,
    from_kind text NOT NULL,
    from_ref uuid NOT NULL,
    from_label text DEFAULT ''::text NOT NULL,
    to_entity text NOT NULL,
    to_attribute text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS metadata_reference_backfill_progress (
    kind text NOT NULL,
    last_ref uuid,
    completed boolean DEFAULT false CONSTRAINT metadata_reference_backfill_progres_completed_not_null NOT NULL,
    rows_written bigint DEFAULT 0 CONSTRAINT metadata_reference_backfill_prog_rows_written_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT metadata_reference_backfill_progre_updated_at_not_null NOT NULL
);

CREATE TABLE IF NOT EXISTS module_configuration (
    singleton boolean DEFAULT true NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    enabled_modules text[] NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT module_configuration_singleton_check CHECK (singleton)
);

CREATE TABLE IF NOT EXISTS organization (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    created_by uuid,
    is_active boolean DEFAULT true,
    organization_ref uuid,
    name character varying
);

CREATE TABLE IF NOT EXISTS outcome (
    id uuid DEFAULT uuidv7() NOT NULL,
    kind text NOT NULL,
    source_module text NOT NULL,
    entity_logicalname text,
    regarding_entity text,
    regarding_id uuid,
    model_id text,
    prompt_version text,
    rule_ref text,
    proposed_by uuid,
    proposed_at timestamp with time zone DEFAULT now() NOT NULL,
    expected_value jsonb,
    actual_value jsonb,
    measured_at timestamp with time zone,
    effectiveness double precision,
    organization_ref uuid,
    CONSTRAINT outcome_effectiveness_needs_measurement_chk CHECK (((effectiveness IS NULL) OR (measured_at IS NOT NULL))),
    CONSTRAINT outcome_kind_chk CHECK ((kind = ANY (ARRAY['ai_suggestion'::text, 'decision'::text, 'recommendation'::text, 'prediction'::text, 'classification'::text, 'edge'::text, 'process_change'::text, 'config_change'::text])))
);

CREATE TABLE IF NOT EXISTS position (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    description character varying,
    parent_position_ref uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    is_customized boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS privilege (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    created_by uuid,
    organization_ref uuid,
    is_active boolean DEFAULT true,
    key character varying NOT NULL,
    name character varying NOT NULL,
    description character varying,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_privilege_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS quality_issue (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    period text NOT NULL,
    dimension text NOT NULL,
    record_id uuid NOT NULL,
    field_logicalname text DEFAULT ''::text NOT NULL,
    related_record_id uuid,
    detail text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    CONSTRAINT quality_issue_dimension_check CHECK ((dimension = ANY (ARRAY['completeness'::text, 'uniqueness'::text]))),
    CONSTRAINT quality_issue_status_check CHECK ((status = ANY (ARRAY['open'::text, 'resolved'::text])))
);

CREATE TABLE IF NOT EXISTS quality_score (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    period text NOT NULL,
    dimension text NOT NULL,
    pass_count bigint NOT NULL,
    fail_count bigint NOT NULL,
    sample_size bigint NOT NULL,
    score numeric(5,2) NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT quality_score_dimension_check CHECK ((dimension = ANY (ARRAY['completeness'::text, 'uniqueness'::text])))
);

CREATE TABLE IF NOT EXISTS record_baseline (
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    field_logicalname text NOT NULL,
    value_hash text NOT NULL,
    live_hash text,
    changeset_id uuid NOT NULL,
    op_seq integer NOT NULL,
    written_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_core_record_baseline_hash CHECK (((value_hash ~ '^sha256:[0-9a-f]{64}$'::text) AND ((live_hash IS NULL) OR (live_hash ~ '^sha256:[0-9a-f]{64}$'::text))))
);

CREATE TABLE IF NOT EXISTS record_share (
    id uuid DEFAULT uuidv7() NOT NULL,
    record_id uuid NOT NULL,
    entity_ref uuid NOT NULL,
    principal_type smallint NOT NULL,
    principal_id uuid NOT NULL,
    capability smallint NOT NULL,
    granted_by uuid,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT core_record_share_capability_range CHECK (((capability >= 0) AND (capability <= 2))),
    CONSTRAINT core_record_share_principal_type_range CHECK (((principal_type >= 0) AND (principal_type <= 1)))
);

CREATE TABLE IF NOT EXISTS recovery_archive (
    id uuid DEFAULT uuidv7() NOT NULL,
    reason text NOT NULL,
    entity_logicalname text NOT NULL,
    field_logicalname text NOT NULL,
    attribute_id uuid NOT NULL,
    record_id uuid NOT NULL,
    field_type text NOT NULL,
    value_enc bytea NOT NULL,
    changeset_id uuid,
    op_seq integer,
    run_ref uuid,
    report_item_ref uuid,
    archived_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '30 days'::interval) NOT NULL,
    restored_at timestamp with time zone,
    restored_by uuid,
    CONSTRAINT ck_core_recovery_archive_op CHECK (((changeset_id IS NULL) = (op_seq IS NULL))),
    CONSTRAINT ck_core_recovery_archive_reason CHECK ((reason = ANY (ARRAY['field_deleted'::text, 'conversion_nulled'::text])))
);

CREATE TABLE IF NOT EXISTS relationship_info (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying(48) NOT NULL,
    entity_a character varying NOT NULL,
    entity_b character varying NOT NULL,
    role_a character varying NOT NULL,
    role_b character varying NOT NULL,
    join_table character varying NOT NULL,
    cascade character varying DEFAULT 'orphan'::character varying NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_relationship_info_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT relationship_info_cascade_check CHECK (((cascade)::text = ANY ((ARRAY['restrict'::character varying, 'orphan'::character varying, 'cascade_deactivate'::character varying, 'cascade-deactivate'::character varying])::text[])))
);

CREATE TABLE IF NOT EXISTS release_report (
    id uuid DEFAULT uuidv7() NOT NULL,
    apply_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    release text NOT NULL,
    source text NOT NULL,
    status text DEFAULT 'building'::text NOT NULL,
    items_total integer DEFAULT 0 NOT NULL,
    items_open integer DEFAULT 0 NOT NULL,
    backup_ref text,
    backup_retain_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ready_at timestamp with time zone,
    notified_at timestamp with time zone,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_core_release_report_counts CHECK (((items_total >= 0) AND (items_open >= 0) AND (items_open <= items_total))),
    CONSTRAINT ck_core_release_report_source CHECK ((source = ANY (ARRAY['boot'::text, 'admin'::text, 'replay'::text, 'change'::text]))),
    CONSTRAINT ck_core_release_report_status CHECK ((status = ANY (ARRAY['building'::text, 'ready'::text])))
);

CREATE TABLE IF NOT EXISTS release_report_item (
    id uuid DEFAULT uuidv7() NOT NULL,
    report_ref uuid NOT NULL,
    kind text NOT NULL,
    actionable boolean NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    entity_logicalname text NOT NULL,
    field_logicalname text,
    record_id uuid,
    object_kind text,
    object_ref uuid,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    values_enc bytea,
    changeset_id uuid,
    op_seq integer,
    decided_by uuid,
    decided_at timestamp with time zone,
    superseded_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_core_release_item_kind CHECK ((kind = ANY (ARRAY['conflict'::text, 'conversion_nulled'::text, 'field_deleted'::text, 'customer_object_adjusted'::text, 'customer_object_removed'::text, 'breaking_api_change'::text, 'choice_removed_in_use'::text, 'required_empty'::text]))),
    CONSTRAINT ck_core_release_item_op CHECK (((changeset_id IS NULL) = (op_seq IS NULL))),
    CONSTRAINT ck_core_release_item_status CHECK ((status = ANY (ARRAY['open'::text, 'info'::text, 'accepted'::text, 'used_mine'::text, 'restored'::text, 'dismissed'::text, 'superseded'::text, 'expired'::text])))
);

CREATE TABLE IF NOT EXISTS role (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    description character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    access_level smallint DEFAULT 3 NOT NULL,
    position_hierarchy_enabled boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    ip_allowlist text[],
    bulk_field_mode smallint DEFAULT 0 NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_role_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT core_role_access_level_range CHECK (((access_level >= 0) AND (access_level <= 3))),
    CONSTRAINT core_role_bulk_field_mode_check CHECK ((bulk_field_mode = ANY (ARRAY[0, 1])))
);

CREATE TABLE IF NOT EXISTS role_bulk_field (
    role_ref uuid NOT NULL,
    entity_logicalname text NOT NULL,
    attribute_logicalname text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_role_bulk_field_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS role_mm_entity_access (
    id uuid DEFAULT uuidv7() NOT NULL,
    role_ref uuid NOT NULL,
    entity_ref uuid NOT NULL,
    read_access_level smallint DEFAULT 3 NOT NULL,
    write_access_level smallint DEFAULT 3 NOT NULL,
    delete_access_level smallint DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    read_owner_visible boolean DEFAULT false NOT NULL,
    write_owner_visible boolean DEFAULT false NOT NULL,
    delete_owner_visible boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_role_mm_entity_access_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT core_role_mm_entity_access_delete_range CHECK (((delete_access_level >= 0) AND (delete_access_level <= 3))),
    CONSTRAINT core_role_mm_entity_access_read_range CHECK (((read_access_level >= 0) AND (read_access_level <= 3))),
    CONSTRAINT core_role_mm_entity_access_write_range CHECK (((write_access_level >= 0) AND (write_access_level <= 3)))
);

CREATE TABLE IF NOT EXISTS role_mm_field_security_profile (
    id uuid DEFAULT uuidv7() NOT NULL,
    role_ref uuid NOT NULL,
    profile_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_role_mm_field_security_profile_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS role_mm_privilege (
    id uuid DEFAULT uuidv7() NOT NULL,
    role_ref uuid NOT NULL,
    privilege_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_role_mm_privilege_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS role_mm_team (
    id uuid DEFAULT uuidv7() NOT NULL,
    role_ref uuid NOT NULL,
    team_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS role_privilege_condition (
    id uuid DEFAULT uuidv7() NOT NULL,
    role_privilege_ref uuid NOT NULL,
    field_logicalname character varying NOT NULL,
    operator smallint NOT NULL,
    value jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_role_privilege_condition_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS rule (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname character varying NOT NULL,
    name character varying(128) NOT NULL,
    kind character varying NOT NULL,
    target_field character varying,
    expression text,
    message character varying,
    severity character varying DEFAULT 'error'::character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    display_name character varying(200),
    description text,
    applies_to text DEFAULT 'all'::text NOT NULL,
    condition jsonb,
    disabled_reason text,
    CONSTRAINT ck_core_rule_applies_to CHECK ((applies_to = ANY (ARRAY['all'::text, 'roles'::text]))),
    CONSTRAINT ck_core_rule_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT ck_core_rule_shape CHECK (((((kind)::text = 'business'::text) AND (condition IS NOT NULL) AND (expression IS NULL)) OR (((kind)::text <> 'business'::text) AND (condition IS NULL) AND (expression IS NOT NULL) AND (applies_to = 'all'::text)))),
    CONSTRAINT rule_severity_check CHECK (((severity)::text = ANY ((ARRAY['error'::character varying, 'warning'::character varying])::text[])))
);

CREATE TABLE IF NOT EXISTS rule_policy (
    id uuid DEFAULT uuidv7() NOT NULL,
    rule_ref uuid NOT NULL,
    ordinal integer NOT NULL,
    policy_type text NOT NULL,
    field_logicalname text,
    message character varying(500),
    severity text,
    value jsonb,
    expression text,
    set_mode text,
    CONSTRAINT ck_core_rule_policy_shape CHECK ((((policy_type = ANY (ARRAY['hidden'::text, 'disabled'::text])) AND (field_logicalname IS NOT NULL) AND (message IS NULL) AND (severity IS NULL) AND (value IS NULL) AND (expression IS NULL) AND (set_mode IS NULL)) OR ((policy_type = 'error'::text) AND (severity IS NOT NULL) AND (value IS NULL) AND (expression IS NULL) AND (set_mode IS NULL)) OR ((policy_type = 'set_value'::text) AND (field_logicalname IS NOT NULL) AND (set_mode IS NOT NULL) AND (num_nonnulls(value, expression) = 1) AND (message IS NULL) AND (severity IS NULL)))),
    CONSTRAINT rule_policy_policy_type_check CHECK ((policy_type = ANY (ARRAY['hidden'::text, 'disabled'::text, 'error'::text, 'set_value'::text]))),
    CONSTRAINT rule_policy_set_mode_check CHECK ((set_mode = ANY (ARRAY['always'::text, 'default'::text]))),
    CONSTRAINT rule_policy_severity_check CHECK ((severity = ANY (ARRAY['error'::text, 'warning'::text])))
);

CREATE TABLE IF NOT EXISTS rule_role (
    id uuid DEFAULT uuidv7() NOT NULL,
    rule_ref uuid NOT NULL,
    role_ref uuid,
    portal_role_ref uuid,
    CONSTRAINT ck_core_rule_role_one CHECK ((num_nonnulls(role_ref, portal_role_ref) = 1))
);

CREATE TABLE IF NOT EXISTS rule_version (
    id uuid DEFAULT uuidv7() NOT NULL,
    rule_id uuid NOT NULL,
    version integer NOT NULL,
    entity_logicalname character varying NOT NULL,
    kind character varying NOT NULL,
    target_field character varying,
    expression text,
    message character varying,
    severity character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    definition jsonb
);

CREATE TABLE IF NOT EXISTS schema_change_operation (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_ref uuid NOT NULL,
    attribute_ref uuid NOT NULL,
    entity_logicalname text NOT NULL,
    field_logicalname text NOT NULL,
    field_type text NOT NULL,
    target_required boolean NOT NULL,
    target_max_length integer,
    previous_required boolean NOT NULL,
    previous_max_length integer,
    backfill_default jsonb,
    backfill_cursor uuid,
    status text DEFAULT 'queued'::text NOT NULL,
    claimed_by text,
    claimed_at timestamp with time zone,
    error_message text,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    is_multi boolean DEFAULT false NOT NULL,
    CONSTRAINT schema_change_operation_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'claimed'::text, 'backfilling'::text, 'altering'::text, 'succeeded'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS search_impression (
    id uuid DEFAULT uuidv7() NOT NULL,
    query_fingerprint bytea NOT NULL,
    route text NOT NULL,
    ranker_id text NOT NULL,
    audience text NOT NULL,
    completeness jsonb DEFAULT '{}'::jsonb NOT NULL,
    caller_ref uuid,
    organization_ref uuid,
    result_count integer DEFAULT 0 NOT NULL,
    latency_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT search_impression_audience_chk CHECK ((audience = ANY (ARRAY['human'::text, 'agent'::text])))
);

CREATE TABLE IF NOT EXISTS search_impression_row (
    impression_ref uuid NOT NULL,
    rank integer NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    feature_vector jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS search_index (
    corpus text NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    title text,
    subtitle text,
    title_norm text,
    body_display text,
    body_indexed text,
    exact_keys text[] DEFAULT '{}'::text[] NOT NULL,
    tsv tsvector,
    organization_ref uuid,
    owner_id uuid,
    state smallint DEFAULT 0 NOT NULL,
    lang text,
    source_modifiedon timestamp with time zone,
    indexed_at timestamp with time zone DEFAULT now() NOT NULL,
    content_hash bytea,
    embedding halfvec(1024),
    embedding_sparse sparsevec(262144),
    embedding_model character varying(128),
    embedding_locality text
);

CREATE TABLE IF NOT EXISTS search_interaction (
    id uuid DEFAULT uuidv7() NOT NULL,
    impression_ref uuid NOT NULL,
    rank integer NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    dwell_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS search_suggestion (
    id uuid DEFAULT uuidv7() NOT NULL,
    kind text NOT NULL,
    suggestion_text text NOT NULL,
    suggestion_norm text NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid,
    weight integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT search_suggestion_kind_chk CHECK ((kind = ANY (ARRAY['entity'::text, 'saved_search'::text])))
);

CREATE TABLE IF NOT EXISTS seed_watermark (
    module text NOT NULL,
    version text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS setting (
    id uuid DEFAULT uuidv7() NOT NULL,
    key text NOT NULL,
    scope text NOT NULL,
    scope_ref uuid,
    value jsonb NOT NULL,
    schema jsonb NOT NULL,
    is_secret boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT setting_is_secret_check CHECK ((is_secret = false)),
    CONSTRAINT setting_scope_check CHECK ((scope = ANY (ARRAY['user'::text, 'organization'::text, 'deployment'::text]))),
    CONSTRAINT setting_scope_ref_shape CHECK ((((scope = 'deployment'::text) AND (scope_ref IS NULL)) OR ((scope = ANY (ARRAY['user'::text, 'organization'::text])) AND (scope_ref IS NOT NULL))))
);

CREATE TABLE IF NOT EXISTS setting_change_log (
    id bigint NOT NULL,
    setting_key text NOT NULL,
    scope text NOT NULL,
    scope_ref uuid,
    change_kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT setting_change_log_change_kind_check CHECK ((change_kind = ANY (ARRAY['upsert'::text, 'delete'::text])))
);

CREATE TABLE IF NOT EXISTS sql_query (
    id uuid NOT NULL,
    sql_query character varying,
    table_definition character varying,
    record_no character varying,
    entity_logical_name uuid,
    is_active boolean DEFAULT true,
    organization_ref uuid,
    created_at timestamp with time zone,
    created_by uuid,
    required_privilege character varying,
    is_report boolean DEFAULT false NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_sql_query_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS sql_query_entity_mapping (
    id uuid DEFAULT uuidv7() NOT NULL,
    query_version_id uuid NOT NULL,
    entity_ref uuid NOT NULL,
    id_column text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS sql_query_version (
    id uuid DEFAULT uuidv7() NOT NULL,
    query_id uuid NOT NULL,
    sql_query text NOT NULL,
    relations text[] DEFAULT '{}'::text[] NOT NULL,
    cost_estimate double precision NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid
);

CREATE TABLE IF NOT EXISTS state_model (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname character varying NOT NULL,
    name character varying NOT NULL,
    state_field character varying NOT NULL,
    initial_state character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_state_model_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS state_transition (
    id uuid DEFAULT uuidv7() NOT NULL,
    model_ref uuid NOT NULL,
    from_state character varying NOT NULL,
    to_state character varying NOT NULL,
    name character varying NOT NULL,
    required_privilege character varying,
    guard_expression text,
    entry_actions text[] DEFAULT '{}'::text[] NOT NULL,
    exit_actions text[] DEFAULT '{}'::text[] NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    approval_plan jsonb,
    pending_state character varying,
    on_reject_state character varying,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_state_transition_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT core_state_transition_approval_shape_chk CHECK ((((approval_plan IS NULL) AND (pending_state IS NULL) AND (on_reject_state IS NULL)) OR ((approval_plan IS NOT NULL) AND (pending_state IS NOT NULL))))
);

CREATE TABLE IF NOT EXISTS survivorship_rule (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    field_logicalname text NOT NULL,
    strategy text NOT NULL,
    priority_owner_ids uuid[],
    row_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT survivorship_rule_strategy_chk CHECK ((strategy = ANY (ARRAY['most_recent'::text, 'most_complete'::text, 'source_priority'::text, 'manual'::text])))
);

CREATE TABLE IF NOT EXISTS user_account_mm_organization (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_ref uuid NOT NULL,
    organization_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS user_account_mm_position (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_ref uuid NOT NULL,
    position_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS user_account_mm_privilege (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    created_by uuid,
    organization_ref uuid,
    user_ref uuid,
    is_active boolean DEFAULT true,
    privilege_ref uuid NOT NULL
);

CREATE TABLE IF NOT EXISTS user_account_mm_role (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_ref uuid NOT NULL,
    role_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS user_account_mm_team (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_ref uuid NOT NULL,
    team_ref uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS team (
    id uuid DEFAULT uuidv7() NOT NULL,
    name character varying NOT NULL,
    description character varying,
    organization_ref uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    is_customized boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS upload_session (
    id uuid DEFAULT uuidv7() NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    field_logicalname text NOT NULL,
    owner_user_ref uuid,
    quarantine_key text NOT NULL,
    final_key text,
    declared_filename text NOT NULL,
    declared_content_type text NOT NULL,
    declared_max_size_bytes bigint NOT NULL,
    declared_checksum_sha256 text,
    actual_size_bytes bigint,
    actual_content_type text,
    actual_checksum_sha256 text,
    status text DEFAULT 'pending'::text NOT NULL,
    reject_reason text,
    claimed_at timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    retention_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    owner_portal_user_ref uuid,
    CONSTRAINT core_upload_session_one_owner CHECK (((owner_user_ref IS NULL) <> (owner_portal_user_ref IS NULL))),
    CONSTRAINT upload_session_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'uploaded'::text, 'scanning'::text, 'clean'::text, 'rejected'::text, 'expired'::text])))
);

CREATE TABLE IF NOT EXISTS view (
    id uuid NOT NULL,
    name character varying NOT NULL,
    entity_logical_name uuid NOT NULL,
    sql_query_ref uuid NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    organization_ref uuid,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    created_by uuid,
    table_definition jsonb DEFAULT '[]'::jsonb NOT NULL,
    icon text DEFAULT 'las la-table'::text NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    owner_ref uuid,
    scope character varying DEFAULT 'system'::character varying NOT NULL,
    kind character varying DEFAULT 'list'::character varying NOT NULL,
    view_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_core_view_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text]))),
    CONSTRAINT core_view_kind_range CHECK (((kind)::text = ANY ((ARRAY['list'::character varying, 'kanban'::character varying, 'calendar'::character varying, 'timeline'::character varying, 'chart'::character varying])::text[]))),
    CONSTRAINT core_view_scope_range CHECK (((scope)::text = ANY ((ARRAY['system'::character varying, 'personal'::character varying, 'shared'::character varying])::text[])))
);

CREATE TABLE IF NOT EXISTS sidebar (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    name text NOT NULL,
    route text,
    icon text,
    color text,
    parent_ref uuid,
    display_order integer DEFAULT 0 NOT NULL,
    is_container boolean DEFAULT false NOT NULL,
    entity_logical_name text,
    is_active boolean DEFAULT true NOT NULL,
    module_key text,
    is_disabled boolean DEFAULT false NOT NULL,
    is_customized boolean DEFAULT false NOT NULL,
    owner_layer text NOT NULL,
    CONSTRAINT ck_sidebar_owner_layer CHECK ((owner_layer = ANY (ARRAY['platform'::text, 'product'::text, 'project'::text, 'customer'::text])))
);

CREATE TABLE IF NOT EXISTS sidebar_mm_privilege (
    id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    sidebar_ref uuid NOT NULL,
    privilege_ref uuid NOT NULL
);

ALTER TABLE ONLY metadata_change_log ALTER COLUMN id SET DEFAULT nextval('metadata_change_log_id_seq'::regclass);

ALTER TABLE ONLY metadata_label_change_log ALTER COLUMN id SET DEFAULT nextval('metadata_label_change_log_id_seq'::regclass);

ALTER TABLE ONLY setting_change_log ALTER COLUMN id SET DEFAULT nextval('setting_change_log_id_seq'::regclass);

ALTER TABLE ONLY audit_signing_key
    ADD CONSTRAINT audit_signing_key_key_id_unique UNIQUE (key_id);

ALTER TABLE rule
    ADD CONSTRAINT ck_core_rule_kind CHECK (((kind)::text = ANY ((ARRAY['business'::character varying, 'visibility'::character varying, 'requirement'::character varying, 'policy'::character varying, 'routing'::character varying])::text[]))) NOT VALID;

ALTER TABLE ONLY event_delivery
    ADD CONSTRAINT core_event_delivery_subs_event_unique UNIQUE (subscription_ref, event_id);

ALTER TABLE ONLY file_version
    ADD CONSTRAINT core_file_version_scope_version_unique UNIQUE (entity, record_id, field, version_no);

ALTER TABLE ONLY sql_query_entity_mapping
    ADD CONSTRAINT core_sql_query_entity_mapping_unique UNIQUE (query_version_id, entity_ref, id_column);

ALTER TABLE ONLY upload_session
    ADD CONSTRAINT core_upload_session_quarantine_key_unique UNIQUE (quarantine_key);

ALTER TABLE ONLY document_folder
    ADD CONSTRAINT document_folder_unique UNIQUE (entity_name, record_id, folder);

ALTER TABLE knowledge_chunk
    ADD CONSTRAINT knowledge_chunk_embedding_locality_chk CHECK ((embedding_locality = ANY (ARRAY['local'::text, 'external'::text]))) NOT VALID;

ALTER TABLE memory
    ADD CONSTRAINT memory_embedding_locality_chk CHECK ((embedding_locality = ANY (ARRAY['local'::text, 'external'::text]))) NOT VALID;

ALTER TABLE ONLY record_baseline
    ADD CONSTRAINT pk_core_record_baseline PRIMARY KEY (entity_logicalname, record_id, field_logicalname);

ALTER TABLE search_index
    ADD CONSTRAINT search_index_embedding_locality_chk CHECK ((embedding_locality = ANY (ARRAY['local'::text, 'external'::text]))) NOT VALID;

ALTER TABLE ONLY calendar
    ADD CONSTRAINT uq_core_calendar_name UNIQUE (name);

ALTER TABLE ONLY changeset_apply
    ADD CONSTRAINT uq_core_changeset_apply_phase UNIQUE (changeset_id, phase);

ALTER TABLE ONLY changeset_operation
    ADD CONSTRAINT uq_core_changeset_operation_seq UNIQUE (changeset_ref, seq);

ALTER TABLE ONLY entity_default_share
    ADD CONSTRAINT uq_core_entity_default_share UNIQUE (entity_ref, principal_type, principal_id, capability);

ALTER TABLE ONLY field_security_profile_field
    ADD CONSTRAINT uq_core_field_security_profile_field UNIQUE (profile_ref, entity_logicalname, field_logicalname);

ALTER TABLE ONLY privilege
    ADD CONSTRAINT uq_core_privilege_key UNIQUE (key);

ALTER TABLE ONLY record_share
    ADD CONSTRAINT uq_core_record_share UNIQUE (record_id, entity_ref, principal_type, principal_id, capability);

ALTER TABLE ONLY recovery_archive
    ADD CONSTRAINT uq_core_recovery_archive_event UNIQUE (attribute_id, record_id, reason, archived_at);

ALTER TABLE ONLY role_mm_entity_access
    ADD CONSTRAINT uq_core_role_mm_entity_access UNIQUE (role_ref, entity_ref);

ALTER TABLE ONLY role_mm_field_security_profile
    ADD CONSTRAINT uq_core_role_mm_field_security_profile UNIQUE (role_ref, profile_ref);

ALTER TABLE ONLY role_mm_privilege
    ADD CONSTRAINT uq_core_role_mm_privilege UNIQUE (role_ref, privilege_ref);

ALTER TABLE ONLY role_mm_team
    ADD CONSTRAINT uq_core_role_mm_team UNIQUE (role_ref, team_ref);

ALTER TABLE ONLY user_account_mm_organization
    ADD CONSTRAINT uq_core_systemuser_mm_organization UNIQUE (user_ref, organization_ref);

ALTER TABLE ONLY user_account_mm_position
    ADD CONSTRAINT uq_core_systemuser_mm_position UNIQUE (user_ref, position_ref);

ALTER TABLE ONLY user_account_mm_role
    ADD CONSTRAINT uq_core_systemuser_mm_role UNIQUE (user_ref, role_ref);

ALTER TABLE ONLY user_account_mm_team
    ADD CONSTRAINT uq_core_systemuser_mm_team UNIQUE (user_ref, team_ref);

ALTER TABLE ONLY knowledge_chunk
    ADD CONSTRAINT uq_knowledge_chunk_source_ordinal UNIQUE (source_type, source_id, ordinal);

ALTER TABLE ONLY user_account_mm_privilege
    ADD CONSTRAINT uq_user_priv UNIQUE (user_ref, privilege_ref);

ALTER TABLE ONLY sidebar_mm_privilege
    ADD CONSTRAINT uq_xrm_sidebar_privilege UNIQUE (sidebar_ref, privilege_ref);

ALTER TABLE ONLY ai_runtime_switch
    ADD CONSTRAINT ai_runtime_switch_pkey PRIMARY KEY (surface);

ALTER TABLE ONLY audit_retention_action
    ADD CONSTRAINT audit_retention_action_pkey PRIMARY KEY (id);

ALTER TABLE ONLY access_review_item
    ADD CONSTRAINT access_review_item_pkey PRIMARY KEY (id);

ALTER TABLE ONLY access_review
    ADD CONSTRAINT access_review_pkey PRIMARY KEY (id);

ALTER TABLE ONLY action_invocation
    ADD CONSTRAINT action_invocation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_session
    ADD CONSTRAINT agent_session_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app
    ADD CONSTRAINT app_pkey PRIMARY KEY (id);

ALTER TABLE ONLY approval_delegation
    ADD CONSTRAINT approval_delegation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY approval_policy
    ADD CONSTRAINT approval_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY archive_record
    ADD CONSTRAINT archive_record_pkey PRIMARY KEY (id);

ALTER TABLE ONLY attribute_info
    ADD CONSTRAINT attribute_info_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_signing_key
    ADD CONSTRAINT audit_signing_key_pkey PRIMARY KEY (id);

ALTER TABLE ONLY bulk_transform_operation_item
    ADD CONSTRAINT bulk_transform_operation_i_operation_id_item_index_key UNIQUE (operation_id, item_index);

ALTER TABLE ONLY bulk_transform_operation_item
    ADD CONSTRAINT bulk_transform_operation_item_pkey PRIMARY KEY (id);

ALTER TABLE ONLY bulk_transform_operation
    ADD CONSTRAINT bulk_transform_operation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY calendar_exception
    ADD CONSTRAINT calendar_exception_pkey PRIMARY KEY (id);

ALTER TABLE ONLY calendar_holiday
    ADD CONSTRAINT calendar_holiday_pkey PRIMARY KEY (id);

ALTER TABLE ONLY calendar
    ADD CONSTRAINT calendar_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cascade_deactivation
    ADD CONSTRAINT cascade_deactivation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY catalog_usage_rollup
    ADD CONSTRAINT catalog_usage_rollup_pkey PRIMARY KEY (entity_logicalname);

ALTER TABLE ONLY change_consumer_cursor
    ADD CONSTRAINT change_consumer_cursor_pkey PRIMARY KEY (consumer);

ALTER TABLE ONLY changeset_apply
    ADD CONSTRAINT changeset_apply_pkey PRIMARY KEY (id);

ALTER TABLE ONLY changeset_operation
    ADD CONSTRAINT changeset_operation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY changeset
    ADD CONSTRAINT changeset_pkey PRIMARY KEY (id);

ALTER TABLE ONLY data_domain
    ADD CONSTRAINT data_domain_pkey PRIMARY KEY (id);

ALTER TABLE ONLY data_export
    ADD CONSTRAINT data_export_pkey PRIMARY KEY (id);

ALTER TABLE ONLY data_mapping
    ADD CONSTRAINT data_mapping_pkey PRIMARY KEY (id);

ALTER TABLE ONLY data_profile
    ADD CONSTRAINT data_profile_pkey PRIMARY KEY (id);

ALTER TABLE ONLY data_step_run
    ADD CONSTRAINT data_step_run_pkey PRIMARY KEY (id);

ALTER TABLE ONLY document_folder
    ADD CONSTRAINT document_folder_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dsr_request
    ADD CONSTRAINT dsr_request_pkey PRIMARY KEY (id);

ALTER TABLE ONLY duplicate_candidate
    ADD CONSTRAINT duplicate_candidate_pkey PRIMARY KEY (id);

ALTER TABLE ONLY entity_change_event
    ADD CONSTRAINT entity_change_event_pkey PRIMARY KEY (id);

ALTER TABLE ONLY entity_default_share
    ADD CONSTRAINT entity_default_share_pkey PRIMARY KEY (id);

ALTER TABLE ONLY entity_info
    ADD CONSTRAINT entity_info_pkey PRIMARY KEY (id);

ALTER TABLE ONLY event_delivery
    ADD CONSTRAINT event_delivery_pkey PRIMARY KEY (id);

ALTER TABLE ONLY event_subscription
    ADD CONSTRAINT event_subscription_pkey PRIMARY KEY (id);

ALTER TABLE ONLY field_security_profile_field
    ADD CONSTRAINT field_security_profile_field_pkey PRIMARY KEY (id);

ALTER TABLE ONLY field_security_profile
    ADD CONSTRAINT field_security_profile_pkey PRIMARY KEY (id);

ALTER TABLE ONLY file_version
    ADD CONSTRAINT file_version_pkey PRIMARY KEY (id);

ALTER TABLE ONLY knowledge_chunk
    ADD CONSTRAINT knowledge_chunk_pkey PRIMARY KEY (id);

ALTER TABLE ONLY knowledge_chunk_retrieval
    ADD CONSTRAINT knowledge_chunk_retrieval_pkey PRIMARY KEY (id);

ALTER TABLE ONLY legal_hold
    ADD CONSTRAINT legal_hold_pkey PRIMARY KEY (id);

ALTER TABLE ONLY match_rule
    ADD CONSTRAINT match_rule_pkey PRIMARY KEY (id);

ALTER TABLE ONLY memory
    ADD CONSTRAINT memory_pkey PRIMARY KEY (id);

ALTER TABLE ONLY metadata_bundle_plan
    ADD CONSTRAINT metadata_bundle_plan_pkey PRIMARY KEY (id);

ALTER TABLE ONLY metadata_change_log
    ADD CONSTRAINT metadata_change_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY metadata_label_change_log
    ADD CONSTRAINT metadata_label_change_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY metadata_label
    ADD CONSTRAINT metadata_label_pkey PRIMARY KEY (id);

ALTER TABLE ONLY metadata_reference_backfill_progress
    ADD CONSTRAINT metadata_reference_backfill_progress_pkey PRIMARY KEY (kind);

ALTER TABLE ONLY metadata_reference
    ADD CONSTRAINT metadata_reference_pkey PRIMARY KEY (id);

ALTER TABLE ONLY module_configuration
    ADD CONSTRAINT module_configuration_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY organization
    ADD CONSTRAINT organization_pkey PRIMARY KEY (id);

ALTER TABLE ONLY outcome
    ADD CONSTRAINT outcome_pkey PRIMARY KEY (id);

ALTER TABLE ONLY position
    ADD CONSTRAINT position_pkey PRIMARY KEY (id);

ALTER TABLE ONLY privilege
    ADD CONSTRAINT privilege_pkey PRIMARY KEY (id);

ALTER TABLE ONLY quality_issue
    ADD CONSTRAINT quality_issue_entity_logicalname_period_dimension__key UNIQUE (entity_logicalname, period, dimension, record_id, field_logicalname);

ALTER TABLE ONLY quality_issue
    ADD CONSTRAINT quality_issue_pkey PRIMARY KEY (id);

ALTER TABLE ONLY quality_score
    ADD CONSTRAINT quality_score_entity_logicalname_period_dimension_key UNIQUE (entity_logicalname, period, dimension);

ALTER TABLE ONLY quality_score
    ADD CONSTRAINT quality_score_pkey PRIMARY KEY (id);

ALTER TABLE ONLY record_share
    ADD CONSTRAINT record_share_pkey PRIMARY KEY (id);

ALTER TABLE ONLY recovery_archive
    ADD CONSTRAINT recovery_archive_pkey PRIMARY KEY (id);

ALTER TABLE ONLY relationship_info
    ADD CONSTRAINT relationship_info_pkey PRIMARY KEY (id);

ALTER TABLE ONLY release_report_item
    ADD CONSTRAINT release_report_item_pkey PRIMARY KEY (id);

ALTER TABLE ONLY release_report
    ADD CONSTRAINT release_report_pkey PRIMARY KEY (id);

ALTER TABLE ONLY role_bulk_field
    ADD CONSTRAINT role_bulk_field_pkey PRIMARY KEY (role_ref, entity_logicalname, attribute_logicalname);

ALTER TABLE ONLY role_mm_entity_access
    ADD CONSTRAINT role_mm_entity_access_pkey PRIMARY KEY (id);

ALTER TABLE ONLY role_mm_field_security_profile
    ADD CONSTRAINT role_mm_field_security_profile_pkey PRIMARY KEY (id);

ALTER TABLE ONLY role_mm_privilege
    ADD CONSTRAINT role_mm_privilege_pkey PRIMARY KEY (id);

ALTER TABLE ONLY role_mm_team
    ADD CONSTRAINT role_mm_team_pkey PRIMARY KEY (id);

ALTER TABLE ONLY role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);

ALTER TABLE ONLY role_privilege_condition
    ADD CONSTRAINT role_privilege_condition_pkey PRIMARY KEY (id);

ALTER TABLE ONLY rule
    ADD CONSTRAINT rule_pkey PRIMARY KEY (id);

ALTER TABLE ONLY rule_policy
    ADD CONSTRAINT rule_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY rule_policy
    ADD CONSTRAINT rule_policy_rule_ref_ordinal_key UNIQUE (rule_ref, ordinal);

ALTER TABLE ONLY rule_role
    ADD CONSTRAINT rule_role_pkey PRIMARY KEY (id);

ALTER TABLE ONLY rule_version
    ADD CONSTRAINT rule_version_pkey PRIMARY KEY (id);

ALTER TABLE ONLY schema_change_operation
    ADD CONSTRAINT schema_change_operation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY search_impression
    ADD CONSTRAINT search_impression_pkey PRIMARY KEY (id);

ALTER TABLE ONLY search_impression_row
    ADD CONSTRAINT search_impression_row_pkey PRIMARY KEY (impression_ref, rank);

ALTER TABLE ONLY search_index
    ADD CONSTRAINT search_index_pkey PRIMARY KEY (corpus, entity_logicalname, record_id);

ALTER TABLE ONLY search_interaction
    ADD CONSTRAINT search_interaction_pkey PRIMARY KEY (id);

ALTER TABLE ONLY search_suggestion
    ADD CONSTRAINT search_suggestion_pkey PRIMARY KEY (id);

ALTER TABLE ONLY seed_watermark
    ADD CONSTRAINT seed_watermark_pkey PRIMARY KEY (module);

ALTER TABLE ONLY setting_change_log
    ADD CONSTRAINT setting_change_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY setting
    ADD CONSTRAINT setting_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sql_query_entity_mapping
    ADD CONSTRAINT sql_query_entity_mapping_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sql_query
    ADD CONSTRAINT sql_query_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sql_query_version
    ADD CONSTRAINT sql_query_version_pkey PRIMARY KEY (id);

ALTER TABLE ONLY state_model
    ADD CONSTRAINT state_model_pkey PRIMARY KEY (id);

ALTER TABLE ONLY state_transition
    ADD CONSTRAINT state_transition_pkey PRIMARY KEY (id);

ALTER TABLE ONLY survivorship_rule
    ADD CONSTRAINT survivorship_rule_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_account_mm_organization
    ADD CONSTRAINT user_account_mm_organization_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_account_mm_position
    ADD CONSTRAINT user_account_mm_position_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_account_mm_privilege
    ADD CONSTRAINT user_account_mm_privilege_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_account_mm_role
    ADD CONSTRAINT user_account_mm_role_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_account_mm_team
    ADD CONSTRAINT user_account_mm_team_pkey PRIMARY KEY (id);

ALTER TABLE ONLY team
    ADD CONSTRAINT team_pkey PRIMARY KEY (id);

ALTER TABLE ONLY upload_session
    ADD CONSTRAINT upload_session_pkey PRIMARY KEY (id);

ALTER TABLE ONLY view
    ADD CONSTRAINT view_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sidebar_mm_privilege
    ADD CONSTRAINT sidebar_mm_privilege_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sidebar
    ADD CONSTRAINT sidebar_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_session_token
    ADD CONSTRAINT webchat_session_pkey PRIMARY KEY (id);

CREATE INDEX IF NOT EXISTS action_invocation_session_idx ON action_invocation USING btree (agent_session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS agent_session_definition_idx ON agent_session USING btree (agent_definition_ref) WHERE (agent_definition_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS agent_session_live_idx ON agent_session USING btree (owner_user_id) WHERE ((ended_at IS NULL) AND (revoked_at IS NULL));

CREATE INDEX IF NOT EXISTS agent_session_paused_idx ON agent_session USING btree (owner_user_id) WHERE (paused_at IS NOT NULL);

CREATE INDEX IF NOT EXISTS audit_signing_key_key_id_idx ON audit_signing_key USING btree (key_id);

CREATE INDEX IF NOT EXISTS core_access_review_due_sweep_idx ON access_review USING btree (status, due_date) WHERE ((is_deleted = false) AND (status = 'active'::text));

CREATE INDEX IF NOT EXISTS core_access_review_item_review_ref_idx ON access_review_item USING btree (review_ref);

CREATE INDEX IF NOT EXISTS core_access_review_item_subject_ref_idx ON access_review_item USING btree (subject_user_ref);

CREATE INDEX IF NOT EXISTS core_app_display_order_idx ON app USING btree (display_order) WHERE ((is_deleted = false) AND (is_active = true));

CREATE UNIQUE INDEX IF NOT EXISTS core_app_name_idx ON app USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_attribute_info_active_logicalname_unique ON attribute_info USING btree (entity_ref, logicalname) WHERE ((is_active IS NULL) OR (is_active = true));

CREATE INDEX IF NOT EXISTS core_entity_change_event_feed_idx ON entity_change_event USING btree (commit_xid, id);

CREATE INDEX IF NOT EXISTS core_entity_change_event_pending_idx ON entity_change_event USING btree (created_at) WHERE (processed_at IS NULL);

CREATE INDEX IF NOT EXISTS core_entity_default_share_entity_idx ON entity_default_share USING btree (entity_ref);

CREATE INDEX IF NOT EXISTS core_entity_default_share_principal_idx ON entity_default_share USING btree (principal_id, entity_ref);

CREATE UNIQUE INDEX IF NOT EXISTS core_entity_info_active_logicalname_unique ON entity_info USING btree (logicalname) WHERE ((is_active IS NULL) OR (is_active = true));

CREATE INDEX IF NOT EXISTS core_event_delivery_status_idx ON event_delivery USING btree (status) WHERE (status = ANY (ARRAY['failed'::text, 'dead_letter'::text]));

CREATE INDEX IF NOT EXISTS core_event_delivery_subscription_idx ON event_delivery USING btree (subscription_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS core_event_subscription_active_idx ON event_subscription USING btree (kind) WHERE ((is_deleted = false) AND (is_active = true));

CREATE INDEX IF NOT EXISTS core_field_security_profile_field_profile_ref_idx ON field_security_profile_field USING btree (profile_ref);

CREATE UNIQUE INDEX IF NOT EXISTS core_field_security_profile_name_active_unique ON field_security_profile USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_file_version_one_current_idx ON file_version USING btree (entity, record_id, field) WHERE ((is_current = true) AND (is_deleted = false));

CREATE INDEX IF NOT EXISTS core_file_version_scope_idx ON file_version USING btree (entity, record_id, field);

CREATE INDEX IF NOT EXISTS core_file_version_uploaded_by_idx ON file_version USING btree (uploaded_by);

CREATE UNIQUE INDEX IF NOT EXISTS core_position_name_active_unique ON position USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_position_parent_ref_idx ON position USING btree (parent_position_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_record_share_principal_idx ON record_share USING btree (principal_id, entity_ref);

CREATE INDEX IF NOT EXISTS core_record_share_record_lookup_idx ON record_share USING btree (record_id, entity_ref, principal_id, capability);

CREATE INDEX IF NOT EXISTS core_relationship_info_entity_a_idx ON relationship_info USING btree (entity_a) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_relationship_info_entity_b_idx ON relationship_info USING btree (entity_b) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_relationship_info_join_table_idx ON relationship_info USING btree (join_table) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_relationship_info_name_idx ON relationship_info USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_role_mm_entity_access_role_entity_idx ON role_mm_entity_access USING btree (role_ref, entity_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_role_mm_field_security_profile_role_ref_idx ON role_mm_field_security_profile USING btree (role_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_role_mm_privilege_role_ref_idx ON role_mm_privilege USING btree (role_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_role_mm_team_role_ref_idx ON role_mm_team USING btree (role_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_role_mm_team_team_ref_idx ON role_mm_team USING btree (team_ref) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_role_name_active_unique ON role USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_role_privilege_condition_grant_idx ON role_privilege_condition USING btree (role_privilege_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_rule_entity_idx ON rule USING btree (entity_logicalname) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_rule_entity_name_idx ON rule USING btree (entity_logicalname, name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_rule_policy_field_idx ON rule_policy USING btree (field_logicalname);

CREATE INDEX IF NOT EXISTS core_rule_role_portal_idx ON rule_role USING btree (portal_role_ref);

CREATE UNIQUE INDEX IF NOT EXISTS core_rule_role_portal_uq ON rule_role USING btree (rule_ref, portal_role_ref) WHERE (portal_role_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS core_rule_role_role_idx ON rule_role USING btree (role_ref);

CREATE UNIQUE INDEX IF NOT EXISTS core_rule_role_staff_uq ON rule_role USING btree (rule_ref, role_ref) WHERE (role_ref IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS core_rule_version_rule_version_idx ON rule_version USING btree (rule_id, version);

CREATE INDEX IF NOT EXISTS core_sql_query_entity_mapping_version_idx ON sql_query_entity_mapping USING btree (query_version_id);

CREATE UNIQUE INDEX IF NOT EXISTS core_state_model_entity_active_idx ON state_model USING btree (entity_logicalname) WHERE ((is_deleted = false) AND (is_active = true));

CREATE INDEX IF NOT EXISTS core_state_model_entity_idx ON state_model USING btree (entity_logicalname) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_state_transition_edge_idx ON state_transition USING btree (model_ref, from_state, to_state) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_state_transition_model_idx ON state_transition USING btree (model_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_organization_org_ref_idx ON user_account_mm_organization USING btree (organization_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_organization_user_ref_idx ON user_account_mm_organization USING btree (user_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_position_position_ref_idx ON user_account_mm_position USING btree (position_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_position_user_ref_idx ON user_account_mm_position USING btree (user_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_role_role_ref_idx ON user_account_mm_role USING btree (role_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_role_user_ref_idx ON user_account_mm_role USING btree (user_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_team_team_ref_idx ON user_account_mm_team USING btree (team_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_systemuser_mm_team_user_ref_idx ON user_account_mm_team USING btree (user_ref) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS core_team_name_active_unique ON team USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS core_upload_session_clean_total_idx ON upload_session USING btree (status) INCLUDE (actual_size_bytes) WHERE ((is_deleted = false) AND (status = 'clean'::text));

CREATE INDEX IF NOT EXISTS core_upload_session_in_flight_idx ON upload_session USING btree (created_at) WHERE (status = ANY (ARRAY['pending'::text, 'uploaded'::text, 'scanning'::text]));

CREATE INDEX IF NOT EXISTS core_upload_session_owner_idx ON upload_session USING btree (owner_user_ref);

CREATE INDEX IF NOT EXISTS core_upload_session_owner_quota_idx ON upload_session USING btree (owner_user_ref, status) INCLUDE (declared_max_size_bytes, actual_size_bytes) WHERE ((is_deleted = false) AND (status = ANY (ARRAY['pending'::text, 'uploaded'::text, 'scanning'::text, 'clean'::text])));

CREATE INDEX IF NOT EXISTS core_upload_session_portal_owner_quota_idx ON upload_session USING btree (owner_portal_user_ref, status) INCLUDE (declared_max_size_bytes, actual_size_bytes) WHERE ((owner_portal_user_ref IS NOT NULL) AND (is_deleted = false) AND (status = ANY (ARRAY['pending'::text, 'uploaded'::text, 'scanning'::text, 'clean'::text])));

CREATE INDEX IF NOT EXISTS core_upload_session_scope_idx ON upload_session USING btree (entity_logicalname, record_id, field_logicalname, status);

CREATE INDEX IF NOT EXISTS document_folder_record_idx ON document_folder USING btree (entity_name, record_id);

CREATE INDEX IF NOT EXISTS idx_cascade_deactivation_parent ON cascade_deactivation USING btree (parent_record_id, dependent_entity, dependent_field);

CREATE INDEX IF NOT EXISTS idx_core_approval_delegation_from_user ON approval_delegation USING btree (from_user, valid_from, valid_to) WHERE (NOT is_deleted);

CREATE INDEX IF NOT EXISTS idx_core_approval_delegation_to_user ON approval_delegation USING btree (to_user) WHERE (NOT is_deleted);

CREATE INDEX IF NOT EXISTS idx_core_approval_policy_action_type ON approval_policy USING btree (action_type) WHERE (NOT is_deleted);

CREATE INDEX IF NOT EXISTS idx_core_archive_record_archived_at ON archive_record USING btree (archived_at DESC) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_core_archive_record_entity_record ON archive_record USING btree (entity_logicalname, record_id) WHERE ((is_deleted = false) AND (restored_at IS NULL));

CREATE INDEX IF NOT EXISTS idx_core_attribute_info_entity_ref ON attribute_info USING btree (entity_ref) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_core_bulk_transform_operation_created_by ON bulk_transform_operation USING btree (created_by, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_bulk_transform_operation_item_status ON bulk_transform_operation_item USING btree (operation_id, status, item_index);

CREATE INDEX IF NOT EXISTS idx_core_calendar_active ON calendar USING btree (is_active);

CREATE INDEX IF NOT EXISTS idx_core_calendar_holiday_calendar ON calendar_holiday USING btree (calendar_id) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_core_changeset_apply_layer ON changeset_apply USING btree (layer, scope, seq);

CREATE INDEX IF NOT EXISTS idx_core_changeset_apply_report ON changeset_apply USING btree (report_ref) WHERE (report_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_core_changeset_apply_status ON changeset_apply USING btree (status);

CREATE INDEX IF NOT EXISTS idx_core_changeset_listing ON changeset USING btree (layer, scope, opened_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_changeset_open_author ON changeset USING btree (author_ref) WHERE (status = 'open'::text);

CREATE INDEX IF NOT EXISTS idx_core_data_domain_name ON data_domain USING btree (name) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_core_data_export_created_by ON data_export USING btree (created_by, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_data_export_pending ON data_export USING btree (created_by, status) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));

CREATE INDEX IF NOT EXISTS idx_core_data_mapping_target_entity ON data_mapping USING btree (target_entity) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_core_data_profile_entity ON data_profile USING btree (entity_logicalname, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_data_step_run_entity ON data_step_run USING btree (entity_logicalname, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_data_step_run_live ON data_step_run USING btree (status) WHERE (status = ANY (ARRAY['queued'::text, 'claimed'::text, 'running'::text]));

CREATE INDEX IF NOT EXISTS idx_core_dsr_request_status ON dsr_request USING btree (status, requested_at DESC) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_core_dsr_request_subject ON dsr_request USING btree (subject_reference) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_core_duplicate_candidate_entity_status ON duplicate_candidate USING btree (entity_logicalname, status);

CREATE INDEX IF NOT EXISTS idx_core_entity_info_domain_ref ON entity_info USING btree (domain_ref) WHERE (domain_ref IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_core_entity_info_logicalname ON entity_info USING btree (logicalname) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_core_legal_hold_active ON legal_hold USING btree (entity_logicalname, record_id) WHERE ((released_at IS NULL) AND (is_deleted = false));

CREATE INDEX IF NOT EXISTS idx_core_legal_hold_active_placed_at ON legal_hold USING btree (placed_at DESC) WHERE ((released_at IS NULL) AND (is_deleted = false));

CREATE INDEX IF NOT EXISTS idx_core_match_rule_entity_active ON match_rule USING btree (entity_logicalname) WHERE (is_active AND (NOT is_deleted));

CREATE INDEX IF NOT EXISTS idx_core_metadata_bundle_plan_created ON metadata_bundle_plan USING btree (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_metadata_bundle_plan_status ON metadata_bundle_plan USING btree (status);

CREATE INDEX IF NOT EXISTS idx_core_metadata_change_log_created ON metadata_change_log USING btree (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_core_metadata_reference_from ON metadata_reference USING btree (from_kind, from_ref);

CREATE INDEX IF NOT EXISTS idx_core_metadata_reference_to_entity ON metadata_reference USING btree (to_entity, to_attribute);

CREATE INDEX IF NOT EXISTS idx_core_quality_issue_entity_dimension_status ON quality_issue USING btree (entity_logicalname, dimension, status, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_quality_score_entity_dimension ON quality_score USING btree (entity_logicalname, dimension, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_recovery_archive_expiry ON recovery_archive USING btree (expires_at);

CREATE INDEX IF NOT EXISTS idx_core_recovery_archive_field ON recovery_archive USING btree (entity_logicalname, field_logicalname, archived_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_recovery_archive_record ON recovery_archive USING btree (entity_logicalname, record_id);

CREATE INDEX IF NOT EXISTS idx_core_release_item_open ON release_report_item USING btree (entity_logicalname, field_logicalname, record_id) WHERE (status = 'open'::text);

CREATE INDEX IF NOT EXISTS idx_core_release_item_record ON release_report_item USING btree (entity_logicalname, record_id) WHERE (record_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_core_release_item_report ON release_report_item USING btree (report_ref, kind);

CREATE INDEX IF NOT EXISTS idx_core_release_report_created ON release_report USING btree (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_core_retention_action_status ON audit_retention_action USING btree (status, proposed_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_core_retention_action_target ON audit_retention_action USING btree (action_type, target) WHERE (status <> 'rejected'::text);

CREATE INDEX IF NOT EXISTS idx_core_schema_change_operation_attribute ON schema_change_operation USING btree (attribute_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_core_sql_query_entity_logical_name ON sql_query USING btree (entity_logical_name) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_core_sql_query_version_current ON sql_query_version USING btree (query_id, id DESC);

CREATE INDEX IF NOT EXISTS idx_core_systemuser_mm_privilege_user_ref ON user_account_mm_privilege USING btree (user_ref) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_core_view_owner ON view USING btree (owner_ref) WHERE ((scope)::text = 'personal'::text);

CREATE INDEX IF NOT EXISTS idx_core_view_query ON view USING btree (sql_query_ref) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_knowledge_chunk_retrieval_chunk_time ON knowledge_chunk_retrieval USING btree (chunk_ref, retrieved_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_xrm_core_agent_session_token_agent_session_id ON agent_session_token USING btree (agent_session_id);

CREATE INDEX IF NOT EXISTS idx_xrm_sidebar_active ON sidebar USING btree (is_active) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_sidebar_parent_ref ON sidebar USING btree (parent_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_sidebar_privilege_privilege ON sidebar_mm_privilege USING btree (privilege_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS idx_xrm_sidebar_privilege_sidebar ON sidebar_mm_privilege USING btree (sidebar_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS knowledge_chunk_embedding_hnsw ON knowledge_chunk USING hnsw (embedding halfvec_cosine_ops) WHERE ((embedding IS NOT NULL) AND (lifecycle = 'published'::text));

CREATE INDEX IF NOT EXISTS knowledge_chunk_parent_idx ON knowledge_chunk USING btree (parent_entity, parent_record_id) WHERE (parent_record_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS knowledge_chunk_published_idx ON knowledge_chunk USING btree (collection_ref) WHERE (lifecycle = 'published'::text);

CREATE INDEX IF NOT EXISTS knowledge_chunk_source_idx ON knowledge_chunk USING btree (source_type, source_id);

CREATE INDEX IF NOT EXISTS knowledge_chunk_tsv_idx ON knowledge_chunk USING gin (tsv) WITH (fastupdate=off) WHERE (lifecycle = 'published'::text);

CREATE INDEX IF NOT EXISTS memory_agent_idx ON memory USING btree (owner_principal, scope_ref) WHERE (scope_kind = 'agent'::text);

CREATE INDEX IF NOT EXISTS memory_conversation_idx ON memory USING btree (owner_principal, scope_ref) WHERE (scope_kind = 'conversation'::text);

CREATE INDEX IF NOT EXISTS memory_created_at_idx ON memory USING btree (created_at);

CREATE INDEX IF NOT EXISTS memory_decision_idx ON memory USING btree (owner_principal, scope_ref) WHERE (scope_kind = 'decision'::text);

CREATE INDEX IF NOT EXISTS memory_embedding_hnsw ON memory USING hnsw (embedding halfvec_cosine_ops) WHERE (embedding IS NOT NULL);

CREATE INDEX IF NOT EXISTS memory_entity_parent_idx ON memory USING btree (parent_entity, parent_record_id) WHERE (scope_kind = 'entity'::text);

CREATE INDEX IF NOT EXISTS memory_organization_idx ON memory USING btree (owner_principal, scope_ref) WHERE (scope_kind = 'organization'::text);

CREATE INDEX IF NOT EXISTS memory_owner_scope_idx ON memory USING btree (owner_principal, scope_kind);

CREATE INDEX IF NOT EXISTS memory_tsv_idx ON memory USING gin (tsv);

CREATE INDEX IF NOT EXISTS memory_workflow_idx ON memory USING btree (owner_principal, scope_ref) WHERE (scope_kind = 'workflow'::text);

CREATE INDEX IF NOT EXISTS search_index_embedding_hnsw ON search_index USING hnsw (embedding halfvec_cosine_ops) WHERE (embedding IS NOT NULL);

CREATE INDEX IF NOT EXISTS search_index_embedding_sparse_hnsw ON search_index USING hnsw (embedding_sparse sparsevec_ip_ops) WHERE (embedding_sparse IS NOT NULL);

CREATE INDEX IF NOT EXISTS search_index_unembedded_idx ON search_index USING btree (corpus, entity_logicalname) WHERE (embedding IS NULL);

CREATE UNIQUE INDEX IF NOT EXISTS uq_action_invocation_tool_call ON action_invocation USING btree (agent_session_id, tool_call_id) WHERE (tool_call_id IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_approval_policy_action_type ON approval_policy USING btree (action_type) WHERE (is_active AND (NOT is_deleted));

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_calendar_default ON calendar USING btree ((true)) WHERE ((is_default = true) AND (is_active = true));

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_calendar_exception_date ON calendar_exception USING btree (calendar_id, exception_date) WHERE (is_active = true);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_calendar_holiday_date ON calendar_holiday USING btree (calendar_id, holiday_date) WHERE (is_active = true);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_changeset_open_name ON changeset USING btree (layer, scope, name) WHERE (status = 'open'::text);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_data_mapping_name ON data_mapping USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_data_step_run_op ON data_step_run USING btree (changeset_id, op_seq) WHERE (changeset_id IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_duplicate_candidate_pair ON duplicate_candidate USING btree (entity_logicalname, record_a, record_b);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_metadata_reference_triple ON metadata_reference USING btree (from_kind, from_ref, to_entity, to_attribute);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_recovery_archive_run_record ON recovery_archive USING btree (run_ref, record_id) WHERE (run_ref IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_sql_query_entity_name ON sql_query USING btree (entity_logical_name, record_no) WHERE (((is_active IS NULL) OR (is_active = true)) AND (record_no IS NOT NULL) AND ((record_no)::text <> ''::text));

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_survivorship_rule_entity_field ON survivorship_rule USING btree (entity_logicalname, field_logicalname) WHERE (NOT is_deleted);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_view_default_per_entity ON view USING btree (entity_logical_name) WHERE ((is_default = true) AND (is_active = true));

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_view_name_personal ON view USING btree (entity_logical_name, name, owner_ref) WHERE ((scope)::text = 'personal'::text);

CREATE UNIQUE INDEX IF NOT EXISTS uq_core_view_name_shared ON view USING btree (entity_logical_name, name) WHERE ((scope)::text = ANY ((ARRAY['system'::character varying, 'shared'::character varying])::text[]));

CREATE UNIQUE INDEX IF NOT EXISTS uq_xrm_sidebar_parent_name ON sidebar USING btree (parent_ref, name) NULLS NOT DISTINCT WHERE ((is_active = true) AND (is_deleted = false));

CREATE UNIQUE INDEX IF NOT EXISTS metadata_label_key_uk ON metadata_label USING btree (object_kind, object_ref, locale) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS metadata_label_object_ref_idx ON metadata_label USING btree (object_kind, object_ref) WHERE (is_deleted = false);

CREATE INDEX IF NOT EXISTS outcome_kind_source_idx ON outcome USING btree (kind, source_module, proposed_at DESC);

CREATE INDEX IF NOT EXISTS outcome_regarding_idx ON outcome USING btree (regarding_entity, regarding_id) WHERE (regarding_entity IS NOT NULL);

CREATE INDEX IF NOT EXISTS outcome_unmeasured_idx ON outcome USING btree (proposed_at) WHERE (measured_at IS NULL);

CREATE INDEX IF NOT EXISTS search_impression_fingerprint_idx ON search_impression USING btree (query_fingerprint, created_at DESC);

CREATE INDEX IF NOT EXISTS search_impression_ranker_idx ON search_impression USING btree (ranker_id, created_at DESC);

CREATE INDEX IF NOT EXISTS search_index_entity_modified_idx ON search_index USING btree (entity_logicalname, source_modifiedon DESC);

CREATE INDEX IF NOT EXISTS search_index_exact_keys_idx ON search_index USING gin (exact_keys) WITH (fastupdate=off);

CREATE INDEX IF NOT EXISTS search_index_org_idx ON search_index USING btree (organization_ref);

CREATE INDEX IF NOT EXISTS search_index_title_prefix_idx ON search_index USING btree (title_norm text_pattern_ops);

CREATE INDEX IF NOT EXISTS search_index_title_trgm_idx ON search_index USING gin (title_norm gin_trgm_ops) WITH (fastupdate=off);

CREATE INDEX IF NOT EXISTS search_index_tsv_idx ON search_index USING gin (tsv) WITH (fastupdate=off);

CREATE INDEX IF NOT EXISTS search_interaction_impression_idx ON search_interaction USING btree (impression_ref);

CREATE INDEX IF NOT EXISTS search_suggestion_prefix_idx ON search_suggestion USING btree (suggestion_norm text_pattern_ops);

CREATE INDEX IF NOT EXISTS search_suggestion_record_idx ON search_suggestion USING btree (entity_logicalname, record_id) WHERE (record_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS search_suggestion_trgm_idx ON search_suggestion USING gin (suggestion_norm gin_trgm_ops) WITH (fastupdate=off);

CREATE INDEX IF NOT EXISTS setting_key_idx ON setting USING btree (key) WHERE (is_deleted = false);

CREATE UNIQUE INDEX IF NOT EXISTS setting_key_scope_ref_uk ON setting USING btree (key, scope, COALESCE(scope_ref, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE (is_deleted = false);

CREATE OR REPLACE TRIGGER role_sync_lifecycle_flags BEFORE INSERT OR UPDATE ON role FOR EACH ROW EXECUTE FUNCTION role_sync_lifecycle_flags();

ALTER TABLE ONLY agent_session_token
    ADD CONSTRAINT agent_session_token_session_fk FOREIGN KEY (agent_session_id) REFERENCES agent_session(id) ON DELETE CASCADE;

ALTER TABLE ONLY attribute_info
    ADD CONSTRAINT core_attribute_info_lookup_entity_ref_fkey FOREIGN KEY (lookup_entity_ref) REFERENCES entity_info(id) ON DELETE RESTRICT;

ALTER TABLE ONLY access_review
    ADD CONSTRAINT access_review_created_by_fkey FOREIGN KEY (created_by) REFERENCES user_account(id);

ALTER TABLE ONLY access_review_item
    ADD CONSTRAINT access_review_item_approval_request_ref_fkey FOREIGN KEY (approval_request_ref) REFERENCES approval_request(id);

ALTER TABLE ONLY access_review_item
    ADD CONSTRAINT access_review_item_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES user_account(id);

ALTER TABLE ONLY access_review_item
    ADD CONSTRAINT access_review_item_review_ref_fkey FOREIGN KEY (review_ref) REFERENCES access_review(id) ON DELETE CASCADE;

ALTER TABLE ONLY access_review_item
    ADD CONSTRAINT access_review_item_reviewer_user_ref_fkey FOREIGN KEY (reviewer_user_ref) REFERENCES user_account(id);

ALTER TABLE ONLY access_review_item
    ADD CONSTRAINT access_review_item_subject_user_ref_fkey FOREIGN KEY (subject_user_ref) REFERENCES user_account(id);

ALTER TABLE ONLY access_review
    ADD CONSTRAINT access_review_scope_entity_ref_fkey FOREIGN KEY (scope_entity_ref) REFERENCES entity_info(id);

ALTER TABLE ONLY access_review
    ADD CONSTRAINT access_review_scope_role_ref_fkey FOREIGN KEY (scope_role_ref) REFERENCES role(id);

ALTER TABLE ONLY access_review
    ADD CONSTRAINT access_review_scope_team_ref_fkey FOREIGN KEY (scope_team_ref) REFERENCES team(id);

ALTER TABLE ONLY action_invocation
    ADD CONSTRAINT action_invocation_agent_session_id_fkey FOREIGN KEY (agent_session_id) REFERENCES agent_session(id) ON DELETE CASCADE;

ALTER TABLE ONLY app
    ADD CONSTRAINT app_sidebar_root_ref_fkey FOREIGN KEY (sidebar_root_ref) REFERENCES sidebar(id);

ALTER TABLE ONLY bulk_transform_operation_item
    ADD CONSTRAINT bulk_transform_operation_item_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES bulk_transform_operation(id);

ALTER TABLE ONLY calendar_exception
    ADD CONSTRAINT calendar_exception_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES calendar(id) ON DELETE CASCADE;

ALTER TABLE ONLY calendar_holiday
    ADD CONSTRAINT calendar_holiday_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES calendar(id) ON DELETE CASCADE;

ALTER TABLE ONLY changeset_operation
    ADD CONSTRAINT changeset_operation_changeset_ref_fkey FOREIGN KEY (changeset_ref) REFERENCES changeset(id);

ALTER TABLE ONLY data_step_run
    ADD CONSTRAINT data_step_run_apply_ref_fkey FOREIGN KEY (apply_ref) REFERENCES changeset_apply(id);

ALTER TABLE ONLY duplicate_candidate
    ADD CONSTRAINT duplicate_candidate_match_rule_id_fkey FOREIGN KEY (match_rule_id) REFERENCES match_rule(id);

ALTER TABLE ONLY entity_default_share
    ADD CONSTRAINT entity_default_share_entity_ref_fkey FOREIGN KEY (entity_ref) REFERENCES entity_info(id) ON DELETE CASCADE;

ALTER TABLE ONLY event_delivery
    ADD CONSTRAINT event_delivery_subscription_ref_fkey FOREIGN KEY (subscription_ref) REFERENCES event_subscription(id) ON DELETE CASCADE;

ALTER TABLE ONLY event_subscription
    ADD CONSTRAINT event_subscription_created_by_fkey FOREIGN KEY (created_by) REFERENCES user_account(id);

ALTER TABLE ONLY event_subscription
    ADD CONSTRAINT event_subscription_owner_ref_fkey FOREIGN KEY (owner_ref) REFERENCES user_account(id);

ALTER TABLE ONLY field_security_profile_field
    ADD CONSTRAINT field_security_profile_field_profile_ref_fkey FOREIGN KEY (profile_ref) REFERENCES field_security_profile(id) ON DELETE CASCADE;

ALTER TABLE ONLY file_version
    ADD CONSTRAINT file_version_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES user_account(id);

ALTER TABLE ONLY knowledge_chunk_retrieval
    ADD CONSTRAINT knowledge_chunk_retrieval_chunk_ref_fkey FOREIGN KEY (chunk_ref) REFERENCES knowledge_chunk(id) ON DELETE CASCADE;

ALTER TABLE ONLY memory
    ADD CONSTRAINT memory_owner_principal_fkey FOREIGN KEY (owner_principal) REFERENCES user_account(id);

ALTER TABLE ONLY position
    ADD CONSTRAINT position_parent_position_ref_fkey FOREIGN KEY (parent_position_ref) REFERENCES position(id);

ALTER TABLE ONLY record_share
    ADD CONSTRAINT record_share_entity_ref_fkey FOREIGN KEY (entity_ref) REFERENCES entity_info(id) ON DELETE CASCADE;

ALTER TABLE ONLY recovery_archive
    ADD CONSTRAINT recovery_archive_run_ref_fkey FOREIGN KEY (run_ref) REFERENCES data_step_run(id);

ALTER TABLE ONLY release_report_item
    ADD CONSTRAINT release_report_item_report_ref_fkey FOREIGN KEY (report_ref) REFERENCES release_report(id);

ALTER TABLE ONLY release_report_item
    ADD CONSTRAINT release_report_item_superseded_by_fkey FOREIGN KEY (superseded_by) REFERENCES release_report_item(id);

ALTER TABLE ONLY role_bulk_field
    ADD CONSTRAINT role_bulk_field_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_entity_access
    ADD CONSTRAINT role_mm_entity_access_entity_ref_fkey FOREIGN KEY (entity_ref) REFERENCES entity_info(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_entity_access
    ADD CONSTRAINT role_mm_entity_access_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_field_security_profile
    ADD CONSTRAINT role_mm_field_security_profile_profile_ref_fkey FOREIGN KEY (profile_ref) REFERENCES field_security_profile(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_field_security_profile
    ADD CONSTRAINT role_mm_field_security_profile_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_privilege
    ADD CONSTRAINT role_mm_privilege_privilege_ref_fkey FOREIGN KEY (privilege_ref) REFERENCES privilege(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_privilege
    ADD CONSTRAINT role_mm_privilege_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_team
    ADD CONSTRAINT role_mm_team_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_mm_team
    ADD CONSTRAINT role_mm_team_team_ref_fkey FOREIGN KEY (team_ref) REFERENCES team(id) ON DELETE CASCADE;

ALTER TABLE ONLY role_privilege_condition
    ADD CONSTRAINT role_privilege_condition_role_privilege_ref_fkey FOREIGN KEY (role_privilege_ref) REFERENCES role_mm_privilege(id) ON DELETE CASCADE;

ALTER TABLE ONLY rule_policy
    ADD CONSTRAINT rule_policy_rule_ref_fkey FOREIGN KEY (rule_ref) REFERENCES rule(id) ON DELETE CASCADE;

ALTER TABLE ONLY rule_role
    ADD CONSTRAINT rule_role_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY rule_role
    ADD CONSTRAINT rule_role_rule_ref_fkey FOREIGN KEY (rule_ref) REFERENCES rule(id) ON DELETE CASCADE;

ALTER TABLE ONLY rule_version
    ADD CONSTRAINT rule_version_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES rule(id);

ALTER TABLE ONLY search_impression_row
    ADD CONSTRAINT search_impression_row_impression_ref_fkey FOREIGN KEY (impression_ref) REFERENCES search_impression(id) ON DELETE CASCADE;

ALTER TABLE ONLY search_interaction
    ADD CONSTRAINT search_interaction_impression_ref_fkey FOREIGN KEY (impression_ref) REFERENCES search_impression(id) ON DELETE CASCADE;

ALTER TABLE ONLY sql_query_entity_mapping
    ADD CONSTRAINT sql_query_entity_mapping_entity_ref_fkey FOREIGN KEY (entity_ref) REFERENCES entity_info(id);

ALTER TABLE ONLY sql_query_entity_mapping
    ADD CONSTRAINT sql_query_entity_mapping_query_version_id_fkey FOREIGN KEY (query_version_id) REFERENCES sql_query_version(id);

ALTER TABLE ONLY sql_query_version
    ADD CONSTRAINT sql_query_version_query_id_fkey FOREIGN KEY (query_id) REFERENCES sql_query(id);

ALTER TABLE ONLY state_transition
    ADD CONSTRAINT state_transition_model_ref_fkey FOREIGN KEY (model_ref) REFERENCES state_model(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_organization
    ADD CONSTRAINT user_account_mm_organization_organization_ref_fkey FOREIGN KEY (organization_ref) REFERENCES organization(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_organization
    ADD CONSTRAINT user_account_mm_organization_user_ref_fkey FOREIGN KEY (user_ref) REFERENCES user_account(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_position
    ADD CONSTRAINT user_account_mm_position_position_ref_fkey FOREIGN KEY (position_ref) REFERENCES position(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_position
    ADD CONSTRAINT user_account_mm_position_user_ref_fkey FOREIGN KEY (user_ref) REFERENCES user_account(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_role
    ADD CONSTRAINT user_account_mm_role_role_ref_fkey FOREIGN KEY (role_ref) REFERENCES role(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_role
    ADD CONSTRAINT user_account_mm_role_user_ref_fkey FOREIGN KEY (user_ref) REFERENCES user_account(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_team
    ADD CONSTRAINT user_account_mm_team_team_ref_fkey FOREIGN KEY (team_ref) REFERENCES team(id) ON DELETE CASCADE;

ALTER TABLE ONLY user_account_mm_team
    ADD CONSTRAINT user_account_mm_team_user_ref_fkey FOREIGN KEY (user_ref) REFERENCES user_account(id) ON DELETE CASCADE;

ALTER TABLE ONLY upload_session
    ADD CONSTRAINT upload_session_owner_user_ref_fkey FOREIGN KEY (owner_user_ref) REFERENCES user_account(id);

ALTER TABLE ONLY view
    ADD CONSTRAINT view_entity_logical_name_fkey FOREIGN KEY (entity_logical_name) REFERENCES entity_info(id);

ALTER TABLE ONLY view
    ADD CONSTRAINT view_owner_ref_fkey FOREIGN KEY (owner_ref) REFERENCES user_account(id);

ALTER TABLE ONLY view
    ADD CONSTRAINT view_sql_query_ref_fkey FOREIGN KEY (sql_query_ref) REFERENCES sql_query(id);

ALTER TABLE ONLY sidebar_mm_privilege
    ADD CONSTRAINT sidebar_mm_privilege_privilege_ref_fkey FOREIGN KEY (privilege_ref) REFERENCES privilege(id) ON DELETE CASCADE;

ALTER TABLE ONLY sidebar_mm_privilege
    ADD CONSTRAINT sidebar_mm_privilege_sidebar_ref_fkey FOREIGN KEY (sidebar_ref) REFERENCES sidebar(id) ON DELETE CASCADE;

ALTER TABLE ONLY sidebar
    ADD CONSTRAINT sidebar_parent_ref_fkey FOREIGN KEY (parent_ref) REFERENCES sidebar(id);

ALTER SEQUENCE metadata_change_log_id_seq OWNED BY metadata_change_log.id;

ALTER SEQUENCE metadata_label_change_log_id_seq OWNED BY metadata_label_change_log.id;

ALTER SEQUENCE setting_change_log_id_seq OWNED BY setting_change_log.id;
