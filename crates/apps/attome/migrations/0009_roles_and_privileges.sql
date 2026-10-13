-- The three database roles and every privilege they hold. v1 built this up
-- across its migrations 0010, 0018, 0023, 0042, 0046, 0050, 0052, 0063, 0065,
-- 0072, 0095-0100, 0123, 0136 and the per-table grants after them; the v2
-- baseline (0001-0008) carried the tables but not the roles. This migration
-- is v1's final privilege state, with v2 table names (V2-D483).
--
--   attome_readonly  SELECT only. Behind /api/v1/query/execute and the read
--                    pool; a stored query can read at most what is granted
--                    here. Never the credential columns.
--   attome_runtime   DML only: request-time record CRUD, no DDL.
--   attome_migrator  DDL-capable: owns the schema's tables and provisions
--                    entity tables.
--
-- All three are created NOLOGIN. The boot-time role seeds apply LOGIN and the
-- configured password, so no credential is checked in and rotation takes
-- effect on restart. Idempotent. current_database() and current_schema() are
-- used throughout, never literal names.
--
-- Not carried over from v1: `ALTER ROLE CURRENT_USER SET statement_timeout`
-- and its siblings. They applied to whichever role ran the migration, and
-- slowed every later migration and seed for it. The timeouts belong to the
-- three roles below.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_readonly') THEN
        CREATE ROLE attome_readonly WITH NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_migrator') THEN
        CREATE ROLE attome_migrator WITH NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_runtime') THEN
        CREATE ROLE attome_runtime WITH NOLOGIN;
    END IF;
END
$$;

DO $$
DECLARE
    target_schema text := current_schema();
    rec RECORD;
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO attome_readonly, attome_migrator, attome_runtime', current_database());
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO attome_readonly, attome_runtime', target_schema);
    EXECUTE format('GRANT USAGE, CREATE ON SCHEMA %I TO attome_migrator', target_schema);

    -- The migrator owns the schema's tables, sequences and views, so it can
    -- ALTER them when an entity evolves. A per-object loop, never
    -- REASSIGN OWNED: that refuses when the bootstrap role also owns the
    -- database itself, which is the ordinary self-hosted setup.
    IF current_user <> 'attome_migrator' THEN
        FOR rec IN
            SELECT tablename AS relname FROM pg_catalog.pg_tables
            WHERE schemaname = target_schema AND tableowner = current_user
        LOOP
            EXECUTE format('ALTER TABLE %I.%I OWNER TO attome_migrator', target_schema, rec.relname);
        END LOOP;
        FOR rec IN
            SELECT sequencename AS relname FROM pg_catalog.pg_sequences
            WHERE schemaname = target_schema AND sequenceowner = current_user
        LOOP
            EXECUTE format('ALTER SEQUENCE %I.%I OWNER TO attome_migrator', target_schema, rec.relname);
        END LOOP;
        FOR rec IN
            SELECT viewname AS relname FROM pg_catalog.pg_views
            WHERE schemaname = target_schema AND viewowner = current_user
        LOOP
            EXECUTE format('ALTER VIEW %I.%I OWNER TO attome_migrator', target_schema, rec.relname);
        END LOOP;

        -- Later migrations run as the bootstrap role; membership keeps them
        -- able to ALTER what the migrator now owns.
        IF NOT pg_has_role(current_user, 'attome_migrator', 'MEMBER') THEN
            EXECUTE format('GRANT attome_migrator TO %I', current_user);
        END IF;
    END IF;

    -- Entity tables are provisioned at runtime by the migrator. These
    -- defaults wire the other two roles to them without a re-grant.
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE attome_migrator IN SCHEMA %I GRANT SELECT ON TABLES TO attome_readonly',
        target_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE attome_migrator IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO attome_runtime',
        target_schema
    );

    -- The job queue's schema: the runtime and migrator enqueue and poll.
    IF EXISTS (SELECT FROM pg_catalog.pg_namespace WHERE nspname = 'apalis') THEN
        GRANT USAGE ON SCHEMA apalis TO attome_migrator, attome_runtime;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA apalis TO attome_migrator, attome_runtime;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA apalis TO attome_migrator, attome_runtime;
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA apalis GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO attome_migrator, attome_runtime',
            current_user
        );
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA apalis GRANT EXECUTE ON FUNCTIONS TO attome_migrator, attome_runtime',
            current_user
        );
    END IF;
END
$$;

-- Function containment. Postgres grants EXECUTE on every function to PUBLIC,
-- which every role inherits, so the read-only role could call generate_ulid()
-- and the pgcrypto functions regardless of its table grants. Revoke them from
-- PUBLIC and hand the two the application needs to the DML roles.
DO $$
DECLARE
    fn RECORD;
BEGIN
    FOR fn IN
        SELECT p.oid::regprocedure::text AS signature
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_depend d
          ON d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
        JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid AND e.extname = 'pgcrypto'
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', fn.signature);
    END LOOP;
END
$$;
REVOKE EXECUTE ON FUNCTION generate_ulid() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION generate_ulid() TO attome_runtime, attome_migrator;
GRANT EXECUTE ON FUNCTION gen_random_bytes(integer) TO attome_runtime, attome_migrator;

-- Role-level settings. Role level (not per connection) so they hold behind a
-- transaction-mode pooler, where session state would leak between clients.
ALTER ROLE attome_readonly SET statement_timeout = '500ms';
ALTER ROLE attome_readonly SET timezone = 'UTC';
ALTER ROLE attome_readonly SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE attome_runtime SET statement_timeout = '500ms';
ALTER ROLE attome_runtime SET timezone = 'UTC';
ALTER ROLE attome_migrator SET statement_timeout = '500ms';
ALTER ROLE attome_migrator SET timezone = 'UTC';

-- Table privileges, per role, as v1 ended up with them (the audit trail and
-- security tables are append-only for the runtime role, and so on).

-- attome_runtime
GRANT DELETE, INSERT, SELECT, UPDATE ON
    access_review,
    access_review_item,
    action_invocation,
    agent_session,
    agent_session_token,
    ai_provider_credential,
    api_key,
    api_key_pepper_registry,
    api_usage,
    app,
    approval_delegation,
    approval_policy,
    approval_request,
    archive_record,
    attribute_info,
    audit_config,
    audit_retention_action,
    automation_bulk_operation,
    automation_bulk_operation_item,
    automation_staged_import,
    automation_staged_import_item,
    bulk_transform_operation,
    bulk_transform_operation_item,
    calendar,
    calendar_exception,
    calendar_holiday,
    cascade_deactivation,
    catalog_usage_rollup,
    change_consumer_cursor,
    content_page,
    content_page_related,
    content_page_stats,
    content_page_view,
    content_page_vote,
    content_space,
    content_space_template,
    content_template,
    data_domain,
    data_export,
    data_mapping,
    data_profile,
    docgen_render,
    document_folder,
    dsr_request,
    duplicate_candidate,
    email_delivery,
    email_suppression,
    email_verification_token,
    entity_change_event,
    entity_default_share,
    entity_info,
    event_delivery,
    event_subscription,
    field_security_profile,
    field_security_profile_field,
    file_version,
    idempotency_record,
    integration_credential,
    invitation_token,
    job_schedule,
    knowledge_chunk,
    knowledge_chunk_retrieval,
    knowledge_gap_topic,
    legal_hold,
    match_rule,
    memory,
    metadata_bundle_plan,
    metadata_change_log,
    metadata_label,
    metadata_reference,
    metadata_reference_backfill_progress,
    metric_snapshot,
    migration_project,
    migration_run,
    migration_run_item,
    module_configuration,
    notification_dispatch,
    notification_inbox,
    notification_preference,
    notification_recipient,
    organization,
    password_reset_token,
    position,
    prediction_model,
    privilege,
    process_case_def,
    process_dfg_snapshot,
    process_event,
    quality_issue,
    quality_score,
    record_baseline,
    record_share,
    recovery_archive,
    refresh_token,
    relationship_info,
    release_report_item,
    report_run,
    role,
    role_bulk_field,
    role_mm_entity_access,
    role_mm_field_security_profile,
    role_mm_privilege,
    role_mm_team,
    role_privilege_condition,
    rule,
    rule_policy,
    rule_role,
    schema_change_operation,
    search_index,
    search_suggestion,
    seed_watermark,
    setting,
    sidebar,
    sidebar_mm_privilege,
    sql_query,
    sql_query_entity_mapping,
    sql_query_version,
    state_model,
    state_transition,
    survivorship_rule,
    team,
    upload_session,
    user_account,
    user_account_mm_organization,
    user_account_mm_position,
    user_account_mm_privilege,
    user_account_mm_role,
    user_account_mm_team,
    user_identity,
    user_mfa,
    user_mfa_recovery_code,
    view,
    webcrawl_page,
    webcrawl_target,
    webportal_auth_policy,
    webportal_consent,
    webportal_credential,
    webportal_entity,
    webportal_erasure_request,
    webportal_grant,
    webportal_grant_condition,
    webportal_grant_field,
    webportal_identity,
    webportal_mfa_recovery_code,
    webportal_refresh_token,
    webportal_role,
    webportal_signup,
    webportal_token,
    webportal_user_role,
    workflow_definition,
    workflow_definition_version,
    workflow_instance,
    workflow_node_run,
    workflow_trigger_failure,
    workflow_trigger_index
TO attome_runtime;
GRANT DELETE, INSERT, SELECT ON
    audit_ingest
TO attome_runtime;
GRANT INSERT, SELECT, UPDATE ON
    ai_suggestion_outcome,
    audit_erasure_key,
    changeset,
    changeset_apply,
    changeset_operation,
    data_step_run,
    fleet_deployment,
    fleet_observation,
    fleet_rollout,
    fleet_target,
    outcome,
    prediction,
    release_report
TO attome_runtime;
GRANT INSERT, SELECT ON
    approval_grant,
    audit_chain_batch,
    audit_detail,
    audit_header,
    audit_ingest_prune,
    audit_signing_key,
    audit_snapshot,
    fleet_action,
    metadata_label_change_log,
    rule_version,
    search_impression,
    search_impression_row,
    search_interaction,
    setting_change_log
TO attome_runtime;

-- attome_migrator
GRANT DELETE, INSERT, SELECT, UPDATE ON
    access_review,
    access_review_item,
    action_invocation,
    agent_session,
    agent_session_token,
    ai_provider_credential,
    api_key,
    api_key_pepper_registry,
    api_usage,
    app,
    approval_delegation,
    approval_grant,
    approval_policy,
    approval_request,
    archive_record,
    attribute_info,
    audit_chain_batch,
    audit_config,
    audit_detail,
    audit_erasure_key,
    audit_header,
    audit_ingest,
    audit_retention_action,
    audit_signing_key,
    audit_snapshot,
    automation_bulk_operation,
    automation_bulk_operation_item,
    automation_staged_import,
    automation_staged_import_item,
    bulk_transform_operation,
    bulk_transform_operation_item,
    calendar,
    calendar_exception,
    calendar_holiday,
    cascade_deactivation,
    catalog_usage_rollup,
    change_consumer_cursor,
    content_page,
    content_page_related,
    content_page_stats,
    content_page_view,
    content_page_vote,
    content_space,
    content_space_template,
    content_template,
    data_domain,
    data_export,
    data_mapping,
    data_profile,
    docgen_render,
    dsr_request,
    duplicate_candidate,
    email_delivery,
    email_suppression,
    email_verification_token,
    entity_change_event,
    entity_default_share,
    entity_info,
    event_delivery,
    event_subscription,
    field_security_profile,
    field_security_profile_field,
    file_version,
    idempotency_record,
    integration_credential,
    invitation_token,
    job_schedule,
    knowledge_chunk,
    knowledge_chunk_retrieval,
    knowledge_gap_topic,
    legal_hold,
    match_rule,
    memory,
    metadata_bundle_plan,
    metadata_change_log,
    metadata_label,
    metadata_reference,
    metadata_reference_backfill_progress,
    metric_snapshot,
    migration_project,
    migration_run,
    migration_run_item,
    module_configuration,
    notification_dispatch,
    notification_inbox,
    notification_preference,
    notification_recipient,
    organization,
    password_reset_token,
    position,
    prediction_model,
    privilege,
    process_case_def,
    process_dfg_snapshot,
    process_event,
    quality_issue,
    quality_score,
    record_baseline,
    record_share,
    recovery_archive,
    refresh_token,
    relationship_info,
    release_report_item,
    report_run,
    role,
    role_mm_entity_access,
    role_mm_field_security_profile,
    role_mm_privilege,
    role_mm_team,
    role_privilege_condition,
    rule,
    rule_policy,
    rule_role,
    schema_change_operation,
    search_suggestion,
    seed_watermark,
    setting,
    sidebar,
    sidebar_mm_privilege,
    sql_query,
    sql_query_entity_mapping,
    sql_query_version,
    state_model,
    state_transition,
    survivorship_rule,
    team,
    upload_session,
    user_account,
    user_account_mm_organization,
    user_account_mm_position,
    user_account_mm_privilege,
    user_account_mm_role,
    user_account_mm_team,
    user_identity,
    user_mfa,
    user_mfa_recovery_code,
    view,
    webcrawl_page,
    webcrawl_target,
    workflow_definition,
    workflow_definition_version,
    workflow_instance,
    workflow_node_run,
    workflow_trigger_failure,
    workflow_trigger_index
TO attome_migrator;
GRANT INSERT, SELECT, UPDATE ON
    changeset,
    changeset_apply,
    changeset_operation,
    data_step_run,
    fleet_deployment,
    fleet_observation,
    fleet_rollout,
    fleet_target,
    prediction,
    release_report
TO attome_migrator;
GRANT INSERT, SELECT ON
    fleet_action,
    metadata_label_change_log,
    rule_version,
    setting_change_log
TO attome_migrator;

-- attome_readonly
GRANT SELECT ON
    access_review,
    access_review_item,
    action_invocation,
    agent_session,
    agent_session_token,
    ai_conversation,
    ai_conversation_event,
    ai_message,
    ai_message_feedback,
    ai_runtime_switch,
    ai_suggestion_outcome,
    ai_tool_call,
    ai_turn_cancel,
    api_usage,
    app,
    approval_delegation,
    approval_policy,
    archive_record,
    attribute_info,
    audit_chain_batch,
    audit_config,
    audit_detail,
    audit_header,
    audit_signing_key,
    audit_snapshot,
    bulk_transform_operation,
    bulk_transform_operation_item,
    calendar,
    calendar_exception,
    calendar_holiday,
    cascade_deactivation,
    catalog_usage_rollup,
    change_consumer_cursor,
    changeset,
    changeset_apply,
    changeset_operation,
    content_page,
    content_page_related,
    content_page_stats,
    content_page_view,
    content_page_vote,
    content_space,
    content_space_template,
    content_template,
    data_domain,
    data_export,
    data_mapping,
    data_profile,
    data_step_run,
    docgen_render,
    duplicate_candidate,
    entity_default_share,
    entity_info,
    event_delivery,
    event_subscription,
    field_security_profile,
    field_security_profile_field,
    file_version,
    job_schedule,
    knowledge_chunk,
    knowledge_chunk_retrieval,
    knowledge_gap_topic,
    match_rule,
    memory,
    metadata_bundle_plan,
    metadata_label,
    metadata_label_change_log,
    metadata_reference,
    metadata_reference_backfill_progress,
    metric_snapshot,
    migration_project,
    migration_run,
    migration_run_item,
    module_configuration,
    notification_preference,
    organization,
    prediction,
    prediction_model,
    privilege,
    process_case_def,
    process_dfg_snapshot,
    process_event,
    quality_issue,
    quality_score,
    record_share,
    relationship_info,
    report_run,
    role,
    role_privilege_condition,
    rule,
    rule_policy,
    rule_role,
    rule_version,
    search_index,
    search_suggestion,
    seed_watermark,
    setting,
    setting_change_log,
    sql_query,
    sql_query_entity_mapping,
    sql_query_version,
    state_model,
    state_transition,
    survivorship_rule,
    team,
    user_account_mm_privilege,
    user_account_mm_team,
    view,
    webcrawl_page,
    webcrawl_target,
    workflow_definition,
    workflow_trigger_failure
TO attome_readonly;

-- The two credential-bearing tables are readable by attome_readonly only
-- column by column, never the secret hashes.
DO $$
DECLARE
    spec RECORD;
    col_list text;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES ('user_account', 'password_hash'), ('api_key', 'secret_hash')) AS t(tbl, secret)
    LOOP
        SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position)
          INTO col_list
          FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = spec.tbl
           AND column_name <> spec.secret;
        IF col_list IS NOT NULL THEN
            EXECUTE format('GRANT SELECT (%s) ON %I TO attome_readonly', col_list, spec.tbl);
        END IF;
    END LOOP;
END
$$;
