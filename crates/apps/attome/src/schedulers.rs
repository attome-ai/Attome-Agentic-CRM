//! The background schedulers the job-worker tier runs (CLEANUP-REVIEW 5.17).
//!
//! One list, called from both places that act as the worker tier: `main.rs`
//! when `jobs.run_worker_inline` is true, and `bin/worker.rs` (a split
//! deployment's dedicated worker) unconditionally. `worker.rs` used to
//! hand-copy `main.rs`'s list and had drifted: it never spawned the
//! query-plan or field-security-profile revalidation sweeps.
//!
//! Deliberately NOT here — they stay in `main.rs`, run by every HTTP-serving
//! node regardless of `jobs.run_worker_inline`: the audit ingest-backlog
//! refresh, the capability probe, the approval-expiry sweep, and the
//! metrics-port gauges. Those maintain per-node request-path state (or are
//! observability for the HTTP process), not job-queue work.
//!
//! A duplicate scheduler tick across replicas/processes is already safe
//! (BJB-4a, D-618: the `attome_jobs::schedule` ledger's row CAS lets one caller
//! win each slot, and the dedup key blocks overlap behind it).
use attome_config::AppConfig;
use attome_server::AppState;

/// Spawns every job-worker-tier background scheduler. Each is a
/// process-lifetime `tokio::spawn` loop; nothing is awaited here.
pub fn spawn_worker_schedulers(config: &AppConfig, base_state: &AppState) {
    let db = &base_state.db;
    // U6-T1: the daily local backup (Solo only, on by default).
    crate::backup::spawn_daily(std::sync::Arc::new(config.clone()));
    // Once/day — never varied per-deployment, not a config knob.
    // Audit 10/10 plan item 2.6 (D-539 ruling 6): hourly until every
    // organization's v1 cutover checkpoint exists, a no-op afterwards.
    crate::jobs::spawn_audit_v1_cutover_checkpoint_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60 * 60),
    );
    crate::jobs::spawn_partition_maintenance_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // Shorter than partition maintenance's interval since upload
    // sessions are short-lived; never varied per-deployment.
    crate::jobs::spawn_upload_session_maintenance_scheduler(
        db.clone(),
        std::time::Duration::from_secs(900),
    );
    // P-job-queue-hardening (D-165): keeps apalis.jobs history (and the
    // dead-letter admin list it backs) bounded. Once/day — this moves far
    // slower than upload sessions or even partitions.
    crate::jobs::spawn_apalis_job_history_prune_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // P-stored-query-containment addendum §11(c): keeps
    // sql_query_version's cached cost_estimate from drifting
    // unboundedly between publishes.
    // Once/day — moves far slower than the schedulers this mirrors;
    // never varied per-deployment, not a config knob.
    crate::jobs::spawn_query_plan_revalidation_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // AA4-T5: tables grow past the trigram threshold slowly; once a day.
    crate::jobs::spawn_trigram_index_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // D-188: keeps field_security_profile_field's logicalname
    // references from drifting silently stale between admin actions —
    // same reactive-lint containment shape as query plan revalidation
    // just above, applied to the other logicalname-reference consumer.
    // Same once/day-by-convention cadence, never varied per-deployment.
    crate::jobs::spawn_field_security_profile_revalidation_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // M34 (AI Governance, D-435): the nightly acceptance/edit/reject
    // drift sweep over `ai_suggestion_outcome`. Once/day, same
    // convention as the maintenance-class schedulers above.
    // C4 (row A-40): reclaims chat confirm leases whose holder died and
    // expires unconfirmed proposals. Once a minute: a crashed confirm's
    // proposal is confirmable again within CONFIRM_LEASE plus a minute.
    crate::jobs::spawn_ai_tool_call_sweep_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // A18-T4: bursts of deletion, checked every five minutes.
    crate::jobs::spawn_bin_delete_alert_scheduler(db.clone(), std::time::Duration::from_secs(300));
    crate::jobs::spawn_tag_expiry_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // E9-T7: marketing hand-offs past their SLA, every five minutes.
    crate::jobs::spawn_marketing_sweep_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // Y2-T8: the table-health sample, daily.
    crate::jobs::spawn_table_health_scheduler(db.clone(), std::time::Duration::from_secs(86_400));
    // Q16-T2: the whole audit chain verified once a week.
    crate::jobs::spawn_audit_chain_verify_scheduler(
        db.clone(),
        std::time::Duration::from_secs(7 * 86_400),
    );
    // K2-T2: files from the last 30 days scanned again once a week.
    crate::jobs::spawn_upload_rescan_scheduler(
        db.clone(),
        std::time::Duration::from_secs(7 * 86_400),
    );
    // AA13-T9: the monthly SLO report (hourly check) and the fast-burn check.
    crate::jobs::spawn_slo_monthly_report_scheduler(
        db.clone(),
        std::time::Duration::from_secs(3600),
    );
    crate::jobs::spawn_slo_burn_check_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // AA9-T7: limits near their value, daily.
    crate::jobs::spawn_limit_warning_scheduler(db.clone(), std::time::Duration::from_secs(86_400));
    // Z1-T8: secrets past their age limit, daily.
    crate::jobs::spawn_secret_age_reminder_scheduler(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // Z1-T11: integration OAuth tokens renewed ahead of expiry, every five minutes.
    crate::jobs::spawn_oauth_refresh_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // D15-T2: personal mail onto matching records, every five minutes.
    crate::jobs::spawn_mail_capture_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // J2-T2: shared mailboxes into cases, leads and contacts, every two minutes.
    crate::jobs::spawn_inbound_mail_scheduler(db.clone(), std::time::Duration::from_secs(120));
    // G1-T3: case summaries for threads quiet two minutes, every minute.
    crate::jobs::spawn_case_summary_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // E16-T1: SMS campaigns, a batch every five minutes.
    crate::jobs::spawn_sms_campaign_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // E6-T8: blocklist check and reputation fetch, daily.
    crate::jobs::spawn_sender_reputation_schedulers(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // E22-T1: webinar registrants and attendance, every fifteen minutes.
    crate::jobs::spawn_webinar_sync_scheduler(db.clone(), std::time::Duration::from_secs(900));
    // E7-T6: live segments, a tick every five seconds.
    crate::jobs::spawn_segment_live_scheduler(db.clone(), std::time::Duration::from_secs(5));
    // I6-T2: work order stock, a tick every minute.
    crate::jobs::spawn_stock_ledger_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // I1-T2: completed work orders invoiced, a tick every five minutes.
    crate::jobs::spawn_work_order_invoicing_scheduler(
        db.clone(),
        std::time::Duration::from_secs(300),
    );
    // G17-T9: intraday offers, every fifteen minutes.
    crate::jobs::spawn_intraday_scheduler(db.clone(), std::time::Duration::from_secs(900));
    // AI8-T3: yesterday's agent performance, checked hourly, rolled up once.
    crate::jobs::spawn_agent_stats_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // A20-T2: missing label translations drafted for review, hourly.
    crate::jobs::spawn_label_drafts_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // AK3-T5: the change feed counted into the work share every minute.
    crate::jobs::spawn_work_share_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // AH5-T2: agents compared with their baselines every five minutes.
    crate::jobs::spawn_agent_check_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // AH5-T1: agent activity rolled up hourly, baselines at 03:00 UTC.
    crate::jobs::spawn_agent_behaviour_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // O10-T1: executed decisions measured after their measure date, daily.
    crate::jobs::spawn_decision_measure_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // F5-T12: overdue accounts put on credit hold, once a day.
    crate::jobs::spawn_credit_hold_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // AK2-T1: the weekly operations digest, checked hourly, sent on Mondays.
    crate::jobs::spawn_ops_digest_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // AI5-T4: promises to pay read from customers' replies, every 5 minutes.
    crate::jobs::spawn_promise_extract_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // AI6-T3: meetings an hour away queued for a brief, every 15 minutes.
    crate::jobs::spawn_meeting_brief_scheduler(db.clone(), std::time::Duration::from_secs(900));
    // G14-T2: surveys sent on record changes, every minute.
    crate::jobs::spawn_survey_send_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // V5-T1: change requests decided by customer sign-off, every minute.
    crate::jobs::spawn_change_signoff_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // W3-T4: sealed RFQ bids opened at their deadline, every five minutes.
    crate::jobs::spawn_rfq_open_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // W2-T1: vendor compliance document reminder timers, daily.
    crate::jobs::spawn_compliance_expiry_scheduler(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // I5-T2: maintenance plan timers and meter checks, daily.
    crate::jobs::spawn_maintenance_scheduler(db.clone(), std::time::Duration::from_secs(86_400));
    // I10-T2: warranty expiry reminders, nightly.
    crate::jobs::spawn_warranty_reminder_scheduler(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // F10-T10: commission plan acceptance, a tick every thirty seconds.
    crate::jobs::spawn_commission_acceptance_scheduler(
        db.clone(),
        std::time::Duration::from_secs(30),
    );
    // H8-T1: status page notices, a tick every thirty seconds.
    crate::jobs::spawn_status_notify_scheduler(db.clone(), std::time::Duration::from_secs(30));
    // D23-T7: deal coverage gaps, a tick every ten seconds.
    crate::jobs::spawn_deal_coverage_scheduler(db.clone(), std::time::Duration::from_secs(10));
    // E8-T5: journey entries, a tick every ten seconds; date sources hourly.
    crate::jobs::spawn_journey_entry_schedulers(db.clone(), std::time::Duration::from_secs(10));
    // E23-T1: profile event months past retention, daily.
    crate::jobs::spawn_profile_event_retention_scheduler(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // E6-T4: the deliverability rollup for today and yesterday, hourly.
    crate::jobs::spawn_deliverability_rollup_scheduler(
        db.clone(),
        std::time::Duration::from_secs(3600),
    );
    // J8-T1: new Google reviews, every 15 minutes.
    crate::jobs::spawn_social_reviews_scheduler(db.clone(), std::time::Duration::from_secs(900));
    // E17-T1: due social posts and their metrics, every five minutes.
    crate::jobs::spawn_social_publish_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // E18-T1: Brandwatch mentions, every 30 minutes.
    crate::jobs::spawn_social_mentions_scheduler(db.clone(), std::time::Duration::from_secs(1800));
    // D15-T3: meetings and people's own calendars, every five minutes.
    crate::jobs::spawn_calendar_sync_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // AA14-T8: p95 regressions since the last upgrade, daily.
    crate::jobs::spawn_perf_regression_scheduler(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // AI4-T5: follow-up stall scans, hourly.
    crate::jobs::spawn_ai_followup_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // D25-T3: win/loss reviews for big closes, every minute.
    crate::jobs::spawn_sales_deal_close_scheduler(db.clone(), std::time::Duration::from_secs(60));
    crate::jobs::spawn_sales_leaver_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    crate::jobs::spawn_sales_mention_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // C2-T1: follower notifications, every minute.
    crate::jobs::spawn_notification_follow_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60),
    );
    // D6-T8: line snapshots older than a day, daily.
    crate::jobs::spawn_sales_snapshot_prune_scheduler(
        db.clone(),
        std::time::Duration::from_secs(86_400),
    );
    // F10-T3: commission credits for won deals, every minute.
    crate::jobs::spawn_commission_credit_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // F4-T9: invoice requests every five minutes, schedules daily.
    crate::jobs::spawn_billing_request_scheduler(db.clone(), std::time::Duration::from_secs(300));
    crate::jobs::spawn_billing_schedule_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // AG2-T3: e-invoices waiting for ZATCA, every five minutes.
    crate::jobs::spawn_billing_einvoice_scheduler(db.clone(), std::time::Duration::from_secs(300));
    // F5-T7: gateway events waiting to apply, every minute.
    crate::jobs::spawn_billing_gateway_event_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60),
    );
    // F5-T9: due invoices charged to saved methods, daily.
    crate::jobs::spawn_billing_charge_due_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // F5-T11: gateway payouts reconciled, daily.
    crate::jobs::spawn_billing_reconcile_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // F4-T10: invoices past due, nightly.
    crate::jobs::spawn_billing_overdue_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // D7-T3: new deals get their owner's default team, every minute.
    crate::jobs::spawn_sales_default_team_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // Q10-T6: role grants past their end date, hourly.
    crate::jobs::spawn_role_grant_expiry_scheduler(
        db.clone(),
        std::time::Duration::from_secs(3600),
    );
    // E7-T4: scheduled marketing lists, checked hourly.
    crate::jobs::spawn_segment_refresh_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // The nightly marketing pass: loyalty, referrals, target accounts, bounces.
    crate::jobs::spawn_marketing_nightly_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // M10-T1: due timers, every 15 seconds.
    crate::jobs::spawn_timer_sweep_scheduler(db.clone(), std::time::Duration::from_secs(15));
    // K6-T3: website sources on a daily or weekly schedule, checked hourly.
    crate::jobs::spawn_webcrawl_recrawl_scheduler(db.clone(), std::time::Duration::from_secs(3600));
    // F3-T10: recurring revenue per account and currency, nightly.
    crate::jobs::spawn_mrr_snapshot_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // D11-T2: forecast cells and the weekly snapshot, nightly.
    crate::jobs::spawn_forecast_recompute_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // D19-T1: deal risk scores and reasons, nightly.
    crate::jobs::spawn_deal_risk_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // D18-T1: lead and contact points scores, nightly.
    crate::jobs::spawn_points_scoring_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // V2-T2: completed recurring tasks get their next task within 15 minutes.
    crate::jobs::spawn_recurring_task_roll_scheduler(
        db.clone(),
        std::time::Duration::from_secs(15 * 60),
    );
    // F3-T11: subscription events to revenue and churn, every minute.
    crate::jobs::spawn_billing_handoff_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // F3-T8: subscription charges planned, daily.
    crate::jobs::spawn_billing_charges_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // F3-T9: subscription renewals and trials, nightly.
    crate::jobs::spawn_billing_renewal_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // W1-T13: contracts from accepted quotes, confirmed orders and intake.
    crate::jobs::spawn_contract_link_scheduler(db.clone(), std::time::Duration::from_secs(15 * 60));
    // W1-T4: contract notice deadlines, renewal tasks and obligations, nightly.
    crate::jobs::spawn_contract_key_dates_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    crate::jobs::spawn_ai_quality_monitor_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // P-idempotency-hardening §4.4/§5 step 11: keeps the durable
    // idempotency tier's completed records bounded, same cadence as the
    // apalis job history prune.
    crate::jobs::spawn_idempotency_record_prune_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // attome-auth plan BAU-13a/13b: dead refresh lineages and expired
    // single-use tokens, daily.
    crate::jobs::spawn_auth_token_prune_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // Solution 7 Phase 2 (D-788 rule 9): the 30-day recovery archive's
    // hourly purge.
    crate::jobs::spawn_recovery_archive_prune_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60 * 60),
    );
    // P-retention-archive-completion §3b/§3c: the daily proposal sweep
    // for partition archive/drop and entity purge. Unconditional, like
    // partition maintenance above — a no-op enqueue when no retention
    // window is configured (today's default).
    crate::jobs::spawn_retention_proposal_scheduler(
        db.clone(),
        std::time::Duration::from_secs(config.retention.propose_interval_secs),
    );
    // M35 (AI Memory, D-451): the daily memory retention sweep. Own
    // scheduler, not folded into the retention-propose one above — see
    // `EngineJob::PruneExpiredMemories`'s doc comment.
    crate::jobs::spawn_memory_retention_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // P-workflow-engine §4.3/§5 step 7: sweeps schedule-type waits past
    // their resume_at. A minute-scale interval, not once/day — unlike the
    // maintenance sweeps above, a late sweep here is a late user-visible
    // workflow resume, not background bookkeeping.
    crate::jobs::spawn_workflow_sla_sweep_scheduler(db.clone(), std::time::Duration::from_secs(60));
    // P-workflow-engine §5 step 6 follow-up (D-267 addendum): drains
    // the entity-change outbox and starts matching workflows. Shorter
    // interval than the SLA sweep above — see that function's doc
    // comment.
    crate::jobs::spawn_workflow_entity_trigger_dispatch_scheduler(
        db.clone(),
        std::time::Duration::from_secs(10),
    );
    // M27 Phase 1 (KPI & Metrics, D-407): sweeps query-backed metric
    // definitions for their current period. Hour-scale interval — see
    // that function's doc comment for why.
    crate::jobs::spawn_metric_snapshot_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60 * 60),
    );

    // M62 Phase 1 (D-403/D-409): drains active webhook subscriptions'
    // outbox cursors and enqueues delivery jobs. Same cadence class as
    // the entity-trigger dispatch just above — both drain the same
    // outbox and neither wants to lag it by more than a few seconds.
    crate::jobs::spawn_events_dispatch_scheduler(db.clone(), std::time::Duration::from_secs(10));

    // M03 (Security & Identity) gap 1 / D-434: auto-completes an access
    // review campaign past its due_date. Once/day, same cadence class as
    // the query-plan/field-security-profile revalidation schedulers
    // above.
    crate::jobs::spawn_access_review_campaign_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // D-432 / M13: sweeps the entity-change outbox for match-rule
    // scoring. 5-minute interval — see that function's doc comment.
    crate::jobs::spawn_data_match_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(5 * 60),
    );

    // M61 Phase 1 (API Management, D-438): drains the per-route/per-key
    // usage-counter buffer into api_usage. Once/day — see that
    // function's doc comment.
    crate::jobs::spawn_api_usage_rollup_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // M56 Content Management Phase 1 (D-436): publishes/unpublishes
    // pages whose publish_at/unpublish_at has passed. Minute-scale
    // interval, same cadence class as the workflow SLA sweep above — see
    // that function's doc comment.
    crate::jobs::spawn_content_scheduled_publish_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60),
    );

    // M25 Phase 1 (Report, D-440): sweeps report_schedule for
    // occurrences past their next_run_at. Minute-scale interval, same
    // cadence class as the workflow SLA sweep / content scheduled-publish
    // sweep above — see that function's doc comment.
    crate::jobs::spawn_report_schedule_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60),
    );

    // AH8 (V2-D693): runs actions whose undo window ended. Every 15 seconds,
    // so an action runs close to the time the person was told.
    crate::jobs::spawn_ai_deferred_action_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(15),
    );

    // AH6-T3 / AH8-T9: compare trial decisions with people, propose raises.
    crate::jobs::spawn_ai_trial_compare_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60 * 60),
    );

    // AH8-T8: the daily summary of what agents ran on their own.
    crate::jobs::spawn_ai_autonomy_summary_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // Audit plan 3.5 (D-541 rule 6): summary events for closed
    // failed-login windows. Once a minute, inside the counters' 10-minute
    // TTL.
    crate::jobs::spawn_failed_login_sweep_scheduler(db.clone(), std::time::Duration::from_secs(60));

    // M11 Search gap list: rebuilds the suggestion/autocomplete
    // materialized table from registered entities + active saved
    // searches. 15-minute interval — a typeahead cache, not something
    // that needs the drain's 5-second staleness budget; each request
    // path also re-checks visibility live regardless of how stale the
    // cached candidate list is (see `attome_search::suggest`'s module doc).
    crate::jobs::spawn_search_suggestion_refresh_scheduler(
        db.clone(),
        std::time::Duration::from_secs(15 * 60),
    );

    // M11 Search gap list: bounded saved-search alert-on-new-results
    // sweep. Hourly — an alert is a convenience notification, not a
    // real-time signal, and the bounded batch (see that function's doc
    // comment) means a large backlog drains over several ticks rather
    // than blocking one.
    crate::jobs::spawn_search_saved_search_alert_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60 * 60),
    );

    // M37 Knowledge Management Phase 2 (D-452): folds page views, votes,
    // and knowledge-chunk retrievals into content_page_stats.
    // Once/day, same cadence class as the API usage rollup above.
    crate::jobs::spawn_content_page_stats_rollup_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // M37 Knowledge Management Phase 2 (D-452): notifies a stale page's
    // owner through M51. Once/day — see that function's doc comment.
    crate::jobs::spawn_content_review_reminder_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // M14 Phase 1 (Data Quality): scores every entity's completeness
    // (required-field null counts) and uniqueness (M13 open duplicate
    // candidates) into quality_score/quality_issue.
    // Once/day — see that function's doc comment.
    crate::jobs::spawn_data_quality_score_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // M41 Phase 1 (Process Intelligence, D-462): incremental cursor-based
    // extraction into process_event + DFG/variant/cycle-time
    // recompute. Minute-scale interval, same cadence class as the
    // workflow SLA sweep / content scheduled-publish sweep above.
    crate::jobs::spawn_process_extraction_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60),
    );

    // M36 Phase 1 (Predictive Intelligence, D-473): rescores relevant
    // live records against every active prediction model. Minute-scale
    // interval, same cadence class as the process extraction sweep
    // above.
    crate::jobs::spawn_predict_scoring_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(60),
    );
    // M36 Phase 1: fills in the actual outcome once a prediction's
    // horizon passes. 15-minute interval, same cadence class as the work
    // queue escalation sweep below.
    crate::jobs::spawn_predict_outcome_fill_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(15 * 60),
    );

    // M84 Phase 1 (Queue Management, D-464): capacity-overflow and
    // idle-item escalation alerts. 15-minute interval, same cadence
    // class as the search suggestion refresh above — see that
    // function's doc comment.
    crate::jobs::spawn_work_queue_escalation_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(15 * 60),
    );

    // M73 (SLA Management, D-422) — REVIEW-2026-09-02 finding #1: these
    // four sweeps existed and were tested since D-422 with no caller
    // outside their own tests, so no SLA breach/warning/escalation ever
    // fired in a deployment. 5-minute interval — see that function's
    // doc comment.
    crate::jobs::spawn_ticket_sla_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(5 * 60),
    );

    // M72 (Resource Management) — see that function's doc comment.
    // Once/day, same cadence class as the content review reminder
    // sweep above.
    crate::jobs::spawn_resource_utilization_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );

    // M18 Data Catalog Phase 1 (D-466): self-converging backfill of
    // metadata_reference for queries/workflows published before
    // this release's live writers existed. 5-minute interval — see that
    // function's doc comment.
    crate::jobs::spawn_catalog_lineage_backfill_scheduler(
        db.clone(),
        std::time::Duration::from_secs(5 * 60),
    );

    // M18 Data Catalog Phase 1 (D-466): drains the dashboard-widget
    // change-feed outbox into metadata_reference. Same 5-minute
    // interval as the mdm match sweep it's modeled on.
    crate::jobs::spawn_catalog_dashboard_lineage_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(5 * 60),
    );

    // M18 Data Catalog Phase 1 (D-466): nightly per-entity usage
    // snapshot for the catalog's entity detail view. Once/day, same
    // cadence class as the API usage rollup above.
    crate::jobs::spawn_catalog_usage_rollup_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // A3-T8: nightly validity score per entity.
    crate::jobs::spawn_validation_score_sweep_scheduler(
        db.clone(),
        std::time::Duration::from_secs(24 * 60 * 60),
    );
    // D-792 (FLEET-CONSOLE-DESIGN.md §6.3) — the fleet console's poll, only in
    // a `fleet-console` build whose gate is open in this process (the same
    // pure decision `boot::init` made and logged); never on a customer server.
    #[cfg(feature = "fleet-console")]
    {
        if matches!(
            attome_fleet::gate::open(config),
            Ok(attome_fleet::Gate::Open)
        ) {
            crate::jobs::spawn_fleet_poll_scheduler(
                db.clone(),
                std::time::Duration::from_secs(config.fleet.poll_interval_secs),
            );
        }
    }

    // P-job-system-hardening (b): the touch-buffer flushers and the
    // access-log stream consumer, same background-maintenance placement
    // as the schedulers above. Unlike the ledger-gated schedulers above, no
    // slot claim is needed here: `write_coalesce::drain`'s atomic
    // HGETALL+DEL means a duplicate tick across replicas just finds an
    // already-empty hash (not a duplicate write), and `XREADGROUP`
    // against a shared consumer group is Redis Streams' own built-in
    // horizontal-scaling mechanism — every replica running its own
    // consumer is the intended scaling model, not a race to prevent.
    // P-job-system-hardening (b): every current caller uses the same
    // cadence class — split this only if a real deployment needs
    // different cadences, not speculatively. Never varied per-deployment
    // today, not a config knob.
    let flush_interval = std::time::Duration::from_secs(30);
    attome_server::apikey_touch::spawn_flush_scheduler(
        db.clone(),
        base_state.redis_coordination.clone(),
        flush_interval,
    );
    // Q8-T3: session activity, folded into refresh_token once a minute.
    attome_server::session_activity::spawn_flush_scheduler(db.clone(), base_state.redis.clone());
    attome_s2s::telemetry::spawn_touch_flush_scheduler(
        db.clone(),
        base_state.redis_coordination.clone(),
        flush_interval,
    );
    if config.s2s.access_log_enabled {
        // batch_size/reclaim_idle_ms: never varied per-deployment, not
        // config knobs — see the flush_interval comment above.
        attome_s2s::telemetry::spawn_access_log_consumer(
            db.clone(),
            base_state.redis_coordination.clone(),
            flush_interval,
            200,
            60_000,
        );
    }
}
