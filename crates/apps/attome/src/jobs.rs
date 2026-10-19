//! P1.4 — the single `EngineJob` handler, registered on the worker
//! `Monitor` in `main.rs`. This is the one place both `base` and `xrm` are
//! visible: `attome_core::jobs::EngineJob` is pure data (base can't depend on xrm),
//! so mapping a job back onto the attome-s2s/attome_db calls that actually perform
//! the work has to happen here.
use apalis::prelude::{Attempt, Data, TaskId};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_core::jobs::{EngineJob, RewrapDomain};
use attome_db::DbPool;
use attome_jobs::JobEnvelope;
use opentelemetry::trace::TraceContextExt;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// P-db-privilege-separation / D-117 — apalis's `Data<T>` extractor keys
/// purely by type, so a second pool of the same `DbPool` type needs a
/// distinct wrapper to be independently injectable/extractable alongside the
/// runtime `Data<DbPool>` above. Wraps `attome_db::create_migrator_pool`'s
/// pool; used only by the two DDL job arms below (`EnsureAuditPartitions`,
/// `PruneNotificationRecipientPartitions`) — every other arm stays on the
/// plain runtime `Data<DbPool>`.
#[derive(Clone)]
pub struct MigratorDb(pub DbPool);

impl std::fmt::Debug for MigratorDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigratorDb").finish_non_exhaustive()
    }
}

/// T2-12 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §3.11) — the actual worker
/// entry point registered on both `WorkerBuilder`s (`main.rs`, `bin/worker.rs`).
/// A thin wrapper around [`dispatch_platform_job`]: on any `Err`, it applies
/// exponential backoff (`attome_jobs::apply_retry_backoff`) to this job's row
/// before letting the error propagate, instead of leaving `run_at` untouched
/// the way apalis-sql 0.7.4's own failure path does (see
/// `apply_retry_backoff`'s doc comment for the full mechanism). `attempt`/
/// `task_id` are apalis's own extractors — both implement `FromRequest`, so
/// `build_fn` hands them in for free, no `WorkerBuilder`/`main.rs` change
/// needed.
pub async fn handle_platform_job(
    job: JobEnvelope<EngineJob>,
    db: Data<DbPool>,
    db_migrator: Data<MigratorDb>,
    config: Data<AppConfig>,
    attome_state: Data<EngineState>,
    attempt: Attempt,
    task_id: TaskId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // P-loading-profiler (M86) — time every queued job as `job.<variant>` so the
    // profiler's Jobs category is populated. This is the one chokepoint both
    // `WorkerBuilder`s register (`main.rs` / `bin/worker.rs`), so bulk, staged
    // import, email, and partition jobs are all covered without touching any
    // dispatch arm. Detached and fail-open, exactly like the request middleware;
    // `dispatch_platform_job`'s own behavior is unchanged.
    //
    // `metric_kind` is the bounded label set: an unrecognized row's variant is
    // row text, so it never becomes a metric label. The profiler name may carry
    // it, because attome-profiler's name guard and name cap bound it.
    let metric_kind = metric_kind(&job);
    let job_name = match &job {
        JobEnvelope::Known { job, .. } => job.variant_name().to_string(),
        JobEnvelope::Unrecognized { variant, .. } => format!("unrecognized.{variant}"),
    };
    // BJB-4d — computed from `&job` before `dispatch_platform_job` consumes it:
    // `Some(name)` only for a kind a `spawn_*_scheduler` enqueues (see
    // `schedule_name_for`), so a successful run can stamp the schedule ledger's
    // `last_succeeded_at`.
    let schedule_name = match &job {
        JobEnvelope::Known { job, .. } => schedule_name_for(job),
        JobEnvelope::Unrecognized { .. } => None,
    };
    let profiler_enabled = config.observability.profiler_enabled;
    let started = std::time::Instant::now();
    let (mut result, probes) = attome_profiler::scope(dispatch_platform_job(
        job,
        db.clone(),
        db_migrator,
        config,
        attome_state.clone(),
        attempt.current(),
        task_id.to_string(),
    ))
    .await;

    if profiler_enabled {
        // BPR-16/BPR-22: the general pool, through the bounded process-wide
        // queue; drops are counted and rate-limit-logged inside attome-profiler.
        attome_profiler::Flusher::shared(&attome_state.base.redis).try_send(
            format!("job.{job_name}"),
            started.elapsed(),
            probes,
        );
    }

    // Y12-T4: a run stopped by a table lock it could not get in time goes
    // back in the queue for later instead of spending its attempts.
    let mut deferred = false;
    if let Err(e) = &result
        && attome_db::is_lock_timeout(&**e)
    {
        match attome_jobs::defer_for_lock(&db, &task_id.to_string()).await {
            Ok(true) => {
                tracing::warn!(
                    task_id = %task_id,
                    kind = metric_kind,
                    delay_secs = attome_jobs::LOCK_DEFERRAL_SECS,
                    "platform job deferred: a table it changes is locked"
                );
                deferred = true;
                result = Ok(());
            }
            Ok(false) => {
                tracing::error!(
                    task_id = %task_id,
                    kind = metric_kind,
                    reason = "lock_timeout",
                    "platform job failed: a table it changes stayed locked through every deferral"
                );
                result = Err(format!(
                    "lock_timeout: a table this job changes stayed locked through {} deferrals",
                    attome_jobs::MAX_LOCK_DEFERRALS
                )
                .into());
            }
            Err(err) => tracing::warn!(
                task_id = %task_id,
                error = %err,
                "platform job: could not defer a lock-blocked run; it fails and retries instead"
            ),
        }
    }

    // BJB-14a — one outcome sample per run, by kind. Emitted through
    // attome-server so this crate carries no metrics dependency of its own.
    attome_server::metrics::record_platform_job_outcome(
        metric_kind,
        if deferred {
            "deferred"
        } else if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
    );
    attome_server::metrics::record_platform_job_duration(
        metric_kind,
        started.elapsed().as_secs_f64(),
    );

    if result.is_ok() && !deferred {
        // BJB-4d — the schedule ledger's last-success stamp: "the sweep ran and
        // succeeded", which is the signal the age gauge alerts on, as distinct
        // from "the scheduler claimed its slot". Only ever set for a
        // schedule-originated kind.
        if let Some(name) = schedule_name
            && let Err(e) = attome_jobs::schedule::mark_succeeded(&db, name).await
        {
            tracing::warn!(
                schedule = name,
                error = %e,
                "platform job: could not stamp the schedule's last_succeeded_at"
            );
        }
    }

    if let Err(e) = &result {
        // A job never reaches `AppError::into_response`, the only place a
        // masked `Internal` detail is logged, and apalis stores only its
        // Display ("internal error") — so this is the error-level sink for it.
        match masked_internal_detail(&**e) {
            Some(detail) => tracing::error!(
                task_id = %task_id,
                kind = metric_kind,
                detail = %detail,
                "platform job failed"
            ),
            None => tracing::warn!(
                task_id = %task_id,
                kind = metric_kind,
                error = %e,
                "platform job failed"
            ),
        }
        // Runs *before* this Err reaches apalis's post-handler `update()`
        // (which never writes `run_at` anyway, so there's no ordering race
        // either way) -- this is what actually stops the next safety poll
        // from re-claiming the row instantly.
        if let Err(e) =
            attome_jobs::apply_retry_backoff(&db, &task_id.to_string(), attempt.current()).await
        {
            tracing::warn!(
                task_id = %task_id,
                attempt = attempt.current(),
                error = %e,
                "platform job: failed to apply retry backoff after a job failure -- apalis will \
                 re-claim it on the next poll with no delay"
            );
        }
    }
    result
}

/// BJB-14a — the `kind` label: a declared variant name or the constant
/// `"unrecognized"`, never an unrecognized row's own text (cardinality).
fn metric_kind(job: &JobEnvelope<EngineJob>) -> &'static str {
    match job {
        // Z7-T1: a registered type's own name, fixed in code, so bounded;
        // a name not registered here stays the variant name.
        JobEnvelope::Known {
            job: EngineJob::Registered(job),
            ..
        } => attome_core::jobs::JOB_TYPES
            .job_type(&job.name)
            .map_or("Registered", |job_type| job_type.name),
        JobEnvelope::Known { job, .. } => job.variant_name(),
        JobEnvelope::Unrecognized { .. } => "unrecognized",
    }
}

/// D-619 — subscribes this process's two job queues to the `LISTEN` wake-up
/// before their storages are cloned into `WorkerBuilder`s, and spawns the
/// listener. Never fails the caller: without a listener the workers still run,
/// on `attome_jobs::SAFETY_POLL_INTERVAL`, and the reason is logged.
pub async fn start_job_wakeup_listener(
    config: &AppConfig,
    jobs: &mut attome_jobs::Jobs<attome_core::jobs::EngineJob>,
) {
    let options = match attome_db::runtime_session_options(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    ) {
        Ok(options) => options.application_name("attome-job-wakeup"),
        Err(e) => {
            tracing::warn!(error = %e, "job wake-up listener: no runtime session endpoint; workers poll every 2 s");
            return;
        }
    };
    match attome_jobs::attach_wakeup_listener(
        options,
        jobs,
        attome_server::metrics::record_job_wakeup_listener_connect,
    )
    .await
    {
        Ok(listen) => {
            // Process-lifetime supervision: losing it degrades to the poll.
            tokio::spawn(async move {
                match listen.await {
                    Ok(()) => tracing::error!(
                        "job wake-up listener stopped; workers fall back to the 2 s safety poll"
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        "job wake-up listener failed; workers fall back to the 2 s safety poll"
                    ),
                }
            });
        }
        Err(e) => tracing::warn!(
            error = %e,
            "job wake-up listener could not connect; workers poll every 2 s until restart"
        ),
    }
}

/// BJB-5 (P-scheduler-singleton §4.2) — runs `fut`, then signals shutdown
/// whatever it returned, so one joined component ending (a crashed monitor, a
/// listener that failed to serve) takes its siblings down instead of leaving a
/// process that looks alive but no longer does its job. `tokio::join!` stays:
/// the siblings still drain on the signal rather than being dropped mid-flight.
pub async fn signal_shutdown_after<F: std::future::Future>(
    shutdown: tokio::sync::watch::Sender<bool>,
    fut: F,
) -> F::Output {
    let output = fut.await;
    // `send` only fails when every receiver is gone, i.e. nobody is left to stop.
    let _ = shutdown.send(true);
    output
}

/// What the `SendEmail` arm does with one send outcome (attome-email plan §4.2).
/// Pure, so the whole table is unit-tested without a relay or a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendEmailDisposition {
    /// Close the ledger row with this status, append the timeline event, and
    /// end the job `Ok` — a finished outcome never re-sends (BEM-15).
    Settle(attome_email::DeliveryStatus),
    /// Count a transient attempt on the ledger row and retry.
    RetryCountingAttempt,
    /// Retry with the ledger untouched (the relay was never reached).
    Retry,
}

fn send_email_disposition(
    result: &Result<(), attome_email::SendError>,
    final_attempt: bool,
) -> SendEmailDisposition {
    use attome_email::{DeliveryStatus, SendError};
    let Err(error) = result else {
        return SendEmailDisposition::Settle(DeliveryStatus::Sent);
    };
    match error {
        SendError::Suppressed
        | SendError::Permanent {
            recipient_attributable: true,
            ..
        } => SendEmailDisposition::Settle(DeliveryStatus::Suppressed),
        // D-661: a relay/credential 5xx, a TLS/AUTH refusal and a malformed
        // message are all terminal, and none of them is the recipient's fault.
        SendError::Permanent { .. } | SendError::Config { .. } | SendError::InvalidAddress(_) => {
            SendEmailDisposition::Settle(DeliveryStatus::Failed)
        }
        // BEM-17: the relay may have taken it; never blind-retried.
        SendError::Unknown { .. } => SendEmailDisposition::Settle(DeliveryStatus::Unknown),
        // BEM-17/F16: the last attempt closes the row instead of leaving it
        // `queued` behind a dead-lettered job.
        SendError::Transient { .. } | SendError::Internal(_) | SendError::Disabled
            if final_attempt =>
        {
            SendEmailDisposition::Settle(DeliveryStatus::Failed)
        }
        SendError::Transient { .. } => SendEmailDisposition::RetryCountingAttempt,
        SendError::Internal(_) | SendError::Disabled => SendEmailDisposition::Retry,
    }
}

/// BEM-15 — everything after the relay answered is advisory: a failed ledger
/// or timeline write is logged and the job still ends `Ok`, because failing it
/// would make apalis re-send mail the relay already accepted (F15).
async fn settle_send_outcome(
    db: &DbPool,
    delivery_id: Option<uuid::Uuid>,
    communication_id: Option<uuid::Uuid>,
    status: attome_email::DeliveryStatus,
    detail: &str,
) {
    if let Some(id) = delivery_id {
        let written = if status == attome_email::DeliveryStatus::Sent {
            attome_email::delivery::mark_sent(db, id).await
        } else {
            attome_email::delivery::mark_terminal(db, id, status, detail).await
        };
        match written {
            Ok(true) => {}
            // BEM-4: a duplicate execution or a resend already resolved it.
            Ok(false) => tracing::info!(
                delivery_id = %id,
                status = status.as_str(),
                "email: delivery row already resolved; leaving it as is"
            ),
            Err(e) => tracing::warn!(
                delivery_id = %id,
                status = status.as_str(),
                error = %e,
                "email: the delivery ledger write failed after the send finished — the outcome \
                 stands and the row may still read queued"
            ),
        }
    }
    if let Some(id) = communication_id {
        let event = if status == attome_email::DeliveryStatus::Sent {
            "sent"
        } else {
            "failed"
        };
        if let Err(e) =
            attome_api::communication::record_delivery_event(db, id, event, Some(detail)).await
        {
            tracing::warn!(
                communication_id = %id,
                error = %e,
                "email: the communication delivery event could not be appended"
            );
        }
    }
}

/// The unmasked detail of an `AppError::Internal` anywhere in `e`'s source
/// chain, or `None` when the failure is not a masked internal error.
fn masked_internal_detail<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a str> {
    let mut current = Some(e);
    while let Some(err) = current {
        if let Some(attome_types::AppError::Internal(detail)) = err.downcast_ref() {
            return Some(detail);
        }
        current = err.source();
    }
    None
}

/// The `SendEmail` arm (attome-email plan §4.2), callable on its own so BEM-9's
/// ledger suite drives it without an apalis worker. `attempt`/`task_id` are
/// the apalis attempt and row id `attome_jobs::is_final_attempt` reads.
pub async fn run_send_email_job(
    db: &DbPool,
    config: &AppConfig,
    msg: attome_email::EmailMessage,
    attempt: usize,
    task_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // M52 Phase 1 (D-465): captured before `msg` moves into `send`, so
    // the outcome can be appended to `communication_event`'s
    // timeline (a new row per outcome; `communication` stays
    // append-only). `None` outside the compose/reply path.
    let delivery_id = msg.delivery_id;
    let communication_id = msg.communication_id;
    let to = msg.to.clone();
    let result = attome_email::send(&config.email, db, msg).await;
    let final_attempt = match &result {
        Err(
            attome_email::SendError::Transient { .. }
            | attome_email::SendError::Internal(_)
            | attome_email::SendError::Disabled,
        ) => attome_jobs::is_final_attempt(db, task_id, attempt)
            .await
            .unwrap_or_else(|e| {
                // Retrying is the safe side: apalis still dead-letters
                // the row at its budget.
                tracing::warn!(
                    task_id = %task_id,
                    error = %e,
                    "email: could not read the job's attempt budget; retrying"
                );
                false
            }),
        _ => false,
    };
    match send_email_disposition(&result, final_attempt) {
        SendEmailDisposition::Settle(status) => {
            let detail = match &result {
                Ok(()) => to,
                Err(e) => {
                    if matches!(
                        e,
                        attome_email::SendError::Config { .. }
                            | attome_email::SendError::Unknown { .. }
                    ) {
                        tracing::error!(
                            delivery_id = ?delivery_id,
                            outcome = e.label(),
                            error = %e.redacted_message(),
                            "email: terminal send failure that no retry can fix — \
                             operator action needed"
                        );
                    }
                    e.to_string()
                }
            };
            settle_send_outcome(db, delivery_id, communication_id, status, &detail).await;
        }
        SendEmailDisposition::RetryCountingAttempt => {
            // No timeline event per attempt: only a resolved outcome
            // belongs there, or a flaky relay reads as repeated failures.
            let message = result
                .err()
                .map(|e| e.redacted_message())
                .unwrap_or_default();
            if let Some(id) = delivery_id
                && let Err(e) =
                    attome_email::delivery::mark_transient_attempt(db, id, &message).await
            {
                tracing::warn!(
                    delivery_id = %id,
                    error = %e,
                    "email: transient attempt not recorded on the delivery row"
                );
            }
            // The wrapper applies exponential backoff (T2-12).
            return Err(message.into());
        }
        SendEmailDisposition::Retry => {
            let message = result
                .err()
                .map(|e| e.redacted_message())
                .unwrap_or_default();
            return Err(message.into());
        }
    }
    Ok(())
}

/// The original per-job-type dispatch, unchanged in behavior except that it
/// no longer owns backoff -- see [`handle_platform_job`], which wraps this.
///
/// Boxed error: `SendEmail` fails with `attome_types::AppError` (SMTP/lettre),
/// every other arm fails with `sqlx::Error` — apalis needs one concrete
/// error type per job function, and both already impl `std::error::Error`.
/// F024's `BulkEntityOperation` and `ApplyStagedImport` fail with
/// `attome_types::AppError` too, from `attome_records::bulk::process`/
/// `process_staged_import` — the two arms here that need the full
/// `EngineState` (metadata registry, audit signer) rather than a bare `DbPool`,
/// since both reuse the exact same validation/audit helpers the interactive
/// `entity_crud.rs` handlers use.
async fn dispatch_platform_job(
    job: JobEnvelope<EngineJob>,
    db: Data<DbPool>,
    db_migrator: Data<MigratorDb>,
    config: Data<AppConfig>,
    attome_state: Data<EngineState>,
    attempt: usize,
    task_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // P-job-envelope-versioning §1/§4.1: a row a newer producer enqueued (an
    // unrecognized variant name, or a version this binary predates) decodes
    // to `Unrecognized` rather than failing inside apalis-sql's own claim
    // query. Failing this attempt here is a normal, bounded apalis
    // retry/failure (governed by that row's own `max_attempts`, per
    // P-job-system-hardening item (d)) with a descriptive `last_error`,
    // instead of an opaque decode crash that never reaches this function at
    // all.
    let job = match job {
        JobEnvelope::Known { job, trace_context } => {
            // P-observability-completion: re-enters the propagating request/
            // job's trace by restoring it as this job's (apalis
            // `.enable_tracing()`-created) current span's parent, so a
            // `SendEmail` job enqueued from within a traced HTTP request
            // shows up as a child span of that request in the OTLP
            // collector, not an orphan — the actual "extract context in
            // workers" half of this plan, not just log correlation. A
            // missing/malformed `traceparent` (every job today while
            // `observability.enable_distributed_tracing = false`, since no
            // producer captures one — see `current_traceparent()` in
            // `attome_jobs::lib`) leaves the span's parent untouched, same
            // no-op posture as every other OTel call site this plan touches.
            if let Some(traceparent) = &trace_context {
                if let Some(span_context) = attome_types::w3c_trace::parse_traceparent(traceparent)
                {
                    let parent_cx =
                        opentelemetry::Context::new().with_remote_span_context(span_context);
                    // Same no-op posture: with no `tracing-opentelemetry` layer
                    // installed this returns `SetParentError::LayerNotFound`,
                    // which is the expected result whenever
                    // `enable_distributed_tracing = false`. Logged at the same
                    // `debug` level as the unparseable-traceparent arm below;
                    // the job itself runs regardless.
                    if let Err(err) = tracing::Span::current().set_parent(parent_cx) {
                        tracing::debug!(
                            error = %err,
                            "platform job: could not restore the stored traceparent as this \
                             job span's parent — processing without a restored span parent"
                        );
                    }
                } else {
                    tracing::debug!(
                        traceparent = %traceparent,
                        "platform job: stored trace_context did not parse as a valid \
                         traceparent — processing without a restored span parent"
                    );
                }
            }
            job
        }
        JobEnvelope::Unrecognized { variant, version } => {
            tracing::warn!(
                variant = %variant,
                envelope_version = version,
                "platform job: unrecognized envelope — this worker binary predates the producer \
                 that enqueued it (or the row is corrupt); failing this attempt instead of \
                 processing it. Bounded by this row's own max_attempts; see the admin failed-jobs \
                 surface (P-job-system-hardening item (d)) once attempts are exhausted."
            );
            return Err(format!(
                "unrecognized platform job envelope: variant='{variant}' envelope_version={version}"
            )
            .into());
        }
    };
    match job {
        EngineJob::SendEmail(msg) => {
            run_send_email_job(&db, &config, *msg, attempt, &task_id).await?;
        }
        // P-db-privilege-separation / D-117: both arms below issue DDL
        // (`CREATE TABLE ... PARTITION OF`, `DROP TABLE`) — migrator pool,
        // not the runtime one every other arm here uses.
        EngineJob::EnsureAuditPartitions => {
            ensure_audit_partitions(&db_migrator.0, &config).await?;
        }
        EngineJob::PruneNotificationRecipientPartitions => {
            attome_notification::recipient::prune_old_partitions(
                &db_migrator.0,
                config.notification.recipient_retention_days,
            )
            .await?;
        }
        EngineJob::FanOutNotification { dispatch_id } => {
            attome_notification::recipient::fan_out_notification(&db, dispatch_id).await?;
        }
        EngineJob::BackfillRecipientForNewUser { user_id } => {
            // How far back a new user sees notifications on first login —
            // a product/UX constant, never varied per-deployment.
            const NEW_USER_BACKFILL_DAYS: u32 = 30;
            attome_notification::recipient::backfill_for_new_user(
                &db,
                user_id,
                NEW_USER_BACKFILL_DAYS,
            )
            .await?;
        }
        EngineJob::BuildAttributeIndex {
            entity_logicalname,
            field_logicalname,
        } => {
            let wanted: Option<bool> = sqlx::query_scalar(
                // A lookup column is always indexed (FK existence and
                // cascade checks), like the admin route's own intent.
                r#"SELECT (COALESCE(a.is_sortable, false) OR COALESCE(a.is_filterable, false)
                           OR a.type = 11)
                   FROM attribute_info a
                   JOIN entity_info e ON e.id = a.entity_ref
                  WHERE e.logicalname = $1 AND a.logicalname = $2
                    AND (e.is_active IS NULL OR e.is_active = true)
                    AND (a.is_active IS NULL OR a.is_active = true)"#,
            )
            .bind(&entity_logicalname)
            .bind(&field_logicalname)
            .fetch_optional(&*db)
            .await?;
            // A retired attribute/entity needs no DDL. For a live attribute,
            // re-read intent is authoritative over the enqueue-time toggle.
            if let Some(wanted) = wanted {
                attome_metadata::provision::sync_attribute_index(
                    &config,
                    &entity_logicalname,
                    &field_logicalname,
                    wanted,
                )
                .await?;
                // AA4-T5: and the trigram index a large filterable text
                // field's `contains` filter uses.
                attome_metadata::provision::sync_trigram_index(
                    &config,
                    &entity_logicalname,
                    &field_logicalname,
                    config.query.trigram_index_min_rows,
                )
                .await?;
            }
        }
        // Solution 7 Phase 2 (D-787 rule 7): the unique index of a declared
        // business key above the size gate. The worker re-reads the entity's
        // current key on its own migrator session, so a key changed again
        // while this was queued builds the newest one; a retired entity
        // needs no DDL.
        EngineJob::BuildBusinessKeyIndex { entity_logicalname } => {
            attome_metadata::provision::sync_business_key_index(&config, &entity_logicalname)
                .await?;
        }
        // P-online-schema-change Step 3: migrator identity, not runtime —
        // same routing note as `EnsureAuditPartitions`/
        // `PruneNotificationRecipientPartitions` above (D-117), since this
        // job's backfill/terminal-ALTER phases both issue DDL.
        EngineJob::ApplySchemaChangePlan { plan_id } => {
            attome_metadata::provision::apply_schema_change_plan(&db_migrator.0, plan_id).await?;
        }
        // P-environment-promotion §5 step 12: the bundle apply job. Same
        // identity note as `ApplySchemaChangePlan` above — entity/attribute
        // objects reach the database through attome-metadata's provisioning
        // primitives, which issue DDL, so the handler takes the migrator
        // pool (`attome_state.base.db_migrator`, D-117) for those and the
        // runtime pool for the ledger and the non-DDL components.
        EngineJob::ApplyMetadataBundle { plan_id } => {
            attome_api::bundle::run_apply_job(&attome_state, plan_id).await?;
        }
        // Solution 7 (D-785, design §5.3): the changeset apply job. Same
        // pool note as `ApplyMetadataBundle` — entity/field operations reach
        // the database through attome-metadata's provisioning primitives on the
        // migrator pool, the ledger through the runtime pool.
        EngineJob::ApplyChangesets { apply_ids } => {
            attome_api::changeset::apply::run_apply_job(&attome_state, &apply_ids).await?;
        }
        // Solution 7 Phase 2 (D-788): a large structure change's batched
        // run (archive copy + drop, or shadow-column backfill + swap). Same
        // pool note as `ApplyChangesets`: its DDL runs on the migrator pool.
        EngineJob::RunDataStep { run_id } => {
            attome_api::field_changes::run_field_run(&attome_state, run_id).await?;
        }
        // D-788 rule 9: the hourly recovery-archive purge (legal holds
        // suspend it per record; `retention.legal_hold` suspends it all).
        EngineJob::PruneRecoveryArchive => {
            let purged = attome_core::recovery_archive::purge_expired(
                &attome_state.base.db,
                config.retention.legal_hold,
            )
            .await?;
            if purged > 0 {
                tracing::info!(purged, "recovery archive purge: run complete");
            }
            // Y12-T8: renamed attributes' old names past their alias period.
            let aliases = attome_metadata::provision::field_change::prune_expired_aliases(
                &attome_state.base.db,
            )
            .await?;
            if aliases > 0 {
                tracing::info!(aliases, "attribute aliases: expired ones removed");
            }
            // Design §8.4: a release-report item whose archived values are
            // all gone can no longer be restored.
            let expired =
                attome_core::release_report::expire_archive_items(&attome_state.base.db).await?;
            if expired > 0 {
                tracing::info!(
                    expired,
                    "release report: archive-backed items expired (no values left to restore)"
                );
            }
        }
        EngineJob::BulkEntityOperation(payload) => {
            attome_records::bulk::process(
                &attome_state,
                payload.bulk_op_id,
                &payload.entity_logicalname,
                &payload.operation,
                payload.records,
                payload.user_id,
            )
            .await?;
        }
        EngineJob::ApplyStagedImport(payload) => {
            attome_records::bulk::process_staged_import(
                &attome_state,
                payload.import_id,
                &payload.entity_logicalname,
                &payload.operation,
                payload.records,
                payload.user_id,
            )
            .await?;
        }
        // M12 (data management) — record export, data profiling, and
        // in-place bulk field transform. Same `&attome_state`-taking shape as
        // `BulkEntityOperation`/`ApplyStagedImport` above: each reuses
        // attome-api's own validation/audit helpers, not a bare `DbPool`.
        EngineJob::DataExport(payload) => {
            attome_api::data_export::process(&attome_state, payload).await?;
        }
        EngineJob::DataProfile(payload) => {
            attome_api::data_profile_admin::process(&attome_state, payload).await?;
        }
        EngineJob::DataBulkTransform(payload) => {
            attome_api::bulk_transform::process(&attome_state, payload).await?;
        }
        // M17 (data migration, D-433) — the rollback worker.
        EngineJob::RollbackMigrationRun { run_id, user_id } => {
            attome_api::migration::process_rollback(&attome_state, run_id, user_id).await?;
        }
        EngineJob::RewrapSecrets { domain } => {
            rewrap_secrets(&db, &config, &attome_state, domain).await?;
        }
        EngineJob::ScanUploadedFile { session_id } => {
            attome_document::files_scan::process(&attome_state, session_id).await?;
        }
        EngineJob::PruneExpiredUploadSessions => {
            attome_document::files_scan::prune_expired_sessions(&attome_state).await?;
        }
        EngineJob::PruneApalisJobHistory => {
            prune_apalis_job_history(&db, &config).await?;
            // Z7-T5: chain steps and finished fan-out groups past 30 days.
            attome_jobs::chain::prune(&db, 30).await?;
            // Z7-T4: finished and cancelled batch jobs past 30 days.
            attome_jobs::batch::prune(&db, 30).await?;
            // M3-T4: the same daily prune clears old workflow step payloads.
            attome_workflow::retention::prune_payloads(
                &attome_state,
                config.jobs.workflow_payload_retention_days,
            )
            .await?;
        }
        EngineJob::TrigramIndexSweep => {
            let candidates = attome_metadata::provision::trigram_index_candidates(
                &db,
                config.query.trigram_index_min_rows,
            )
            .await?;
            let mut queued = 0usize;
            for (entity, field) in candidates {
                let key = format!("trigram-index:{entity}:{field}");
                let job = EngineJob::BuildAttributeIndex {
                    entity_logicalname: entity,
                    field_logicalname: field,
                };
                if attome_jobs::enqueue_dedup(&db, job, &key).await? {
                    queued += 1;
                }
            }
            tracing::info!(queued, "trigram index sweep: builds queued");
        }
        EngineJob::RevalidateQueryPlans => {
            let summary =
                attome_records::query_admin::revalidate_all(&attome_state.base.db_readonly, &db)
                    .await?;
            tracing::info!(
                revalidated = summary.revalidated,
                unchanged = summary.unchanged,
                failed = summary.failed,
                "query plan revalidation: run complete"
            );
        }
        EngineJob::PruneIdempotencyRecords => {
            prune_idempotency_records(&db, &config).await?;
        }
        EngineJob::PruneAuthTokens => {
            prune_auth_tokens(&db).await?;
        }
        EngineJob::ProposeRetentionActions => {
            let proposed =
                attome_compliance::retention::propose_retention_actions(&attome_state).await?;
            tracing::info!(proposed, "retention propose: sweep complete");
        }
        EngineJob::ExecuteRetentionAction { action_id } => {
            attome_compliance::retention::execute_action(&attome_state, action_id).await?;
        }
        EngineJob::PruneExpiredMemories => {
            let deleted =
                attome_compliance::retention::prune_expired_memories(&attome_state).await?;
            if deleted > 0 {
                tracing::info!(deleted, "memory retention sweep: run complete");
            }
        }
        // M41 Phase 1 (Process Intelligence, D-462) — see this variant's doc
        // comment in attome_jobs::job. Runtime pool only: extraction reads
        // attome-workflow's/attome-audit's tables and writes attome-process's own by
        // plain SQL, no metadata registry or audit-signer access needed.
        EngineJob::ProcessExtractionSweep => {
            let stats = attome_process::extraction::run_sweep(&db).await?;
            if stats.events_written > 0 {
                tracing::info!(
                    case_defs_processed = stats.case_defs_processed,
                    events_written = stats.events_written,
                    "process extraction sweep: run complete"
                );
            }
        }
        EngineJob::WorkflowExecute { instance_id } => {
            attome_workflow::scheduler::execute_instance(&attome_state, instance_id).await?;
        }
        EngineJob::WorkflowSlaSweep => {
            let resumed = attome_workflow::sla_sweep::sweep(&attome_state).await?;
            if resumed > 0 {
                tracing::info!(resumed, "workflow SLA sweep: run complete");
            }
            // M1-T2: schedule-triggered flows ride the same minute sweep.
            let started = attome_workflow::schedule_trigger::run_due(&attome_state).await?;
            if started > 0 {
                tracing::info!(started, "workflow schedule triggers: flows started");
            }
            // M1-T5: queued runs of capped flows start as slots free up.
            let promoted = attome_workflow::instance_admin::promote_queued(&attome_state).await?;
            if promoted > 0 {
                tracing::info!(promoted, "workflow queued runs: started");
            }
        }
        EngineJob::WorkflowEntityTriggerDispatch => {
            let started = attome_workflow::entity_trigger::dispatch_pending(&attome_state).await?;
            if started > 0 {
                tracing::info!(started, "workflow entity-trigger dispatch: run complete");
            }
        }
        EngineJob::CrawlWebsite { target_id } => {
            attome_webcrawl::crawl::run(&attome_state, target_id).await?;
        }
        // F10-T9: one period's recalculation previews.
        EngineJob::CommissionRecalcPreview { period_id } => {
            let written =
                attome_commission::recalc::preview_period(&attome_state, period_id).await?;
            tracing::info!(%period_id, written, "commission recalc preview: complete");
        }
        // F4-T6: the work that follows an issued invoice.
        // F5-T10: one refund through its gateway.
        EngineJob::BillingExecuteRefund { refund_id } => {
            attome_billing::payment::refund::execute_refund(
                &attome_state,
                refund_id,
                &attome_billing::payment::recurring::LiveAdapters,
            )
            .await?;
            tracing::info!(%refund_id, "billing refund: settled");
        }
        EngineJob::BillingAfterIssue { invoice_id } => {
            attome_billing::issue::run_after_issue(&attome_state, invoice_id).await?;
            tracing::info!(%invoice_id, "billing after-issue hooks: complete");
        }
        // F10-T5: one commission calculation run.
        EngineJob::CommissionRun { run_id } => {
            let paid = attome_commission::run::execute(&attome_state, run_id).await?;
            tracing::info!(%run_id, participants = paid, "commission run: complete");
        }
        EngineJob::EventsDispatchTick => {
            let enqueued = attome_events::dispatch::dispatch_pending(&attome_state).await?;
            if enqueued > 0 {
                tracing::info!(enqueued, "events dispatch tick: run complete");
            }
            // M19 gap list — the `kind = 'audit'` source is a second,
            // independent read (audit_header, not the entity-change
            // outbox) piggybacked on the same scheduled tick rather than a
            // second `EngineJob` variant/scheduler; see
            // `attome_events::audit_dispatch`'s module doc for why it can't
            // share `dispatch::dispatch_pending`'s outbox read. A failure
            // here is independent of the webhook tick above (each catches
            // its own errors internally per-subscription; nothing here can
            // roll the other back since neither holds a transaction across
            // the other).
            let audit_enqueued =
                attome_events::audit_dispatch::dispatch_pending(&attome_state).await?;
            if audit_enqueued > 0 {
                tracing::info!(
                    enqueued = audit_enqueued,
                    "audit events dispatch tick: run complete"
                );
            }
        }
        EngineJob::EventsDeliverWebhook { delivery_id } => {
            attome_events::delivery::deliver(&attome_state, delivery_id).await?;
        }
        // TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.2 (T2-2) — see this
        // variant's doc comment in attome_core::jobs::EngineJob. Runtime pool: the
        // handler only ever touches provisioned entity tables through
        // ordinary DML, never DDL, so there is no D-117 reason to route it
        // through `db_migrator` the way `ApplySchemaChangePlan` above does.
        EngineJob::CascadeDeactivateDependents {
            target_entity,
            target_record_id,
            dependent_entity,
            dependent_field,
            deactivated_by,
        } => {
            attome_records::entity_mutation::run_cascade_deactivate_job(
                &db,
                &target_entity,
                target_record_id,
                &dependent_entity,
                &dependent_field,
                deactivated_by,
            )
            .await?;
        }
        EngineJob::RevalidateFieldSecurityProfiles => {
            let summary = attome_security::revalidation::revalidate_field_security_profiles(
                &attome_state.base.db_readonly,
            )
            .await?;
            tracing::info!(
                checked = summary.checked,
                stale = summary.stale,
                "field security profile revalidation: run complete"
            );
        }
        // M27 Phase 1 (KPI & Metrics, D-407). D-786: query metrics run
        // through `query_exec` under the metric service principal, so the
        // sweep takes the `EngineState` (query_exec picks the SELECT-only pool
        // itself, P1.1e/D-126). D-480 (M26 R-14) moved this crate out of
        // attome-dashboard.
        EngineJob::ComputeMetricSnapshots => {
            let computed =
                attome_metric::metric::run_scheduled_snapshot_sweep(&attome_state).await?;
            if computed > 0 {
                tracing::info!(computed, "metric snapshot sweep: run complete");
            }
        }
        // M34 (AI Governance, D-435): self-contained in attome-ai (only
        // needs the runtime pool + notification config), same shape as
        // `ComputeMetricSnapshots` immediately above.
        EngineJob::AiQualityMonitor => {
            let summary = attome_ai::quality_monitor::run(&db, &config.notification).await?;
            tracing::info!(
                groups_checked = summary.groups_checked,
                groups_flagged = summary.groups_flagged,
                "ai quality monitor: run complete"
            );
            // N31-T1: a severe drop switches the action off until an
            // administrator turns it back on. A failed trip is logged; the
            // alert above has already gone out.
            for action in &summary.severe_actions {
                if let Err(error) = attome_ai::scope_switch::trip(
                    &attome_state,
                    "tool",
                    action,
                    "quality",
                    "acceptance fell by 30 points or more against the prior period",
                )
                .await
                {
                    tracing::error!(%error, action, "ai quality monitor: automatic switch-off failed");
                } else {
                    tracing::warn!(
                        action,
                        "ai quality monitor: action switched off automatically"
                    );
                }
            }
            // N25-T2: re-run each pinned model's eval suite and alert on drift.
            match attome_ai::model_drift::check(&attome_state, &config.notification).await {
                Ok(drift) => tracing::info!(
                    checked = drift.checked,
                    drifted = drift.drifted,
                    skipped = drift.skipped,
                    "ai quality monitor: pinned-model drift check complete"
                ),
                Err(error) => {
                    tracing::error!(%error, "ai quality monitor: pinned-model drift check failed");
                }
            }
        }
        // C4 (row A-40): the confirm-lease backstop. Self-contained in
        // attome-ai, runtime pool only, same shape as `AiQualityMonitor` above.
        // E9-T7: overdue marketing hand-offs, every five minutes.
        EngineJob::MarketingSweep => {
            let overdue = attome_marketing::handoff_sla::sweep_overdue(
                &db,
                &config.notification,
                chrono::Utc::now(),
            )
            .await?;
            if overdue > 0 {
                tracing::info!(overdue, "marketing hand-offs: overdue ones escalated");
            }
            // E9-T4: people move between nurture tracks as they change.
            let moved = attome_marketing::nurture_tracks::run(&db).await?;
            if moved > 0 {
                tracing::info!(moved, "nurture: people moved between tracks");
            }
        }
        // Y2-T8: the daily table-health sample.
        EngineJob::TableHealthSample => {
            let sampled = attome_api::table_health::sample_all(&attome_state).await?;
            tracing::info!(sampled, "table health: daily sample taken");
            // Y2-T9: fill factors from the measured updates, when enabled.
            if config.metadata.storage_tuning_enabled {
                let tuned = attome_api::table_health::tune_storage(&attome_state).await?;
                tracing::info!(tuned, "storage tuning: daily pass done");
            }
        }
        // Q16-T2: the weekly audit chain verification.
        EngineJob::AuditChainVerify => {
            let store = if config.audit.external_anchoring_enabled {
                match attome_audit::anchor::create_anchor_store(&config).await {
                    Ok(store) => Some(store),
                    Err(e) => {
                        tracing::warn!(error = %e, "audit verify: anchor store unavailable; verifying the database only");
                        None
                    }
                }
            } else {
                None
            };
            let summary = attome_audit::verify_job::run(
                &db,
                attome_state.audit_signer.as_deref(),
                store.as_ref(),
            )
            .await?;
            tracing::info!(
                organizations = summary.organizations,
                failed = summary.failed,
                "audit chain verification: weekly run done"
            );
        }
        // AA13-T9: the monthly SLO report, written once per month.
        EngineJob::SloMonthlyReport => {
            if attome_api::slo_admin::monthly_report(&attome_state, chrono::Utc::now()).await? {
                tracing::info!("slo: monthly report written");
            }
        }
        // AA13-T9: fast burns of an SLO class's error budget.
        // AA9-T7: limits near their value, once per limit per day.
        EngineJob::LimitWarningCheck => {
            let notified = attome_api::limits_admin::limit_warning_check(
                &attome_state,
                &config.notification,
                chrono::Utc::now(),
            )
            .await?;
            if !notified.is_empty() {
                tracing::warn!(limits = ?notified, "limit warning: administrators told");
            }
        }
        // AA14-T8: latency regressions since the last upgrade.
        EngineJob::PerfRegressionCheck => {
            let findings = attome_server::slo::perf_regression_check(
                &attome_state.base.db,
                chrono::Utc::now(),
            )
            .await?;
            let regressed: Vec<&str> = findings
                .iter()
                .filter(|f| f.regressed)
                .map(|f| f.class.as_str())
                .collect();
            if regressed.is_empty() {
                tracing::info!(
                    compared = findings.len(),
                    "perf regression check: no regression"
                );
            } else {
                tracing::warn!(classes = ?regressed, "perf regression check: p95 regressed since the upgrade");
            }
        }
        EngineJob::SloBurnCheck => {
            let notified = attome_api::slo_admin::burn_check(
                &attome_state,
                &config.notification,
                chrono::Utc::now(),
            )
            .await?;
            if !notified.is_empty() {
                tracing::warn!(classes = ?notified, "slo: fast burn notified");
            }
        }
        // AI4-T5: the follow-up rules' stall scans.
        EngineJob::AiFollowupScan => {
            let now = chrono::Utc::now();
            let mut found = 0;
            for rule in attome_ai::followup::active_rules(&attome_state.base.db).await? {
                match attome_ai::followup::detect(&attome_state, &rule, now).await {
                    Ok(n) => found += n,
                    // One broken rule never stops the others.
                    Err(e) => {
                        tracing::warn!(rule = %rule.id, error = %e, "follow-up scan: rule skipped")
                    }
                }
            }
            if found > 0 {
                tracing::info!(found, "follow-up scan: new stalls recorded");
            }
            // One job per open, unclaimed item; the key makes a rescan
            // enqueue nothing twice.
            let db = &attome_state.base.db;
            for item_id in attome_ai::followup_run::open_items(db).await? {
                attome_jobs::enqueue_dedup(
                    db,
                    EngineJob::AiFollowupItem { item_id },
                    &format!("ai-followup-item:{item_id}"),
                )
                .await?;
            }
        }
        // AI4-T5: one follow-up item, run for the record's owner.
        EngineJob::AiFollowupItem { item_id } => {
            let outcome = attome_ai::followup_run::run_item(&attome_state, item_id).await?;
            tracing::info!(item = %item_id, ?outcome, "follow-up item run");
        }
        // D25-T4: competitor mentions proposed from new emails and notes.
        EngineJob::SalesMentionScan => {
            let proposed = attome_sales::competitor_mentions::sweep_mentions(&attome_state).await?;
            if proposed > 0 {
                tracing::info!(proposed, "competitor mentions: proposals written");
            }
        }
        // D25-T3: win/loss reviews for big closes.
        EngineJob::SalesDealCloseSweep => {
            let created = attome_sales::win_loss::sweep_closes(&attome_state).await?;
            if created > 0 {
                tracing::info!(created, "win/loss: reviews created for big closes");
            }
        }
        // D7-T6: managers hear about disabled users' open deals.
        EngineJob::SalesLeaverSweep => {
            let reported = attome_sales::leavers::sweep_leavers(&attome_state).await?;
            if reported > 0 {
                tracing::info!(reported, "leavers: managers told about open deals");
            }
        }
        // C2-T1: followers hear about changes to records they follow.
        EngineJob::NotificationFollowSweep => {
            let sent = attome_notification::follows::sweep(&attome_state).await?;
            if sent > 0 {
                tracing::info!(sent, "follows: followers notified");
            }
        }
        // D6-T8: line snapshots past their day.
        EngineJob::SalesSnapshotPrune => {
            let removed = attome_sales::undo::prune(&attome_state.base.db).await?;
            tracing::info!(removed, "sales line snapshots: pruned");
        }
        // F10-T3: commission credits for won deals.
        EngineJob::CommissionCreditSweep => {
            let written = attome_commission::credit::sweep_won_deals(&attome_state).await?;
            if written > 0 {
                tracing::info!(written, "commission credits: written for won deals");
            }
        }
        // F4-T9: invoice requests into draft invoices.
        EngineJob::BillingRequestSweep => {
            let invoices = attome_billing::requests::process_pending(&attome_state).await?;
            if invoices > 0 {
                tracing::info!(invoices, "billing requests: draft invoices created");
            }
        }
        // F4-T9: due invoice schedules into draft invoices.
        EngineJob::BillingScheduleRun => {
            let invoices = attome_billing::requests::run_schedules(&attome_state).await?;
            if invoices > 0 {
                tracing::info!(invoices, "billing schedules: draft invoices created");
            }
        }
        // AG2-T3: e-invoices ZATCA could not take yet.
        EngineJob::BillingEinvoiceSweep => {
            let transport = attome_einvoice::zatca::api::HttpTransport::new(
                attome_billing::einvoice::ZATCA_TIMEOUT,
            )
            .map_err(|e| e.to_string())?;
            let settled = attome_billing::einvoice::sweep(&attome_state, &transport).await?;
            if settled > 0 {
                tracing::info!(settled, "billing e-invoicing sweep: documents settled");
            }
        }
        // F5-T7: payment gateway events, each applied once.
        EngineJob::BillingGatewayEventApply => {
            let changed = attome_billing::gateway::webhook::apply_events(&attome_state).await?;
            if changed > 0 {
                tracing::info!(changed, "billing gateway events: payments updated");
            }
        }
        // F5-T11: yesterday's gateway payouts, matched to their payments.
        EngineJob::BillingReconcile => {
            let outcome = attome_billing::payment::reconcile::reconcile_yesterday(
                &attome_state,
                &attome_billing::payment::recurring::LiveAdapters,
            )
            .await?;
            tracing::info!(?outcome, "billing payout reconciliation");
        }
        // F5-T9: due invoices charged to saved methods, when turned on.
        EngineJob::BillingChargeDue => {
            if attome_billing::payment::recurring::enabled(&attome_state) {
                let run = attome_billing::payment::recurring::charge_due(
                    &attome_state,
                    chrono::Utc::now().date_naive(),
                    &attome_billing::payment::recurring::LiveAdapters,
                )
                .await?;
                tracing::info!(?run, "billing recurring charges");
            }
        }
        // F4-T10: issued invoices past due.
        EngineJob::BillingOverdueSweep => {
            let marked = attome_billing::status::overdue_sweep(&attome_state).await?;
            if marked > 0 {
                tracing::info!(marked, "billing overdue sweep: invoices marked overdue");
            }
        }
        // D7-T3: new deals get their owner's default team.
        EngineJob::SalesDefaultTeamSweep => {
            let added = attome_sales::team_defaults::sweep_new_deals(&attome_state).await?;
            if added > 0 {
                tracing::info!(added, "default team: members added to new deals");
            }
        }
        EngineJob::AiFollowupRuleRun { rule_id } => {
            let found = attome_ai::followup_routes::run_rule(&attome_state, rule_id).await?;
            tracing::info!(%rule_id, found, "follow-up rule run: complete");
        }
        EngineJob::SalesCallOutcomeRules { attempt_id } => {
            attome_sales::dialer::outcome::apply_rules(&attome_state, attempt_id).await?;
        }
        EngineJob::SalesScheduleShift {
            opportunity_id,
            months,
        } => {
            let moved =
                attome_sales::schedules::run_shift(&attome_state, opportunity_id, months).await?;
            tracing::info!(%opportunity_id, months, moved, "sales schedule shift: complete");
        }
        EngineJob::SalesDefaultTeamApply { owner_id } => {
            let added = attome_sales::team_defaults::run_apply(&attome_state, owner_id).await?;
            tracing::info!(%owner_id, added, "default team: applied to open deals");
        }
        // Q10-T6: role grants past their end, hourly.
        EngineJob::RoleGrantExpiry => {
            let removed = attome_security::grant_expiry::expire_role_grants(
                &attome_state,
                chrono::Utc::now(),
            )
            .await?;
            if removed > 0 {
                tracing::info!(removed, "role grants: expired grants removed");
            }
        }
        // E7-T4: scheduled segment refreshes, hourly.
        EngineJob::SegmentRefreshDue => {
            let refreshed =
                attome_marketing::segment::refresh_due(&attome_state, chrono::Utc::now()).await?;
            if refreshed > 0 {
                tracing::info!(refreshed, "segments: scheduled lists refreshed");
            }
        }
        // E30-T1: loyalty earning and expiry, nightly.
        EngineJob::MarketingNightly => {
            let now = chrono::Utc::now();
            let orders = attome_marketing::loyalty::earn_from_orders(&db, now).await?;
            let expired = attome_marketing::loyalty::expire_due(&db, now).await?;
            // E31-T1: converted referrals earn their referrer points.
            let referrals = attome_marketing::referral::reward_converted(&db, now).await?;
            // E20-T1: target accounts rescored on the same nightly pass.
            let target_accounts = attome_marketing::abm::rescore(&db, now).await?;
            // E6-T5: bounces and complaints reach the people who own the address.
            let effects = attome_marketing::deliverability::effects::apply(&db).await?;
            tracing::info!(
                orders,
                expired,
                referrals,
                target_accounts,
                invalidated = effects.invalidated,
                consent_withdrawn = effects.withdrawn,
                "marketing nightly: run finished"
            );
        }
        // M10-T1: due timers become one job each.
        EngineJob::TimerSweep => {
            let mut conn = db.acquire().await?;
            let claimed = attome_core::timer::claim_due(&mut conn, chrono::Utc::now()).await?;
            drop(conn);
            for timer in &claimed {
                attome_jobs::enqueue_on_pool(&db, EngineJob::TimerFire { timer_id: timer.id })
                    .await?;
            }
            if !claimed.is_empty() {
                tracing::info!(fired = claimed.len(), "timers: due timers queued");
            }
        }
        // M10-T1: one fired timer. No kind has an action yet; each later
        // feature registers its kind here.
        EngineJob::TimerFire { timer_id } => {
            let mut conn = db.acquire().await?;
            if let Some(timer) = attome_core::timer::load(&mut conn, timer_id).await? {
                let error = format!("no action is registered for timer kind {:?}", timer.kind);
                tracing::warn!(%timer_id, kind = %timer.kind, "timers: no action for this kind");
                attome_core::timer::settle(&mut conn, timer_id, Some(&error)).await?;
            }
        }
        // K6-T3: scheduled recrawls, hourly.
        EngineJob::WebcrawlRecrawlDue => {
            let queued =
                attome_webcrawl::schedule::enqueue_due(&attome_state, chrono::Utc::now()).await?;
            if queued > 0 {
                tracing::info!(queued, "webcrawl: scheduled recrawls queued");
            }
        }
        // F3-T10: the recurring-revenue snapshot, nightly.
        EngineJob::MrrSnapshot => {
            let rows =
                attome_billing::metrics::snapshot(&db, chrono::Utc::now().date_naive()).await?;
            tracing::info!(rows, "recurring revenue: snapshot stored");
        }
        // D11-T2: forecast cells, nightly.
        EngineJob::ForecastRecompute => {
            let run = attome_sales::forecast::run(&db, chrono::Utc::now()).await?;
            tracing::info!(
                periods = run.periods,
                cells = run.cells,
                snapshots = run.snapshots,
                "forecast: cells recomputed"
            );
        }
        // D19-T1: deal risk, nightly.
        EngineJob::DealRiskEvaluation => {
            let scored = attome_sales::deal_risk::run(&db, chrono::Utc::now()).await?;
            tracing::info!(scored, "deal risk: run finished");
        }
        // D18-T1: points scores, nightly.
        EngineJob::PointsScoring => {
            let run = attome_sales::scoring_run::run(&attome_state, chrono::Utc::now()).await?;
            tracing::info!(
                models = run.models,
                records = run.records,
                "points scoring: run finished"
            );
        }
        // V2-T2: the next task of every completed recurring task.
        EngineJob::RecurringTaskRoll => {
            let created =
                attome_project::tasks::roll_recurring(&db, chrono::Utc::now().date_naive()).await?;
            if created > 0 {
                tracing::info!(created, "recurring tasks: next tasks created");
            }
        }
        // W1-T3: counterparty match proposals, on demand.
        EngineJob::ContractCounterpartyMatch => {
            let run = attome_contract::counterparty::run_match(&db).await?;
            tracing::info!(
                contracts = run.contracts_seen,
                proposals = run.proposals,
                "contract counterparty match: run finished"
            );
        }
        // W1-T4: contract key dates, nightly.
        EngineJob::ContractKeyDates => {
            let run = attome_contract::dates::run(
                &db,
                &config.notification,
                attome_contract::dates::KeyDateSettings::default(),
                chrono::Utc::now().date_naive(),
            )
            .await?;
            tracing::info!(
                deadlines = run.deadlines_written,
                renewal_tasks = run.renewal_tasks,
                reminders = run.reminders,
                escalations = run.escalations,
                rolled_forward = run.rolled_forward,
                amendments = run.amendments_applied,
                "contract key dates: run finished"
            );
        }
        // B4-T3: tag links past their expiry go.
        EngineJob::TagExpirySweep => {
            let removed = attome_records::entity_crud::tags::sweep_expired_links(&db).await?;
            if removed > 0 {
                tracing::info!(removed, "tags: expired tag links removed");
            }
        }
        // A18-T4: a burst of deletions goes to the administrators.
        EngineJob::BinDeleteAlertSweep => {
            let bursts = attome_records::entity_crud::take_large_deletes(&db).await?;
            for burst in bursts {
                tracing::warn!(
                    user_id = %burst.user_id, entity = %burst.entity, count = burst.count,
                    "recycle bin: many records deleted in ten minutes"
                );
                attome_ai::quality_monitor::alert_admins(
                    &db,
                    &config.notification,
                    format!(
                        "{} {} records deleted in ten minutes",
                        burst.count, burst.entity
                    ),
                    format!(
                        "User {} deleted {} {} records in the last ten minutes. They are in the \
                         recycle bin and can be restored there.",
                        burst.user_id, burst.count, burst.entity
                    ),
                    &format!("/xrm/bin/{}", burst.entity),
                )
                .await;
            }
        }
        EngineJob::AiToolCallSweep => {
            let (reclaimed, expired) = attome_ai::tool_call::sweep(&db).await?;
            if reclaimed > 0 || expired > 0 {
                tracing::info!(reclaimed, expired, "ai tool-call sweep: run complete");
            }
        }
        // M03 (Security & Identity) gap 1 / D-434: auto-completes an access
        // review campaign once its due_date has passed. Runtime pool only —
        // the handler never touches provisioned entity tables.
        EngineJob::AccessReviewCampaignSweep => {
            let completed = attome_security::admin::sweep_due_campaigns(&db).await?;
            if completed > 0 {
                tracing::info!(completed, "access review campaign sweep: run complete");
            }
        }
        // D-432 / M13 — see this variant's doc comment in attome_jobs::job.
        EngineJob::DataMatchSweep => {
            let stats = attome_api::duplicates_match::run_match_sweep(&attome_state).await?;
            if stats.candidates_written > 0 || stats.auto_merge_submitted > 0 {
                tracing::info!(
                    events_processed = stats.events_processed,
                    candidates_written = stats.candidates_written,
                    auto_merge_submitted = stats.auto_merge_submitted,
                    "mdm match sweep: run complete"
                );
            }
        }
        // A15-T6 — one page of a match rule's full scan; it enqueues the next.
        EngineJob::DataMatchScan { rule_id, after_id } => {
            let stats =
                attome_api::duplicates_match::run_match_scan(&attome_state, rule_id, after_id)
                    .await?;
            tracing::info!(
                %rule_id,
                rows = stats.events_processed,
                candidates_written = stats.candidates_written,
                "mdm match scan: page done"
            );
        }
        // M61 Phase 1 (API Management, D-438) — drains the Redis usage-
        // counter buffer into api_usage. Runtime pool + the
        // coordination Redis role (same role apikey_touch's write-coalescing
        // buffer uses) — a plain aggregate UPSERT, no DDL.
        EngineJob::ApiUsageRollup => {
            let flushed =
                attome_server::api_usage::flush(&db, &attome_state.base.redis_coordination).await?;
            if flushed > 0 {
                tracing::info!(flushed, "api usage rollup: run complete");
            }
        }
        // M18 Data Catalog Phase 1 (D-466) — see this variant's doc comment
        // in attome_jobs::job. Composes the query-kind and workflow-kind
        // backfill halves from their respective owning crates, mirroring
        // how `ContentPageStatsRollup` composes `attome_content`/`attome_search`
        // below.
        EngineJob::CatalogLineageBackfill => {
            let queries = attome_records::query_admin::backfill_catalog_lineage(&db, 200).await?;
            let workflows =
                attome_workflow::catalog_backfill::backfill_catalog_lineage(&db, 200).await?;
            if queries > 0 || workflows > 0 {
                tracing::info!(queries, workflows, "catalog lineage backfill: run complete");
            }
        }
        // M18 Data Catalog Phase 1 (D-466) — see this variant's doc comment.
        EngineJob::CatalogDashboardLineageSweep => {
            let stats =
                attome_api::catalog_admin::run_dashboard_lineage_sweep(&attome_state).await?;
            if stats.widgets_synced > 0 {
                tracing::info!(
                    events_processed = stats.events_processed,
                    widgets_synced = stats.widgets_synced,
                    "catalog dashboard lineage sweep: run complete"
                );
            }
        }
        // M18 Data Catalog Phase 1 (D-466) — see this variant's doc comment.
        EngineJob::CatalogUsageRollup => {
            let stats = attome_api::catalog_admin::run_usage_rollup(&db).await?;
            tracing::info!(
                entities_computed = stats.entities_computed,
                "catalog usage rollup: run complete"
            );
        }
        // M56 Content Management Phase 1 (D-436) — see this variant's doc
        // comment in attome_jobs::job. Needs the full `EngineState`, not just the
        // runtime pool, to write the scheduler-actor audit event.
        EngineJob::ContentScheduledPublishSweep => {
            let stats =
                attome_content::scheduling::sweep_scheduled_transitions(&attome_state).await?;
            if stats.total_transitions() > 0 || stats.publish_validation_failed > 0 {
                tracing::info!(
                    published = stats.published,
                    unpublished = stats.unpublished,
                    publish_validation_failed = stats.publish_validation_failed,
                    "content scheduled publish sweep: run complete"
                );
            }
        }
        // M14 Phase 1 (Data Quality) — see this variant's doc comment in
        // attome_jobs::job. Needs the full `EngineState` (the entity metadata
        // registry snapshot + the runtime pool), not just the runtime pool.
        EngineJob::DataQualityScoreSweep => {
            let stats =
                attome_api::quality_score::run_sweep(&attome_state, &config.notification).await?;
            tracing::info!(
                entities_scored = stats.entities_scored,
                scores_written = stats.scores_written,
                issues_written = stats.issues_written,
                alerts_sent = stats.alerts_sent,
                "data quality score sweep: run complete"
            );
        }
        // M25 Phase 1 (Report, D-440) — see this variant's doc comment in
        // attome_jobs::job. Needs the full `EngineState` for `query_exec`,
        // attome-storage, and the audit write.
        EngineJob::ReportRun { run_id } => {
            attome_report::run::process(&attome_state, run_id).await?;
        }
        // M57 Phase 1 (Document Generation, D-463) — see this variant's doc
        // comment in attome_jobs::job. Needs the full `EngineState` for
        // `entity_crud`, attome-storage, the render sidecar client, and the
        // audit write.
        EngineJob::DocgenRender { render_id } => {
            attome_docgen::render::process(&attome_state, render_id).await?;
        }
        // M36 Phase 1 (Predictive Intelligence, D-473) — see this variant's
        // doc comment in attome_jobs::job. Runtime pool only: training reads
        // ticket/SLA history and writes `prediction_model` by plain SQL,
        // no metadata registry or audit-signer access needed. The CPU-bound
        // fit itself runs inside `train::run`'s own `spawn_blocking`
        // (guidelines §10).
        EngineJob::PredictTrainModel { model_id } => {
            attome_predict::train::run(&db, model_id).await?;
        }
        // M36 Phase 1 — see this variant's doc comment.
        EngineJob::PredictScoringSweep => {
            let stats = attome_predict::score::run_scoring_sweep(&db).await?;
            if stats.scored > 0 {
                tracing::info!(
                    models_considered = stats.models_considered,
                    scored = stats.scored,
                    "predict scoring sweep: run complete"
                );
            }
        }
        // M36 Phase 1 — see this variant's doc comment. `fill_outcomes` lives
        // in `score.rs` alongside the scoring sweep (both read/write the
        // same `prediction` rows), not a separate `outcome_fill` module.
        EngineJob::PredictOutcomeFillSweep => {
            let stats = attome_predict::score::fill_outcomes(&db).await?;
            if stats.filled > 0 {
                tracing::info!(
                    filled = stats.filled,
                    "predict outcome-fill sweep: run complete"
                );
            }
        }
        // M25 Phase 1 (Report, D-440) — see this variant's doc comment.
        EngineJob::ReportScheduleSweep => {
            let stats = attome_report::scheduler::sweep(&attome_state).await?;
            if stats.dispatched > 0 || stats.deactivated > 0 {
                tracing::info!(
                    dispatched = stats.dispatched,
                    deactivated = stats.deactivated,
                    "report schedule sweep: run complete"
                );
            }
        }
        // M23 Records Management (D-456) — see these variants' doc comments
        // in attome_jobs::job.
        EngineJob::LegalMatterCollect {
            matter_id,
            collected_by,
        } => {
            attome_compliance::legal_matter_admin::run_collect_job(
                &attome_state,
                matter_id,
                collected_by,
            )
            .await?;
        }
        EngineJob::LegalMatterRelease {
            matter_id,
            released_by,
        } => {
            attome_compliance::legal_matter_admin::run_release_job(
                &attome_state,
                matter_id,
                released_by,
            )
            .await?;
        }
        // M04 (License Management) usage-reporting gap — self-contained in
        // attome-notification (only needs the runtime pool + notification
        // config), same shape as `AiQualityMonitor` above.
        // Audit plan 3.5 (D-541 rule 6): summary events for closed
        // failed-login windows. See `crate::auth::failed_login`.
        EngineJob::FailedLoginSweep => {
            let auditor = attome_audit::security::SecurityAuditor::from_state(&attome_state);
            let summary = crate::auth::failed_login::sweep(
                &auditor,
                &db,
                &attome_state.base.redis_coordination,
                chrono::Utc::now().timestamp(),
            )
            .await?;
            if summary.summaries_written > 0 {
                tracing::info!(
                    keys_seen = summary.keys_seen,
                    summaries_written = summary.summaries_written,
                    "failed-login sweep wrote summary events"
                );
            }
        }
        EngineJob::LicenseExpiryCheck => {
            // D-778: no licence is checked, so nothing expires and nothing
            // schedules this job any more. A row queued by an older build
            // completes as a no-op rather than failing.
            tracing::debug!("license expiry check skipped: licensing removed (D-778)");
        }
        // M11 Search gap list — rebuilds the suggestion/autocomplete
        // materialized table (`search_suggestion`) from registered
        // entities' display names and active `saved_search` records. See
        // `attome_search::suggest`'s module doc for why the latter substitutes
        // for "frequent successful queries from interaction telemetry" —
        // that telemetry never stores raw query text, by design.
        EngineJob::SearchSuggestionRefresh => {
            let stats = attome_search::refresh_suggestions(&attome_state).await?;
            tracing::info!(
                entity_rows = stats.entity_rows,
                saved_search_rows = stats.saved_search_rows,
                "search suggestion refresh: run complete"
            );
        }
        // M11 Search gap list — bounded, scheduled saved-search
        // alert-on-new-results sweep. See `attome_search::sweep_alerts`'s own
        // doc comment for why "new results" is a result-count high-water
        // mark rather than a per-row timestamp comparison.
        EngineJob::SearchSavedSearchAlertSweep => {
            let stats = attome_search::sweep_alerts(&attome_state).await?;
            if stats.notified > 0 {
                tracing::info!(
                    checked = stats.checked,
                    notified = stats.notified,
                    "saved search alert sweep: run complete"
                );
            }
        }
        // M37 Knowledge Management Phase 2 (D-452) — composed here, not in
        // either engine crate: `attome-content` and `attome-search` are siblings
        // with no dependency edge between them, so the retrieval-count join
        // happens at this, the established composition layer, the same way
        // `jobs.rs` already composes several other engine crates' outputs.
        EngineJob::ContentPageStatsRollup => {
            let since = chrono::Utc::now() - chrono::Duration::days(1);
            let retrieval_counts = attome_search::retrieval_counts_by_source(&db, since).await?;
            let stats =
                attome_content::analytics::rollup_page_stats(&db, &retrieval_counts).await?;
            if stats.pages_touched > 0 {
                tracing::info!(
                    pages_touched = stats.pages_touched,
                    views_folded_in = stats.views_folded_in,
                    votes_folded_in = stats.votes_folded_in,
                    "content page stats rollup: run complete"
                );
            }
        }
        // M37 Knowledge Management Phase 2 (D-452) — needs the full
        // `EngineState.base.config.notification` section, not just the runtime
        // pool, to build the `DispatchRequest` the same way `attome-service`'s
        // SLA escalation does.
        EngineJob::ContentReviewReminderSweep => {
            let stats = attome_content::analytics::sweep_review_reminders(
                &db,
                &attome_state.base.config.notification,
            )
            .await?;
            if stats.reminders_sent > 0 {
                tracing::info!(
                    reminders_sent = stats.reminders_sent,
                    "content review reminder sweep: run complete"
                );
            }
        }
        // M84 Phase 1 (Queue Management, D-464) — see this variant's doc
        // comment in attome_jobs::job. Runtime pool + notification config
        // only, same shape as `ContentReviewReminderSweep` immediately
        // above.
        EngineJob::WorkQueueEscalationSweep => {
            let stats = attome_service::queue::run_escalation_sweep(
                &db,
                &attome_state.base.config.notification,
            )
            .await?;
            if stats.overflow_alerts > 0 || stats.idle_escalations > 0 {
                tracing::info!(
                    overflow_alerts = stats.overflow_alerts,
                    idle_escalations = stats.idle_escalations,
                    "work queue escalation sweep: run complete"
                );
            }
        }
        // M73 (SLA Management, D-422) — see this variant's doc comment in
        // attome_jobs::job. Order matters: auto-pause reconciles each
        // ticket's clock against its current status first, so the three
        // sweeps that read clock/breach state afterward see it up to date.
        // Each call is independently best-effort at the row level (see
        // each function's own doc comment); a later sweep's failure does
        // not roll back an earlier one's committed work.
        EngineJob::TicketSlaSweep => {
            let reconciled = attome_service::clock::sweep_auto_pause(&db).await?;
            let warned =
                attome_service::sla::sweep_warnings(&db, &attome_state.base.config.notification)
                    .await?;
            let breached =
                attome_service::sla::sweep_breaches(&db, &attome_state.base.config.notification)
                    .await?;
            let escalated = attome_service::clock::sweep_escalations(
                &db,
                &attome_state.base.config.notification,
            )
            .await?;
            if reconciled > 0 || warned > 0 || breached > 0 || escalated > 0 {
                tracing::info!(
                    reconciled,
                    warned,
                    breached,
                    escalated,
                    "ticket SLA sweep: run complete"
                );
            }
        }
        // M72 (Resource Management) — see this variant's doc comment in
        // attome_jobs::job. Threshold/lookback match the values
        // `attome_project::utilization`'s own code-seeded report query already
        // establishes as the platform default (its module doc: "the
        // utilization report query above uses 28"; the same doc's headline
        // KPI is "sustained-over-85%-alert").
        EngineJob::ResourceUtilizationSweep => {
            const UTILIZATION_THRESHOLD_PCT: f64 = 85.0;
            const UTILIZATION_LOOKBACK_DAYS: i64 = 28;
            let alerted = attome_project::utilization::sweep_utilization_alerts(
                &db,
                &attome_state.base.config.notification,
                UTILIZATION_THRESHOLD_PCT,
                UTILIZATION_LOOKBACK_DAYS,
            )
            .await?;
            if alerted > 0 {
                tracing::info!(alerted, "resource utilization sweep: run complete");
            }
        }
        EngineJob::PruneChangeFeed => {
            prune_change_feed(&db, &config).await?;
        }
        // Audit 10/10 plan item 2.6 (D-539 ruling 6) — see this variant's doc
        // comment in attome_jobs::job. Business logic lives in attome-audit.
        EngineJob::AuditV1CutoverCheckpoint => {
            audit_v1_cutover_checkpoint(&db, &config, &attome_state).await?;
        }
        // BAP-11b — the claim inside makes a duplicate delivery a no-op; an
        // `Err` (executor error, failed close-out) retries through backoff.
        EngineJob::ExecuteApprovedRequest { request_id } => {
            let outcome = attome_api::execute_approved_request(&attome_state, request_id).await?;
            tracing::info!(
                %request_id,
                ?outcome,
                "auto-approved request execution job finished"
            );
        }
        // D-792 — the fleet console's jobs. Their handlers exist only in a
        // `fleet-console` build (and re-check the gate); anywhere else the
        // attempt fails like an unknown handler.
        EngineJob::FleetPoll => run_fleet_poll(&attome_state).await?,
        EngineJob::FleetRolloutStep { target_id } => {
            run_fleet_rollout_step(&attome_state, target_id).await?
        }
        // Z7-T1 — a run-time registered type: its handler, by name. An
        // unknown name fails with `unknown_job_type` and dead-letters at the
        // row's budget. Z7-T5: then what follows it (a chained job, a
        // fan-out's count), at most once per step.
        EngineJob::Registered(job) => {
            let next = job.next.clone();
            attome_core::jobs::JOB_TYPES
                .run((*attome_state).clone(), job)
                .await?;
            attome_jobs::chain::after_success(&db, next.as_ref(), EngineJob::Registered).await?;
        }
    }
    Ok(())
}

/// D-792 — `EngineJob::FleetPoll` (FLEET-CONSOLE-DESIGN.md §6.3).
#[cfg(feature = "fleet-console")]
async fn run_fleet_poll(
    attome_state: &EngineState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let summary = attome_fleet::poll::run(attome_state).await?;
    tracing::info!(
        synced = summary.synced,
        failed = summary.failed,
        steps_rearmed = summary.steps_rearmed,
        rollouts_evaluated = summary.rollouts_evaluated,
        "fleet poll: run complete"
    );
    Ok(())
}

/// D-792 — `EngineJob::FleetRolloutStep` (design §6.4).
#[cfg(feature = "fleet-console")]
async fn run_fleet_rollout_step(
    attome_state: &EngineState,
    target_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    attome_fleet::publish::run_step(attome_state, target_id).await?;
    Ok(())
}

/// What a binary without the fleet console answers a fleet job with.
#[cfg(not(feature = "fleet-console"))]
const NO_FLEET_CONSOLE: &str =
    "this binary has no fleet console (built without the fleet-console feature, D-792)";

#[cfg(not(feature = "fleet-console"))]
async fn run_fleet_poll(
    _xrm_state: &EngineState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err(NO_FLEET_CONSOLE.into())
}

#[cfg(not(feature = "fleet-console"))]
async fn run_fleet_rollout_step(
    _xrm_state: &EngineState,
    _target_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err(NO_FLEET_CONSOLE.into())
}

/// BJB-15 — rows per delete statement. The old single unbounded
/// `DELETE` held its locks and wrote its whole WAL segment in one statement
/// after a long gap (BJB-F9); 5 000 rows per statement is the plan's budget.
const HISTORY_PRUNE_BATCH_SIZE: i64 = 5_000;

/// BJB-15 — how many batches one run may delete before it stops and lets the
/// next scheduled run continue. Bounds how long a single run holds the table.
const HISTORY_PRUNE_MAX_BATCHES: u32 = 20;

/// BJB-D4 — a `Done` row's payload is scrubbed this long after it finished.
/// Replay needs a **dead letter's** payload, never a done one's.
const DONE_PAYLOAD_SCRUB_AFTER_HOURS: i32 = 24;

/// P-job-queue-hardening (D-165), extended by BJB-11 and BJB-15 — the periodic
/// sweep over terminal `apalis.jobs` rows. Re-reads config on every run (not
/// an enqueue-time snapshot), same convention as `ensure_audit_partitions`,
/// so a retention change takes effect on the next scheduled run without
/// needing a re-enqueue.
///
/// Three operations, in this order, each batched and each committing per
/// batch:
///
/// 1. **Scrub** (BJB-11/BJB-D4) the payload of `Done` rows older than 24 h,
///    keeping `version`/`variant` in the envelope so `job_variant_tag` still
///    reads the kind. A finished job's payload is the one place a rendered
///    email body with a live reset/verification token, or a batch of customer
///    records, outlives its purpose (BJB-F6); a dead letter is deliberately
///    **not** scrubbed, because replaying it is the whole point of keeping it.
/// 2. **Delete history** (D-165) — `Done` rows older than
///    `jobs.history_retention_days`.
/// 3. **Delete dead letters** (BJB-15) — `Killed` rows older than
///    `jobs.dead_letter_retention_days`, which defaults to 3× the history
///    window, and logs the count: deleting a dead letter destroys the only
///    record of a job that exhausted its attempts without an operator ever
///    triaging it.
pub async fn prune_apalis_job_history(
    db: &DbPool,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    scrub_done_payloads(db).await?;
    delete_terminal_rows(
        db,
        "Done",
        config.jobs.history_retention_days as i32,
        "history",
    )
    .await?;
    delete_terminal_rows(
        db,
        "Killed",
        config.jobs.dead_letter_retention_days as i32,
        "dead letter",
    )
    .await?;
    Ok(())
}

/// BJB-11 — scrubs the payload of `Done` rows past
/// [`DONE_PAYLOAD_SCRUB_AFTER_HOURS`], in [`HISTORY_PRUNE_BATCH_SIZE`]
/// batches. The envelope's `version` and `variant` are preserved (the
/// dead-letter list and `job_variant_tag` read the tag, not the payload) and
/// `scrubbed: true` makes the operation idempotent — a second sweep does not
/// rewrite rows it already cleared.
async fn scrub_done_payloads(db: &DbPool) -> Result<u64, sqlx::Error> {
    let mut total = 0_u64;
    for _ in 0..HISTORY_PRUNE_MAX_BATCHES {
        let scrubbed = sqlx::query(
            "UPDATE apalis.jobs SET job = jsonb_build_object( \
                 'version', job->'version', 'variant', job->'variant', \
                 'payload', NULL, 'scrubbed', true) \
             WHERE id IN ( \
                 SELECT id FROM apalis.jobs \
                 WHERE status = 'Done' \
                   AND done_at < now() - make_interval(hours => $1) \
                   AND job->'scrubbed' IS DISTINCT FROM 'true'::jsonb \
                 ORDER BY done_at ASC \
                 LIMIT $2 \
             )",
        )
        .bind(DONE_PAYLOAD_SCRUB_AFTER_HOURS)
        .bind(HISTORY_PRUNE_BATCH_SIZE)
        .execute(db)
        .await?
        .rows_affected();
        total += scrubbed;
        if scrubbed < HISTORY_PRUNE_BATCH_SIZE as u64 {
            break;
        }
    }
    if total > 0 {
        tracing::info!(
            scrubbed = total,
            after_hours = DONE_PAYLOAD_SCRUB_AFTER_HOURS,
            "apalis job history prune: scrubbed done-job payloads past the window \
             (variant kept, payload cleared)"
        );
    }
    Ok(total)
}

/// BJB-15 — bounded, batched hard delete of terminal rows in one status.
/// `done_at` is the clock for both statuses (apalis writes it when the row
/// leaves `Running`). Each batch is its own implicit transaction, so the
/// statement's locks are released between batches; returning early when a batch
/// came back short means a sweep that finds nothing runs exactly one statement.
async fn delete_terminal_rows(
    db: &DbPool,
    status: &str,
    retention_days: i32,
    subject: &str,
) -> Result<u64, sqlx::Error> {
    let mut total = 0_u64;
    for _ in 0..HISTORY_PRUNE_MAX_BATCHES {
        let deleted = sqlx::query(
            "DELETE FROM apalis.jobs WHERE id IN ( \
                 SELECT id FROM apalis.jobs \
                 WHERE status = $1 \
                   AND done_at < now() - make_interval(days => $2) \
                 ORDER BY done_at ASC \
                 LIMIT $3 \
             )",
        )
        .bind(status)
        .bind(retention_days)
        .bind(HISTORY_PRUNE_BATCH_SIZE)
        .execute(db)
        .await?
        .rows_affected();
        total += deleted;
        if deleted < HISTORY_PRUNE_BATCH_SIZE as u64 {
            break;
        }
    }
    if total > 0 {
        tracing::info!(
            deleted = total,
            status,
            retention_days,
            subject,
            "apalis job history prune: removed terminal rows past retention"
        );
    }
    Ok(total)
}

/// P-idempotency-hardening §4.4/§5 step 11 — soft-deletes
/// `idempotency_record` rows past `idempotency.durable_retention_hours`.
/// Soft (`is_deleted = TRUE`), not a hard `DELETE`, unlike
/// `prune_apalis_job_history` — a completed idempotency record is kept for
/// audit/debugging traceability (`mutation_ref`) rather than discarded
/// outright, same posture as every other mutable-class table in this
/// codebase (D-005/guidelines §4). Re-reads config on every run, same
/// convention as `prune_apalis_job_history`.
pub async fn prune_idempotency_records(
    db: &DbPool,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // S9-T2: a bulk job's record keeps its own, longer window.
    let result = sqlx::query(
        "UPDATE idempotency_record \
         SET is_deleted = TRUE, updated_at = NOW(), row_version = row_version + 1 \
         WHERE is_deleted = FALSE \
           AND created_at < now() - make_interval(hours => \
               CASE WHEN operation LIKE '%/bulk' THEN $2 ELSE $1 END)",
    )
    .bind(config.idempotency.durable_retention_hours as i32)
    .bind(config.idempotency.bulk_retention_hours as i32)
    .execute(db)
    .await?;
    if result.rows_affected() > 0 {
        tracing::info!(
            pruned = result.rows_affected(),
            "idempotency durable tier: soft-deleted records past retention"
        );
    }
    hard_delete_swept_idempotency_records(db).await?;
    Ok(())
}

/// attome-server plan B2 / BSV-D1 — how long a soft-deleted idempotency record
/// stays for traceability before it is removed. A reused key already
/// hard-deletes its swept row at acquire time; this bounds the stored bodies
/// of every key nobody reuses.
pub const IDEMPOTENCY_HARD_DELETE_AFTER_DAYS: i32 = 30;

/// B2's second window: hard-deletes rows soft-deleted more than
/// [`IDEMPOTENCY_HARD_DELETE_AFTER_DAYS`] ago (`updated_at` is the sweep's
/// timestamp), in the same bounded batches as the apalis history prune.
async fn hard_delete_swept_idempotency_records(db: &DbPool) -> Result<u64, sqlx::Error> {
    let mut total = 0_u64;
    for _ in 0..HISTORY_PRUNE_MAX_BATCHES {
        let deleted = sqlx::query(
            "DELETE FROM idempotency_record WHERE id IN ( \
                 SELECT id FROM idempotency_record \
                 WHERE is_deleted = TRUE \
                   AND updated_at < now() - make_interval(days => $1) \
                 LIMIT $2 \
             )",
        )
        .bind(IDEMPOTENCY_HARD_DELETE_AFTER_DAYS)
        .bind(HISTORY_PRUNE_BATCH_SIZE)
        .execute(db)
        .await?
        .rows_affected();
        total += deleted;
        if deleted < HISTORY_PRUNE_BATCH_SIZE as u64 {
            break;
        }
    }
    if total > 0 {
        tracing::info!(
            deleted = total,
            after_days = IDEMPOTENCY_HARD_DELETE_AFTER_DAYS,
            "idempotency durable tier: hard-deleted swept records past the second window"
        );
    }
    Ok(total)
}

/// attome-auth plan BAU-13a/13b — how long a dead refresh lineage, or a reset,
/// verification or invitation token past its `expires_at`, is kept before the
/// prune removes it: long enough to investigate a reuse alarm or a disputed
/// reset, short enough to bound the tables.
pub const AUTH_TOKEN_PRUNE_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

/// Rows (refresh: families) per prune statement. Each call is its own short
/// statement, so a large backlog never holds one long lock.
const AUTH_TOKEN_PRUNE_BATCH: i64 = 500;

/// Upper bound on batches per table per run; the next run continues.
const AUTH_TOKEN_PRUNE_MAX_BATCHES: u32 = 200;

/// BAU-13a/13b — the `PruneAuthTokens` handler. Loops each attome-auth prune
/// query until it deletes nothing (or the per-run cap), table by table. Every
/// query is safe against a concurrent redeem or consume (see each one's doc).
pub async fn prune_auth_tokens(
    db: &DbPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let retention = AUTH_TOKEN_PRUNE_RETENTION_SECS;
    let refresh = drain_prune("refresh families", || {
        attome_auth::refresh::prune_dead_families(db, retention, AUTH_TOKEN_PRUNE_BATCH)
    })
    .await?;
    let reset = drain_prune("password reset tokens", || {
        attome_auth::reset::prune_expired(db, retention, AUTH_TOKEN_PRUNE_BATCH)
    })
    .await?;
    let verification = drain_prune("verification tokens", || {
        attome_auth::verification::prune_expired(db, retention, AUTH_TOKEN_PRUNE_BATCH)
    })
    .await?;
    let invitation = drain_prune("invitation tokens", || {
        attome_auth::invitation::prune_expired(db, retention, AUTH_TOKEN_PRUNE_BATCH)
    })
    .await?;
    // Z4-T5: the Postgres denylist of a deployment without Redis. An entry
    // is useless once its token has expired, so no retention applies.
    let denylist = drain_prune("token denylist", || {
        attome_auth::revocation::prune_expired(db, 0, AUTH_TOKEN_PRUNE_BATCH)
    })
    .await?;
    tracing::info!(
        refresh,
        reset,
        verification,
        invitation,
        denylist,
        "auth token prune: run complete"
    );
    Ok(())
}

async fn drain_prune<F, Fut>(
    what: &'static str,
    mut batch: F,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<u64, attome_types::AppError>>,
{
    let mut total = 0_u64;
    for _ in 0..AUTH_TOKEN_PRUNE_MAX_BATCHES {
        let deleted = batch()
            .await
            .map_err(|e| format!("auth token prune ({what}): {e}"))?;
        total += deleted;
        if deleted == 0 {
            return Ok(total);
        }
    }
    tracing::warn!(
        what,
        deleted = total,
        "auth token prune: per-run cap reached; the next run continues"
    );
    Ok(total)
}

/// M01 §7 C-04 — deletes `entity_change_event` rows every
/// registered consumer cursor has passed and that are older than
/// `change_feed.retention_days`. Re-reads config on every run, same
/// convention as `prune_apalis_job_history`/`prune_idempotency_records`.
///
/// The actual deletion, the "never delete ahead of the slowest cursor"
/// invariant, the bounded-batch loop and the per-batch advisory lock all
/// live in `attome_core::change_feed::prune` — this wrapper only derives
/// the retention floor from current config and hands it a plain pooled
/// connection. Unlike `rewrap_secrets` above, no dedicated direct connection
/// is needed here: `prune`'s lock is transaction-scoped and re-acquired per
/// batch (see its doc comment), not held for the whole run, so an ordinary
/// pool connection returning to the pool between runs is fine.
pub async fn prune_change_feed(
    db: &DbPool,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = db.acquire().await?;
    // L7-T1: a consumer too far behind is expired first, so the prune below
    // moves past it; each one is an operator alert.
    attome_core::change_feed::expire_lagging(&mut conn).await?;
    let retention =
        std::time::Duration::from_secs(config.change_feed.retention_days as u64 * 24 * 60 * 60);
    let deleted = attome_core::change_feed::prune(&mut conn, retention).await?;
    if deleted > 0 {
        tracing::info!(deleted, "change feed prune: run complete");
    }
    Ok(())
}

/// Audit 10/10 plan item 2.6 — thin wrapper: builds the anchor store the same
/// way `audit_chainer` does (D-352) when anchoring is on, and hands the
/// signer from `EngineState` to `attome_audit::checkpoint`. A per-organization
/// failure fails the job so apalis retries it with backoff; a deferral is not
/// a failure (the next scheduler tick retries).
pub async fn audit_v1_cutover_checkpoint(
    db: &DbPool,
    config: &AppConfig,
    attome_state: &EngineState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = if config.audit.external_anchoring_enabled {
        Some(attome_audit::anchor::create_anchor_store(config).await?)
    } else {
        None
    };
    let results = attome_audit::checkpoint::run_v1_cutover_checkpoints(
        db,
        attome_state.audit_signer.as_deref(),
        store.as_ref(),
        attome_audit::checkpoint::DEFAULT_QUIET_PERIOD,
    )
    .await?;
    let mut failed = 0usize;
    for (org, outcome) in results {
        match outcome {
            Ok(attome_audit::checkpoint::CheckpointOutcome::Deferred(reason)) => {
                tracing::info!(organization_ref = %org, %reason, "audit v1 cutover checkpoint deferred");
            }
            Ok(_) => {}
            Err(_) => failed += 1,
        }
    }
    if failed > 0 {
        return Err(
            format!("audit v1 cutover checkpoint failed for {failed} organization(s)").into(),
        );
    }
    Ok(())
}

/// P-key-rotation-and-jwt (b) — drains `domain`'s table to convergence: loops
/// each domain's cursor-driven `rewrap_secrets` batch until a call reports
/// nothing left to scan. Reads the ring from `attome_state.base.secrets` for
/// jwt/mfa/s2s (config-sourced, D-549 — rotates via a config edit and
/// restart) — `erasure` rotates the same way (D-110: rolling restart), so
/// its ring comes straight from `EngineState.audit_erasure_key`, already parsed
/// once at boot.
const REWRAP_BATCH_SIZE: i64 = 500;

async fn rewrap_secrets(
    db: &DbPool,
    config: &AppConfig,
    attome_state: &EngineState,
    domain: RewrapDomain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Session-level, not transaction-level: the lock must cover every batch.
    // A dedicated connection is intentional; cancellation or panic closes the
    // session and PostgreSQL releases the lock instead of returning a locked
    // session to the application pool.
    let mut lock_connection =
        attome_db::UnpooledSession::new(attome_db::create_runtime_session(config).await?);
    let lock_key = format!("attome-auth/rewrap:{domain}");
    // `attome-auth`'s namespace, not `server`'s — `attome-api`'s trigger handler
    // takes this same key transaction-scoped to reject a concurrent trigger,
    // so both must name the same namespace or the two would stop conflicting
    // (L-1 / TODO-027).
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(attome_auth::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *lock_connection)
        .await?;
    if !locked {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!("a {domain} secret rewrap is already running"),
        )
        .into());
    }

    let result = drain_rewrap_secrets(db, attome_state, domain).await;
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1, hashtext($2))")
        .bind(attome_auth::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *lock_connection)
        .await?;
    if !unlocked {
        return Err(std::io::Error::other(format!(
            "lost the advisory lock for {domain} secret rewrap"
        ))
        .into());
    }
    result
}

async fn drain_rewrap_secrets(
    db: &DbPool,
    attome_state: &EngineState,
    domain: RewrapDomain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match domain {
        RewrapDomain::Mfa => {
            let ring = attome_state.base.secrets.load().mfa_encryption_key.clone();
            let mut after_id = None;
            loop {
                let progress =
                    attome_auth::mfa::rewrap_secrets(db, &ring, after_id, REWRAP_BATCH_SIZE)
                        .await?;
                tracing::info!(
                    domain = ?domain,
                    rewrapped = progress.rewrapped,
                    "rewrap batch complete"
                );
                if progress.scanned == 0 {
                    break;
                }
                after_id = progress.last_id;
            }
        }
        RewrapDomain::S2s => {
            let ring = attome_state
                .base
                .secrets
                .load()
                .s2s_key_encryption_key
                .clone();
            let mut after_id = None;
            loop {
                let progress =
                    attome_s2s::rewrap::rewrap_secrets(db, &ring, after_id, REWRAP_BATCH_SIZE)
                        .await?;
                tracing::info!(
                    domain = ?domain,
                    rewrapped = progress.rewrapped,
                    "rewrap batch complete"
                );
                if progress.scanned == 0 {
                    break;
                }
                after_id = progress.last_id;
            }
        }
        RewrapDomain::Erasure => {
            let Some(ring) = attome_state.audit_erasure_key.clone() else {
                tracing::warn!(
                    "RewrapSecrets(erasure): audit encryption is not active, nothing to do"
                );
                return Ok(());
            };
            let mut after_id = None;
            loop {
                let progress =
                    attome_audit::erasure::rewrap_secrets(db, &ring, after_id, REWRAP_BATCH_SIZE)
                        .await?;
                tracing::info!(
                    domain = ?domain,
                    rewrapped = progress.rewrapped,
                    "rewrap batch complete"
                );
                if progress.scanned == 0 {
                    break;
                }
                after_id = progress.last_id;
            }
        }
    }
    Ok(())
}

/// The four tables migrations/0026_audit_partitioning.sql made
/// `PARTITION BY RANGE` — the one place both attome-audit's and attome-s2s's tables
/// are visible, same reason this whole file exists. Storage params mirror
/// migration 0026 and attome-metadata::provision's `APPEND_ONLY_STORAGE_PARAMS` —
/// all four are append-only.
const PARTITIONED_TABLES: &[(&str, &str)] = &[
    ("audit_header", "created_at"),
    ("audit_detail", "created_at"),
    ("audit_snapshot", "created_at"),
    ("s2s_access_log", "created_at"),
];

const PARTITION_STORAGE_PARAMS: &str = "fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2";

/// The notification inbox is also range-partitioned by creation time. It is
/// mutable (read/clear updates rows), so it uses the mutable-table fillfactor
/// rather than the append-only setting above.
const NOTIFICATION_PARTITIONED_TABLES: &[(&str, &str)] =
    &[("notification_recipient", "created_at")];

const NOTIFICATION_PARTITION_STORAGE_PARAMS: &str = "fillfactor = 90, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2";

/// M27 Phase 1 (KPI & Metrics, D-407) — `metric_snapshot`
/// (migrations/0160_metric_snapshot.sql) is also RANGE-partitioned by month,
/// append-only (never UPDATEd — see attome-dashboard/src/metric.rs's doc
/// comment), so it reuses `PARTITION_STORAGE_PARAMS` above. Kept as its own
/// list, not folded into `PARTITIONED_TABLES`, because that constant's own
/// test (`partitioned_tables_lists_exactly_the_four_tables_migration_0026_created`)
/// asserts it names exactly migration 0026's four tables — same "separate
/// list, same maintenance job" shape `NOTIFICATION_PARTITIONED_TABLES`
/// already uses for the same reason.
const METRIC_PARTITIONED_TABLES: &[(&str, &str)] = &[("metric_snapshot", "computed_at")];

/// M41 Phase 1 (Process Intelligence, D-462) — `process_event`
/// (migrations/0297_xrm_process_event.sql) is also RANGE-partitioned by
/// month, append-only, so it reuses `PARTITION_STORAGE_PARAMS` above. Own
/// list for the same reason `METRIC_PARTITIONED_TABLES` is its own list, not
/// folded into `PARTITIONED_TABLES`.
const PROCESS_PARTITIONED_TABLES: &[(&str, &str)] = &[("process_event", "ts_start")];

/// E14-T2 — `marketing_web_event` (migrations/0085_marketing_web_events.sql),
/// RANGE-partitioned by month on `occurred_at` and append-only.
const MARKETING_PARTITIONED_TABLES: &[(&str, &str)] = &[
    ("marketing_web_event", "occurred_at"),
    // F3-T7 — `billing_usage_record` (migrations/0088_billing_usage.sql).
    ("billing_usage_record", "occurred_at"),
];

/// Detached `tokio::spawn` loop, same shape as
/// `attome_api::spawn_chainer_lag_refresh` — periodically enqueues
/// `EngineJob::EnsureAuditPartitions` onto the reliable apalis queue rather
/// than creating partitions directly from the timer tick, so a crash between
/// enqueue and processing still gets picked up by the worker on restart
/// (P1.4's whole point). Runs unconditionally, unlike the metrics-gated
/// spawns in main.rs — partition maintenance isn't an observability concern.
/// Dedup keys for the periodic maintenance jobs below (`enqueue_dedup`,
/// migration `0060`) — fixed constants, one per scheduled job kind. A slow
/// run can otherwise still be `Pending`/`Running` when the next tick fires;
/// without these, that tick would enqueue a second, redundant row instead of
/// being absorbed by the partial unique index. This also closes the
/// multi-replica double-enqueue race ENTERPRISE-AUDIT-2026-07-24.md finding
/// #18 (P-scheduler-singleton §4.1) describes: with N replicas each running
/// this same timer, the partial unique index on `(job_type, dedup_key)`
/// absorbs every replica's tick but the one that wins the row insert, the
/// same "only one winner" guarantee an explicit advisory lock would give,
/// without needing a separate lock/transaction per scheduler.
const DEDUP_KEY_ENSURE_AUDIT_PARTITIONS: &str = "ensure-audit-partitions";
const DEDUP_KEY_PRUNE_NOTIFICATION_PARTITIONS: &str = "prune-notification-partitions";
const DEDUP_KEY_PRUNE_EXPIRED_UPLOAD_SESSIONS: &str = "prune-expired-upload-sessions";
const DEDUP_KEY_PRUNE_APALIS_JOB_HISTORY: &str = "prune-apalis-job-history";
const DEDUP_KEY_REVALIDATE_QUERY_PLANS: &str = "revalidate-query-plans";
const DEDUP_KEY_TRIGRAM_INDEX_SWEEP: &str = "trigram-index-sweep";
const DEDUP_KEY_PRUNE_IDEMPOTENCY_RECORDS: &str = "prune-idempotency-records";
const DEDUP_KEY_PRUNE_AUTH_TOKENS: &str = "prune-auth-tokens";
const DEDUP_KEY_PRUNE_RECOVERY_ARCHIVE: &str = "prune-recovery-archive";
const DEDUP_KEY_RETENTION_PROPOSE: &str = "retention-propose";
const DEDUP_KEY_REVALIDATE_FIELD_SECURITY_PROFILES: &str = "revalidate-field-security-profiles";
const DEDUP_KEY_WORKFLOW_SLA_SWEEP: &str = "workflow-sla-sweep";
const DEDUP_KEY_WORKFLOW_ENTITY_TRIGGER_DISPATCH: &str = "workflow-entity-trigger-dispatch";
const DEDUP_KEY_COMPUTE_METRIC_SNAPSHOTS: &str = "compute-metric-snapshots";
const DEDUP_KEY_EVENTS_DISPATCH_TICK: &str = "events-dispatch-tick";
const DEDUP_KEY_AI_QUALITY_MONITOR: &str = "ai-quality-monitor";
const DEDUP_KEY_AI_TOOL_CALL_SWEEP: &str = "ai-tool-call-sweep";
const DEDUP_KEY_BIN_DELETE_ALERT: &str = "bin-delete-alert";
const DEDUP_KEY_TAG_EXPIRY: &str = "tag-expiry";
const DEDUP_KEY_CONTRACT_KEY_DATES: &str = "contract-key-dates";
const DEDUP_KEY_RECURRING_TASK_ROLL: &str = "recurring-task-roll";
const DEDUP_KEY_POINTS_SCORING: &str = "points-scoring";
const DEDUP_KEY_DEAL_RISK: &str = "deal-risk";
const DEDUP_KEY_FORECAST_RECOMPUTE: &str = "forecast-recompute";
const DEDUP_KEY_MRR_SNAPSHOT: &str = "mrr-snapshot";
const DEDUP_KEY_WEBCRAWL_RECRAWL_DUE: &str = "webcrawl-recrawl-due";
const DEDUP_KEY_TIMER_SWEEP: &str = "timer-sweep";
const DEDUP_KEY_MARKETING_NIGHTLY: &str = "marketing-nightly";
const DEDUP_KEY_SEGMENT_REFRESH_DUE: &str = "segment-refresh-due";
const DEDUP_KEY_MARKETING_SWEEP: &str = "marketing-sweep";
const DEDUP_KEY_ROLE_GRANT_EXPIRY: &str = "role-grant-expiry";
const DEDUP_KEY_SALES_DEFAULT_TEAM_SWEEP: &str = "sales-default-team-sweep";
const DEDUP_KEY_COMMISSION_CREDIT_SWEEP: &str = "commission-credit-sweep";
const DEDUP_KEY_BILLING_REQUEST_SWEEP: &str = "billing-request-sweep";
const DEDUP_KEY_BILLING_SCHEDULE_RUN: &str = "billing-schedule-run";
const DEDUP_KEY_BILLING_OVERDUE_SWEEP: &str = "billing-overdue-sweep";
const DEDUP_KEY_BILLING_CHARGE_DUE: &str = "billing-charge-due";
const DEDUP_KEY_BILLING_RECONCILE: &str = "billing-reconcile";
const DEDUP_KEY_BILLING_EINVOICE_SWEEP: &str = "billing-einvoice-sweep";
const DEDUP_KEY_BILLING_GATEWAY_EVENT_APPLY: &str =
    attome_billing::gateway::webhook::APPLY_DEDUP_KEY;
const DEDUP_KEY_SALES_SNAPSHOT_PRUNE: &str = "sales-snapshot-prune";
const DEDUP_KEY_NOTIFICATION_FOLLOW_SWEEP: &str = "notification-follow-sweep";
const DEDUP_KEY_SALES_DEAL_CLOSE_SWEEP: &str = "sales-deal-close-sweep";
const DEDUP_KEY_SALES_LEAVER_SWEEP: &str = "sales-leaver-sweep";
const DEDUP_KEY_AI_FOLLOWUP_SCAN: &str = "ai-followup-scan";
const DEDUP_KEY_TABLE_HEALTH_SAMPLE: &str = "table-health-sample";
const DEDUP_KEY_AUDIT_CHAIN_VERIFY: &str = "audit-chain-verify";
const DEDUP_KEY_SLO_MONTHLY_REPORT: &str = "slo-monthly-report";
const DEDUP_KEY_SLO_BURN_CHECK: &str = "slo-burn-check";
const DEDUP_KEY_PERF_REGRESSION_CHECK: &str = "perf-regression-check";
const DEDUP_KEY_LIMIT_WARNING_CHECK: &str = "limit-warning-check";
const DEDUP_KEY_SALES_MENTION_SCAN: &str = "sales-mention-scan";
const DEDUP_KEY_ACCESS_REVIEW_CAMPAIGN_SWEEP: &str = "access-review-campaign-sweep";
const DEDUP_KEY_DATA_MATCH_SWEEP: &str = "data-match-sweep";
const DEDUP_KEY_API_USAGE_ROLLUP: &str = "api-usage-rollup";
const DEDUP_KEY_CONTENT_SCHEDULED_PUBLISH_SWEEP: &str = "content-scheduled-publish-sweep";
const DEDUP_KEY_REPORT_SCHEDULE_SWEEP: &str = "report-schedule-sweep";
const DEDUP_KEY_LICENSE_EXPIRY_CHECK: &str = "license-expiry-check";
const DEDUP_KEY_FAILED_LOGIN_SWEEP: &str = "failed-login-sweep";
const DEDUP_KEY_SEARCH_SUGGESTION_REFRESH: &str = "search-suggestion-refresh";
const DEDUP_KEY_SEARCH_SAVED_SEARCH_ALERT_SWEEP: &str = "search-saved-search-alert-sweep";
const DEDUP_KEY_CONTENT_PAGE_STATS_ROLLUP: &str = "content-page-stats-rollup";
const DEDUP_KEY_CONTENT_REVIEW_REMINDER_SWEEP: &str = "content-review-reminder-sweep";
const DEDUP_KEY_PRUNE_EXPIRED_MEMORIES: &str = "prune-expired-memories";
const DEDUP_KEY_DATA_QUALITY_SCORE_SWEEP: &str = "data-quality-score-sweep";
const DEDUP_KEY_PROCESS_EXTRACTION_SWEEP: &str = "process-extraction-sweep";
const DEDUP_KEY_WORK_QUEUE_ESCALATION_SWEEP: &str = "work-queue-escalation-sweep";
const DEDUP_KEY_TICKET_SLA_SWEEP: &str = "ticket-sla-sweep";
const DEDUP_KEY_RESOURCE_UTILIZATION_SWEEP: &str = "resource-utilization-sweep";
const DEDUP_KEY_CATALOG_LINEAGE_BACKFILL: &str = "catalog-lineage-backfill";
const DEDUP_KEY_CATALOG_DASHBOARD_LINEAGE_SWEEP: &str = "catalog-dashboard-lineage-sweep";
const DEDUP_KEY_CATALOG_USAGE_ROLLUP: &str = "catalog-usage-rollup";
const DEDUP_KEY_PREDICT_SCORING_SWEEP: &str = "predict-scoring-sweep";
const DEDUP_KEY_PREDICT_OUTCOME_FILL_SWEEP: &str = "predict-outcome-fill-sweep";
const DEDUP_KEY_PRUNE_CHANGE_FEED: &str = "prune-change-feed";
const DEDUP_KEY_AUDIT_V1_CUTOVER_CHECKPOINT: &str = "audit-v1-cutover-checkpoint";
/// D-792 — the fleet console's poll; the same string the console's "sync now"
/// route uses (`attome_fleet::routes::deployments::FLEET_POLL_KEY`), so a manual
/// sync and the schedule never queue two polls.
const DEDUP_KEY_FLEET_POLL: &str = "fleet-poll";
/// Z1-T8: the daily secret age reminder (a registered job type).
const DEDUP_KEY_SECRET_AGE_REMINDER: &str = "secret-age-reminder";

/// Z1-T8: reminds administrators of secrets older than
/// `security.secret_max_age_days`. A registered type (Z7-T1), not an
/// `EngineJob` variant.
pub const SECRET_AGE_REMINDER: attome_jobs::JobType =
    attome_jobs::JobType::new("secret_age_reminder", 1);

/// Z7-T1/Z1-T8: registers this binary's run-time job types, once per
/// process. The worker calls it before it runs jobs and each scheduler that
/// builds one calls it first, so a node that only schedules or only works
/// knows the types it needs.
pub fn register_job_types() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SECRET_AGE_REMINDER,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                secret_age_reminder(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
    });
}

/// Z1-T8: one admin notification per secret past the age limit, each
/// claimed first so it goes out at most once per 30 days whichever worker
/// runs it.
async fn secret_age_reminder(state: &EngineState) -> Result<(), attome_types::AppError> {
    let config = &state.base.config;
    let due = attome_compliance::secret_inventory::claim_due_reminders(
        &state.base.db,
        config.secret_inventory(),
        config.security.secret_max_age_days,
    )
    .await?;
    for secret in due {
        tracing::warn!(secret = %secret.name, age_days = secret.age_days, "secret age reminder: administrators told");
        attome_ai::quality_monitor::alert_admins(
            &state.base.db,
            &config.notification,
            format!("Secret {} is {} days old", secret.name, secret.age_days),
            format!(
                "The active key of {} has been in use for {} days, more than the {} days \
                 security.secret_max_age_days allows. It is used by: {}. Rotate it (for a key \
                 ring, add a new key and make it active) and restart.",
                secret.name,
                secret.age_days,
                config.security.secret_max_age_days,
                secret.used_by.join(", ")
            ),
            "/xrm/admin/settings",
        )
        .await;
    }
    Ok(())
}

/// BJB-4d — the schedule-ledger name for a kind a `spawn_*_scheduler` below
/// enqueues, so a successful run can stamp `job_schedule.last_succeeded_at`
/// (backing `job_schedule_last_success_age_seconds{name}`, BJB-14b).
///
/// Deliberately the *same string* as that schedule's dedup key constant
/// (D-618): one name per periodic kind, so the ledger row, the overlap guard
/// and the schedule cannot drift apart. `None` for every kind no scheduler
/// enqueues (the handler still runs it; there is just no schedule to stamp).
///
/// The 41 arms mirror the 41 `DEDUP_KEY_*` constants above one for one; the
/// wildcard is not an omission but the "not scheduled" case, which is the
/// majority of the contract.
fn schedule_name_for(job: &EngineJob) -> Option<&'static str> {
    Some(match job {
        EngineJob::EnsureAuditPartitions => DEDUP_KEY_ENSURE_AUDIT_PARTITIONS,
        EngineJob::PruneNotificationRecipientPartitions => DEDUP_KEY_PRUNE_NOTIFICATION_PARTITIONS,
        EngineJob::PruneExpiredUploadSessions => DEDUP_KEY_PRUNE_EXPIRED_UPLOAD_SESSIONS,
        EngineJob::PruneApalisJobHistory => DEDUP_KEY_PRUNE_APALIS_JOB_HISTORY,
        EngineJob::RevalidateQueryPlans => DEDUP_KEY_REVALIDATE_QUERY_PLANS,
        EngineJob::TrigramIndexSweep => DEDUP_KEY_TRIGRAM_INDEX_SWEEP,
        EngineJob::RevalidateFieldSecurityProfiles => DEDUP_KEY_REVALIDATE_FIELD_SECURITY_PROFILES,
        EngineJob::AuditV1CutoverCheckpoint => DEDUP_KEY_AUDIT_V1_CUTOVER_CHECKPOINT,
        EngineJob::PruneChangeFeed => DEDUP_KEY_PRUNE_CHANGE_FEED,
        EngineJob::AiToolCallSweep => DEDUP_KEY_AI_TOOL_CALL_SWEEP,
        EngineJob::BinDeleteAlertSweep => DEDUP_KEY_BIN_DELETE_ALERT,
        EngineJob::TagExpirySweep => DEDUP_KEY_TAG_EXPIRY,
        EngineJob::ContractKeyDates => DEDUP_KEY_CONTRACT_KEY_DATES,
        EngineJob::RecurringTaskRoll => DEDUP_KEY_RECURRING_TASK_ROLL,
        EngineJob::PointsScoring => DEDUP_KEY_POINTS_SCORING,
        EngineJob::DealRiskEvaluation => DEDUP_KEY_DEAL_RISK,
        EngineJob::ForecastRecompute => DEDUP_KEY_FORECAST_RECOMPUTE,
        EngineJob::MrrSnapshot => DEDUP_KEY_MRR_SNAPSHOT,
        EngineJob::WebcrawlRecrawlDue => DEDUP_KEY_WEBCRAWL_RECRAWL_DUE,
        EngineJob::TimerSweep => DEDUP_KEY_TIMER_SWEEP,
        EngineJob::MarketingNightly => DEDUP_KEY_MARKETING_NIGHTLY,
        EngineJob::SegmentRefreshDue => DEDUP_KEY_SEGMENT_REFRESH_DUE,
        EngineJob::MarketingSweep => DEDUP_KEY_MARKETING_SWEEP,
        EngineJob::RoleGrantExpiry => DEDUP_KEY_ROLE_GRANT_EXPIRY,
        EngineJob::SalesDefaultTeamSweep => DEDUP_KEY_SALES_DEFAULT_TEAM_SWEEP,
        EngineJob::CommissionCreditSweep => DEDUP_KEY_COMMISSION_CREDIT_SWEEP,
        EngineJob::BillingRequestSweep => DEDUP_KEY_BILLING_REQUEST_SWEEP,
        EngineJob::BillingScheduleRun => DEDUP_KEY_BILLING_SCHEDULE_RUN,
        EngineJob::BillingOverdueSweep => DEDUP_KEY_BILLING_OVERDUE_SWEEP,
        EngineJob::BillingChargeDue => DEDUP_KEY_BILLING_CHARGE_DUE,
        EngineJob::BillingReconcile => DEDUP_KEY_BILLING_RECONCILE,
        EngineJob::BillingEinvoiceSweep => DEDUP_KEY_BILLING_EINVOICE_SWEEP,
        EngineJob::BillingGatewayEventApply => DEDUP_KEY_BILLING_GATEWAY_EVENT_APPLY,
        EngineJob::SalesSnapshotPrune => DEDUP_KEY_SALES_SNAPSHOT_PRUNE,
        EngineJob::NotificationFollowSweep => DEDUP_KEY_NOTIFICATION_FOLLOW_SWEEP,
        EngineJob::SalesDealCloseSweep => DEDUP_KEY_SALES_DEAL_CLOSE_SWEEP,
        EngineJob::SalesLeaverSweep => DEDUP_KEY_SALES_LEAVER_SWEEP,
        EngineJob::AiFollowupScan => DEDUP_KEY_AI_FOLLOWUP_SCAN,
        EngineJob::TableHealthSample => DEDUP_KEY_TABLE_HEALTH_SAMPLE,
        EngineJob::AuditChainVerify => DEDUP_KEY_AUDIT_CHAIN_VERIFY,
        EngineJob::SloMonthlyReport => DEDUP_KEY_SLO_MONTHLY_REPORT,
        EngineJob::SloBurnCheck => DEDUP_KEY_SLO_BURN_CHECK,
        EngineJob::PerfRegressionCheck => DEDUP_KEY_PERF_REGRESSION_CHECK,
        EngineJob::LimitWarningCheck => DEDUP_KEY_LIMIT_WARNING_CHECK,
        EngineJob::SalesMentionScan => DEDUP_KEY_SALES_MENTION_SCAN,
        EngineJob::AiQualityMonitor => DEDUP_KEY_AI_QUALITY_MONITOR,
        EngineJob::PruneIdempotencyRecords => DEDUP_KEY_PRUNE_IDEMPOTENCY_RECORDS,
        EngineJob::PruneAuthTokens => DEDUP_KEY_PRUNE_AUTH_TOKENS,
        EngineJob::PruneRecoveryArchive => DEDUP_KEY_PRUNE_RECOVERY_ARCHIVE,
        EngineJob::ProposeRetentionActions => DEDUP_KEY_RETENTION_PROPOSE,
        EngineJob::PruneExpiredMemories => DEDUP_KEY_PRUNE_EXPIRED_MEMORIES,
        EngineJob::WorkflowSlaSweep => DEDUP_KEY_WORKFLOW_SLA_SWEEP,
        EngineJob::WorkflowEntityTriggerDispatch => DEDUP_KEY_WORKFLOW_ENTITY_TRIGGER_DISPATCH,
        EngineJob::ComputeMetricSnapshots => DEDUP_KEY_COMPUTE_METRIC_SNAPSHOTS,
        EngineJob::EventsDispatchTick => DEDUP_KEY_EVENTS_DISPATCH_TICK,
        EngineJob::AccessReviewCampaignSweep => DEDUP_KEY_ACCESS_REVIEW_CAMPAIGN_SWEEP,
        EngineJob::DataMatchSweep => DEDUP_KEY_DATA_MATCH_SWEEP,
        EngineJob::ApiUsageRollup => DEDUP_KEY_API_USAGE_ROLLUP,
        EngineJob::SearchSuggestionRefresh => DEDUP_KEY_SEARCH_SUGGESTION_REFRESH,
        EngineJob::SearchSavedSearchAlertSweep => DEDUP_KEY_SEARCH_SAVED_SEARCH_ALERT_SWEEP,
        EngineJob::ContentScheduledPublishSweep => DEDUP_KEY_CONTENT_SCHEDULED_PUBLISH_SWEEP,
        EngineJob::DataQualityScoreSweep => DEDUP_KEY_DATA_QUALITY_SCORE_SWEEP,
        EngineJob::ReportScheduleSweep => DEDUP_KEY_REPORT_SCHEDULE_SWEEP,
        EngineJob::FailedLoginSweep => DEDUP_KEY_FAILED_LOGIN_SWEEP,
        EngineJob::LicenseExpiryCheck => DEDUP_KEY_LICENSE_EXPIRY_CHECK,
        EngineJob::ContentPageStatsRollup => DEDUP_KEY_CONTENT_PAGE_STATS_ROLLUP,
        EngineJob::ContentReviewReminderSweep => DEDUP_KEY_CONTENT_REVIEW_REMINDER_SWEEP,
        EngineJob::ProcessExtractionSweep => DEDUP_KEY_PROCESS_EXTRACTION_SWEEP,
        EngineJob::WorkQueueEscalationSweep => DEDUP_KEY_WORK_QUEUE_ESCALATION_SWEEP,
        EngineJob::TicketSlaSweep => DEDUP_KEY_TICKET_SLA_SWEEP,
        EngineJob::ResourceUtilizationSweep => DEDUP_KEY_RESOURCE_UTILIZATION_SWEEP,
        EngineJob::CatalogLineageBackfill => DEDUP_KEY_CATALOG_LINEAGE_BACKFILL,
        EngineJob::CatalogDashboardLineageSweep => DEDUP_KEY_CATALOG_DASHBOARD_LINEAGE_SWEEP,
        EngineJob::CatalogUsageRollup => DEDUP_KEY_CATALOG_USAGE_ROLLUP,
        EngineJob::PredictScoringSweep => DEDUP_KEY_PREDICT_SCORING_SWEEP,
        EngineJob::PredictOutcomeFillSweep => DEDUP_KEY_PREDICT_OUTCOME_FILL_SWEEP,
        EngineJob::FleetPoll => DEDUP_KEY_FLEET_POLL,
        EngineJob::Registered(job) if job.name == SECRET_AGE_REMINDER.name => {
            DEDUP_KEY_SECRET_AGE_REMINDER
        }
        _ => return None,
    })
}

/// BJB-4c — upper bound on a scheduler's per-tick sleep jitter, as a share of
/// the interval. Without it all 39 schedulers tick in the order they were
/// spawned on every interval, so a deployment's whole maintenance load lands in
/// one burst; up to 10% of spread removes that synchrony. The jitter is only
/// ever **added**, never subtracted: a tick that arrived before its slot would
/// be refused by the ledger CAS and the schedule would silently skip it.
const SCHEDULE_JITTER_PERCENT: u64 = 10;

/// One scheduler tick's sleep: `interval` plus up to
/// [`SCHEDULE_JITTER_PERCENT`]% of it, derived deterministically from `random`
/// so the bound is unit-testable.
fn jittered_interval(interval: std::time::Duration, random: u64) -> std::time::Duration {
    let max_ms = (interval.as_millis() as u64) * SCHEDULE_JITTER_PERCENT / 100;
    if max_ms == 0 {
        return interval;
    }
    interval + std::time::Duration::from_millis(random % (max_ms + 1))
}

/// Longest startup stagger before a scheduler's first tick.
const SCHEDULE_STARTUP_STAGGER_MAX: std::time::Duration = std::time::Duration::from_secs(60);

/// The sleep before a scheduler's first tick: `0..=min(interval, 60 s)`,
/// derived deterministically from `random` so the bound is unit-testable. Short
/// enough that a node restarting more often than its interval still ticks.
fn startup_stagger(interval: std::time::Duration, random: u64) -> std::time::Duration {
    let max_ms = interval.min(SCHEDULE_STARTUP_STAGGER_MAX).as_millis() as u64;
    std::time::Duration::from_millis(random % (max_ms + 1))
}

/// A per-call-varying seed for [`jittered_interval`]. These schedulers are not
/// security-sensitive, so nanos since the epoch are enough to de-synchronize
/// them and add no dependency.
fn jitter_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0)
}

/// BJB-4b — one schedule slot, the enqueue-or-warn half of every scheduler
/// below (MAINT-3, PLATFORM-REVIEW-2026-08-24 §4).
///
/// [`attome_jobs::schedule::tick`] claims the slot with a per-schedule row CAS
/// *before* enqueuing; that is what makes a periodic job run **once per slot**
/// across N replicas and restarts (BJB-F4/D-618). The fixed dedup key it passes
/// as the ledger name stays as the overlap guard behind it, so a slot whose job
/// is still running when the next slot comes due still cannot double-enqueue.
/// `name` is that same dedup key, so one periodic kind owns exactly one ledger
/// row.
///
/// A failed tick is deliberately a `warn!` and not a retry or a propagated
/// error: these are periodic maintenance ticks, so the next interval claims the
/// next slot and the loss self-heals. `what` is the operator-facing subject of
/// the log line, rendered exactly as each call site rendered it before.
async fn tick_or_warn(
    db: &DbPool,
    name: &'static str,
    interval: std::time::Duration,
    job: EngineJob,
    what: &str,
) {
    if let Err(e) = attome_jobs::schedule::tick(db, name, interval, job).await {
        tracing::warn!(error = %e, schedule = name, "{what}: schedule tick failed");
    }
}

/// The detached-timer half, shared by every scheduler that enqueues exactly one
/// job per tick. Each public `spawn_*_scheduler` below keeps its own name, doc
/// comment and `main.rs` wiring — they differ only in job, dedup key, log
/// subject and interval, so only the body is shared.
///
/// `spawn_partition_maintenance_scheduler` is the one exception: it enqueues two
/// jobs per tick, so it keeps its own loop and calls [`tick_or_warn`] twice.
///
/// BJB-4c: the first tick follows a short random [`startup_stagger`], so a
/// freshly booted deployment does not fire every schedule in the same second,
/// yet a node that restarts more often than its interval (a 24 h schedule on a
/// daily restart) still reaches its first tick and runs an overdue slot. A tick
/// inside a slot the ledger still considers current enqueues nothing (the
/// `next_due_at <= now()` CAS), so ticking at start is safe. Later ticks sleep
/// [`jittered_interval`].
///
/// A bare `tokio::spawn` is correct here per guidelines §10 — this is
/// process-lifetime supervision, and a lost tick costs nothing because the next
/// one claims the next slot.
fn spawn_dedup_scheduler(
    db: DbPool,
    interval: std::time::Duration,
    job: EngineJob,
    dedup_key: &'static str,
    what: &'static str,
) {
    tokio::spawn(async move {
        tokio::time::sleep(startup_stagger(interval, jitter_seed())).await;
        loop {
            tick_or_warn(&db, dedup_key, interval, job.clone(), what).await;
            tokio::time::sleep(jittered_interval(interval, jitter_seed())).await;
        }
    });
}

pub fn spawn_partition_maintenance_scheduler(db: DbPool, interval: std::time::Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(startup_stagger(interval, jitter_seed())).await;
        loop {
            tick_or_warn(
                &db,
                DEDUP_KEY_ENSURE_AUDIT_PARTITIONS,
                interval,
                EngineJob::EnsureAuditPartitions,
                "partition maintenance",
            )
            .await;
            tick_or_warn(
                &db,
                DEDUP_KEY_PRUNE_NOTIFICATION_PARTITIONS,
                interval,
                EngineJob::PruneNotificationRecipientPartitions,
                "notification retention",
            )
            .await;
            tokio::time::sleep(jittered_interval(interval, jitter_seed())).await;
        }
    });
}

/// P-file-upload-pipeline — sibling of `spawn_partition_maintenance_scheduler`
/// above, at its own (shorter) interval since upload sessions are short-lived
/// compared to partitions. Enqueues the durable job rather than sweeping
/// directly from the timer tick, so a crash between enqueue and processing
/// still gets picked up by the worker on restart (P1.4).
pub fn spawn_upload_session_maintenance_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneExpiredUploadSessions,
        DEDUP_KEY_PRUNE_EXPIRED_UPLOAD_SESSIONS,
        "upload session maintenance",
    );
}

/// P-job-queue-hardening (D-165) — sibling of the schedulers above, once/day
/// by convention (`apalis.jobs` history moves far slower than upload
/// sessions or even partitions). Enqueues the durable job rather than
/// deleting directly from the timer tick, for the same restart-safety reason
/// every other scheduler here does.
pub fn spawn_apalis_job_history_prune_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneApalisJobHistory,
        DEDUP_KEY_PRUNE_APALIS_JOB_HISTORY,
        "apalis job history prune",
    );
}

/// P-stored-query-containment addendum §11(c) — sibling of the schedulers
/// above, once/day by convention (same cadence as
/// `spawn_apalis_job_history_prune_scheduler`; `sql_query` moves far
/// slower than upload sessions or partitions, and `revalidate_all`'s own
/// drift check keeps a run that finds nothing changed cheap). Enqueues the
/// durable job rather than re-planning directly from the timer tick, for the
/// same restart-safety reason every other scheduler here does.
/// AA4-T5: enqueues `EngineJob::TrigramIndexSweep` once a day.
pub fn spawn_trigram_index_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::TrigramIndexSweep,
        DEDUP_KEY_TRIGRAM_INDEX_SWEEP,
        "trigram index sweep",
    );
}

pub fn spawn_query_plan_revalidation_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::RevalidateQueryPlans,
        DEDUP_KEY_REVALIDATE_QUERY_PLANS,
        "query plan revalidation",
    );
}

/// D-188 — sibling of `spawn_query_plan_revalidation_scheduler` above, same
/// once/day-by-convention cadence: `field_security_profile_field` moves
/// far slower than upload sessions or partitions, and a run that finds
/// nothing stale is cheap (two read-only queries). Enqueues the durable job
/// rather than checking directly from the timer tick, for the same
/// restart-safety reason every other scheduler here does.
pub fn spawn_field_security_profile_revalidation_scheduler(
    db: DbPool,
    interval: std::time::Duration,
) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::RevalidateFieldSecurityProfiles,
        DEDUP_KEY_REVALIDATE_FIELD_SECURITY_PROFILES,
        "field security profile revalidation",
    );
}

/// Audit 10/10 plan item 2.6 — enqueues `EngineJob::AuditV1CutoverCheckpoint`
/// hourly. The handler is a cheap no-op once every organization's checkpoint
/// exists and is anchored, and defers while the v1 set is still open, so an
/// hourly tick bounds the unprotected window after a deploy (D-539 G1-3 a)
/// without a one-shot trigger that a crash could lose.
pub fn spawn_audit_v1_cutover_checkpoint_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AuditV1CutoverCheckpoint,
        DEDUP_KEY_AUDIT_V1_CUTOVER_CHECKPOINT,
        "audit v1 cutover checkpoint",
    );
}

/// M01 §7 C-04 — sibling of the schedulers above, once/day by convention
/// (same cadence as `spawn_apalis_job_history_prune_scheduler`/
/// `spawn_idempotency_record_prune_scheduler`: the change feed moves far
/// slower than upload sessions or partitions, and `change_feed::prune`'s own
/// per-batch advisory lock makes an overlapping run with a slow previous one
/// cheap rather than racy). Enqueues the durable job rather than deleting
/// directly from the timer tick, for the same restart-safety reason every
/// other scheduler here does.
pub fn spawn_change_feed_prune_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneChangeFeed,
        DEDUP_KEY_PRUNE_CHANGE_FEED,
        "change feed prune",
    );
}

/// D-792 (FLEET-CONSOLE-DESIGN.md §6.3) — the fleet console's periodic sync,
/// every `fleet.poll_interval_secs`. Spawned only by
/// `schedulers::spawn_worker_schedulers` in a `fleet-console` build whose gate
/// is open; the job body re-checks the gate.
pub fn spawn_fleet_poll_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::FleetPoll,
        DEDUP_KEY_FLEET_POLL,
        "fleet poll",
    );
}

/// C4 (row A-40) — sibling of the schedulers above. Reclaims chat confirm
/// leases whose holder died and expires unconfirmed proposals. The cadence
/// bounds how long a crashed confirm's proposal stays apparently stuck (at
/// most `CONFIRM_LEASE` plus one interval); it is an operational setting,
/// not a safety margin — the D-502 invocation ledger, not the lease, decides
/// whether anything runs. Enqueues the durable job rather than sweeping from
/// the timer tick, for the same restart-safety reason every other scheduler
/// here does.
pub fn spawn_ai_tool_call_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AiToolCallSweep,
        DEDUP_KEY_AI_TOOL_CALL_SWEEP,
        "ai tool-call sweep",
    );
}

/// A18-T4: every few minutes, reports bursts of deletion to administrators.
pub fn spawn_bin_delete_alert_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BinDeleteAlertSweep,
        DEDUP_KEY_BIN_DELETE_ALERT,
        "recycle bin delete alert",
    );
}

/// B4-T3: every hour, removes tag links past their expiry.
pub fn spawn_tag_expiry_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::TagExpirySweep,
        DEDUP_KEY_TAG_EXPIRY,
        "tag expiry",
    );
}

/// E9-T7: every five minutes, the overdue marketing hand-offs.
pub fn spawn_marketing_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::MarketingSweep,
        DEDUP_KEY_MARKETING_SWEEP,
        "marketing sweep",
    );
}

/// Y2-T8: daily, the table-health sample.
/// Q16-T2: the audit chain verification, weekly.
pub fn spawn_audit_chain_verify_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AuditChainVerify,
        DEDUP_KEY_AUDIT_CHAIN_VERIFY,
        "audit chain verification",
    );
}

pub fn spawn_table_health_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::TableHealthSample,
        DEDUP_KEY_TABLE_HEALTH_SAMPLE,
        "table health sample",
    );
}

/// AA13-T9: hourly, the monthly SLO report (written once, when missing).
pub fn spawn_slo_monthly_report_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SloMonthlyReport,
        DEDUP_KEY_SLO_MONTHLY_REPORT,
        "slo monthly report",
    );
}

/// AA13-T9: every five minutes, the SLO fast-burn check.
pub fn spawn_slo_burn_check_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SloBurnCheck,
        DEDUP_KEY_SLO_BURN_CHECK,
        "slo burn check",
    );
}

/// AA14-T8: daily, the latency regression check after an upgrade.
pub fn spawn_perf_regression_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PerfRegressionCheck,
        DEDUP_KEY_PERF_REGRESSION_CHECK,
        "perf regression check",
    );
}

/// Z1-T8: daily, the reminder about secrets past their age limit.
pub fn spawn_secret_age_reminder_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(SECRET_AGE_REMINDER.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "secret age reminder: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_SECRET_AGE_REMINDER,
        "secret age reminder",
    );
}

/// AA9-T7: daily, the warning about limits near their value.
pub fn spawn_limit_warning_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::LimitWarningCheck,
        DEDUP_KEY_LIMIT_WARNING_CHECK,
        "limit warning check",
    );
}

/// AI4-T5: every hour, the follow-up stall scans.
pub fn spawn_ai_followup_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AiFollowupScan,
        DEDUP_KEY_AI_FOLLOWUP_SCAN,
        "ai follow-up scan",
    );
}

/// D25-T4: every minute, competitor mentions in new emails and notes.
pub fn spawn_sales_mention_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SalesMentionScan,
        DEDUP_KEY_SALES_MENTION_SCAN,
        "sales mention scan",
    );
}

/// D25-T3: every minute, win/loss reviews for big closes.
pub fn spawn_sales_deal_close_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SalesDealCloseSweep,
        DEDUP_KEY_SALES_DEAL_CLOSE_SWEEP,
        "sales deal close sweep",
    );
}

/// D7-T6: every hour, disabled users' open deals for their managers.
pub fn spawn_sales_leaver_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SalesLeaverSweep,
        DEDUP_KEY_SALES_LEAVER_SWEEP,
        "sales leaver sweep",
    );
}

/// C2-T1: every minute, follower notifications.
pub fn spawn_notification_follow_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::NotificationFollowSweep,
        DEDUP_KEY_NOTIFICATION_FOLLOW_SWEEP,
        "notification follow sweep",
    );
}

/// D6-T8: daily, line snapshots older than a day.
pub fn spawn_sales_snapshot_prune_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SalesSnapshotPrune,
        DEDUP_KEY_SALES_SNAPSHOT_PRUNE,
        "sales snapshot prune",
    );
}

/// F10-T3: every minute, commission credits for won deals.
pub fn spawn_commission_credit_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::CommissionCreditSweep,
        DEDUP_KEY_COMMISSION_CREDIT_SWEEP,
        "commission credits",
    );
}

/// F4-T9: every five minutes, pending invoice requests.
pub fn spawn_billing_request_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingRequestSweep,
        DEDUP_KEY_BILLING_REQUEST_SWEEP,
        "billing requests",
    );
}

/// F4-T9: daily, due invoice schedules.
pub fn spawn_billing_schedule_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingScheduleRun,
        DEDUP_KEY_BILLING_SCHEDULE_RUN,
        "billing schedules",
    );
}

/// AG2-T3: every five minutes, e-invoices ZATCA could not take yet.
pub fn spawn_billing_einvoice_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingEinvoiceSweep,
        DEDUP_KEY_BILLING_EINVOICE_SWEEP,
        "billing e-invoicing",
    );
}

/// F5-T7: every minute, gateway events not applied yet (a retry after a
/// failure; a new event enqueues its own run).
pub fn spawn_billing_gateway_event_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingGatewayEventApply,
        DEDUP_KEY_BILLING_GATEWAY_EVENT_APPLY,
        "billing gateway events",
    );
}

/// F5-T9: daily, due invoices charged to saved methods (the job does
/// nothing unless `billing.saved_methods.enabled` is on).
pub fn spawn_billing_charge_due_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingChargeDue,
        DEDUP_KEY_BILLING_CHARGE_DUE,
        "billing recurring charges",
    );
}

/// F5-T11: daily, yesterday's gateway payouts.
pub fn spawn_billing_reconcile_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingReconcile,
        DEDUP_KEY_BILLING_RECONCILE,
        "billing payout reconciliation",
    );
}

/// F4-T10: nightly, invoices past due.
pub fn spawn_billing_overdue_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingOverdueSweep,
        DEDUP_KEY_BILLING_OVERDUE_SWEEP,
        "billing overdue",
    );
}

/// D7-T3: every minute, new deals' default teams.
pub fn spawn_sales_default_team_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SalesDefaultTeamSweep,
        DEDUP_KEY_SALES_DEFAULT_TEAM_SWEEP,
        "sales default team",
    );
}

/// Q10-T6: every hour, the role grants past their end.
pub fn spawn_role_grant_expiry_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::RoleGrantExpiry,
        DEDUP_KEY_ROLE_GRANT_EXPIRY,
        "role grant expiry",
    );
}

/// E7-T4: every hour, the scheduled marketing lists that are due.
pub fn spawn_segment_refresh_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SegmentRefreshDue,
        DEDUP_KEY_SEGMENT_REFRESH_DUE,
        "segment refresh due",
    );
}

/// E30-T1: once a day, loyalty earning and expiry.
pub fn spawn_marketing_nightly_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::MarketingNightly,
        DEDUP_KEY_MARKETING_NIGHTLY,
        "marketing nightly",
    );
}

/// M10-T1: every 15 seconds, the due timers.
pub fn spawn_timer_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::TimerSweep,
        DEDUP_KEY_TIMER_SWEEP,
        "timer sweep",
    );
}

/// K6-T3: every hour, the website sources due for a recrawl.
pub fn spawn_webcrawl_recrawl_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::WebcrawlRecrawlDue,
        DEDUP_KEY_WEBCRAWL_RECRAWL_DUE,
        "webcrawl recrawl due",
    );
}

/// F3-T10: once a day, the recurring-revenue snapshot.
pub fn spawn_mrr_snapshot_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::MrrSnapshot,
        DEDUP_KEY_MRR_SNAPSHOT,
        "mrr snapshot",
    );
}

/// D11-T2: once a day, every open forecast period.
pub fn spawn_forecast_recompute_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ForecastRecompute,
        DEDUP_KEY_FORECAST_RECOMPUTE,
        "forecast recompute",
    );
}

/// D19-T1: once a day, every open deal's risk.
pub fn spawn_deal_risk_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::DealRiskEvaluation,
        DEDUP_KEY_DEAL_RISK,
        "deal risk",
    );
}

/// D18-T1: once a day, every points model rescored so decay applies.
pub fn spawn_points_scoring_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PointsScoring,
        DEDUP_KEY_POINTS_SCORING,
        "points scoring",
    );
}

/// V2-T2: every quarter hour, the next task of each completed recurring task.
pub fn spawn_recurring_task_roll_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::RecurringTaskRoll,
        DEDUP_KEY_RECURRING_TASK_ROLL,
        "recurring task roll",
    );
}

/// W1-T4: once a day, the contract key-date run.
pub fn spawn_contract_key_dates_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ContractKeyDates,
        DEDUP_KEY_CONTRACT_KEY_DATES,
        "contract key dates",
    );
}

/// M34 (AI Governance, D-435) — sibling of the schedulers above, once/day by
/// convention: a nightly quality sweep over `ai_suggestion_outcome`
/// matches the plan's own "nightly job" framing, and there is no reason for
/// this to run more often than the data it reads meaningfully changes.
/// Enqueues the durable job rather than sweeping directly from the timer
/// tick, for the same restart-safety reason every other scheduler here does.
pub fn spawn_ai_quality_monitor_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AiQualityMonitor,
        DEDUP_KEY_AI_QUALITY_MONITOR,
        "ai quality monitor",
    );
}

/// P-idempotency-hardening §4.4/§5 step 11 — sibling of the schedulers
/// above, once/day by convention (the durable tier's retention window
/// defaults to 24h, same order of magnitude as `apalis.jobs` history — no
/// need for a tighter cadence). Enqueues the durable job rather than
/// soft-deleting directly from the timer tick, for the same restart-safety
/// reason every other scheduler here does.
pub fn spawn_idempotency_record_prune_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneIdempotencyRecords,
        DEDUP_KEY_PRUNE_IDEMPOTENCY_RECORDS,
        "idempotency durable-tier prune",
    );
}

/// attome-auth plan BAU-13a/13b — once a day, like the idempotency prune: the
/// auth token tables grow by one row per login, refresh and reset, and
/// nothing else removes them.
pub fn spawn_auth_token_prune_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneAuthTokens,
        DEDUP_KEY_PRUNE_AUTH_TOKENS,
        "auth token prune",
    );
}

/// Solution 7 Phase 2 (D-788 rule 9, design §8.4) — the recovery archive's
/// purge, hourly: expired values leave the archive within the hour after
/// their 30 days. Enqueues the durable job, as every scheduler here does.
pub fn spawn_recovery_archive_prune_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneRecoveryArchive,
        DEDUP_KEY_PRUNE_RECOVERY_ARCHIVE,
        "recovery archive prune",
    );
}

/// P-retention-archive-completion §3b/§3c/§5 step 7 — sibling of the
/// schedulers above. Enqueues `EngineJob::ProposeRetentionActions` on the
/// durable queue rather than proposing directly from the timer tick, for the
/// same restart-safety reason every other scheduler here does. Runs
/// unconditionally (like `spawn_partition_maintenance_scheduler`) — the
/// propose step itself is a no-op when every `retention.*_days`/
/// `entity_purge_grace_days` window is unset (today's default), so an
/// idle deployment pays only for a cheap no-op enqueue+config-check per
/// interval, not for a special "is retention configured" gate here.
pub fn spawn_retention_proposal_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ProposeRetentionActions,
        DEDUP_KEY_RETENTION_PROPOSE,
        "retention propose",
    );
}

/// M35 (AI Memory, D-451) — sibling of the schedulers above, own scheduler
/// rather than folded into `spawn_retention_proposal_scheduler`: see
/// `EngineJob::PruneExpiredMemories`'s doc comment for why memory
/// retention deliberately does not go through the propose/approve/execute
/// ledger the other retention sweep uses. Runs unconditionally, like
/// `spawn_retention_proposal_scheduler` — `ai.memory_retention_days` always
/// has an effective value (a code default), so there is no "not configured"
/// no-op state to special-case here.
pub fn spawn_memory_retention_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PruneExpiredMemories,
        DEDUP_KEY_PRUNE_EXPIRED_MEMORIES,
        "memory retention sweep",
    );
}

/// P-workflow-engine §4.3/§5 step 7 — sibling of the schedulers above.
/// Enqueues the durable job rather than sweeping `workflow_trigger_index`
/// directly from the timer tick, for the same restart-safety reason every
/// other scheduler here does. A shorter interval than the daily-cadence
/// schedulers above is appropriate — SLA/schedule waits are user-visible
/// wall-clock deadlines, not background maintenance.
pub fn spawn_workflow_sla_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::WorkflowSlaSweep,
        DEDUP_KEY_WORKFLOW_SLA_SWEEP,
        "workflow SLA sweep",
    );
}

/// P-workflow-engine §5 step 6 follow-up (D-267 addendum) — sibling of
/// `spawn_workflow_sla_sweep_scheduler` above, but a shorter interval:
/// "a record was created, a listening workflow should start" reads as more
/// time-sensitive to an operator than a wait-node/SLA timer, even though
/// both share the same dedup-keyed enqueue-a-durable-job shape.
pub fn spawn_workflow_entity_trigger_dispatch_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::WorkflowEntityTriggerDispatch,
        DEDUP_KEY_WORKFLOW_ENTITY_TRIGGER_DISPATCH,
        "workflow entity-trigger dispatch",
    );
}

/// M27 Phase 1 (KPI & Metrics, D-407) — sibling of the schedulers above.
/// Enqueues the durable job rather than sweeping metric definitions directly
/// from the timer tick, for the same restart-safety reason every other
/// scheduler here does. An hour-scale interval, not once/day: metric periods
/// range from `day` to `year` (`dashboard_metric_definition.period`), so a `day`
/// metric wants same-day freshness — but not minute-scale either, since
/// `attome_metric::metric::compute_and_record`'s idempotency check makes a
/// tick that finds nothing new to compute cheap regardless of frequency.
pub fn spawn_metric_snapshot_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ComputeMetricSnapshots,
        DEDUP_KEY_COMPUTE_METRIC_SNAPSHOTS,
        "metric snapshot sweep",
    );
}

/// M62 Phase 1 (D-403/D-409) — sibling of `spawn_workflow_entity_trigger_
/// dispatch_scheduler` above, same shape: enqueues the durable
/// `EventsDispatchTick` job rather than draining subscriptions directly from
/// the timer tick, and the dedup key absorbs every replica's own timer down
/// to one winning row per tick the same way every scheduler in this file
/// does.
pub fn spawn_events_dispatch_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::EventsDispatchTick,
        DEDUP_KEY_EVENTS_DISPATCH_TICK,
        "events dispatch tick",
    );
}

/// M03 (Security & Identity) gap 1 / D-434 — sibling of the schedulers
/// above, once/day by convention (a campaign's `due_date` is set in days,
/// same order of magnitude as `sql_query`/`apalis.jobs` history —
/// no need for a tighter cadence). Enqueues the durable job rather than
/// completing overdue campaigns directly from the timer tick, for the same
/// restart-safety reason every other scheduler here does.
pub fn spawn_access_review_campaign_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AccessReviewCampaignSweep,
        DEDUP_KEY_ACCESS_REVIEW_CAMPAIGN_SWEEP,
        "access review campaign sweep",
    );
}

/// D-432 / M13 — sibling of the schedulers above. Enqueues the durable
/// `DataMatchSweep` job rather than scoring records directly from the timer
/// tick, for the same restart-safety reason every other scheduler here does.
/// A slower cadence than the two entity-change-outbox consumers above
/// (`spawn_workflow_entity_trigger_dispatch_scheduler`/
/// `spawn_events_dispatch_scheduler`, both 10s) — duplicate detection is a
/// background data-quality sweep, not a user-visible-latency concern, and
/// each tick's per-record peer scan is the more expensive kind of work this
/// file schedules.
pub fn spawn_data_match_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::DataMatchSweep,
        DEDUP_KEY_DATA_MATCH_SWEEP,
        "mdm match sweep",
    );
}

/// M61 Phase 1 (API Management, D-438) — sibling of the schedulers above,
/// once/day by convention: the source Redis buffer
/// (`attome_server::api_usage`) only needs draining well ahead of its own
/// defensive TTL (3 days), not near-real-time — usage analytics is a
/// backward-looking report, not a user-visible-latency concern. Enqueues the
/// durable job rather than draining the buffer directly from the timer tick,
/// for the same restart-safety reason every other scheduler here does.
pub fn spawn_api_usage_rollup_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ApiUsageRollup,
        DEDUP_KEY_API_USAGE_ROLLUP,
        "api usage rollup",
    );
}

/// M56 Content Management Phase 1 (D-436) — sibling of the schedulers above.
/// Enqueues the durable job rather than transitioning pages directly from
/// the timer tick, for the same restart-safety reason every other scheduler
/// here does. A minute-scale interval, like the workflow SLA sweep — a
/// scheduled publish/unpublish is a user-visible wall-clock deadline an
/// editor set deliberately, not background maintenance that can lag a day.
/// M11 Search gap list — see `EngineJob::SearchSuggestionRefresh`'s doc
/// comment for what the handler rebuilds and why.
pub fn spawn_search_suggestion_refresh_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SearchSuggestionRefresh,
        DEDUP_KEY_SEARCH_SUGGESTION_REFRESH,
        "search suggestion refresh",
    );
}

/// M11 Search gap list — see `EngineJob::SearchSavedSearchAlertSweep`'s doc
/// comment for what the handler checks and why.
pub fn spawn_search_saved_search_alert_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::SearchSavedSearchAlertSweep,
        DEDUP_KEY_SEARCH_SAVED_SEARCH_ALERT_SWEEP,
        "saved search alert sweep",
    );
}

pub fn spawn_content_scheduled_publish_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ContentScheduledPublishSweep,
        DEDUP_KEY_CONTENT_SCHEDULED_PUBLISH_SWEEP,
        "content scheduled publish sweep",
    );
}

/// M14 Phase 1 (Data Quality) — sibling of `spawn_api_usage_rollup_scheduler`,
/// once/day by the same convention: a quality score is a backward-looking
/// per-period metric (the sweep's own period key is a calendar day, see
/// `quality_score::today_period`'s doc comment), not a user-visible-latency
/// concern. Enqueues the durable job rather than scoring entities directly
/// from the timer tick, for the same restart-safety reason every other
/// scheduler here does.
pub fn spawn_data_quality_score_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::DataQualityScoreSweep,
        DEDUP_KEY_DATA_QUALITY_SCORE_SWEEP,
        "data quality score sweep",
    );
}

/// M25 Phase 1 (Report, D-440) — sibling of the schedulers above. Enqueues
/// the durable job rather than sweeping `report_schedule` directly from
/// the timer tick, for the same restart-safety reason every other scheduler
/// here does. A minute-scale interval, same cadence class as the workflow
/// SLA sweep and content scheduled-publish sweep above — a due schedule is a
/// user-visible wall-clock deadline an admin set deliberately, not
/// background maintenance that can lag a day.
pub fn spawn_report_schedule_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ReportScheduleSweep,
        DEDUP_KEY_REPORT_SCHEDULE_SWEEP,
        "report schedule sweep",
    );
}

/// M04 (License Management) usage-reporting gap — sibling of the schedulers
/// above, once/day by convention: the 30/7/1-day thresholds this checks
/// against move on a day-scale cadence, same order of magnitude as the other
/// once-daily sweeps (`AiQualityMonitor`, `ApiUsageRollup`). Enqueues the
/// durable job rather than checking expiry directly from the timer tick, for
/// the same restart-safety reason every other scheduler here does.
/// Audit plan 3.5 (D-541 rule 6) — once a minute, well inside the two-window
/// TTL of the counters it summarizes, so a closed window is swept before its
/// counters can expire. Enqueues the durable job rather than sweeping from the
/// timer tick, for the same restart-safety reason every other scheduler here
/// does.
pub fn spawn_failed_login_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::FailedLoginSweep,
        DEDUP_KEY_FAILED_LOGIN_SWEEP,
        "failed-login sweep",
    );
}

/// M37 Knowledge Management Phase 2 (D-452) — sibling of
/// `spawn_api_usage_rollup_scheduler`, once/day by the same convention:
/// article analytics is a backward-looking report, not a user-visible-
/// latency concern. Enqueues the durable job rather than rolling up
/// directly from the timer tick, for the same restart-safety reason every
/// other scheduler here does.
pub fn spawn_content_page_stats_rollup_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ContentPageStatsRollup,
        DEDUP_KEY_CONTENT_PAGE_STATS_ROLLUP,
        "content page stats rollup",
    );
}

/// M37 Knowledge Management Phase 2 (D-452) — sibling of
/// `spawn_content_scheduled_publish_sweep_scheduler`, but once/day: unlike a
/// scheduled publish (a wall-clock deadline an editor set deliberately for a
/// specific minute), a review-by reminder is "notice this soon", not
/// "notice this the instant it passes" — the same daily cadence
/// `spawn_api_usage_rollup_scheduler` above already uses.
pub fn spawn_content_review_reminder_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ContentReviewReminderSweep,
        DEDUP_KEY_CONTENT_REVIEW_REMINDER_SWEEP,
        "content review reminder sweep",
    );
}

/// M41 Phase 1 (Process Intelligence, D-462) — sibling of the schedulers
/// above. Enqueues the durable job rather than extracting directly from the
/// timer tick, for the same restart-safety reason every other scheduler here
/// does. Minute-scale interval, same cadence class as the workflow SLA sweep
/// and content scheduled-publish sweep — process mining views should stay
/// reasonably fresh, not lag a full day, though nothing here is a
/// user-visible wall-clock deadline the way those two are.
pub fn spawn_process_extraction_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ProcessExtractionSweep,
        DEDUP_KEY_PROCESS_EXTRACTION_SWEEP,
        "process extraction sweep",
    );
}

/// M84 Phase 1 (Queue Management, D-464) — sibling of the schedulers above.
/// Enqueues the durable job rather than alerting directly from the timer
/// tick, for the same restart-safety reason every other scheduler here does.
/// A 15-minute interval, the same cadence class
/// `spawn_search_suggestion_refresh_scheduler` uses — capacity overflow and
/// idle backlog are operationally important but not minute-scale-urgent, and
/// the sweep re-nags every tick the condition still holds (see
/// `attome_service::queue::run_escalation_sweep`'s own doc comment), so a
/// missed tick is never a missed alert, only a delayed one.
pub fn spawn_work_queue_escalation_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::WorkQueueEscalationSweep,
        DEDUP_KEY_WORK_QUEUE_ESCALATION_SWEEP,
        "work queue escalation sweep",
    );
}

/// M73 (SLA Management, D-422) — see `EngineJob::TicketSlaSweep`'s doc
/// comment. A 5-minute interval: unlike `WorkQueueEscalationSweep`'s re-nag
/// posture, an SLA breach/warning is a user-visible wall-clock deadline, so
/// this runs closer to the minute-scale cadence class
/// (`spawn_process_extraction_sweep_scheduler`) than the 15-minute one.
pub fn spawn_ticket_sla_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::TicketSlaSweep,
        DEDUP_KEY_TICKET_SLA_SWEEP,
        "ticket SLA sweep",
    );
}

/// M72 (Resource Management) — see `EngineJob::ResourceUtilizationSweep`'s
/// doc comment. Once/day, same cadence class as
/// `spawn_content_review_reminder_sweep_scheduler` — a "sustained" alert
/// over a 28-day lookback has no minute-scale urgency.
pub fn spawn_resource_utilization_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ResourceUtilizationSweep,
        DEDUP_KEY_RESOURCE_UTILIZATION_SWEEP,
        "resource utilization sweep",
    );
}

/// M18 Data Catalog Phase 1 (D-466) — see `EngineJob::CatalogLineageBackfill`'s
/// doc comment. A short interval (5 minutes, same cadence class as
/// `spawn_data_match_sweep_scheduler`) is safe specifically because the
/// handler is a self-converging no-op once both kinds report `completed` —
/// unlike a wall-clock-deadline sweep, there is no downside to checking
/// often while historical data is still being caught up on a fresh
/// deployment.
pub fn spawn_catalog_lineage_backfill_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::CatalogLineageBackfill,
        DEDUP_KEY_CATALOG_LINEAGE_BACKFILL,
        "catalog lineage backfill",
    );
}

/// M18 Data Catalog Phase 1 (D-466) — see `EngineJob::
/// CatalogDashboardLineageSweep`'s doc comment. Same 5-minute cadence as
/// `spawn_data_match_sweep_scheduler`, the sibling outbox-consumer sweep
/// this one is modeled on.
pub fn spawn_catalog_dashboard_lineage_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::CatalogDashboardLineageSweep,
        DEDUP_KEY_CATALOG_DASHBOARD_LINEAGE_SWEEP,
        "catalog dashboard lineage sweep",
    );
}

/// M18 Data Catalog Phase 1 (D-466) — see `EngineJob::CatalogUsageRollup`'s
/// doc comment. Once/day, same cadence class as `spawn_api_usage_rollup_scheduler`
/// — usage analytics is a backward-looking snapshot, not a user-visible-
/// latency concern.
pub fn spawn_catalog_usage_rollup_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::CatalogUsageRollup,
        DEDUP_KEY_CATALOG_USAGE_ROLLUP,
        "catalog usage rollup",
    );
}

async fn ensure_audit_partitions(
    db: &DbPool,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let months_ahead = config.audit.partition_create_ahead_months;
    for (table, col) in PARTITIONED_TABLES {
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db,
            table,
            col,
            PARTITION_STORAGE_PARAMS,
            months_ahead,
        )
        .await?;
        if created > 0 {
            tracing::info!(table = %table, created, "partition create-ahead: new partitions created");
        }
    }
    for (table, col) in NOTIFICATION_PARTITIONED_TABLES {
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db,
            table,
            col,
            NOTIFICATION_PARTITION_STORAGE_PARAMS,
            months_ahead,
        )
        .await?;
        if created > 0 {
            tracing::info!(table = %table, created, "partition create-ahead: new partitions created");
        }
    }
    for (table, col) in METRIC_PARTITIONED_TABLES {
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db,
            table,
            col,
            PARTITION_STORAGE_PARAMS,
            months_ahead,
        )
        .await?;
        if created > 0 {
            tracing::info!(table = %table, created, "partition create-ahead: new partitions created");
        }
    }
    for (table, col) in MARKETING_PARTITIONED_TABLES {
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db,
            table,
            col,
            PARTITION_STORAGE_PARAMS,
            months_ahead,
        )
        .await?;
        if created > 0 {
            tracing::info!(table = %table, created, "partition create-ahead: new partitions created");
        }
    }
    for (table, col) in PROCESS_PARTITIONED_TABLES {
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db,
            table,
            col,
            PARTITION_STORAGE_PARAMS,
            months_ahead,
        )
        .await?;
        if created > 0 {
            tracing::info!(table = %table, created, "partition create-ahead: new partitions created");
        }
    }
    Ok(())
}

/// M36 Phase 1 (Predictive Intelligence, D-473) — see
/// `EngineJob::PredictScoringSweep`'s doc comment. Minute-scale interval,
/// same cadence class as the process extraction sweep above — SLA-breach
/// risk changes on the same timescale as ticket updates, not hourly.
pub fn spawn_predict_scoring_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PredictScoringSweep,
        DEDUP_KEY_PREDICT_SCORING_SWEEP,
        "predict scoring sweep",
    );
}

/// M36 Phase 1 — see `EngineJob::PredictOutcomeFillSweep`'s doc comment.
/// 15-minute interval, same cadence class as the work queue escalation sweep
/// above: a prediction's horizon passing is not minute-scale-urgent to
/// notice, and the sweep is a no-op once nothing's horizon has passed.
pub fn spawn_predict_outcome_fill_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PredictOutcomeFillSweep,
        DEDUP_KEY_PREDICT_OUTCOME_FILL_SWEEP,
        "predict outcome-fill sweep",
    );
}

/// `PARTITIONED_TABLES` has no other caller to catch a typo against — it's a
/// hand-transcribed copy of the four `PARTITION BY RANGE` tables
/// `migrations/0026_audit_partitioning.sql` actually created, each keyed to
/// that table's own partition column (`s2s_access_log` uses
/// `created_at`, not `created_at`, per that migration's comment). A dropped
/// entry silently stops create-ahead maintenance for that table until it
/// runs out of future partitions; a column typo fails loudly against a live
/// database instead (`ensure_ahead_partitions`), but only in production —
/// this test catches both without one.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitioned_tables_lists_exactly_the_four_tables_migration_0026_created() {
        assert_eq!(
            PARTITIONED_TABLES,
            &[
                ("audit_header", "created_at"),
                ("audit_detail", "created_at"),
                ("audit_snapshot", "created_at"),
                ("s2s_access_log", "created_at"),
            ]
        );
    }

    #[test]
    fn partitioned_tables_has_no_duplicate_table_names() {
        let mut names: Vec<&str> = PARTITIONED_TABLES.iter().map(|(table, _)| *table).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "PARTITIONED_TABLES has a duplicate entry"
        );
    }

    #[test]
    fn partition_storage_params_marks_every_partitioned_table_append_only() {
        // fillfactor = 100 (never leave gap for in-place UPDATEs) is the
        // guidelines §4 APPEND_ONLY_STORAGE_PARAMS convention — all four
        // partitioned tables are append-only audit/access-log data, never a
        // mutable-entity fillfactor like 90.
        assert!(
            PARTITION_STORAGE_PARAMS.contains("fillfactor = 100"),
            "got: {PARTITION_STORAGE_PARAMS}"
        );
    }

    #[test]
    fn notification_partitioned_tables_tracks_recipient_inbox() {
        assert_eq!(
            NOTIFICATION_PARTITIONED_TABLES,
            &[("notification_recipient", "created_at")]
        );
        assert!(NOTIFICATION_PARTITION_STORAGE_PARAMS.contains("fillfactor = 90"));
    }

    #[test]
    fn schedule_jitter_is_bounded_by_ten_percent_of_the_interval() {
        // BJB-4c — the sleep is never shorter than the interval (a tick that
        // arrived early would be refused by the ledger CAS and the schedule
        // would skip its slot) and never more than 10% longer.
        let interval = std::time::Duration::from_secs(600);
        assert_eq!(jittered_interval(interval, 0), interval);
        for seed in [1_u64, 7, 999, 123_456, u64::MAX] {
            let jittered = jittered_interval(interval, seed);
            assert!(
                jittered >= interval,
                "{jittered:?} must not precede the slot"
            );
            assert!(
                jittered <= interval + std::time::Duration::from_secs(60),
                "{jittered:?} must stay within 10% of {interval:?}"
            );
        }
        // An interval whose 10% rounds to zero milliseconds is returned
        // unchanged rather than panicking on a modulo by zero.
        let tiny = std::time::Duration::from_millis(5);
        assert_eq!(jittered_interval(tiny, 12_345), tiny);
    }

    #[test]
    fn startup_stagger_is_bounded_by_the_interval_and_sixty_seconds() {
        // BJB-4c — the first tick must come well inside one interval, so a node
        // that restarts daily still runs a 24 h schedule.
        let day = std::time::Duration::from_secs(24 * 60 * 60);
        let short = std::time::Duration::from_secs(10);
        assert_eq!(startup_stagger(day, 0), std::time::Duration::ZERO);
        for seed in [1_u64, 7, 999, 123_456, 59_999, 60_000, u64::MAX] {
            assert!(startup_stagger(day, seed) <= std::time::Duration::from_secs(60));
            assert!(startup_stagger(short, seed) <= short);
        }
        assert_eq!(
            startup_stagger(std::time::Duration::ZERO, 12_345),
            std::time::Duration::ZERO
        );
    }

    #[test]
    fn a_masked_internal_job_error_keeps_its_detail_for_the_log() {
        let direct: Box<dyn std::error::Error + Send + Sync> =
            Box::new(attome_types::AppError::Internal("pool timed out".into()));
        assert_eq!(masked_internal_detail(&*direct), Some("pool timed out"));

        let other: Box<dyn std::error::Error + Send + Sync> =
            Box::new(attome_types::AppError::NotFound);
        assert_eq!(masked_internal_detail(&*other), None);

        #[derive(Debug)]
        struct Wrapper(attome_types::AppError);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("wrapped")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let nested: Box<dyn std::error::Error + Send + Sync> = Box::new(Wrapper(
            attome_types::AppError::Internal("deadlock detected".into()),
        ));
        assert_eq!(masked_internal_detail(&*nested), Some("deadlock detected"));
    }

    #[test]
    fn schedule_name_for_resolves_scheduled_kinds_to_their_dedup_key() {
        // BJB-4d — the ledger name is the schedule's dedup key constant, so a
        // schedule has exactly one name across both mechanisms.
        assert_eq!(
            schedule_name_for(&EngineJob::EnsureAuditPartitions),
            Some(DEDUP_KEY_ENSURE_AUDIT_PARTITIONS)
        );
        assert_eq!(
            schedule_name_for(&EngineJob::ProposeRetentionActions),
            Some(DEDUP_KEY_RETENTION_PROPOSE)
        );
        assert_eq!(
            schedule_name_for(&EngineJob::PredictOutcomeFillSweep),
            Some(DEDUP_KEY_PREDICT_OUTCOME_FILL_SWEEP)
        );
        // A kind no scheduler enqueues has no ledger row to stamp.
        assert_eq!(
            schedule_name_for(&EngineJob::BuildAttributeIndex {
                entity_logicalname: "contact".to_string(),
                field_logicalname: "name".to_string(),
            }),
            None
        );
    }

    /// attome-email plan §4.2 — the whole send-outcome table, one row per class.
    #[test]
    fn every_send_outcome_has_one_disposition() {
        use attome_email::{DeliveryStatus, SendError};
        let permanent = |recipient_attributable| SendError::Permanent {
            code: "550".into(),
            message: "reply".into(),
            recipient_attributable,
        };
        let transient = || SendError::Transient {
            message: "451".into(),
        };
        let settle = SendEmailDisposition::Settle;
        let cases: Vec<(Result<(), SendError>, bool, SendEmailDisposition)> = vec![
            (Ok(()), false, settle(DeliveryStatus::Sent)),
            (
                Err(SendError::Suppressed),
                false,
                settle(DeliveryStatus::Suppressed),
            ),
            (
                Err(permanent(true)),
                false,
                settle(DeliveryStatus::Suppressed),
            ),
            (Err(permanent(false)), false, settle(DeliveryStatus::Failed)),
            (
                Err(SendError::Config {
                    message: "tls".into(),
                }),
                false,
                settle(DeliveryStatus::Failed),
            ),
            (
                Err(SendError::InvalidAddress("x".into())),
                false,
                settle(DeliveryStatus::Failed),
            ),
            (
                Err(SendError::Unknown {
                    message: "stall".into(),
                }),
                false,
                settle(DeliveryStatus::Unknown),
            ),
            (
                Err(transient()),
                false,
                SendEmailDisposition::RetryCountingAttempt,
            ),
            (Err(transient()), true, settle(DeliveryStatus::Failed)),
            (
                Err(SendError::Internal("db".into())),
                false,
                SendEmailDisposition::Retry,
            ),
            (
                Err(SendError::Internal("db".into())),
                true,
                settle(DeliveryStatus::Failed),
            ),
            (Err(SendError::Disabled), false, SendEmailDisposition::Retry),
            (
                Err(SendError::Disabled),
                true,
                settle(DeliveryStatus::Failed),
            ),
        ];
        for (result, final_attempt, expected) in cases {
            assert_eq!(
                send_email_disposition(&result, final_attempt),
                expected,
                "{result:?} (final_attempt = {final_attempt})"
            );
        }
    }

    /// BEM-15 — a terminal outcome is never retried, whatever the attempt.
    #[test]
    fn a_terminal_send_outcome_is_never_retried_on_any_attempt() {
        use attome_email::SendError;
        for final_attempt in [false, true] {
            for result in [
                Ok(()),
                Err(SendError::Suppressed),
                Err(SendError::Config {
                    message: "auth".into(),
                }),
                Err(SendError::Unknown {
                    message: "stall".into(),
                }),
            ] {
                assert!(matches!(
                    send_email_disposition(&result, final_attempt),
                    SendEmailDisposition::Settle(_)
                ));
            }
        }
    }

    /// BJB-14a — the `kind` label set is closed: an unrecognized row's own
    /// variant text never becomes a label.
    #[test]
    fn the_job_metric_kind_label_is_closed() {
        let known = JobEnvelope::Known {
            job: EngineJob::EnsureAuditPartitions,
            trace_context: None,
        };
        assert_eq!(metric_kind(&known), "EnsureAuditPartitions");
        let unknown = JobEnvelope::Unrecognized {
            variant: "AttackerChosen-1234".into(),
            version: 9,
        };
        assert_eq!(metric_kind(&unknown), "unrecognized");
    }

    /// BJB-5 — a component that ends for any reason stops its siblings.
    #[tokio::test]
    async fn a_component_that_ends_signals_its_siblings() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let failing = signal_shutdown_after(tx.clone(), async { Err::<(), &str>("monitor died") });
        let sibling = async move {
            rx.wait_for(|stop| *stop).await.expect("sender alive");
            "drained"
        };
        let (failed, drained) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(failing, sibling)
        })
        .await
        .expect("the sibling must observe the shutdown signal");
        assert_eq!(failed, Err("monitor died"));
        assert_eq!(drained, "drained");
        assert!(*tx.borrow(), "the signal stays set for late subscribers");
    }

    #[test]
    fn metric_partitioned_tables_tracks_snapshot_table() {
        assert_eq!(
            METRIC_PARTITIONED_TABLES,
            &[("metric_snapshot", "computed_at")]
        );
        // Append-only (D-407) — same class as PARTITIONED_TABLES, not the
        // mutable NOTIFICATION_PARTITION_STORAGE_PARAMS fillfactor.
        assert!(PARTITION_STORAGE_PARAMS.contains("fillfactor = 100"));
    }
}
