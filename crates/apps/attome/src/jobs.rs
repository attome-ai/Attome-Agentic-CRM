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
    // S9-T5: an outbound call the job makes carries `job:<task id>`, the
    // same on every retry of this job.
    let job_key = format!("job:{task_id}");
    let (mut result, probes) = attome_types::request_scope::with_idempotency_key(
        Some(&job_key),
        attome_profiler::scope(dispatch_platform_job(
            job,
            db.clone(),
            db_migrator,
            config,
            attome_state.clone(),
            attempt.current(),
            task_id.to_string(),
        )),
    )
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
    // AB9-T6: a job delivered again after its row settled (a worker killed
    // after the send was recorded, before the queue saw the job finish) must
    // not send a second copy. Only a `queued` row is still owed a send.
    if let Some(id) = delivery_id
        && let Some(row) = attome_email::delivery::get_by_id(db, id).await?
        && row.status != "queued"
    {
        tracing::info!(
            delivery_id = %id,
            status = %row.status,
            "email: the delivery is already settled; this run sends nothing"
        );
        return Ok(());
    }
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
                           OR a.type = 11
                           -- AA3-T1: the index advisor chose it.
                           OR EXISTS (SELECT 1 FROM index_advice x
                                       WHERE x.entity_logicalname = e.logicalname
                                         AND x.attribute = a.logicalname))
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
            // C9-T1: chat messages past their channel's retention (legal
            // holds suspend it per channel; `retention.legal_hold` suspends
            // it all).
            let chat = attome_chat::retention::purge_expired(
                &attome_state.base.db,
                config.retention.legal_hold,
            )
            .await?;
            if chat > 0 {
                tracing::info!(purged = chat, "chat retention: expired messages removed");
            }
            // N22-T2: transcripts whose recording no document names any more.
            let transcripts =
                attome_document::transcribe::prune_orphans(&attome_state.base.db).await?;
            if transcripts > 0 {
                tracing::info!(transcripts, "recording transcripts: orphans removed");
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
        // K1-T4 — see this variant's doc comment.
        EngineJob::DocumentTextExtract { session_id } => {
            attome_document::text_extract::process(&attome_state, session_id).await?;
        }
        // Z6-T6 — see this variant's doc comment.
        EngineJob::FileThumbnail { session_id } => {
            attome_document::thumbnail::process(&attome_state, session_id).await?;
        }
        // N22-T2 — see this variant's doc comment.
        EngineJob::TranscribeRecording { document_id } => {
            attome_document::transcribe::process(&attome_state, document_id).await?;
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
            // AA3-T1: and the indexes the advisor chooses for what views and
            // definitions filter and sort on.
            let advised = attome_metadata::provision::index_advisor::advise(&db).await?;
            let mut advised_queued = 0usize;
            for (entity, field) in advised {
                let key = format!("index-advice:{entity}:{field}");
                let job = EngineJob::BuildAttributeIndex {
                    entity_logicalname: entity,
                    field_logicalname: field,
                };
                if attome_jobs::enqueue_dedup(&db, job, &key).await? {
                    advised_queued += 1;
                }
            }
            tracing::info!(advised_queued, "index advisor: builds queued");
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
            // E27-T3: consent older than compliance.consent_expiry_days lapses.
            let lapsed = attome_compliance::double_opt_in::expire_grants(&attome_state).await?;
            if lapsed > 0 {
                tracing::info!(lapsed, "consent expiry: grants withdrawn");
            }
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
        // K2-T2: recent files scanned again with today's signatures.
        EngineJob::UploadRescanSweep => {
            let stats = attome_document::files_scan::rescan_recent(&attome_state).await?;
            if stats.scanned > 0 || stats.infected > 0 || stats.missing > 0 {
                tracing::info!(
                    scanned = stats.scanned,
                    infected = stats.infected,
                    missing = stats.missing,
                    "upload rescan: run complete"
                );
            }
        }
        // Z6-T3: a sample of stored files read back and compared.
        EngineJob::FileIntegritySample => {
            let live = attome_document::integrity::live_versions(&db).await?;
            let stats = attome_document::integrity::sample_check(
                &db,
                attome_state.base.storage.store(),
                &attome_document::integrity::SampleScope::weekly(live),
            )
            .await?;
            if stats.mismatched > 0 || stats.missing > 0 {
                tracing::error!(
                    checked = stats.checked,
                    mismatched = stats.mismatched,
                    missing = stats.missing,
                    "file integrity: stored files differ from what was uploaded"
                );
            } else {
                tracing::info!(
                    checked = stats.checked,
                    "file integrity: weekly sample clean"
                );
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
            // AI5-T2: the collection rules write to the same ledger, from
            // 08:00 deployment time each day (AI5-T5).
            let zone = attome_ai::followup_collections::deployment_zone(&attome_state);
            let collections_day = attome_ai::followup_collections::collections_day(now, zone);
            let collection_rules = match collections_day {
                Some(_) => {
                    attome_ai::followup_collections::active_rules(&attome_state.base.db).await?
                }
                None => Vec::new(),
            };
            let today = collections_day.unwrap_or_else(|| now.date_naive());
            for rule in collection_rules {
                match attome_ai::followup_collections::detect_collections(
                    &attome_state,
                    &rule,
                    today,
                )
                .await
                {
                    Ok(n) => found += n,
                    Err(e) => {
                        tracing::warn!(rule = %rule.id, error = %e, "collections scan: rule skipped")
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
            // D24-T4: and new leads get the account their work email's
            // domain matches, as a suggestion.
            let suggested =
                attome_sales::enrichment::domain::sweep_new_leads(&attome_state).await?;
            if suggested > 0 {
                tracing::info!(suggested, "lead domain: accounts suggested for new leads");
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
        // AA10-T4: one chunk of a background mass operation.
        EngineJob::HeavyOpChunk {
            operation_id,
            chunk_no,
            after_id,
        } => {
            let changed =
                attome_records::mass::run_chunk(&attome_state, operation_id, chunk_no, after_id)
                    .await?;
            tracing::info!(%operation_id, chunk_no, changed, "mass operation: chunk done");
            // AA10-T9: after the chunk committed, the starter hears once that it ended.
            attome_notification::mass_notice::notify_finished(&attome_state, operation_id).await?;
        }
        // AA10-T5: one chunk of a large mass operation written back.
        EngineJob::HeavyOpUndoChunk {
            operation_id,
            chunk_no,
        } => {
            let restored =
                attome_records::mass::run_undo_chunk(&attome_state, operation_id, chunk_no).await?;
            tracing::info!(%operation_id, chunk_no, restored, "mass operation: chunk undone");
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
        // Q10-T9: removal proposals for unused role privileges, daily.
        EngineJob::PrivilegeUsageDaily => {
            let drafted =
                attome_security::usage::propose_unused(&attome_state.base.db, chrono::Utc::now())
                    .await?;
            tracing::info!(
                drafted,
                dropped = attome_server::privilege_usage::dropped(),
                "privilege usage: removal proposals drafted"
            );
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
            // M10-T2: timers that follow a record's date move or go first,
            // so a moved timer is not claimed at its old time. Its failure
            // must not hold back the due timers.
            match attome_workflow::timer_follow::sweep(&attome_state).await {
                Ok(run) if run.moved + run.cancelled > 0 => tracing::info!(
                    moved = run.moved,
                    cancelled = run.cancelled,
                    "timers: date-following timers updated"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = ?e, "timers: the date-following sweep failed"),
            }
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
            // G9-T1: SLA clocks whose warning or breach moment has come, on
            // time. Its own failure must not hold back the timers above.
            match attome_service::clock::sweep_due_clocks(
                &db,
                &attome_state.base.config.notification,
                chrono::Utc::now(),
            )
            .await
            {
                Ok(0) => {}
                Ok(acted) => tracing::info!(acted, "timers: SLA clocks warned or breached"),
                Err(e) => tracing::warn!(error = ?e, "timers: the SLA due-clock sweep failed"),
            }
        }
        // M10-T1: one fired timer. No kind has an action yet; each later
        // feature registers its kind here.
        EngineJob::TimerFire { timer_id } => {
            let mut conn = db.acquire().await?;
            if let Some(timer) = attome_core::timer::load(&mut conn, timer_id).await? {
                drop(conn);
                let outcome = if timer.kind == attome_procurement::compliance::TIMER_KIND {
                    // W2-T1: a vendor compliance document about to expire.
                    attome_procurement::compliance::fire(
                        &attome_state,
                        &timer,
                        chrono::Utc::now().date_naive(),
                    )
                    .await
                    .map_err(|e| e.to_string())
                } else if timer.kind == attome_service::maintenance::TIMER_KIND {
                    // I5-T2: a maintenance plan's work order, ahead of its due date.
                    attome_service::maintenance::fire(
                        &attome_state,
                        &timer,
                        chrono::Utc::now().date_naive(),
                    )
                    .await
                    .map_err(|e| e.to_string())
                } else if timer.kind == attome_compliance::breach::TIMER_KIND {
                    // R5-T2: a breach's regulator notice is near or late.
                    attome_compliance::breach::fire(&db, &timer, chrono::Utc::now())
                        .await
                        .map_err(|e| e.to_string())
                } else if timer.kind == attome_workflow::speed_to_lead::TIMER_KIND {
                    // D4-T2: a new lead's first-touch deadline.
                    attome_workflow::speed_to_lead::fire(&attome_state, &timer)
                        .await
                        .map_err(|e| e.to_string())
                } else if timer.kind == attome_service::escalation::TIMER_KIND {
                    // G8-T1: one step of a service escalation rule.
                    attome_service::escalation::fire(
                        &db,
                        &attome_state.base.config.notification,
                        &timer,
                    )
                    .await
                    .map_err(|e| e.to_string())
                } else {
                    tracing::warn!(%timer_id, kind = %timer.kind, "timers: no action for this kind");
                    Err(format!(
                        "no action is registered for timer kind {:?}",
                        timer.kind
                    ))
                };
                let mut conn = db.acquire().await?;
                attome_core::timer::settle(&mut conn, timer_id, outcome.err().as_deref()).await?;
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
        // F3-T11: subscription events handed to revenue and churn.
        EngineJob::BillingHandoffSweep => {
            let run = attome_billing::handoff::run(&db).await?;
            if run.churned > 0 || run.revenue_events > 0 {
                tracing::info!(
                    churned = run.churned,
                    revenue_events = run.revenue_events,
                    "billing hand-offs: run finished"
                );
            }
        }
        // F3-T8: subscription charges planned up to the horizon.
        EngineJob::BillingGenerateCharges => {
            let run = attome_billing::billing_run::generate_charges(
                &attome_state,
                chrono::Utc::now().date_naive(),
                attome_billing::billing_run::DEFAULT_HORIZON_DAYS,
            )
            .await?;
            if run.charges > 0 {
                tracing::info!(
                    subscriptions = run.subscriptions,
                    charges = run.charges,
                    "billing: charges planned"
                );
            }
        }
        // F3-T8: one billing run, resumable.
        EngineJob::BillingExecuteRun { run_id } => {
            attome_billing::billing_run::execute_run(&attome_state, run_id).await?;
        }
        // F3-T9: renewals and trials.
        EngineJob::BillingRenewalSweep => {
            let run = attome_billing::renewal::run(&attome_state, chrono::Utc::now().date_naive())
                .await?;
            tracing::info!(
                renewed = run.renewed,
                opportunities = run.opportunities,
                reminders = run.reminders,
                trials_converted = run.trials_converted,
                trials_ended = run.trials_ended,
                "billing renewals: run finished"
            );
        }
        // B15-T1: changed addresses get coordinates.
        EngineJob::GeocodeSweep => {
            let run = attome_integration::connector::adapters::geocode::run(&attome_state).await?;
            if run.lookups > 0 || run.located > 0 {
                tracing::info!(
                    events = run.events,
                    lookups = run.lookups,
                    located = run.located,
                    "geocode: run finished"
                );
            }
        }
        // W1-T13: contracts drafted from quotes, orders and intake requests.
        EngineJob::ContractLinkSweep => {
            let run = attome_contract::links::run(&attome_state).await?;
            if run.drafts > 0 || run.offerings > 0 {
                tracing::info!(
                    events = run.events,
                    drafts = run.drafts,
                    offerings = run.offerings,
                    "contract links: run finished"
                );
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
            // S8-T4: the per-version counters ride the same nightly run.
            let versions =
                attome_server::api_version_usage::flush(&db, &attome_state.base.redis_coordination)
                    .await?;
            if versions > 0 {
                tracing::info!(versions, "api version usage rollup: run complete");
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
            // P10-T1: metrics and the widgets that show them.
            let metrics = attome_metric::lineage_graph::backfill_catalog_lineage(&db, 200).await?;
            let widgets =
                attome_api::catalog_admin::backfill_widget_metric_lineage(&attome_state, 200)
                    .await?;
            if queries > 0 || workflows > 0 || metrics > 0 || widgets > 0 {
                tracing::info!(
                    queries,
                    workflows,
                    metrics,
                    widgets,
                    "catalog lineage backfill: run complete"
                );
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
        // A3-T8: nightly validity score per entity.
        EngineJob::ValidationScoreSweep => {
            attome_api::validation_stats::run_score_sweep(&attome_state).await?;
        }
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
        // L2-T3: scoring runs as records change; the daily job writes the
        // snapshot and the alerts.
        EngineJob::DataQualityScoreSweep => {
            let stats =
                attome_api::quality_score::run_snapshot(&attome_state, &config.notification)
                    .await?;
            tracing::info!(?stats, "data quality daily snapshot: run complete");
        }
        // F11-T3: revenue contracts from confirmed orders and active
        // subscriptions.
        EngineJob::RevrecContractSweep => {
            let queued = attome_ledger::revrec::contract::sweep(&attome_state).await?;
            if queued > 0 {
                tracing::info!(queued, "revenue contracts: builds queued");
            }
        }
        EngineJob::RevrecContractFromSource {
            source_kind,
            source_id,
        } => {
            let built = attome_ledger::revrec::contract::build_from_source(
                &attome_state,
                &source_kind,
                source_id,
            )
            .await?;
            tracing::info!(%source_kind, %source_id, ?built, "revenue contract built");
        }
        EngineJob::QualityIncrementalSweep => {
            let stats = attome_api::quality::incremental::tick(&attome_state).await?;
            if stats != attome_api::quality::incremental::TickStats::default() {
                tracing::info!(?stats, "data quality incremental: tick complete");
            }
        }
        EngineJob::MasterRebuild {
            entity,
            golden_id,
            actor,
        } => {
            let rebuilt = attome_records::entity_crud::master::rebuild(
                &attome_state,
                &entity,
                golden_id,
                actor,
            )
            .await?;
            tracing::info!(%entity, %golden_id, ?rebuilt, "master data: golden record rebuilt");
        }
        EngineJob::QualityRescan { entity, after } => {
            let next = attome_api::quality::incremental::rescan_step(&attome_state, &entity, after)
                .await?;
            tracing::info!(%entity, ?after, ?next, "data quality rescan: batch complete");
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
        // G11-T1 — see this variant's doc comment. Needs the full
        // `EngineState`: it writes the knowledge item through the entity
        // engine.
        EngineJob::ContentArticleIndex { page_id } => {
            attome_content::article::sync(&attome_state, page_id).await?;
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
        // AH6-T3 / AH8-T9 — compare trial decisions, then propose raises.
        EngineJob::AiTrialCompare => {
            let compared = attome_ai::trial::compare_due(&attome_state).await?;
            let proposals = attome_ai::autonomy::propose_raises(&attome_state).await?;
            if compared.compared + proposals.proposed + proposals.expired > 0 {
                tracing::info!(
                    compared = compared.compared,
                    proposed = proposals.proposed,
                    expired = proposals.expired,
                    "trial compare: run complete"
                );
            }
        }
        // AH8-T8 — the daily summary of what agents ran on their own.
        EngineJob::AiAutonomySummary => {
            let stats = attome_ai::autonomy::daily_summary(&attome_state).await?;
            tracing::info!(
                people = stats.people,
                actions = stats.actions,
                pruned = stats.pruned,
                "autonomy summary: run complete"
            );
        }
        // AH8 — actions whose undo window ended.
        EngineJob::AiDeferredActionSweep => {
            let stats = attome_ai::deferred::sweep(&attome_state).await?;
            if stats.executed + stats.ended + stats.retried + stats.interrupted > 0 {
                tracing::info!(
                    executed = stats.executed,
                    ended = stats.ended,
                    retried = stats.retried,
                    interrupted = stats.interrupted,
                    "deferred action sweep: run complete"
                );
            }
        }
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
        // A3-T5: a published rule's clean-up queue, from a full scan.
        EngineJob::ValidationCleanupScan { rule_id } => {
            attome_api::validation_simulation::run_cleanup_scan(&attome_state, rule_id).await?;
        }
        // M12-T2: one report schedule occurrence the Z7 ledger claimed.
        EngineJob::ReportScheduleFire { schedule_id } => {
            attome_report::scheduler::fire(&attome_state, schedule_id).await?;
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
            // G4-T2: the V7 queues' backlog alerts, first, so a service
            // sweep error does not stop them.
            let backlog = attome_project::queue::run_backlog_sweep(
                &db,
                &attome_state.base.config.notification,
            )
            .await?;
            if backlog > 0 {
                tracing::info!(alerts = backlog, "queue backlog sweep: run complete");
            }
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
            // G7-T1: the case steps of ticket merges (messages, notes,
            // documents and links to the survivor; the number as an alias).
            let merged = attome_service::case_merge::sweep_case_merges(&db).await?;
            // G3-T2: order items move on as their approvals and tasks do.
            let orders = attome_service::order::advance_orders(&db).await?;
            if orders > 0 {
                tracing::info!(orders, "ticket SLA sweep: order items moved on");
            }
            if reconciled > 0 || warned > 0 || breached > 0 || escalated > 0 || merged > 0 {
                tracing::info!(
                    reconciled,
                    warned,
                    breached,
                    escalated,
                    merged,
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
            // Y7-T3: partition DDL, so the migrator pool (D-117).
            maintain_change_feed_partitions(
                &db,
                &db_migrator.0,
                &config,
                chrono::Utc::now().date_naive(),
            )
            .await?;
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

/// Y7-T3: the outbox's daily partitions, after the row prune above. The
/// days ahead of `today` are created, days past `change_feed.retention_days`
/// that no consumer still needs are dropped (both DDL, on `ddl`, the
/// migrator pool), and the applied rows of events now gone are deleted.
pub async fn maintain_change_feed_partitions(
    db: &DbPool,
    ddl: &DbPool,
    config: &AppConfig,
    today: chrono::NaiveDate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use attome_core::change_feed::partitions;
    let retention_days = u32::try_from(config.change_feed.retention_days).unwrap_or(u32::MAX);
    let created = partitions::ensure_ahead(ddl, today).await?;
    let dropped = partitions::drop_expired(ddl, today, retention_days).await?;
    let applied = partitions::prune_applied(db).await?;
    if created > 0 || !dropped.is_empty() || applied > 0 {
        tracing::info!(
            created,
            dropped = dropped.len(),
            applied,
            "change feed partitions: run complete"
        );
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
        RewrapDomain::Registry => {
            let report = attome_auth::key_rewrap::rewrap_registry(db, |domain| {
                registry_ring(attome_state, domain)
            })
            .await?;
            let totals = report.totals();
            let skipped: Vec<String> = report
                .skipped
                .iter()
                .map(|c| format!("{}.{}", c.table, c.column))
                .collect();
            tracing::info!(
                columns = report.columns.len(),
                scanned = totals.scanned,
                rewrapped = totals.rewrapped,
                failed = totals.failed,
                skipped = ?skipped,
                "registry rewrap complete"
            );
            // Q18-T4: one security event per run, with its totals.
            attome_audit::security::SecurityAuditor::from_state(attome_state)
                .write(
                    attome_audit::security::SecurityEvent::new(
                        attome_audit::security::MandatoryCategory::Configuration,
                        attome_audit::AuditOperation::Update,
                        uuid::Uuid::nil(),
                        "key_rewrap",
                        None,
                    )
                    .named("rewrap:registry:complete")
                    .comment(format!(
                        "{} columns: {} scanned, {} rewrapped, {} failed; no ring for {}",
                        report.columns.len(),
                        totals.scanned,
                        totals.rewrapped,
                        totals.failed,
                        if skipped.is_empty() {
                            "none".to_owned()
                        } else {
                            skipped.join(", ")
                        }
                    )),
                )
                .await?;
            if totals.failed > 0 {
                return Err(std::io::Error::other(format!(
                    "registry rewrap: {} value(s) did not open with their ring",
                    totals.failed
                ))
                .into());
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

/// Q18-T4: the ring each encrypted-column registry domain is sealed with,
/// or `None` when this deployment configures none (its columns are skipped).
/// Q1-T3: `oidc` is the on-screen providers' client secrets.
fn registry_ring(state: &EngineState, domain: &str) -> Option<attome_config::KeyRing> {
    let secrets = state.base.secrets.load();
    let config = &state.base.config;
    let ring = match domain {
        "ai_provider" | "mcp" => secrets.ai_provider_credential_key.clone(),
        "einvoice" => config.einvoice.key_encryption_key.clone(),
        "environment_variable" => config.integration.credential_encryption_key.clone(),
        "integration" => secrets.integration_credential_key.clone(),
        "events_webhook" => secrets.webhook_signing_key.clone(),
        "fleet" => config.fleet.credential_encryption_key.clone(),
        "recovery_archive" | "release_report" => {
            config.metadata.recovery_archive_key_encryption_key.clone()
        }
        "s2s" => secrets.s2s_key_encryption_key.clone(),
        "oidc" => config.oidc.client_secret_encryption_key.clone(),
        "mfa" | "portal_mfa" => secrets.mfa_encryption_key.clone(),
        _ => return None,
    };
    (!ring.is_empty()).then_some(ring)
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
    // E23-T1 — `profile_event` (migrations/0167_profile_event.sql).
    ("profile_event", "at"),
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
const DEDUP_KEY_CONTRACT_LINK_SWEEP: &str = "contract-link-sweep";
const DEDUP_KEY_GEOCODE_SWEEP: &str = "geocode-sweep";
const DEDUP_KEY_BILLING_HANDOFF_SWEEP: &str = "billing-handoff-sweep";
const DEDUP_KEY_BILLING_RENEWAL_SWEEP: &str = "billing-renewal-sweep";
const DEDUP_KEY_BILLING_GENERATE_CHARGES: &str = "billing-generate-charges";
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
const DEDUP_KEY_PRIVILEGE_USAGE_DAILY: &str = "privilege-usage-daily";
const DEDUP_KEY_SALES_DEFAULT_TEAM_SWEEP: &str = "sales-default-team-sweep";
const DEDUP_KEY_QUALITY_INCREMENTAL_SWEEP: &str = "quality-incremental-sweep";
const DEDUP_KEY_REVREC_CONTRACT_SWEEP: &str = "revrec-contract-sweep";
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
const DEDUP_KEY_UPLOAD_RESCAN_SWEEP: &str = "upload-rescan-sweep";
const DEDUP_KEY_FILE_INTEGRITY_SAMPLE: &str = "file-integrity-sample";
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
const DEDUP_KEY_AI_DEFERRED_ACTION_SWEEP: &str = "ai-deferred-action-sweep";
const DEDUP_KEY_AI_AUTONOMY_SUMMARY: &str = "ai-autonomy-summary";
const DEDUP_KEY_AI_TRIAL_COMPARE: &str = "ai-trial-compare";
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
const DEDUP_KEY_VALIDATION_SCORE_SWEEP: &str = "validation-score-sweep";
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
/// D15-T3: the calendar sync (a registered job type).
const DEDUP_KEY_CALENDAR_SYNC: &str = "calendar-sync";
/// Z1-T11: integration OAuth tokens renewed before expiry.
const DEDUP_KEY_OAUTH_REFRESH: &str = "integration-oauth-refresh";
const DEDUP_KEY_DEAD_LETTER_SWEEP: &str = "dead-letter-sweep";
/// M9-T3: approval request steps mailed to their approvers.
const DEDUP_KEY_APPROVAL_EMAIL_LINKS: &str = "approval-email-links";
/// L6-T5: scheduled data profiles and snapshot retention.
const DEDUP_KEY_DATA_PROFILE_SCHEDULE: &str = "data-profile-schedule";
const DEDUP_KEY_NOTIFICATION_QUEUE: &str = "notification-queue-sweep";
/// D15-T2: the personal mail capture (a registered job type).
const DEDUP_KEY_MAIL_CAPTURE: &str = "mail-capture";
/// J2-T2: the shared mailbox routing (a registered job type).
const DEDUP_KEY_INBOUND_MAIL: &str = "inbound-mail";
/// G1-T3: case summaries for quiet threads (a registered job type).
const DEDUP_KEY_CASE_SUMMARY: &str = "case-summary";
/// E16-T1: SMS campaign sending (a registered job type).
const DEDUP_KEY_SMS_CAMPAIGN: &str = "sms-campaign";
/// E3-T1: the email campaign sweep (a registered job type).
const DEDUP_KEY_EMAIL_CAMPAIGN: &str = "email-campaign";
const DEDUP_KEY_WEBINAR_SYNC: &str = "webinar-sync";
const DEDUP_KEY_BLOCKLIST_CHECK: &str = "marketing-blocklist-check";
const DEDUP_KEY_REPUTATION_FETCH: &str = "marketing-reputation-fetch";
/// E6-T4: the daily deliverability rollup (a registered job type).
const DEDUP_KEY_DELIVERABILITY_ROLLUP: &str = "deliverability-rollup";
/// M8-T1: the transition actions sweep (a registered job type).
const DEDUP_KEY_TRANSITION_ACTIONS_SWEEP: &str = "state-transition-actions-sweep";
/// D17-T1: the sequence exits sweep (a registered job type).
const DEDUP_KEY_SEQUENCE_EXITS: &str = "workflow-sequence-exits";
/// M8-T3: the automatic transitions passes (registered job types).
const DEDUP_KEY_AUTO_TRANSITIONS: &str = "state-auto-transitions";
const DEDUP_KEY_AUTO_TRANSITIONS_DAILY: &str = "state-auto-transitions-daily";
/// F11-T9: the nightly loyalty revenue run (a registered job type).
const DEDUP_KEY_REVREC_LOYALTY: &str = "revrec-loyalty";
/// G17-T10: the nightly adherence roll-up (a registered job type).
const DEDUP_KEY_WFM_ADHERENCE_DAY: &str = "wfm-adherence-day";
/// E15-T1: the nightly attribution run (a registered job type).
const DEDUP_KEY_MARKETING_ATTRIBUTION: &str = "marketing-attribution";
/// E7-T6: the live segment tick (a registered job type).
const DEDUP_KEY_SEGMENT_LIVE: &str = "marketing-segment-live";
/// E8-T5: the journey entry tick and the date entry (registered job types).
const DEDUP_KEY_JOURNEY_ENTRY: &str = "marketing-journey-entry";
const DEDUP_KEY_JOURNEY_DATE_ENTRY: &str = "marketing-journey-date-entry";
/// I6-T2: work order stock reserved, issued and released (a registered job type).
const DEDUP_KEY_STOCK_LEDGER: &str = "stock-ledger";
/// I1-T2: completed work orders invoiced (a registered job type).
const DEDUP_KEY_WORK_ORDER_INVOICING: &str = "work-order-invoicing";
/// F10-T10: commission plan acceptance (a registered job type).
const DEDUP_KEY_COMMISSION_ACCEPTANCE: &str = "commission-acceptance";
/// G17-T9: intraday offers (a registered job type).
const DEDUP_KEY_INTRADAY: &str = "workforce-intraday";
/// G14-T2: surveys sent on record changes (a registered job type).
const DEDUP_KEY_SURVEY_SEND: &str = "survey-send";
/// AI6-T3: the meeting brief scan (a registered job type).
const DEDUP_KEY_MEETING_BRIEF_SCAN: &str = "ai-meeting-brief-scan";
/// AI5-T4: the promise reader (a registered job type).
const DEDUP_KEY_PROMISE_EXTRACT: &str = "ai-promise-extract";
/// AI8-T3: the nightly agent performance rollup (a registered job type).
const DEDUP_KEY_AGENT_STATS: &str = "ai-agent-stats-rollup";
/// A20-T2: the hourly label translation drafts (a registered job type).
const DEDUP_KEY_LABEL_DRAFTS: &str = "label-translation-drafts";
/// AK3-T5: the one-minute work-share consumer (a registered job type).
const DEDUP_KEY_WORK_SHARE: &str = "ai-work-share-consume";
/// AH5-T2: the five-minute agent departure check (a registered job type).
const DEDUP_KEY_AGENT_CHECK: &str = "ai-agent-behaviour-check";
/// AH5-T1: the hourly agent activity roll-up (a registered job type).
const DEDUP_KEY_AGENT_BEHAVIOUR: &str = "ai-agent-behaviour-rollup";
/// O10-T1: the daily decision measurement (a registered job type).
const DEDUP_KEY_DECISION_MEASURE: &str = "dashboard-decision-measure";
/// F5-T12: the nightly credit-hold sweep (a registered job type).
const DEDUP_KEY_CREDIT_HOLD: &str = "billing-credit-hold";
/// AK2-T1: the weekly operations digest (a registered job type).
const DEDUP_KEY_OPS_DIGEST: &str = "ai-ops-weekly-digest";
/// V5-T1: change requests decided by their customer sign-off (a registered job type).
const DEDUP_KEY_CHANGE_SIGNOFF: &str = "change-signoff";
/// W3-T4: sealed RFQ bids opened at the deadline (a registered job type).
const DEDUP_KEY_RFQ_OPEN: &str = "rfq-open";
/// W2-T1: vendor compliance document reminder timers (a registered job type).
const DEDUP_KEY_COMPLIANCE_EXPIRY: &str = "compliance-expiry";
/// I5-T2: maintenance plan timers and meter checks (a registered job type).
const DEDUP_KEY_MAINTENANCE: &str = "maintenance-generation";
/// I7-T1: device readings and device rules (a registered job type).
const DEDUP_KEY_DEVICE_READINGS: &str = "device-readings";
/// R9-T1: policy reviews, attestations and exceptions (a registered job type).
const DEDUP_KEY_GRC_POLICY_SWEEP: &str = "grc-policy-sweep";
/// Q22-T1: detection rules over security events (a registered job type).
const DEDUP_KEY_SECURITY_DETECTIONS: &str = "security-detections";
const DEDUP_KEY_CONTENT_SITEMAP: &str = "content-sitemap";
const DEDUP_KEY_FULFILMENT_SPLIT: &str = "fulfilment-split";
/// F6-T13: shipments billed on shipment or delivery (a registered job type).
const DEDUP_KEY_FULFILMENT_BILLING: &str = "fulfilment-billing";
/// D4-T1: new leads assigned by the rule set (a registered job type).
const DEDUP_KEY_LEAD_ASSIGNMENT: &str = "lead-assignment";
/// AA11-T1: entities the change feed saw change, marked for the aggregate
/// cache (a registered job type).
const DEDUP_KEY_AGGREGATE_CACHE_MARKS: &str = "aggregate-cache-marks";
const DEDUP_KEY_ROLLUP_FAST: &str = "rollup-fast";
const DEDUP_KEY_ROLLUP_HEAL: &str = "rollup-heal";
/// Q4-T2: the nightly directory sync (a registered job type).
const DEDUP_KEY_LDAP_SYNC: &str = "ldap-sync";
const DEDUP_KEY_LEAD_FIRST_TOUCH: &str = "lead-first-touch";
const DEDUP_KEY_LEAD_REBALANCE: &str = "lead-rebalance";
/// E14-T8: closed web sessions summarised onto timelines (a registered job type).
const DEDUP_KEY_WEB_VISIT_SUMMARY: &str = "web-visit-summary";
/// F6-T14: late and stuck fulfilment orders (a registered job type).
const DEDUP_KEY_FULFILMENT_EXCEPTIONS: &str = "fulfilment-exceptions";
/// F6-T10: the carrier tracking poll (a registered job type).
const DEDUP_KEY_FULFILMENT_TRACKING: &str = "fulfilment-tracking";
/// O1-T2: the weekly drift check of active prediction models.
const DEDUP_KEY_PREDICT_DRIFT: &str = "predict-drift";
const DEDUP_KEY_CONTENT_SEO_AUDIT: &str = "content-seo-audit";
/// AB2-T6: the Patroni cluster poll (a registered job type).
const DEDUP_KEY_OPS_CLUSTER_POLL: &str = "ops-cluster-poll";
/// AB4-T7: the daily overdue-drill check (a registered job type).
const DEDUP_KEY_OPS_DRILL_SKIP_CHECK: &str = "ops-drill-skip-check";
/// AB4-T9: the daily drill freshness notice (a registered job type).
const DEDUP_KEY_OPS_DRILL_FRESHNESS: &str = "ops-drill-freshness";
const DEDUP_KEY_S2S_CLIENT_EXPIRY: &str = "s2s-client-expiry";
/// AB3-T2: the one-minute live recovery point (a registered job type).
const DEDUP_KEY_OPS_LIVE_RPO: &str = "ops-live-rpo";
/// L4-T2: the catalog asset index rebuild (a registered job type).
const DEDUP_KEY_CATALOG_ASSET_REBUILD: &str = "catalog-asset-rebuild";
/// Z8-T4: the daily sending-domain check (a registered job type).
const DEDUP_KEY_EMAIL_DOMAIN_CHECK: &str = "email-domain-check";
/// Z12-T8: the daily calendar feed fetch (a registered job type).
const DEDUP_KEY_CALENDAR_FEED_FETCH: &str = "calendar-feed-fetch";
/// A23-T7: the recurring-import tick (a registered job type).
const DEDUP_KEY_IMPORT_SCHEDULE_TICK: &str = "import-schedule-tick";
/// P13-T1: the warehouse export (a registered job type).
const DEDUP_KEY_WAREHOUSE_EXPORT: &str = "warehouse-export";
/// E13-T10: the daily search-console pull (a registered job type).
const DEDUP_KEY_CONTENT_SEARCH_CONSOLE: &str = "content-search-console";
/// R11-T1: evidence collectors (a registered job type).
const DEDUP_KEY_GRC_EVIDENCE: &str = "grc-evidence-collect";
/// I10-T2: warranty expiry reminders (a registered job type).
const DEDUP_KEY_WARRANTY_REMINDER: &str = "warranty-expiry-reminder";
/// H8-T1: status page notices from the change feed (a registered job type).
const DEDUP_KEY_STATUS_NOTIFY: &str = "status-page-notify";
/// D23-T7: deal coverage gaps from the change feed (a registered job type).
const DEDUP_KEY_DEAL_COVERAGE: &str = "sales-deal-coverage";
/// J10-T1: the unified router's tick (a registered job type).
const DEDUP_KEY_SERVICE_ROUTER: &str = "service-router-tick";
const DEDUP_KEY_OPS_STATUS_WATCH: &str = "ops-status-watch";
/// Z12-T7: the yearly Hijri holiday review check (a registered job type).
const DEDUP_KEY_CALENDAR_REVIEW: &str = "calendar-yearly-review";
/// E23-T1: profile event retention (a registered job type).
const DEDUP_KEY_PROFILE_EVENT_RETENTION: &str = "profile-event-retention";
/// J8-T1: the Google reviews read (a registered job type).
const DEDUP_KEY_SOCIAL_REVIEWS_SYNC: &str = "social-reviews-sync";
const DEDUP_KEY_SOCIAL_MENTIONS_SYNC: &str = "social-mentions-sync";
const DEDUP_KEY_SOCIAL_PUBLISH: &str = "social-publish";
/// AA10-T5: mass-operation undo values past retention (a registered job type).
const DEDUP_KEY_HEAVY_OP_UNDO_RETENTION: &str = "heavy-op-undo-retention";
const DEDUP_KEY_TIME_FORMULA_RECOMPUTE: &str = "time-formula-recompute";

/// Z1-T8: reminds administrators of secrets older than
/// `security.secret_max_age_days`. A registered type (Z7-T1), not an
/// `EngineJob` variant.
pub const SECRET_AGE_REMINDER: attome_jobs::JobType =
    attome_jobs::JobType::new("secret_age_reminder", 1);

/// D15-T3: two-way sync of meetings with people's own calendars. A
/// registered type, like the reminder above.
pub const CALENDAR_SYNC: attome_jobs::JobType = attome_jobs::JobType::new("calendar_sync", 1);

/// Z1-T11: every OAuth token of an integration system with under ten
/// minutes left is renewed (fast lane; no payload).
pub const OAUTH_REFRESH: attome_jobs::JobType =
    attome_jobs::JobType::new("integration_oauth_refresh", 1);

/// J6-T3: a call's recording to a document on the call, then to
/// transcription (payload `{"call_id"}`).
pub const VOICE_RECORDING: attome_jobs::JobType = attome_jobs::JobType::new("voice_recording", 1);

/// Q14-T5: a bulk reassign or bulk share, run as a batch in chunks of 500
/// (payload `attome_security::admin::BulkAccessPayload`).
pub const SECURITY_BULK_ACCESS: attome_jobs::JobType = attome_jobs::JobType {
    lane: attome_jobs::Lane::Batch,
    ..attome_jobs::JobType::new(attome_security::admin::BULK_ACCESS_JOB, 1)
};

/// A5-T2: an option set value merged into another, rewritten on every record
/// that holds it, as the person who asked (payload
/// `attome_api::model_admin::option_merge::MergePayload`).
pub const OPTION_SET_MERGE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::model_admin::option_merge::MERGE_JOB, 1);

/// M15-T2: every five minutes, held notifications that are due (quiet hours
/// over, digest slot reached) are sent (no payload).
pub const NOTIFICATION_QUEUE_SWEEP: attome_jobs::JobType =
    attome_jobs::JobType::new("notification_queue_sweep", 1);

/// M12-T1: a schedule slot's flow runs over a view's records, as a batch
/// (payload `attome_workflow::schedule_trigger::RecordSchedulePayload`).
pub const WORKFLOW_RECORD_SCHEDULE: attome_jobs::JobType = attome_jobs::JobType {
    lane: attome_jobs::Lane::Batch,
    ..attome_jobs::JobType::new(attome_workflow::schedule_trigger::RECORD_SCHEDULE_JOB, 1)
};

/// L6-T5: every five minutes, scheduled data profiles started and old
/// snapshots pruned (no payload).
pub const DATA_PROFILE_SCHEDULE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::data_profile_admin::drift::SCHEDULE_JOB, 1);

/// M14-T3: one inbound hook event processed, in its key's order (payload
/// `attome_api::inbound_hooks::ProcessEvent`). Five attempts, as the inbox
/// row counts them, then the dead-letter inbox.
pub const INBOUND_HOOK_PROCESS: attome_jobs::JobType = attome_jobs::JobType {
    max_attempts: attome_api::inbound_hooks::MAX_ATTEMPTS,
    ..attome_jobs::JobType::new(attome_api::inbound_hooks::PROCESS_JOB, 1)
};

/// M9-T3: every minute, each pending request step's approvers mailed a
/// one-time link (no payload).
pub const APPROVAL_EMAIL_LINKS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::approval_email::SWEEP_JOB, 1);

/// M5-T4: hourly, dead-letter retention and the new / growing group
/// counters the built-in alerts watch (no payload).
pub const DEAD_LETTER_SWEEP: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::dead_letter_inbox::SWEEP_JOB, 1);

/// M5-T2: a dead-letter group replayed at a set pace, as the person who
/// started it (payload `attome_api::dead_letter_inbox::GroupReplayPayload`).
/// One attempt: a replay that fails part-way leaves the rest in the dead
/// letters, and a retried job would replay items a second time.
pub const DEAD_LETTER_GROUP_REPLAY: attome_jobs::JobType = attome_jobs::JobType {
    lane: attome_jobs::Lane::Batch,
    max_attempts: 1,
    ..attome_jobs::JobType::new(attome_api::dead_letter_inbox::GROUP_REPLAY_JOB, 1)
};

/// D13-T3: territory realignment, run as the person who asked (payload
/// `{"user_id"}`).
pub const TERRITORY_REALIGN: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_sales::territory::REALIGN_JOB, 1);

/// D15-T2: emails in people's own mailboxes captured onto matching records.
pub const MAIL_CAPTURE: attome_jobs::JobType = attome_jobs::JobType::new("mail_capture", 1);

/// J2-T2: shared mailboxes routed into cases, leads and contacts.
pub const INBOUND_MAIL: attome_jobs::JobType = attome_jobs::JobType::new("inbound_mail", 1);

/// G1-T3: a case's summary made for its assignee once its thread is quiet.
pub const CASE_SUMMARY: attome_jobs::JobType = attome_jobs::JobType::new("case_summary", 1);

/// E16-T1: SMS campaigns sent in batches outside each recipient's quiet hours.
pub const SMS_CAMPAIGN: attome_jobs::JobType = attome_jobs::JobType::new("sms_campaign", 1);
/// E3-T1: the next batch of each email campaign.
pub const EMAIL_CAMPAIGN: attome_jobs::JobType = attome_jobs::JobType::new("email_campaign", 1);

/// E6-T4: today's and yesterday's deliverability rollup, recomputed.
pub const DELIVERABILITY_ROLLUP: attome_jobs::JobType =
    attome_jobs::JobType::new("deliverability_rollup", 1);

/// M8-T1: one change's transition actions (payload
/// `attome_state::transition_actions::TransitionActions`). Only enqueued.
pub const STATE_TRANSITION_ACTIONS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_state::transition_actions::JOB, 1);

/// M8-T1: reads committed transitions from the change feed and queues their
/// actions, every minute.
pub const STATE_TRANSITION_ACTIONS_SWEEP: attome_jobs::JobType =
    attome_jobs::JobType::new("state_transition_actions_sweep", 1);

/// D17-T1: exits contacts who answered a sequence, every minute.
pub const WORKFLOW_SEQUENCE_EXITS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workflow::sequence::SWEEP_JOB, 1);

/// M8-T3: automatic transitions of the records written since the last
/// pass, every minute.
pub const STATE_AUTO_TRANSITIONS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_state::auto_transitions::SWEEP_JOB, 1);

/// M8-T3: automatic transitions whose conditions became true with time,
/// daily.
pub const STATE_AUTO_TRANSITIONS_DAILY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_state::auto_transitions::DAILY_JOB, 1);

/// F11-T9: loyalty points deferred and recognised, nightly.
pub const REVREC_LOYALTY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ledger::revrec::loyalty::JOB, 1);

/// G17-T10: yesterday's adherence and conformance per person, nightly.
pub const WFM_ADHERENCE_DAY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workforce::adherence::DAY_JOB, 1);

/// E15-T1: attribution credit for won opportunities, nightly.
pub const MARKETING_ATTRIBUTION: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::attribution_store::JOB, 1);

/// E7-T6: live segments re-checked for the people a change-feed batch touched.
pub const SEGMENT_LIVE: attome_jobs::JobType =
    attome_jobs::JobType::new("marketing_segment_live", 1);

/// E23-T1: drops profile event months past retention.
pub const PROFILE_EVENT_RETENTION: attome_jobs::JobType =
    attome_jobs::JobType::new("profile_event_retention", 1);

/// E7-T5: one static list import (payload `{"import_id"}`).
pub const MARKETING_LIST_IMPORT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::static_list::IMPORT_JOB, 1);

/// E1-T3: a marketing list's people added to a campaign (payload
/// `{"campaign", "list", "purpose", "user"}`). Only enqueued.
pub const CAMPAIGN_MEMBERS_FROM_LIST: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::campaign::MEMBERS_JOB, 1);

/// E14-T5: writes a queued collection batch into `marketing_web_event` and
/// upserts `marketing_web_session`; filters bots, staff and office networks
/// first. Only enqueued (by the collect route), never scheduled.
pub const MARKETING_WEB_EVENT_BATCH: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::tracking::writer::JOB, 1);

/// E8-T4: one chunk (at most 1,000 people) of a journey entry. Only
/// enqueued (`attome_marketing::journey::enrol::queue_enrol`), never
/// scheduled.
pub const MARKETING_JOURNEY_ENROL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::journey::enrol::JOB, 1);

/// E8-T5: journey entries from list joins, events and due list_at sources,
/// read from the change feed.
pub const MARKETING_JOURNEY_ENTRY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::journey::entry::TICK_JOB, 1);

/// I6-T2: part lines reserved for scheduled work, issued on completion and
/// released on cancellation.
pub const STOCK_LEDGER: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::inventory::JOB, 1);

/// I1-T2: completed work orders split into covered and billable lines, and
/// the billable ones sent to billing as an invoice request.
pub const WORK_ORDER_INVOICING: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::work_order::JOB, 1);

/// F10-T10: plan documents sent for signature once rendered, and signed
/// envelopes recorded as accepted.
pub const COMMISSION_ACCEPTANCE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_commission::acceptance::JOB, 1);

/// I10-T1: asset warranty dates filled from warranty entitlements, as the
/// person who confirmed (payload `attome_service::warranty::BackfillJob`).
pub const WARRANTY_BACKFILL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::warranty::JOB, 1);

/// G17-T9: intraday groups compared with their actuals, short and over runs
/// proposed as overtime and time-off offers.
pub const WORKFORCE_INTRADAY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workforce::intraday::JOB, 1);

/// G14-T2: published surveys sent, from the change feed, when a record
/// reaches their trigger value (a closed case).
/// AI7-T4: a ticket handed back to the agent that handed it off.
pub const AI_HANDBACK: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::handoff::HANDBACK_JOB, 1);

/// N18-T1: a channel's bot answers one WhatsApp or SMS message.
pub const BOT_REPLY: attome_jobs::JobType =
    attome_jobs::JobType::new(crate::bot_channels::BOT_REPLY_JOB, 1);

/// AI8-T3: yesterday's per-agent rollup, and a backfill of a range.
pub const AGENT_STATS_ROLLUP: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::agent_stats::NIGHTLY_JOB, 1);
pub const AGENT_STATS_BACKFILL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::agent_stats::BACKFILL_JOB, 1);

/// A20-T2: missing label translations drafted for review.
pub const LABEL_DRAFTS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::label_drafts::DRAFT_JOB, 1);

/// AK3-T5: the change feed counted into the work share.
pub const WORK_SHARE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::work_share::CONSUME_JOB, 1);

/// AK3-T5: one date range of the work share recounted.
pub const WORK_SHARE_REBUILD: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::work_share::REBUILD_JOB, 1);

/// AH5-T2: each agent's current hour compared with its baseline.
pub const AGENT_CHECK: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::behaviour::CHECK_JOB, 1);

/// AH5-T1: each agent's hourly activity, and its baseline nightly.
pub const AGENT_BEHAVIOUR: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::behaviour::ROLLUP_JOB, 1);

/// AH1-T4: an undo of what an agent session wrote, applied item by item.
pub const AI_UNDO: attome_jobs::JobType = attome_jobs::JobType::new(attome_ai::undo::UNDO_JOB, 1);

/// O10-T1: executed decisions measured once their measure date passes.
pub const DECISION_MEASURE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_dashboard::decision_outcome::MEASURE_JOB, 1);

/// F5-T12: accounts with long-overdue invoices put on credit hold.
pub const CREDIT_HOLD: attome_jobs::JobType = attome_jobs::JobType::new("billing_credit_hold", 1);

/// AK2-T1: the weekly operations digest to administrators.
pub const OPS_DIGEST: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::ops_agent::WEEKLY_JOB, 1);

/// AI5-T4: promises to pay read from customers' replies.
pub const PROMISE_EXTRACT: attome_jobs::JobType =
    attome_jobs::JobType::new("ai_promise_extract", 1);

/// AI6-T3: meetings an hour away queued for a brief.
pub const MEETING_BRIEF_SCAN: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::meeting::run::SCAN_JOB, 1);

/// AI6-T3: one meeting's brief, made as its owner.
pub const MEETING_BRIEF: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::meeting::run::BRIEF_JOB, 1);

/// AI6-T6: one transcript's meeting notes, made as the person who asked.
pub const MEETING_NOTES: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ai::meeting::run::NOTES_JOB, 1);

pub const SURVEY_SEND: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::survey_send::JOB, 1);

/// G17-T6: a draft schedule built for a planning group and period (payload
/// `attome_workforce::build_job::BuildJob`). Only enqueued, never scheduled.
pub const WORKFORCE_BUILD: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workforce::build_job::JOB, 1);

/// V5-T1: change requests whose sign-off envelope finished are approved
/// (and rebaselined) or rejected.
pub const CHANGE_SIGNOFF: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_project::change_signoff::JOB, 1);

/// W3-T4: requests for quotation past their deadline have their sealed bids
/// opened and are closed.
pub const RFQ_OPEN: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_procurement::rfq::JOB, 1);

/// W2-T1: a reminder timer set for every vendor compliance document that
/// has not been reminded for its expiry date.
pub const COMPLIANCE_EXPIRY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_procurement::compliance::JOB, 1);

/// I5-T2: one maintenance timer kept per date plan, and work orders made for
/// meter plans whose reading passed the threshold.
pub const MAINTENANCE_GENERATION: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::maintenance::JOB, 1);

/// I7-T1: new device readings counted into latest values and hourly
/// summaries, and the device rules they meet fired.
pub const DEVICE_READINGS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::iot::JOB, 1);

/// R9-T1: policy review reminders, attestation requests, closed campaigns
/// and expired exceptions.
pub const GRC_POLICY_SWEEP: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_grc::policy::JOB, 1);

/// Q22-T1: spray, impossible travel, mass export, privilege escalation and
/// new-device detections, each a security case.
pub const SECURITY_DETECTIONS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_audit::detections::JOB, 1);

/// F6-T3: confirmed orders split into fulfilment orders.
pub const FULFILMENT_SPLIT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_fulfilment::split::JOB, 1);

/// F6-T13: shipped and delivered shipments asked for billing.
pub const FULFILMENT_BILLING: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_fulfilment::billing_trigger::JOB, 1);

/// D4-T1: new leads given an owner by the lead assignment rule set.
pub const LEAD_ASSIGNMENT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workflow::lead_assignment::JOB, 1);

/// AA11-T1: changed entities marked so their cached aggregates are recomputed.
pub const AGGREGATE_CACHE_MARKS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_search::aggregate_cache::JOB, 1);

/// A10-T2: fast rollups recomputed from the change feed.
pub const ROLLUP_FAST: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_records::rollup_fast::JOB, 1);

/// A10-T4: a rollup filled for its parents, a batch per run.
pub const ROLLUP_BACKFILL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_records::rollup_heal::BACKFILL_JOB, 1);

/// P9-T10: a metric's past periods, twelve per run.
pub const METRIC_BACKFILL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_metric::backfill::BACKFILL_JOB, 1);

/// Q4-T2: users and their groups' roles synced from the directory, nightly.
pub const LDAP_SYNC: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_security::ldap_sync::LDAP_SYNC_JOB, 1);

/// A10-T4: rollups verified and healed nightly.
pub const ROLLUP_HEAL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_records::rollup_heal::HEAL_JOB, 1);

/// D4-T2: new leads given their first-touch timer.
pub const LEAD_FIRST_TOUCH: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workflow::speed_to_lead::SCHEDULE_JOB, 1);

/// D4-T2: stale leads given to someone else by their assignment rule.
pub const LEAD_REBALANCE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_workflow::speed_to_lead::REBALANCE_JOB, 1);

/// E14-T8: one visit summary per closed, identified web session.
pub const WEB_VISIT_SUMMARY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::tracking::summary::JOB, 1);

/// O1-T2: active prediction models checked for feature drift.
pub const PREDICT_DRIFT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_predict::train::DRIFT_JOB, 1);

/// F6-T14: late and stuck fulfilment orders raised as exceptions.
pub const FULFILMENT_EXCEPTIONS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_fulfilment::exceptions::JOB, 1);

/// F6-T10: booked shipments' status read from their carriers.
pub const FULFILMENT_TRACKING: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_fulfilment::tracking::JOB, 1);

/// E13-T9: the stored sitemaps of sites whose pages changed, rebuilt.
pub const CONTENT_SITEMAP: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_content::seo::sitemap::JOB, 1);

/// E13-T9: every published page re-audited when `content.seo_audit` is on.
pub const CONTENT_SEO_AUDIT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_content::seo::audit::NIGHTLY_JOB, 1);

/// AB2-T6: the database leader read from Patroni, every 15 seconds.
pub const OPS_CLUSTER_POLL: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ops::cluster::JOB, 1);

/// AB4-T7: enabled drill schedules more than two days overdue, daily.
pub const OPS_DRILL_SKIP_CHECK: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ops::drill_schedules::SKIP_CHECK_JOB, 1);

/// AB4-T9: stale or failed drill kinds told to `ops.read` holders, daily.
pub const OPS_DRILL_FRESHNESS: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ops::freshness::JOB, 1);

/// S11-T4: S2S clients expiring in 14 days told to their owners, and
/// expired ones suspended, daily.
pub const S2S_CLIENT_EXPIRY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_s2s::service_account::JOB, 1);

/// AB3-T2: the live recovery point, every minute.
pub const OPS_LIVE_RPO: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ops::live_rpo::JOB, 1);

/// L4-T2: the catalog asset index, every 15 minutes (first at boot).
pub const CATALOG_ASSET_REBUILD: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::catalog_index::JOB, 1);

/// Z8-T4: every configured sending domain's DNS records, daily.
pub const EMAIL_DOMAIN_CHECK: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::email_domains::JOB, 1);

/// Z12-T8: holidays read from calendar iCal feeds, daily.
pub const CALENDAR_FEED_FETCH: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::calendar_feed::JOB, 1);

/// E13-T10: yesterday's search statistics from connected engines, daily.
pub const CONTENT_SEARCH_CONSOLE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_content::seo::console::PULL_JOB, 1);

/// E13-T10: an IndexNow submission after a publish.
pub const CONTENT_INDEXNOW: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_content::seo::console::PING_JOB, 1);

/// A23-T7: a file import's phases, each queued by the one before it.
pub const IMPORT_STAGE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_document::import_jobs::STAGE_JOB, 1);
pub const IMPORT_VALIDATE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_document::import_jobs::VALIDATE_JOB, 1);
pub const IMPORT_APPLY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_document::import_jobs::APPLY_JOB, 1);
pub const IMPORT_UNDO: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_document::import_jobs::UNDO_JOB, 1);

/// AB11-T4: the status watch, every minute.
pub const OPS_STATUS_WATCH: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_ops::status_watch::TICK_JOB, 1);

/// Z12-T7: the check for December's Hijri holiday review reminder.
pub const CALENDAR_YEARLY_REVIEW: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::calendar_packs::REVIEW_JOB, 1);

/// J10-T1: the unified router: expire offers, overflow, offer waiting work.
pub const SERVICE_ROUTER_TICK: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::router::TICK_JOB, 1);

/// A24-T4: one migration wave (metadata, then a queued import per page).
pub const MIGRATION_WAVE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_api::migration_run::WAVE_JOB, 1);

/// P13-T1: the warehouse export, every five minutes when entities are named.
pub const WAREHOUSE_EXPORT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_integration::warehouse_export::JOB, 1);

/// A23-T7: recurring imports that are due, every minute.
pub const IMPORT_SCHEDULE_TICK: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_document::import_jobs::SCHEDULE_JOB, 1);

/// R11-T1: evidence collectors writing evidence and, on failure, findings.
pub const GRC_EVIDENCE_COLLECT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_grc::collectors::JOB, 1);

/// I10-T2: warranty owners told 30 days before a warranty ends, once per
/// end date.
pub const WARRANTY_REMINDER: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::warranty::REMINDER_JOB, 1);

/// H8-T1: status page updates emailed to confirmed subscribers, once each.
pub const STATUS_PAGE_NOTIFY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_service::status_page::JOB, 1);

/// W1-T7: one contract comparison, computed as its requester (payload
/// `attome_contract::compare::CompareJob`). Only enqueued.
pub const CONTRACT_COMPARE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_contract::compare::JOB, 1);

/// D23-T10: one account's org chart drafts, written as the requester
/// (payload `attome_sales::orgchart::drafts::DraftJob`). Only enqueued.
pub const SALES_ORGCHART_DRAFT: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_sales::orgchart::drafts::JOB, 1);

/// D23-T7: deal coverage gaps recomputed for the deals a change-feed batch
/// touched.
pub const SALES_DEAL_COVERAGE: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_sales::orgchart::committee::JOB, 1);

/// E8-T5: journey entries from date sources, once a deployment day.
pub const MARKETING_JOURNEY_DATE_ENTRY: attome_jobs::JobType =
    attome_jobs::JobType::new(attome_marketing::journey::entry::DATE_JOB, 1);

/// E6-T8: the daily blocklist check of sending domains and IPs.
pub const BLOCKLIST_CHECK: attome_jobs::JobType =
    attome_jobs::JobType::new("marketing_blocklist_check", 1);

/// E6-T8: the daily Postmaster Tools and SNDS reputation fetch.
pub const REPUTATION_FETCH: attome_jobs::JobType =
    attome_jobs::JobType::new("marketing_reputation_fetch", 1);

/// E22-T1: webinar registrants pushed and attendance read.
pub const WEBINAR_SYNC: attome_jobs::JobType = attome_jobs::JobType::new("webinar_sync", 1);

/// E17-T1: due social posts published and their metrics read.
pub const SOCIAL_PUBLISH: attome_jobs::JobType = attome_jobs::JobType::new("social_publish", 1);

/// E18-T1: new Brandwatch mentions for the configured queries.
pub const SOCIAL_MENTIONS_SYNC: attome_jobs::JobType =
    attome_jobs::JobType::new("social_mentions_sync", 1);

/// J8-T1: new Google reviews become inbound communications.
pub const SOCIAL_REVIEWS_SYNC: attome_jobs::JobType =
    attome_jobs::JobType::new("social_reviews_sync", 1);

/// A9-T3: daily, stored formulas over `today()` or `now()` recomputed.
pub const TIME_FORMULA_RECOMPUTE: attome_jobs::JobType = attome_jobs::JobType {
    lane: attome_jobs::Lane::Batch,
    ..attome_jobs::JobType::new("time_formula_recompute", 1)
};

/// AA10-T5: daily, the values mass operations replaced are cleared once
/// past `limits.heavy_op.undo_retention_days`.
pub const HEAVY_OP_UNDO_RETENTION: attome_jobs::JobType =
    attome_jobs::JobType::new("heavy_op_undo_retention", 1);

/// Z7-T1/Z1-T8: registers this binary's run-time job types, once per
/// process. The worker calls it before it runs jobs and each scheduler that
/// builds one calls it first, so a node that only schedules or only works
/// knows the types it needs.
pub fn register_job_types() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // T5-T1: a sandbox copy asked for through the API.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            attome_api::sandboxes::SANDBOX_COPY,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_api::sandboxes::SandboxCopyPayload = job.payload()?;
                let Some(request) = attome_api::sandboxes::start(&state, payload.request_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?
                else {
                    return Ok(());
                };
                let args = crate::scratch::ScratchArgs {
                    name: request.database_name.clone(),
                    from: None,
                    mode: crate::scratch::ScratchMode::parse(&request.mode)
                        .unwrap_or(crate::scratch::ScratchMode::Full),
                    percent: request
                        .sample_percent
                        .and_then(|p| u8::try_from(p).ok())
                        .unwrap_or(crate::scratch::DEFAULT_SAMPLE_PERCENT),
                };
                let (done, detail) = match crate::scratch::create(&state.base.config, &args).await {
                    Ok(report) => (
                        true,
                        format!(
                            "{} labelled field(s) masked, {} left as is, {} entities sampled",
                            report.masked.len(),
                            report.unmasked_required.len(),
                            report.sampled.len()
                        ),
                    ),
                    Err(error) => (false, error),
                };
                tracing::info!(request = %payload.request_id, done, "sandbox copy finished");
                attome_api::sandboxes::finish(&state, payload.request_id, done, &detail)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // AD6-T2: a published version's documentation.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            attome_ai::builder::docs::PUBLISH_DOCS,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_ai::builder::docs::PublishDocsPayload = job.payload()?;
                attome_ai::builder::docs::generate(&state, payload.version)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(version = payload.version, "metadata version documented");
                Ok(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // Q8-T5: a large role's holders' sessions, ended in batches.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            attome_security::admin::REVOKE_ROLE_SESSIONS,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_security::admin::RevokeRoleSessionsPayload = job.payload()?;
                let ended = attome_security::admin::revoke_role_sessions_job(
                    &state,
                    payload.role_id,
                    payload.cutoff,
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(role_id = %payload.role_id, ended, "role sessions ended");
                Ok(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            HEAVY_OP_UNDO_RETENTION,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let cleared = attome_records::mass::purge_undo_values(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if cleared > 0 {
                    tracing::info!(cleared, "mass operations: undo values past retention cleared");
                }
                Ok(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            TIME_FORMULA_RECOMPUTE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let changed = attome_records::entity_mutation::recompute_time_based_formulas(
                    &state,
                    chrono::Utc::now(),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if changed > 0 {
                    tracing::info!(changed, "time-based formulas recomputed");
                }
                Ok(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
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
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            NOTIFICATION_QUEUE_SWEEP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let counts = attome_notification::notify::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if counts.quiet_sent + counts.digests_sent > 0 {
                    tracing::info!(?counts, "notification queue: sent held notifications");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORKFLOW_RECORD_SCHEDULE,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_workflow::schedule_trigger::RecordSchedulePayload =
                    job.payload()?;
                attome_workflow::schedule_trigger::run_record_batch(&state, payload).await
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            DATA_PROFILE_SCHEDULE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let summary = attome_api::data_profile_admin::drift::schedule_sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if summary.started > 0 || summary.pruned > 0 {
                    tracing::info!(
                        started = summary.started,
                        pruned = summary.pruned,
                        "data profile schedule: done"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            INBOUND_HOOK_PROCESS,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_api::inbound_hooks::ProcessEvent = job.payload()?;
                attome_api::inbound_hooks::process_event(&state, payload.event_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            APPROVAL_EMAIL_LINKS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let summary = attome_api::approval_email::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if summary.steps > 0 {
                    tracing::info!(
                        steps = summary.steps,
                        links = summary.links,
                        "approval email links: mailed"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            DEAD_LETTER_SWEEP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let days = state.base.config.jobs.dead_letter_retention_days;
                let summary = attome_api::dead_letter_inbox::sweep(&state, days)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(
                    new_groups = summary.new_groups.len(),
                    growing_groups = summary.growing_groups.len(),
                    archived = summary.archived,
                    "dead-letter sweep: done"
                );
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            DEAD_LETTER_GROUP_REPLAY,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_api::dead_letter_inbox::GroupReplayPayload = job.payload()?;
                attome_api::dead_letter_inbox::run_group_replay(&state, payload).await
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            TERRITORY_REALIGN,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                #[derive(serde::Deserialize)]
                struct Payload {
                    user_id: uuid::Uuid,
                }
                let payload: Payload = job.payload()?;
                attome_sales::territory::apply(&state, payload.user_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SECURITY_BULK_ACCESS,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_security::admin::BulkAccessPayload = job.payload()?;
                attome_security::admin::run_bulk_access(&state, payload).await
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPTION_SET_MERGE,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_api::model_admin::option_merge::MergePayload = job.payload()?;
                attome_api::model_admin::option_merge::apply(&state, &payload)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MAIL_CAPTURE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let summary = crate::mail_capture::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(?summary, "mail capture: run complete");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            INBOUND_MAIL,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let summary = crate::inbound_mail::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(?summary, "inbound mail: run complete");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CASE_SUMMARY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let made = attome_ai::case_summary::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if made > 0 {
                    tracing::info!(made, "case summary: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            EMAIL_CAMPAIGN,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let queued = attome_marketing::email_campaign::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if queued > 0 {
                    tracing::info!(queued, "email campaign: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SMS_CAMPAIGN,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let sent = attome_marketing::sms_campaign::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if sent > 0 {
                    tracing::info!(sent, "sms campaign: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MARKETING_LIST_IMPORT,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                #[derive(serde::Deserialize)]
                struct Payload {
                    import_id: uuid::Uuid,
                }
                let payload: Payload = job.payload()?;
                attome_marketing::static_list::run_import(&state, payload.import_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CAMPAIGN_MEMBERS_FROM_LIST,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: serde_json::Value = job.payload()?;
                attome_marketing::campaign::run_from_list(&state, payload)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            BLOCKLIST_CHECK,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let run = attome_marketing::blocklist::run(
                    &state,
                    &attome_marketing::blocklist::SystemResolver,
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if run.checks > 0 {
                    tracing::info!(
                        checks = run.checks,
                        listed = run.listed,
                        newly_listed = run.newly_listed,
                        "blocklist check: run complete"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            REPUTATION_FETCH,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let written = attome_marketing::reputation::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if written > 0 {
                    tracing::info!(written, "reputation fetch: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WEBINAR_SYNC,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let pushed = attome_marketing::webinar_sync::push_due(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                let read = attome_marketing::webinar_sync::pull_due(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if pushed + read > 0 {
                    tracing::info!(pushed, read, "webinar sync: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MARKETING_JOURNEY_ENROL,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let chunk: attome_marketing::journey::enrol::EnrolJob = job.payload()?;
                let outcome = attome_marketing::journey::enrol(
                    &state,
                    chunk.journey_id,
                    chunk.people,
                    &chunk.source,
                    chunk.is_test,
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(
                    journey = %chunk.journey_id,
                    enrolled = outcome.enrolled,
                    skipped_active = outcome.skipped_active,
                    skipped_re_entry = outcome.skipped_re_entry,
                    skipped_cap = outcome.skipped_cap,
                    "journey enrolment chunk done"
                );
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MARKETING_WEB_EVENT_BATCH,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let batch: attome_marketing::tracking::writer::WebEventBatch = job.payload()?;
                let counts =
                    attome_marketing::tracking::writer::write_batch(&state.base.db, &batch)
                        .await
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(
                    site = %batch.site_key,
                    written = counts.written,
                    duplicates = counts.duplicates,
                    dropped_bot = counts.dropped_bot,
                    dropped_staff = counts.dropped_staff,
                    dropped_office = counts.dropped_office,
                    dropped_invalid = counts.dropped_invalid,
                    "web event batch written"
                );
                // E14-T9: a known visitor's watched-page views start flows.
                if counts.written > 0
                    && let Some(session) = batch
                        .batch
                        .get("session")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| uuid::Uuid::parse_str(s.trim()).ok())
                {
                    let alerted = attome_marketing::tracking::alerts::after_batch(
                        &state,
                        batch.site_key.trim(),
                        session,
                    )
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                    if alerted > 0 {
                        tracing::info!(site = %batch.site_key, alerted, "watched pages viewed");
                    }
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            STOCK_LEDGER,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let changed = attome_service::inventory::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if changed > 0 {
                    tracing::info!(changed, "work order stock moved");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORK_ORDER_INVOICING,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let handled = attome_service::work_order::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if handled > 0 {
                    tracing::info!(handled, "work orders sent for invoicing");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            COMMISSION_ACCEPTANCE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_COMMISSION) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let changed = attome_commission::acceptance::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if changed > 0 {
                    tracing::info!(changed, "commission plan acceptance moved on");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WARRANTY_BACKFILL,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let payload: attome_service::warranty::BackfillJob = job.payload()?;
                let ctx = state
                    .base
                    .security
                    .resolve_strict(payload.user_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                let written = attome_service::warranty::run(&state, &ctx)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(written, "asset warranty dates filled");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORKFORCE_INTRADAY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_WORKFORCE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let proposed = attome_workforce::intraday::tick(
                    &state,
                    &attome_workforce::intraday::TicketActuals,
                    chrono::Utc::now(),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if proposed > 0 {
                    tracing::info!(proposed, "intraday offers proposed");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AI_HANDBACK,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let handback: attome_service::handoff::HandBack = job.payload()?;
                let outcome = attome_ai::handback::run(&state, &handback)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(handoff = %handback.handoff_id, ?outcome, "hand-back run");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            BOT_REPLY,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let modules = state.modules.load();
                if !modules.has(attome_modules::MODULE_AI)
                    || !modules.has(attome_modules::MODULE_OMNICHANNEL)
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                drop(modules);
                let message: crate::bot_channels::BotMessage = job.payload()?;
                crate::bot_channels::run(&state, &message)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AGENT_STATS_ROLLUP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                if let Some(written) =
                    attome_ai::agent_stats::nightly(&state, chrono::Utc::now())
                        .await
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?
                {
                    tracing::info!(written, "agent performance: yesterday rolled up");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            LABEL_DRAFTS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                attome_api::label_drafts::draft_missing(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORK_SHARE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_ai::work_share::consume(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORK_SHARE_REBUILD,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let range: attome_ai::work_share::RebuildRange = job.payload()?;
                attome_ai::work_share::rebuild(&state, range)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AGENT_CHECK,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_ai::behaviour::run_check(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AGENT_BEHAVIOUR,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_ai::behaviour::run(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AI_UNDO,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let run: attome_ai::undo::UndoRunJob = job.payload()?;
                attome_ai::undo::run_undo(&state, run.undo_run_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            DECISION_MEASURE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_DASHBOARD) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_dashboard::decision_outcome::measure_due(
                    &state,
                    chrono::Utc::now().date_naive(),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CREDIT_HOLD,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_BILLING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_billing::payment::credit::hold_overdue(
                    &state,
                    chrono::Utc::now().date_naive(),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPS_DIGEST,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if let Some(proposals) = attome_ai::ops_agent::weekly(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?
                {
                    tracing::info!(proposals, "operations digest: sent");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AGENT_STATS_BACKFILL,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let range: attome_ai::agent_stats::AgentStatsBackfill = job.payload()?;
                let written = attome_ai::agent_stats::run_backfill(&state, &range)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(from = %range.from, to = %range.to, written, "agent performance backfilled");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            PROMISE_EXTRACT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let recorded = attome_ai::followup_promise::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if recorded > 0 {
                    tracing::info!(recorded, "payment promises read from replies");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MEETING_BRIEF_SCAN,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let queued = attome_ai::meeting::run::scan(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if queued > 0 {
                    tracing::info!(queued, "meeting briefs queued");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MEETING_NOTES,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let notes: attome_ai::meeting::run::NotesJob = job.payload()?;
                let made = attome_ai::meeting::run::run_notes(&state, &notes)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::debug!(meeting = %notes.meeting_id, made, "meeting notes run");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MEETING_BRIEF,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_AI) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let brief: attome_ai::meeting::run::BriefJob = job.payload()?;
                let made = attome_ai::meeting::run::run_brief(&state, brief.meeting_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::debug!(meeting = %brief.meeting_id, made, "meeting brief run");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SURVEY_SEND,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let sent = attome_service::survey_send::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if sent > 0 {
                    tracing::info!(sent, "surveys sent");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORKFORCE_BUILD,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_WORKFORCE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let payload: attome_workforce::build_job::BuildJob = job.payload()?;
                let built = attome_workforce::build_job::run(&state, &payload)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(
                    schedule = %built.schedule_id,
                    assignments = built.assignments,
                    "workforce schedule built"
                );
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CHANGE_SIGNOFF,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let decided = attome_project::change_signoff::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if decided > 0 {
                    tracing::info!(decided, "change requests decided by customer sign-off");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            RFQ_OPEN,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_PROCUREMENT) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let opened = attome_procurement::rfq::tick(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if opened > 0 {
                    tracing::info!(opened, "rfq bids opened");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            COMPLIANCE_EXPIRY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let scheduled = attome_procurement::compliance::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if scheduled > 0 {
                    tracing::info!(scheduled, "compliance document reminders set");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MAINTENANCE_GENERATION,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let run =
                    attome_service::maintenance::tick(&state, chrono::Utc::now().date_naive())
                        .await
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if run != attome_service::maintenance::MaintenanceRun::default() {
                    tracing::info!(
                        scheduled = run.timers_scheduled,
                        moved = run.timers_moved,
                        generated = run.generated,
                        "maintenance plans checked"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            DEVICE_READINGS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let run = attome_service::iot::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if run.fired > 0 || run.failed > 0 {
                    tracing::info!(
                        readings = run.readings,
                        counted = run.counted,
                        fired = run.fired,
                        failed = run.failed,
                        "device readings processed"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            GRC_EVIDENCE_COLLECT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_GRC) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let inputs = attome_grc::collectors::Inputs {
                    last_drill: crate::backup::last_drill(&state.base.config)
                        .await
                        .map(|d| (d.at, d.passed, d.detail)),
                    release_version: env!("CARGO_PKG_VERSION").to_owned(),
                };
                let run = attome_grc::collectors::collect(&state, &inputs)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(
                    collected = run.collected,
                    failed = run.failed,
                    findings = run.findings_opened,
                    "grc evidence collected"
                );
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            PREDICT_DRIFT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_PREDICT)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let drifted = attome_predict::train::drift_check(&state.base.db)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if drifted > 0 {
                    tracing::warn!(drifted, "prediction models whose features drifted");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            FULFILMENT_EXCEPTIONS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_FULFILMENT)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let opened = attome_fulfilment::exceptions::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if opened > 0 {
                    tracing::info!(opened, "fulfilment exceptions opened");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            FULFILMENT_TRACKING,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_FULFILMENT)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let moved = attome_fulfilment::tracking::poll(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if moved > 0 {
                    tracing::info!(moved, "fulfilment shipments tracked");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            FULFILMENT_SPLIT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_FULFILMENT)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let written = attome_fulfilment::split::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if written > 0 {
                    tracing::info!(written, "fulfilment orders split from confirmed orders");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            FULFILMENT_BILLING,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_FULFILMENT)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let created = attome_fulfilment::billing_trigger::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if created > 0 {
                    tracing::info!(created, "shipments asked for billing");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            METRIC_BACKFILL,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_metric::backfill::BackfillPayload =
                    serde_json::from_value(job.payload)
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                let run = attome_metric::backfill::backfill(
                    &state,
                    payload.metric_id,
                    payload.from,
                    payload.to,
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                // The next run is queued without the dedup key: this run's
                // own row still holds it.
                if let Some(from) = run.next {
                    let next = attome_metric::backfill::BackfillPayload { from, ..payload };
                    attome_jobs::enqueue_on_pool(
                        &state.base.db,
                        attome_metric::backfill::backfill_job(&next),
                    )
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            ROLLUP_BACKFILL,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_records::rollup_heal::BackfillPayload =
                    serde_json::from_value(job.payload)
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if let Some(next) = attome_records::rollup_heal::backfill_step(&state, &payload)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?
                {
                    let job = attome_records::rollup_heal::backfill_job(
                        &next.entity,
                        &next.field,
                        next.after,
                    );
                    attome_jobs::enqueue_on_pool(&state.base.db, job)
                        .await
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            LDAP_SYNC,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                // Off unless auth.ldap is configured.
                let Some(settings) = state.base.config.auth.ldap.clone() else {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                };
                attome_security::ldap_sync::run(&state, &settings)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            ROLLUP_HEAL,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let healed = attome_records::rollup_heal::heal(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if healed > 0 {
                    tracing::warn!(healed, "rollup values healed");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            ROLLUP_FAST,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let read = attome_records::rollup_fast::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if read > 0 {
                    tracing::debug!(read, "rollup fast mode read change events");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            AGGREGATE_CACHE_MARKS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let marked = attome_search::aggregate_cache::mark_changes(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if marked > 0 {
                    tracing::debug!(marked, "entities marked changed for the aggregate cache");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            LEAD_ASSIGNMENT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let assigned = attome_workflow::lead_assignment::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if assigned > 0 {
                    tracing::info!(assigned, "new leads assigned");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            LEAD_FIRST_TOUCH,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let scheduled = attome_workflow::speed_to_lead::schedule_timers(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if scheduled > 0 {
                    tracing::info!(scheduled, "first-touch timers scheduled for new leads");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            LEAD_REBALANCE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let moved = attome_workflow::speed_to_lead::rebalance(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if moved > 0 {
                    tracing::info!(moved, "stale leads rebalanced");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WEB_VISIT_SUMMARY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let written = attome_marketing::tracking::summary::summarise_closed_sessions(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if written > 0 {
                    tracing::info!(written, "web visits summarised");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CONTENT_SITEMAP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let counts = attome_content::seo::sitemap::regenerate_all(&state.base.db)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(
                    sites = counts.sites,
                    skipped = counts.skipped,
                    written = counts.written,
                    unchanged = counts.unchanged,
                    removed = counts.removed,
                    "content sitemaps rebuilt"
                );
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CONTENT_SEO_AUDIT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let audited = attome_content::seo::audit::run_nightly(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(audited, "nightly seo audit done");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPS_CLUSTER_POLL,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_OPS)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                // AB2-T8: approved switchovers first, then the leader they
                // moved is read like any other.
                match attome_ops::switchover::run_approved(&state).await {
                    Ok(0) => {}
                    Ok(ran) => tracing::info!(ran, "approved switchovers carried out"),
                    Err(error) => tracing::error!(%error, "ops switchover: not carried out"),
                }
                match attome_ops::cluster::poll(&state).await {
                    Ok(true) => tracing::info!("database leader recorded"),
                    Ok(false) => {}
                    // A node that does not answer is the operator's alert,
                    // not a job failure to retry every 15 seconds.
                    Err(error) => tracing::warn!(%error, "ops cluster poll: no Patroni node answered"),
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPS_DRILL_SKIP_CHECK,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_OPS)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let skipped = attome_ops::drill_schedules::record_skips(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if skipped > 0 {
                    tracing::warn!(skipped, "recovery drills overdue");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPS_LIVE_RPO,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_OPS)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let turned = attome_ops::live_rpo::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if turned > 0 {
                    tracing::warn!(turned, "live recovery point over its target");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPS_DRILL_FRESHNESS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if state
                    .modules
                    .load()
                    .require(attome_modules::MODULE_OPS)
                    .is_err()
                {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let reported = attome_ops::freshness::notify_stale(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if reported > 0 {
                    tracing::warn!(reported, "recovery drills stale or failed");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            S2S_CLIENT_EXPIRY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let notices = attome_s2s::service_account::expiry_sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                for notice in &notices {
                    notify_s2s_client_owner(&state, notice).await;
                }
                if !notices.is_empty() {
                    tracing::info!(clients = notices.len(), "s2s client expiry sweep");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CATALOG_ASSET_REBUILD,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let counts = attome_api::catalog_index::rebuild_assets(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::debug!(
                    upserted = counts.upserted,
                    removed = counts.removed,
                    "catalog asset index rebuilt"
                );
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            EMAIL_DOMAIN_CHECK,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let broken = attome_api::email_domains::check_all(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if broken > 0 {
                    tracing::warn!(broken, "sending domains with broken records");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            IMPORT_SCHEDULE_TICK,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let started = attome_document::import_jobs::run_schedules(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if started > 0 {
                    tracing::info!(started, "recurring imports started");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WAREHOUSE_EXPORT,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let files = attome_integration::warehouse_export::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if files > 0 {
                    tracing::info!(files, "warehouse export wrote files");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // Z12-T7: the yearly Hijri holiday review reminder.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CALENDAR_YEARLY_REVIEW,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let sent = attome_api::calendar_packs::yearly_review(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if sent > 0 {
                    tracing::info!(sent, "calendar yearly review: reminders sent");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // AB11-T4: the status watch.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OPS_STATUS_WATCH,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_OPS) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let stats = attome_ops::status_watch::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if stats.drafted > 0 || stats.published > 0 {
                    tracing::warn!(
                        drafted = stats.drafted,
                        published = stats.published,
                        "status watch: automatic incidents"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // J10-T1: the unified router.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SERVICE_ROUTER_TICK,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let stats = attome_service::router::tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if stats.offered > 0 || stats.expired > 0 || stats.overflowed > 0 {
                    tracing::info!(
                        offered = stats.offered,
                        expired = stats.expired,
                        overflowed = stats.overflowed,
                        "service router: tick"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // A24-T4: a migration wave.
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MIGRATION_WAVE,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_api::migration_run::WaveJob = job.payload()?;
                attome_api::migration_run::run_wave(&state, payload.wave_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        // A23-T7: one handler per import phase; the payload names the job.
        {
            use attome_document::import_jobs::{Phase, PhaseJob};
            for (job_type, phase) in [
                (IMPORT_STAGE, Phase::Stage),
                (IMPORT_VALIDATE, Phase::Validate),
                (IMPORT_APPLY, Phase::Apply),
                (IMPORT_UNDO, Phase::Undo),
            ] {
                if let Err(error) = attome_core::jobs::JOB_TYPES.register(
                    job_type,
                    move |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                        let payload: PhaseJob = job.payload()?;
                        attome_document::import_jobs::run(&state, phase, &payload)
                            .await
                            .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)
                    },
                ) {
                    tracing::error!(%error, "job type registration failed");
                }
            }
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CALENDAR_FEED_FETCH,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let read = attome_api::calendar_feed::fetch_all(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if read > 0 {
                    tracing::info!(read, "calendar feeds read");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CONTENT_SEARCH_CONSOLE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let pulled = attome_content::seo::console::pull_daily(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if pulled.rows > 0 {
                    tracing::info!(sites = pulled.sites, rows = pulled.rows, "search statistics stored");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CONTENT_INDEXNOW,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let ping: attome_content::seo::console::PingJob = job.payload()?;
                attome_content::seo::console::ping(&state, &ping)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SECURITY_DETECTIONS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let now = chrono::Utc::now();
                let run = attome_audit::detections::run(&state.base.db, now)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                // R5-T2: open breaches (from these cases or entered by hand)
                // get their regulator-deadline timers.
                let timed = attome_compliance::breach::schedule_due(&state.base.db, now)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if timed > 0 {
                    tracing::info!(timed, "privacy breaches: deadline timers set");
                }
                if run.cases_opened > 0 {
                    tracing::warn!(
                        events = run.events,
                        opened = run.cases_opened,
                        breaches = run.breaches_opened,
                        open = run.open_cases,
                        "security detections opened cases"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            GRC_POLICY_SWEEP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_GRC) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let run = attome_grc::policy::sweep(&state, chrono::Utc::now().date_naive())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if run != attome_grc::policy::PolicySweep::default() {
                    tracing::info!(
                        reviews = run.review_reminders,
                        attestations = run.attestation_requests,
                        closed = run.campaigns_closed,
                        expired = run.exceptions_expired,
                        "grc policies swept"
                    );
                }
                // R14-T1: vendor assessments opened, scored and expired.
                let today = chrono::Utc::now().date_naive();
                let tprm = attome_grc::tprm::sweep(&state, today)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if tprm != attome_grc::tprm::TprmSweep::default() {
                    tracing::info!(
                        opened = tprm.opened,
                        scored = tprm.scored,
                        expired = tprm.expired,
                        unscorable = tprm.unscorable,
                        "vendor assessments swept"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WARRANTY_REMINDER,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let sent = attome_service::warranty::remind_expiring(
                    &state,
                    chrono::Utc::now().date_naive(),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if sent > 0 {
                    tracing::info!(sent, "warranty expiry reminders sent");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            STATUS_PAGE_NOTIFY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SERVICE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let sent = attome_service::status_page::notify_tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if sent > 0 {
                    tracing::info!(sent, "status page updates emailed");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CONTRACT_COMPARE,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_CONTRACT) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let payload: attome_contract::compare::CompareJob = job.payload()?;
                let ctx = state
                    .base
                    .security
                    .resolve_strict(payload.user_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                attome_contract::compare::run_compare(&state, &ctx, payload.comparison_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SALES_ORGCHART_DRAFT,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SALES) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let payload: attome_sales::orgchart::drafts::DraftJob = job.payload()?;
                let ctx = state
                    .base
                    .security
                    .resolve_strict(payload.user_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                let written =
                    attome_sales::orgchart::drafts::propose(&state, &ctx, payload.account_id)
                        .await
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(account = %payload.account_id, written, "org chart drafts written");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SALES_DEAL_COVERAGE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_SALES) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_sales::orgchart::committee::coverage_tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        for (job_type, date) in [
            (MARKETING_JOURNEY_ENTRY, false),
            (MARKETING_JOURNEY_DATE_ENTRY, true),
        ] {
            if let Err(error) = attome_core::jobs::JOB_TYPES.register(
                job_type,
                move |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                    if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                        return Ok::<(), attome_jobs::registry::BoxError>(());
                    }
                    let queued = if date {
                        attome_marketing::journey::entry::date_entry(&state).await
                    } else {
                        attome_marketing::journey::entry::entry_tick(&state).await
                    }
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                    if queued > 0 {
                        tracing::info!(queued, date, "journey entries queued");
                    }
                    Ok::<(), attome_jobs::registry::BoxError>(())
                },
            ) {
                tracing::error!(%error, "job type registration failed");
            }
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SEGMENT_LIVE,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_marketing::segment_live::live_tick(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            PROFILE_EVENT_RETENTION,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let dropped = attome_marketing::profile_events::apply_retention(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if dropped > 0 {
                    tracing::info!(dropped, "profile event retention: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            STATE_AUTO_TRANSITIONS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let moved = attome_state::auto_transitions::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if moved > 0 {
                    tracing::info!(moved, "automatic transitions: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            STATE_AUTO_TRANSITIONS_DAILY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let moved = attome_state::auto_transitions::daily(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(moved, "automatic transitions (daily): run complete");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WORKFLOW_SEQUENCE_EXITS,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let outcome = attome_workflow::sequence::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if outcome.exited > 0 || outcome.closed > 0 {
                    tracing::info!(
                        exited = outcome.exited,
                        closed = outcome.closed,
                        "sequence exits: run complete"
                    );
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            STATE_TRANSITION_ACTIONS_SWEEP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                attome_state::transition_actions::sweep(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            STATE_TRANSITION_ACTIONS,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                let payload: attome_state::transition_actions::TransitionActions =
                    job.payload()?;
                run_transition_actions(&state, payload)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            REVREC_LOYALTY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_LEDGER) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_ledger::revrec::loyalty::sweep(&state, chrono::Utc::now())
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            WFM_ADHERENCE_DAY,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_WORKFORCE) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let today = chrono::Utc::now().date_naive();
                attome_workforce::adherence::roll_up_day(
                    &state.base.db,
                    today.pred_opt().unwrap_or(today),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            MARKETING_ATTRIBUTION,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                attome_marketing::attribution_store::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            DELIVERABILITY_ROLLUP,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                // Marketing only: an unlicensed deployment has nothing to roll up.
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let today = chrono::Utc::now().date_naive();
                for day in [today.pred_opt().unwrap_or(today), today] {
                    attome_marketing::deliverability::rollup::rollup_day(&state.base.db, day)
                        .await
                        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                }
                // E6-T10: yesterday's alerts, each raised and notified once.
                let raised = attome_marketing::alerts::evaluate(
                    &state,
                    attome_marketing::alerts::evaluation_day(today),
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if !raised.is_empty() {
                    tracing::warn!(alerts = raised.len(), "deliverability alerts raised");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            VOICE_RECORDING,
            |state: EngineState, job: attome_jobs::RegisteredJob| async move {
                #[derive(serde::Deserialize)]
                struct Payload {
                    call_id: uuid::Uuid,
                }
                let payload: Payload = job.payload()?;
                crate::voice::attach_recording(&state, payload.call_id)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SOCIAL_PUBLISH,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
                    return Ok::<(), attome_jobs::registry::BoxError>(());
                }
                let now = chrono::Utc::now();
                let published = attome_marketing::social_publish::publish_due(&state, now)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                let read = attome_marketing::social_publish::read_metrics(&state, now)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if published + read > 0 {
                    tracing::info!(published, read, "social publish: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SOCIAL_MENTIONS_SYNC,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let written = crate::social::sync_mentions(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if written > 0 {
                    tracing::info!(written, "social mentions sync: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            SOCIAL_REVIEWS_SYNC,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let written = crate::social::sync_reviews(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(written, "social reviews sync: run complete");
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            OAUTH_REFRESH,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let endpoint = attome_integration::oauth::GuardedEndpoint::new()
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                let summary = attome_integration::oauth::refresh_due(
                    &state.base.db,
                    &attome_integration::credential::ring(&state),
                    &endpoint,
                )
                .await
                .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                if summary.refreshed + summary.failed > 0 {
                    tracing::info!(?summary, "integration OAuth refresh: run complete");
                }
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        ) {
            tracing::error!(%error, "job type registration failed");
        }
        if let Err(error) = attome_core::jobs::JOB_TYPES.register(
            CALENDAR_SYNC,
            |state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                let summary = attome_integration::connector::adapters::calendar_sync::run(&state)
                    .await
                    .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
                tracing::info!(?summary, "calendar sync: run complete");
                Ok::<(), attome_jobs::registry::BoxError>(())
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
        EngineJob::ContractLinkSweep => DEDUP_KEY_CONTRACT_LINK_SWEEP,
        EngineJob::GeocodeSweep => DEDUP_KEY_GEOCODE_SWEEP,
        EngineJob::BillingHandoffSweep => DEDUP_KEY_BILLING_HANDOFF_SWEEP,
        EngineJob::BillingRenewalSweep => DEDUP_KEY_BILLING_RENEWAL_SWEEP,
        EngineJob::BillingGenerateCharges => DEDUP_KEY_BILLING_GENERATE_CHARGES,
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
        EngineJob::PrivilegeUsageDaily => DEDUP_KEY_PRIVILEGE_USAGE_DAILY,
        EngineJob::SalesDefaultTeamSweep => DEDUP_KEY_SALES_DEFAULT_TEAM_SWEEP,
        EngineJob::QualityIncrementalSweep => DEDUP_KEY_QUALITY_INCREMENTAL_SWEEP,
        EngineJob::RevrecContractSweep => DEDUP_KEY_REVREC_CONTRACT_SWEEP,
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
        EngineJob::UploadRescanSweep => DEDUP_KEY_UPLOAD_RESCAN_SWEEP,
        EngineJob::FileIntegritySample => DEDUP_KEY_FILE_INTEGRITY_SAMPLE,
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
        EngineJob::AiDeferredActionSweep => DEDUP_KEY_AI_DEFERRED_ACTION_SWEEP,
        EngineJob::AiAutonomySummary => DEDUP_KEY_AI_AUTONOMY_SUMMARY,
        EngineJob::AiTrialCompare => DEDUP_KEY_AI_TRIAL_COMPARE,
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
        EngineJob::ValidationScoreSweep => DEDUP_KEY_VALIDATION_SCORE_SWEEP,
        EngineJob::PredictScoringSweep => DEDUP_KEY_PREDICT_SCORING_SWEEP,
        EngineJob::PredictOutcomeFillSweep => DEDUP_KEY_PREDICT_OUTCOME_FILL_SWEEP,
        EngineJob::FleetPoll => DEDUP_KEY_FLEET_POLL,
        EngineJob::Registered(job) if job.name == SECRET_AGE_REMINDER.name => {
            DEDUP_KEY_SECRET_AGE_REMINDER
        }
        EngineJob::Registered(job) if job.name == HEAVY_OP_UNDO_RETENTION.name => {
            DEDUP_KEY_HEAVY_OP_UNDO_RETENTION
        }
        EngineJob::Registered(job) if job.name == TIME_FORMULA_RECOMPUTE.name => {
            DEDUP_KEY_TIME_FORMULA_RECOMPUTE
        }
        EngineJob::Registered(job) if job.name == CALENDAR_SYNC.name => DEDUP_KEY_CALENDAR_SYNC,
        EngineJob::Registered(job) if job.name == OAUTH_REFRESH.name => DEDUP_KEY_OAUTH_REFRESH,
        EngineJob::Registered(job) if job.name == NOTIFICATION_QUEUE_SWEEP.name => {
            DEDUP_KEY_NOTIFICATION_QUEUE
        }
        EngineJob::Registered(job) if job.name == DEAD_LETTER_SWEEP.name => {
            DEDUP_KEY_DEAD_LETTER_SWEEP
        }
        EngineJob::Registered(job) if job.name == APPROVAL_EMAIL_LINKS.name => {
            DEDUP_KEY_APPROVAL_EMAIL_LINKS
        }
        EngineJob::Registered(job) if job.name == DATA_PROFILE_SCHEDULE.name => {
            DEDUP_KEY_DATA_PROFILE_SCHEDULE
        }
        EngineJob::Registered(job) if job.name == MAIL_CAPTURE.name => DEDUP_KEY_MAIL_CAPTURE,
        EngineJob::Registered(job) if job.name == INBOUND_MAIL.name => DEDUP_KEY_INBOUND_MAIL,
        EngineJob::Registered(job) if job.name == CASE_SUMMARY.name => DEDUP_KEY_CASE_SUMMARY,
        EngineJob::Registered(job) if job.name == SMS_CAMPAIGN.name => DEDUP_KEY_SMS_CAMPAIGN,
        EngineJob::Registered(job) if job.name == EMAIL_CAMPAIGN.name => DEDUP_KEY_EMAIL_CAMPAIGN,
        EngineJob::Registered(job) if job.name == WEBINAR_SYNC.name => DEDUP_KEY_WEBINAR_SYNC,
        EngineJob::Registered(job) if job.name == BLOCKLIST_CHECK.name => DEDUP_KEY_BLOCKLIST_CHECK,
        EngineJob::Registered(job) if job.name == REPUTATION_FETCH.name => {
            DEDUP_KEY_REPUTATION_FETCH
        }
        EngineJob::Registered(job) if job.name == SEGMENT_LIVE.name => DEDUP_KEY_SEGMENT_LIVE,
        EngineJob::Registered(job) if job.name == STOCK_LEDGER.name => DEDUP_KEY_STOCK_LEDGER,
        EngineJob::Registered(job) if job.name == WORK_ORDER_INVOICING.name => {
            DEDUP_KEY_WORK_ORDER_INVOICING
        }
        EngineJob::Registered(job) if job.name == WARRANTY_REMINDER.name => {
            DEDUP_KEY_WARRANTY_REMINDER
        }
        EngineJob::Registered(job) if job.name == MAINTENANCE_GENERATION.name => {
            DEDUP_KEY_MAINTENANCE
        }
        EngineJob::Registered(job) if job.name == DEVICE_READINGS.name => DEDUP_KEY_DEVICE_READINGS,
        EngineJob::Registered(job) if job.name == SECURITY_DETECTIONS.name => {
            DEDUP_KEY_SECURITY_DETECTIONS
        }
        EngineJob::Registered(job) if job.name == CONTENT_SITEMAP.name => DEDUP_KEY_CONTENT_SITEMAP,
        EngineJob::Registered(job) if job.name == FULFILMENT_SPLIT.name => {
            DEDUP_KEY_FULFILMENT_SPLIT
        }
        EngineJob::Registered(job) if job.name == FULFILMENT_BILLING.name => {
            DEDUP_KEY_FULFILMENT_BILLING
        }
        EngineJob::Registered(job) if job.name == LEAD_ASSIGNMENT.name => DEDUP_KEY_LEAD_ASSIGNMENT,
        EngineJob::Registered(job) if job.name == AGGREGATE_CACHE_MARKS.name => {
            DEDUP_KEY_AGGREGATE_CACHE_MARKS
        }
        EngineJob::Registered(job) if job.name == ROLLUP_FAST.name => DEDUP_KEY_ROLLUP_FAST,
        EngineJob::Registered(job) if job.name == ROLLUP_HEAL.name => DEDUP_KEY_ROLLUP_HEAL,
        EngineJob::Registered(job) if job.name == LDAP_SYNC.name => DEDUP_KEY_LDAP_SYNC,
        EngineJob::Registered(job) if job.name == LEAD_FIRST_TOUCH.name => {
            DEDUP_KEY_LEAD_FIRST_TOUCH
        }
        EngineJob::Registered(job) if job.name == LEAD_REBALANCE.name => DEDUP_KEY_LEAD_REBALANCE,
        EngineJob::Registered(job) if job.name == WEB_VISIT_SUMMARY.name => {
            DEDUP_KEY_WEB_VISIT_SUMMARY
        }
        EngineJob::Registered(job) if job.name == FULFILMENT_EXCEPTIONS.name => {
            DEDUP_KEY_FULFILMENT_EXCEPTIONS
        }
        EngineJob::Registered(job) if job.name == FULFILMENT_TRACKING.name => {
            DEDUP_KEY_FULFILMENT_TRACKING
        }
        EngineJob::Registered(job) if job.name == PREDICT_DRIFT.name => DEDUP_KEY_PREDICT_DRIFT,
        EngineJob::Registered(job) if job.name == CONTENT_SEO_AUDIT.name => {
            DEDUP_KEY_CONTENT_SEO_AUDIT
        }
        EngineJob::Registered(job) if job.name == OPS_CLUSTER_POLL.name => {
            DEDUP_KEY_OPS_CLUSTER_POLL
        }
        EngineJob::Registered(job) if job.name == OPS_DRILL_SKIP_CHECK.name => {
            DEDUP_KEY_OPS_DRILL_SKIP_CHECK
        }
        EngineJob::Registered(job) if job.name == OPS_DRILL_FRESHNESS.name => {
            DEDUP_KEY_OPS_DRILL_FRESHNESS
        }
        EngineJob::Registered(job) if job.name == S2S_CLIENT_EXPIRY.name => {
            DEDUP_KEY_S2S_CLIENT_EXPIRY
        }
        EngineJob::Registered(job) if job.name == OPS_LIVE_RPO.name => DEDUP_KEY_OPS_LIVE_RPO,
        EngineJob::Registered(job) if job.name == CATALOG_ASSET_REBUILD.name => {
            DEDUP_KEY_CATALOG_ASSET_REBUILD
        }
        EngineJob::Registered(job) if job.name == EMAIL_DOMAIN_CHECK.name => {
            DEDUP_KEY_EMAIL_DOMAIN_CHECK
        }
        EngineJob::Registered(job) if job.name == CALENDAR_FEED_FETCH.name => {
            DEDUP_KEY_CALENDAR_FEED_FETCH
        }
        EngineJob::Registered(job) if job.name == IMPORT_SCHEDULE_TICK.name => {
            DEDUP_KEY_IMPORT_SCHEDULE_TICK
        }
        EngineJob::Registered(job) if job.name == WAREHOUSE_EXPORT.name => {
            DEDUP_KEY_WAREHOUSE_EXPORT
        }
        EngineJob::Registered(job) if job.name == CONTENT_SEARCH_CONSOLE.name => {
            DEDUP_KEY_CONTENT_SEARCH_CONSOLE
        }
        EngineJob::Registered(job) if job.name == GRC_POLICY_SWEEP.name => {
            DEDUP_KEY_GRC_POLICY_SWEEP
        }
        EngineJob::Registered(job) if job.name == GRC_EVIDENCE_COLLECT.name => {
            DEDUP_KEY_GRC_EVIDENCE
        }
        EngineJob::Registered(job) if job.name == COMPLIANCE_EXPIRY.name => {
            DEDUP_KEY_COMPLIANCE_EXPIRY
        }
        EngineJob::Registered(job) if job.name == RFQ_OPEN.name => DEDUP_KEY_RFQ_OPEN,
        EngineJob::Registered(job) if job.name == CHANGE_SIGNOFF.name => DEDUP_KEY_CHANGE_SIGNOFF,
        EngineJob::Registered(job) if job.name == SURVEY_SEND.name => DEDUP_KEY_SURVEY_SEND,
        EngineJob::Registered(job) if job.name == MEETING_BRIEF_SCAN.name => {
            DEDUP_KEY_MEETING_BRIEF_SCAN
        }
        EngineJob::Registered(job) if job.name == PROMISE_EXTRACT.name => DEDUP_KEY_PROMISE_EXTRACT,
        EngineJob::Registered(job) if job.name == AGENT_STATS_ROLLUP.name => DEDUP_KEY_AGENT_STATS,
        EngineJob::Registered(job) if job.name == OPS_DIGEST.name => DEDUP_KEY_OPS_DIGEST,
        EngineJob::Registered(job) if job.name == CREDIT_HOLD.name => DEDUP_KEY_CREDIT_HOLD,
        EngineJob::Registered(job) if job.name == AGENT_BEHAVIOUR.name => DEDUP_KEY_AGENT_BEHAVIOUR,
        EngineJob::Registered(job) if job.name == AGENT_CHECK.name => DEDUP_KEY_AGENT_CHECK,
        EngineJob::Registered(job) if job.name == WORK_SHARE.name => DEDUP_KEY_WORK_SHARE,
        EngineJob::Registered(job) if job.name == LABEL_DRAFTS.name => DEDUP_KEY_LABEL_DRAFTS,
        EngineJob::Registered(job) if job.name == DECISION_MEASURE.name => {
            DEDUP_KEY_DECISION_MEASURE
        }
        EngineJob::Registered(job) if job.name == WORKFORCE_INTRADAY.name => DEDUP_KEY_INTRADAY,
        EngineJob::Registered(job) if job.name == COMMISSION_ACCEPTANCE.name => {
            DEDUP_KEY_COMMISSION_ACCEPTANCE
        }
        EngineJob::Registered(job) if job.name == STATUS_PAGE_NOTIFY.name => {
            DEDUP_KEY_STATUS_NOTIFY
        }
        EngineJob::Registered(job) if job.name == SALES_DEAL_COVERAGE.name => {
            DEDUP_KEY_DEAL_COVERAGE
        }
        EngineJob::Registered(job) if job.name == SERVICE_ROUTER_TICK.name => {
            DEDUP_KEY_SERVICE_ROUTER
        }
        EngineJob::Registered(job) if job.name == OPS_STATUS_WATCH.name => {
            DEDUP_KEY_OPS_STATUS_WATCH
        }
        EngineJob::Registered(job) if job.name == CALENDAR_YEARLY_REVIEW.name => {
            DEDUP_KEY_CALENDAR_REVIEW
        }
        EngineJob::Registered(job) if job.name == MARKETING_JOURNEY_ENTRY.name => {
            DEDUP_KEY_JOURNEY_ENTRY
        }
        EngineJob::Registered(job) if job.name == MARKETING_JOURNEY_DATE_ENTRY.name => {
            DEDUP_KEY_JOURNEY_DATE_ENTRY
        }
        EngineJob::Registered(job) if job.name == PROFILE_EVENT_RETENTION.name => {
            DEDUP_KEY_PROFILE_EVENT_RETENTION
        }
        EngineJob::Registered(job) if job.name == DELIVERABILITY_ROLLUP.name => {
            DEDUP_KEY_DELIVERABILITY_ROLLUP
        }
        EngineJob::Registered(job) if job.name == MARKETING_ATTRIBUTION.name => {
            DEDUP_KEY_MARKETING_ATTRIBUTION
        }
        EngineJob::Registered(job) if job.name == WFM_ADHERENCE_DAY.name => {
            DEDUP_KEY_WFM_ADHERENCE_DAY
        }
        EngineJob::Registered(job) if job.name == REVREC_LOYALTY.name => DEDUP_KEY_REVREC_LOYALTY,
        EngineJob::Registered(job) if job.name == STATE_TRANSITION_ACTIONS_SWEEP.name => {
            DEDUP_KEY_TRANSITION_ACTIONS_SWEEP
        }
        EngineJob::Registered(job) if job.name == WORKFLOW_SEQUENCE_EXITS.name => {
            DEDUP_KEY_SEQUENCE_EXITS
        }
        EngineJob::Registered(job) if job.name == STATE_AUTO_TRANSITIONS.name => {
            DEDUP_KEY_AUTO_TRANSITIONS
        }
        EngineJob::Registered(job) if job.name == STATE_AUTO_TRANSITIONS_DAILY.name => {
            DEDUP_KEY_AUTO_TRANSITIONS_DAILY
        }
        EngineJob::Registered(job) if job.name == SOCIAL_REVIEWS_SYNC.name => {
            DEDUP_KEY_SOCIAL_REVIEWS_SYNC
        }
        EngineJob::Registered(job) if job.name == SOCIAL_MENTIONS_SYNC.name => {
            DEDUP_KEY_SOCIAL_MENTIONS_SYNC
        }
        EngineJob::Registered(job) if job.name == SOCIAL_PUBLISH.name => DEDUP_KEY_SOCIAL_PUBLISH,
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
/// Y4-T2: the module each module-owned schedule belongs to, by its schedule
/// key. A schedule not listed is platform work and always runs.
pub const SCHEDULE_MODULES: &[(&str, &str)] = &[
    ("billing-handoff-sweep", "billing"),
    ("billing-renewal-sweep", "billing"),
    ("billing-generate-charges", "billing"),
    ("mrr-snapshot", "billing"),
    ("billing-request-sweep", "billing"),
    ("billing-schedule-run", "billing"),
    ("billing-overdue-sweep", "billing"),
    ("billing-charge-due", "billing"),
    ("billing-reconcile", "billing"),
    ("billing-einvoice-sweep", "billing"),
    ("billing-credit-hold", "billing"),
    ("marketing-nightly", "marketing"),
    ("segment-refresh-due", "marketing"),
    ("marketing-sweep", "marketing"),
    ("sms-campaign", "marketing"),
    ("email-campaign", "marketing"),
    ("webinar-sync", "marketing"),
    ("marketing-blocklist-check", "marketing"),
    ("marketing-reputation-fetch", "marketing"),
    ("deliverability-rollup", "marketing"),
    ("marketing-segment-live", "marketing"),
    ("marketing-journey-entry", "marketing"),
    ("marketing-journey-date-entry", "marketing"),
    ("social-publish", "marketing"),
    ("social-mentions-sync", "marketing"),
    ("social-reviews-sync", "omnichannel"),
    ("deal-risk", "sales"),
    ("forecast-recompute", "sales"),
    ("sales-default-team-sweep", "sales"),
    ("sales-snapshot-prune", "sales"),
    ("sales-deal-close-sweep", "sales"),
    ("sales-leaver-sweep", "sales"),
    ("sales-mention-scan", "sales"),
    ("sales-deal-coverage", "sales"),
    ("commission-credit-sweep", "commission"),
    ("commission-acceptance", "commission"),
    ("revrec-contract-sweep", "ledger"),
    ("contract-key-dates", "contract"),
    ("contract-link-sweep", "contract"),
    ("workflow-sla-sweep", "workflow"),
    ("workflow-entity-trigger-dispatch", "workflow"),
    ("compute-metric-snapshots", "dashboard"),
    ("dashboard-decision-measure", "dashboard"),
    ("ai-quality-monitor", "ai"),
    ("ai-tool-call-sweep", "ai"),
    ("ai-followup-scan", "ai"),
    ("ai-deferred-action-sweep", "ai"),
    ("ai-autonomy-summary", "ai"),
    ("ai-trial-compare", "ai"),
    ("ai-meeting-brief-scan", "ai"),
    ("ai-promise-extract", "ai"),
    ("ai-agent-stats-rollup", "ai"),
    ("ai-work-share-consume", "ai"),
    ("ai-agent-behaviour-check", "ai"),
    ("ai-agent-behaviour-rollup", "ai"),
    ("ai-ops-weekly-digest", "ai"),
    ("case-summary", "ai"),
    ("search-suggestion-refresh", "search"),
    ("search-saved-search-alert-sweep", "search"),
    ("content-scheduled-publish-sweep", "content"),
    ("content-page-stats-rollup", "content"),
    ("content-review-reminder-sweep", "content"),
    ("content-sitemap", "content"),
    ("content-seo-audit", "content"),
    ("content-search-console", "content"),
    ("report-schedule-sweep", "report"),
    ("process-extraction-sweep", "process"),
    ("ticket-sla-sweep", "service"),
    ("work-queue-escalation-sweep", "service"),
    ("maintenance-generation", "service"),
    ("device-readings", "service"),
    ("warranty-expiry-reminder", "service"),
    ("resource-utilization-sweep", "project"),
    ("predict-scoring-sweep", "predict"),
    ("predict-outcome-fill-sweep", "predict"),
    ("predict-drift", "predict"),
    ("fulfilment-split", "fulfilment"),
    ("fulfilment-exceptions", "fulfilment"),
    ("fulfilment-tracking", "fulfilment"),
    ("workforce-intraday", "workforce"),
    ("rfq-open", "procurement"),
    ("grc-policy-sweep", "grc"),
    ("grc-evidence-collect", "grc"),
    ("ops-cluster-poll", "ops"),
    ("ops-drill-skip-check", "ops"),
    ("ops-drill-freshness", "ops"),
    ("ops-live-rpo", "ops"),
];

/// How long a node trusts the module configuration it read for schedules.
/// Module Management's change reaches schedules within this, and turning a
/// module back on resumes its schedules without a restart.
const SCHEDULE_MODULES_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// The module configuration last read for schedules, and when (observational
/// per-node state, rebuilt from the database; guidelines §5).
static SCHEDULE_MODULE_SET: std::sync::Mutex<
    Option<(std::time::Instant, attome_modules::ModuleSet)>,
> = std::sync::Mutex::new(None);

/// Y4-T2: whether schedule `name` may tick now: true unless it belongs to a
/// module the deployment's module configuration has off. A failed read of
/// the configuration keeps the schedule running (the safe direction for
/// work that was running before this check existed).
pub async fn schedule_allowed(db: &DbPool, name: &str) -> bool {
    let Some(module) = SCHEDULE_MODULES
        .iter()
        .find(|(key, _)| *key == name)
        .and_then(|(_, module)| attome_modules::module_by_name(module))
    else {
        return true;
    };
    let cached = SCHEDULE_MODULE_SET
        .lock()
        .ok()
        .and_then(|guard| *guard)
        .filter(|(at, _)| at.elapsed() < SCHEDULE_MODULES_TTL)
        .map(|(_, set)| set);
    let set = match cached {
        Some(set) => set,
        None => {
            let set = attome_api::load_license(db).await;
            if let Ok(mut guard) = SCHEDULE_MODULE_SET.lock() {
                *guard = Some((std::time::Instant::now(), set));
            }
            set
        }
    };
    set.has(module)
}

/// Y4-T2: forgets the cached module configuration, so the next tick reads
/// it again (tests, and an operator's change on this node).
pub fn forget_schedule_modules() {
    if let Ok(mut guard) = SCHEDULE_MODULE_SET.lock() {
        *guard = None;
    }
}

async fn tick_or_warn(
    db: &DbPool,
    name: &'static str,
    interval: std::time::Duration,
    job: EngineJob,
    what: &str,
) {
    if !schedule_allowed(db, name).await {
        tracing::debug!(schedule = name, "{what}: its module is off; not scheduled");
        return;
    }
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
/// K2-T2: recent uploads rescanned, weekly.
pub fn spawn_upload_rescan_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::UploadRescanSweep,
        DEDUP_KEY_UPLOAD_RESCAN_SWEEP,
        "upload rescan",
    );
}

/// Z6-T3: a sample of stored files read back, weekly.
pub fn spawn_file_integrity_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::FileIntegritySample,
        DEDUP_KEY_FILE_INTEGRITY_SAMPLE,
        "file integrity sample",
    );
}

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

/// AA10-T5: daily, mass-operation undo values past retention cleared.
pub fn spawn_heavy_op_undo_retention_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(HEAVY_OP_UNDO_RETENTION.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "mass undo retention: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_HEAVY_OP_UNDO_RETENTION,
        "mass undo retention",
    );
}

/// A9-T3: daily, stored formulas over the clock recomputed.
pub fn spawn_time_formula_recompute_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(TIME_FORMULA_RECOMPUTE.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "time-based formula recompute: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_TIME_FORMULA_RECOMPUTE,
        "time-based formula recompute",
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

/// M15-T2: every five minutes, the held-notification sweep.
pub fn spawn_notification_queue_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(NOTIFICATION_QUEUE_SWEEP.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "notification queue sweep: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_NOTIFICATION_QUEUE,
        "notification queue sweep",
    );
}

/// L6-T5: every five minutes, scheduled data profiles and retention.
pub fn spawn_data_profile_schedule_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(DATA_PROFILE_SCHEDULE.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "data profile schedule: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_DATA_PROFILE_SCHEDULE,
        "data profile schedule",
    );
}

/// M9-T3: every minute, the approval email links.
pub fn spawn_approval_email_links_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(APPROVAL_EMAIL_LINKS.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "approval email links: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_APPROVAL_EMAIL_LINKS,
        "approval email links",
    );
}

/// M5-T4: hourly, the dead-letter sweep.
pub fn spawn_dead_letter_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(DEAD_LETTER_SWEEP.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "dead-letter sweep: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_DEAD_LETTER_SWEEP,
        "dead-letter sweep",
    );
}

/// Z1-T11: every five minutes, integration OAuth tokens renewed before
/// they expire.
pub fn spawn_oauth_refresh_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(OAUTH_REFRESH.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "integration OAuth refresh: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_OAUTH_REFRESH,
        "integration OAuth refresh",
    );
}

/// D15-T3: every five minutes, meetings and people's calendars in step.
pub fn spawn_calendar_sync_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(CALENDAR_SYNC.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "calendar sync: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_CALENDAR_SYNC, "calendar sync");
}

/// D15-T2: every five minutes, personal mail onto matching records.
pub fn spawn_mail_capture_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(MAIL_CAPTURE.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "mail capture: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_MAIL_CAPTURE, "mail capture");
}

/// J2-T2: every two minutes, shared mailboxes into the desk.
pub fn spawn_inbound_mail_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(INBOUND_MAIL.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "inbound mail: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_INBOUND_MAIL, "inbound mail");
}

/// G1-T3: every minute, summaries for case threads gone quiet.
pub fn spawn_case_summary_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(CASE_SUMMARY.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "case summary: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_CASE_SUMMARY, "case summary");
}

/// E3-T1: every minute, the next batch of each email campaign.
pub fn spawn_email_campaign_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(EMAIL_CAMPAIGN.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "email campaign: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_EMAIL_CAMPAIGN,
        "email campaign",
    );
}

/// E16-T1: every five minutes, the next batch of each SMS campaign.
pub fn spawn_sms_campaign_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(SMS_CAMPAIGN.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "sms campaign: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_SMS_CAMPAIGN, "sms campaign");
}

/// E6-T8: the daily blocklist check and reputation fetch.
pub fn spawn_sender_reputation_schedulers(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    for (job_type, key, what) in [
        (
            BLOCKLIST_CHECK,
            DEDUP_KEY_BLOCKLIST_CHECK,
            "blocklist check",
        ),
        (
            REPUTATION_FETCH,
            DEDUP_KEY_REPUTATION_FETCH,
            "reputation fetch",
        ),
    ] {
        match attome_core::jobs::JOB_TYPES.job(job_type.name, &()) {
            Ok(job) => {
                spawn_dedup_scheduler(db.clone(), interval, EngineJob::Registered(job), key, what)
            }
            Err(error) => tracing::error!(%error, what, "not scheduled"),
        }
    }
}

/// E22-T1: every fifteen minutes, webinar registrants and attendance.
pub fn spawn_webinar_sync_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(WEBINAR_SYNC.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "webinar sync: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_WEBINAR_SYNC, "webinar sync");
}

/// E7-T6: every five seconds, one tick of live segments (one pending at most).
pub fn spawn_segment_live_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(SEGMENT_LIVE.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "live segments: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(db, interval, job, DEDUP_KEY_SEGMENT_LIVE, "live segments");
}

/// I6-T2: every minute, one tick of work order stock.
pub fn spawn_stock_ledger_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(STOCK_LEDGER.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_STOCK_LEDGER,
            "work order stock",
        ),
        Err(error) => tracing::error!(%error, "work order stock: not scheduled"),
    }
}

/// I1-T2: every five minutes, one tick of work order invoicing.
pub fn spawn_work_order_invoicing_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(WORK_ORDER_INVOICING.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_WORK_ORDER_INVOICING,
            "work order invoicing",
        ),
        Err(error) => tracing::error!(%error, "work order invoicing: not scheduled"),
    }
}

/// G17-T9: every fifteen minutes, intraday offers.
pub fn spawn_intraday_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(WORKFORCE_INTRADAY.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_INTRADAY,
            "workforce intraday",
        ),
        Err(error) => tracing::error!(%error, "workforce intraday: not scheduled"),
    }
}

/// G14-T2: every minute, surveys sent on record changes.
/// AI8-T3: every hour, yesterday's agent rollup once the day reaches 02:00.
pub fn spawn_agent_stats_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(AGENT_STATS_ROLLUP.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_AGENT_STATS,
            "agent performance rollup",
        ),
        Err(error) => tracing::error!(%error, "agent performance rollup: not scheduled"),
    }
}

/// A20-T2: every hour, missing label translations drafted for review.
pub fn spawn_label_drafts_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(LABEL_DRAFTS.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_LABEL_DRAFTS,
            "label translation drafts",
        ),
        Err(error) => tracing::error!(%error, "label translation drafts: not scheduled"),
    }
}

/// AK3-T5: every minute, the change feed counted into the work share.
pub fn spawn_work_share_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(WORK_SHARE.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_WORK_SHARE,
            "work share",
        ),
        Err(error) => tracing::error!(%error, "work share: not scheduled"),
    }
}

/// AH5-T2: every five minutes, agents compared with their baselines.
pub fn spawn_agent_check_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(AGENT_CHECK.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_AGENT_CHECK,
            "agent departure check",
        ),
        Err(error) => tracing::error!(%error, "agent departure check: not scheduled"),
    }
}

/// AH5-T1: every hour, the hour just ended rolled up per agent.
pub fn spawn_agent_behaviour_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(AGENT_BEHAVIOUR.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_AGENT_BEHAVIOUR,
            "agent behaviour roll-up",
        ),
        Err(error) => tracing::error!(%error, "agent behaviour roll-up: not scheduled"),
    }
}

/// O10-T1: once a day, executed decisions measured after their measure date.
pub fn spawn_decision_measure_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(DECISION_MEASURE.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_DECISION_MEASURE,
            "decision measurement",
        ),
        Err(error) => tracing::error!(%error, "decision measurement: not scheduled"),
    }
}

/// F5-T12: once a day, accounts with long-overdue invoices put on credit hold.
pub fn spawn_credit_hold_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CREDIT_HOLD.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CREDIT_HOLD,
            "credit hold",
        ),
        Err(error) => tracing::error!(%error, "credit hold: not scheduled"),
    }
}

/// AK2-T1: every hour, the operations digest once Monday reaches 06:00 UTC.
pub fn spawn_ops_digest_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(OPS_DIGEST.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_OPS_DIGEST,
            "operations digest",
        ),
        Err(error) => tracing::error!(%error, "operations digest: not scheduled"),
    }
}

/// AI5-T4: every five minutes, promises to pay read from replies.
pub fn spawn_promise_extract_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(PROMISE_EXTRACT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_PROMISE_EXTRACT,
            "promise reader",
        ),
        Err(error) => tracing::error!(%error, "promise reader: not scheduled"),
    }
}

/// AI6-T3: every fifteen minutes, meetings an hour away queued for a brief.
pub fn spawn_meeting_brief_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(MEETING_BRIEF_SCAN.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_MEETING_BRIEF_SCAN,
            "meeting brief scan",
        ),
        Err(error) => tracing::error!(%error, "meeting brief scan: not scheduled"),
    }
}

pub fn spawn_survey_send_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(SURVEY_SEND.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_SURVEY_SEND,
            "survey sending",
        ),
        Err(error) => tracing::error!(%error, "survey sending: not scheduled"),
    }
}

/// V5-T1: every minute, change requests decided by customer sign-off.
pub fn spawn_change_signoff_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CHANGE_SIGNOFF.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CHANGE_SIGNOFF,
            "change sign-off",
        ),
        Err(error) => tracing::error!(%error, "change sign-off: not scheduled"),
    }
}

/// W3-T4: every five minutes, sealed RFQ bids opened at their deadline.
pub fn spawn_rfq_open_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(RFQ_OPEN.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_RFQ_OPEN,
            "rfq opening",
        ),
        Err(error) => tracing::error!(%error, "rfq opening: not scheduled"),
    }
}

/// W2-T1: daily, vendor compliance document reminder timers.
pub fn spawn_compliance_expiry_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(COMPLIANCE_EXPIRY.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_COMPLIANCE_EXPIRY,
            "compliance document reminders",
        ),
        Err(error) => tracing::error!(%error, "compliance document reminders: not scheduled"),
    }
}

/// I5-T2: daily, maintenance plan timers and meter checks.
pub fn spawn_maintenance_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(MAINTENANCE_GENERATION.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_MAINTENANCE,
            "maintenance generation",
        ),
        Err(error) => tracing::error!(%error, "maintenance generation: not scheduled"),
    }
}

/// I7-T1: every minute, new device readings and device rules.
pub fn spawn_device_readings_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(DEVICE_READINGS.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_DEVICE_READINGS,
            "device readings",
        ),
        Err(error) => tracing::error!(%error, "device readings: not scheduled"),
    }
}

/// Q22-T1: every five minutes, the security detection rules.
pub fn spawn_security_detections_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(SECURITY_DETECTIONS.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_SECURITY_DETECTIONS,
            "security detections",
        ),
        Err(error) => tracing::error!(%error, "security detections: not scheduled"),
    }
}

/// F6-T3: every 30 seconds, confirmed orders into fulfilment orders.
pub fn spawn_fulfilment_split_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(FULFILMENT_SPLIT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_FULFILMENT_SPLIT,
            "fulfilment split",
        ),
        Err(error) => tracing::error!(%error, "fulfilment split: not scheduled"),
    }
}

/// F6-T13: every minute, shipped and delivered shipments asked for billing.
pub fn spawn_fulfilment_billing_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(FULFILMENT_BILLING.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_FULFILMENT_BILLING,
            "fulfilment billing",
        ),
        Err(error) => tracing::error!(%error, "fulfilment billing: not scheduled"),
    }
}

/// AA11-T1: every 30 seconds, entities changed since the last run marked
/// for the aggregate cache.
pub fn spawn_aggregate_cache_marks_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(AGGREGATE_CACHE_MARKS.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_AGGREGATE_CACHE_MARKS,
            "aggregate cache marks",
        ),
        Err(error) => tracing::error!(%error, "aggregate cache marks: not scheduled"),
    }
}

/// A10-T2: every few seconds, fast rollups the change feed's events affect
/// recomputed.
pub fn spawn_rollup_fast_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(ROLLUP_FAST.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_ROLLUP_FAST,
            "rollup fast mode",
        ),
        Err(error) => tracing::error!(%error, "rollup fast mode: not scheduled"),
    }
}

/// Q4-T2: nightly, users and roles synced from the directory (a no-op
/// without `auth.ldap`).
pub fn spawn_ldap_sync_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(LDAP_SYNC.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_LDAP_SYNC,
            "ldap sync",
        ),
        Err(error) => tracing::error!(%error, "ldap sync: not scheduled"),
    }
}

/// A10-T4: nightly, rollups verified and healed.
pub fn spawn_rollup_heal_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(ROLLUP_HEAL.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_ROLLUP_HEAL,
            "rollup heal",
        ),
        Err(error) => tracing::error!(%error, "rollup heal: not scheduled"),
    }
}

/// D4-T1: every 30 seconds, new leads assigned by the rule set.
pub fn spawn_lead_assignment_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(LEAD_ASSIGNMENT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_LEAD_ASSIGNMENT,
            "lead assignment",
        ),
        Err(error) => tracing::error!(%error, "lead assignment: not scheduled"),
    }
}

/// D4-T2: every minute, new leads given their first-touch timer.
pub fn spawn_lead_first_touch_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(LEAD_FIRST_TOUCH.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_LEAD_FIRST_TOUCH,
            "lead first touch",
        ),
        Err(error) => tracing::error!(%error, "lead first touch: not scheduled"),
    }
}

/// D4-T2: daily, stale leads rebalanced.
pub fn spawn_lead_rebalance_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(LEAD_REBALANCE.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_LEAD_REBALANCE,
            "lead rebalance",
        ),
        Err(error) => tracing::error!(%error, "lead rebalance: not scheduled"),
    }
}

/// E14-T8: every ten minutes, closed web sessions summarised onto timelines.
pub fn spawn_web_visit_summary_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(WEB_VISIT_SUMMARY.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_WEB_VISIT_SUMMARY,
            "web visit summary",
        ),
        Err(error) => tracing::error!(%error, "web visit summary: not scheduled"),
    }
}

/// O1-T2: weekly, active prediction models checked for drift.
pub fn spawn_predict_drift_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(PREDICT_DRIFT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_PREDICT_DRIFT,
            "predict drift",
        ),
        Err(error) => tracing::error!(%error, "predict drift: not scheduled"),
    }
}

/// F6-T14: every 15 minutes, late and stuck fulfilment orders.
pub fn spawn_fulfilment_exceptions_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(FULFILMENT_EXCEPTIONS.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_FULFILMENT_EXCEPTIONS,
            "fulfilment exceptions",
        ),
        Err(error) => tracing::error!(%error, "fulfilment exceptions: not scheduled"),
    }
}

/// F6-T10: every 30 minutes, booked shipments' status from their carriers.
pub fn spawn_fulfilment_tracking_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(FULFILMENT_TRACKING.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_FULFILMENT_TRACKING,
            "fulfilment tracking",
        ),
        Err(error) => tracing::error!(%error, "fulfilment tracking: not scheduled"),
    }
}

/// E13-T9: hourly, the sitemaps of sites whose pages changed.
pub fn spawn_content_sitemap_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CONTENT_SITEMAP.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CONTENT_SITEMAP,
            "content sitemaps",
        ),
        Err(error) => tracing::error!(%error, "content sitemaps: not scheduled"),
    }
}

/// E13-T9: nightly, the SEO audit of every published page.
pub fn spawn_content_seo_audit_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CONTENT_SEO_AUDIT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CONTENT_SEO_AUDIT,
            "content seo audit",
        ),
        Err(error) => tracing::error!(%error, "content seo audit: not scheduled"),
    }
}

/// AB2-T6: every 15 seconds, the Patroni cluster's leader.
pub fn spawn_ops_cluster_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(OPS_CLUSTER_POLL.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_OPS_CLUSTER_POLL,
            "ops cluster poll",
        ),
        Err(error) => tracing::error!(%error, "ops cluster poll: not scheduled"),
    }
}

/// AB3-T2: every minute, the live recovery point.
pub fn spawn_ops_live_rpo_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(OPS_LIVE_RPO.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_OPS_LIVE_RPO,
            "ops live rpo",
        ),
        Err(error) => tracing::error!(%error, "ops live rpo: not scheduled"),
    }
}

/// S11-T4: tells one client's owner it expires soon, or has expired and was
/// suspended. A client with no owner (created before S11-T4) is only
/// logged; a failed dispatch is logged, never fatal to the sweep.
async fn notify_s2s_client_owner(
    state: &EngineState,
    notice: &attome_s2s::service_account::ExpiryNotice,
) {
    use attome_s2s::service_account::ExpiryAction;
    let Some(owner) = notice.owner else {
        tracing::warn!(client = %notice.client_id, action = ?notice.action, "s2s client expiry: no owner to tell");
        return;
    };
    let date = notice.expires_at.format("%Y-%m-%d");
    let (subject, body) = match notice.action {
        ExpiryAction::Remind => (
            format!("Integration client \"{}\" expires on {date}", notice.name),
            format!(
                "The integration client \"{}\" ({}) that you own stops working on {date}. \
                 Extend its expiry on the client's admin page if it is still needed.",
                notice.name, notice.client_id
            ),
        ),
        ExpiryAction::Suspend => (
            format!(
                "Integration client \"{}\" expired and was suspended",
                notice.name
            ),
            format!(
                "The integration client \"{}\" ({}) that you own expired on {date} and was \
                 suspended. Set a new expiry and reactivate it if it is still needed.",
                notice.name, notice.client_id
            ),
        ),
    };
    let request = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_owned(),
        recipient_user_ref: Some(owner),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: Some(format!("/xrm/admin/s2s/clients/{}", notice.client_db_id)),
        variables: std::collections::HashMap::new(),
        priority: "high".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        request,
    )
    .await
    {
        tracing::error!(%error, %owner, client = %notice.client_id, "s2s client expiry: notification failed");
    }
}

/// S11-T4: daily, S2S client expiry reminders and suspensions.
pub fn spawn_s2s_client_expiry_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(S2S_CLIENT_EXPIRY.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_S2S_CLIENT_EXPIRY,
            "s2s client expiry",
        ),
        Err(error) => tracing::error!(%error, "s2s client expiry: not scheduled"),
    }
}

/// AB4-T9: daily, stale or failed recovery drills.
pub fn spawn_ops_drill_freshness_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(OPS_DRILL_FRESHNESS.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_OPS_DRILL_FRESHNESS,
            "ops drill freshness",
        ),
        Err(error) => tracing::error!(%error, "ops drill freshness: not scheduled"),
    }
}

/// AB4-T7: daily, the overdue recovery drills.
pub fn spawn_ops_drill_skip_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(OPS_DRILL_SKIP_CHECK.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_OPS_DRILL_SKIP_CHECK,
            "ops drill skip check",
        ),
        Err(error) => tracing::error!(%error, "ops drill skip check: not scheduled"),
    }
}

/// L4-T2: every 15 minutes, the catalog asset index.
pub fn spawn_catalog_asset_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CATALOG_ASSET_REBUILD.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CATALOG_ASSET_REBUILD,
            "catalog asset index",
        ),
        Err(error) => tracing::error!(%error, "catalog asset index: not scheduled"),
    }
}

/// Z8-T4: daily, the configured sending domains' DNS records.
pub fn spawn_email_domain_check_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(EMAIL_DOMAIN_CHECK.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_EMAIL_DOMAIN_CHECK,
            "email domain check",
        ),
        Err(error) => tracing::error!(%error, "email domain check: not scheduled"),
    }
}

/// P13-T1: every five minutes, the warehouse export (a no-op until the
/// setting names entities).
pub fn spawn_warehouse_export_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(WAREHOUSE_EXPORT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_WAREHOUSE_EXPORT,
            "warehouse export",
        ),
        Err(error) => tracing::error!(%error, "warehouse export: not scheduled"),
    }
}

/// A23-T7: every minute, the recurring imports that are due.
pub fn spawn_import_schedule_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(IMPORT_SCHEDULE_TICK.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_IMPORT_SCHEDULE_TICK,
            "recurring imports",
        ),
        Err(error) => tracing::error!(%error, "recurring imports: not scheduled"),
    }
}

/// Z12-T8: daily, the calendar iCal feeds.
pub fn spawn_calendar_feed_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CALENDAR_FEED_FETCH.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CALENDAR_FEED_FETCH,
            "calendar feeds",
        ),
        Err(error) => tracing::error!(%error, "calendar feeds: not scheduled"),
    }
}

/// E13-T10: daily, yesterday's search statistics.
pub fn spawn_content_search_console_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CONTENT_SEARCH_CONSOLE.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CONTENT_SEARCH_CONSOLE,
            "content search console",
        ),
        Err(error) => tracing::error!(%error, "content search console: not scheduled"),
    }
}

/// R11-T1: daily, the evidence collectors.
pub fn spawn_grc_evidence_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(GRC_EVIDENCE_COLLECT.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_GRC_EVIDENCE,
            "grc evidence collection",
        ),
        Err(error) => tracing::error!(%error, "grc evidence collection: not scheduled"),
    }
}

/// R9-T1: daily, policy reviews, attestations and exceptions.
pub fn spawn_grc_policy_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(GRC_POLICY_SWEEP.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_GRC_POLICY_SWEEP,
            "grc policy sweep",
        ),
        Err(error) => tracing::error!(%error, "grc policy sweep: not scheduled"),
    }
}

/// I10-T2: nightly, warranty expiry reminders.
pub fn spawn_warranty_reminder_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(WARRANTY_REMINDER.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_WARRANTY_REMINDER,
            "warranty expiry reminders",
        ),
        Err(error) => tracing::error!(%error, "warranty expiry reminders: not scheduled"),
    }
}

/// F10-T10: every thirty seconds, one tick of plan acceptance.
pub fn spawn_commission_acceptance_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(COMMISSION_ACCEPTANCE.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_COMMISSION_ACCEPTANCE,
            "commission plan acceptance",
        ),
        Err(error) => tracing::error!(%error, "commission plan acceptance: not scheduled"),
    }
}

/// H8-T1: every thirty seconds, one tick of status page notices.
pub fn spawn_status_notify_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(STATUS_PAGE_NOTIFY.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_STATUS_NOTIFY,
            "status page notices",
        ),
        Err(error) => tracing::error!(%error, "status page notices: not scheduled"),
    }
}

/// D23-T7: every ten seconds, one tick of deal coverage (one pending at most).
pub fn spawn_deal_coverage_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(SALES_DEAL_COVERAGE.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_DEAL_COVERAGE,
            "deal coverage",
        ),
        Err(error) => tracing::error!(%error, "deal coverage: not scheduled"),
    }
}

/// J10-T1: every fifteen seconds, one tick of the unified router (one
/// pending at most).
pub fn spawn_service_router_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(SERVICE_ROUTER_TICK.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_SERVICE_ROUTER,
            "service router",
        ),
        Err(error) => tracing::error!(%error, "service router: not scheduled"),
    }
}

/// Z12-T7: every hour, one yearly review check (one pending at most); the
/// check itself sends only once a year.
pub fn spawn_calendar_review_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(CALENDAR_YEARLY_REVIEW.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_CALENDAR_REVIEW,
            "calendar yearly review",
        ),
        Err(error) => tracing::error!(%error, "calendar yearly review: not scheduled"),
    }
}

/// AB11-T4: every minute, one status watch run (one pending at most).
pub fn spawn_ops_status_watch_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    match attome_core::jobs::JOB_TYPES.job(OPS_STATUS_WATCH.name, &()) {
        Ok(job) => spawn_dedup_scheduler(
            db,
            interval,
            EngineJob::Registered(job),
            DEDUP_KEY_OPS_STATUS_WATCH,
            "ops status watch",
        ),
        Err(error) => tracing::error!(%error, "ops status watch: not scheduled"),
    }
}

/// E8-T5: the journey entry tick (every ten seconds) and the date entry
/// (hourly; each date source runs once a deployment day), one pending each.
pub fn spawn_journey_entry_schedulers(db: DbPool, tick: std::time::Duration) {
    register_job_types();
    for (job_type, key, interval, label) in [
        (
            MARKETING_JOURNEY_ENTRY,
            DEDUP_KEY_JOURNEY_ENTRY,
            tick,
            "journey entry",
        ),
        (
            MARKETING_JOURNEY_DATE_ENTRY,
            DEDUP_KEY_JOURNEY_DATE_ENTRY,
            std::time::Duration::from_secs(3_600),
            "journey date entry",
        ),
    ] {
        match attome_core::jobs::JOB_TYPES.job(job_type.name, &()) {
            Ok(job) => {
                spawn_dedup_scheduler(db.clone(), interval, EngineJob::Registered(job), key, label)
            }
            Err(error) => tracing::error!(%error, label, "not scheduled"),
        }
    }
}

/// E23-T1: daily, profile event months past retention.
pub fn spawn_profile_event_retention_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(PROFILE_EVENT_RETENTION.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "profile event retention: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_PROFILE_EVENT_RETENTION,
        "profile event retention",
    );
}

/// E6-T4: hourly, today's and yesterday's deliverability rollup.
pub fn spawn_deliverability_rollup_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(DELIVERABILITY_ROLLUP.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "deliverability rollup: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_DELIVERABILITY_ROLLUP,
        "deliverability rollup",
    );
}

/// M8-T1: runs one change's transition actions through the action gate, in
/// order, as the person who made the change, each with its own idempotency
/// key so a retried job never runs one twice. An action that needs a
/// person's confirmation or approval is left to that path; any refusal or
/// failure fails the job (retried, then a dead letter).
async fn run_transition_actions(
    state: &EngineState,
    payload: attome_state::transition_actions::TransitionActions,
) -> Result<(), attome_types::AppError> {
    let Some(actor) = payload.actor else {
        tracing::warn!(
            entity = %payload.entity,
            record = %payload.record_id,
            "transition actions skipped: no one to run them as"
        );
        return Ok(());
    };
    let security = state.base.security.resolve(actor).await?;
    let registry = attome_ai::ActionRegistry::new();
    let executors = attome_ai::Executors::new();
    let args = serde_json::json!({
        "entity": payload.entity,
        "record_id": payload.record_id,
        "from_state": payload.from_state,
        "to_state": payload.to_state,
    });
    for (index, action) in payload.actions.iter().enumerate() {
        let descriptor = registry.resolve(action).ok_or_else(|| {
            attome_types::AppError::Validation(format!(
                "transition action {action} is not a registered action"
            ))
        })?;
        let mut ctx = attome_ai::ActionContext::user(std::sync::Arc::clone(&security));
        ctx.idempotency_key = Some(attome_state::transition_actions::action_key(
            payload.event_id,
            index,
        ));
        let inputs = attome_ai::GateInputs {
            licensed: state.modules.load().has(descriptor.module),
            ai: &state.base.config.inference.ai,
            surface: Some(attome_config::AiSurface::WorkflowNodes),
            external_effects_enabled: state.base.config.security.external_effects_enabled,
        };
        match attome_ai::dispatch(state, &registry, &executors, action, &ctx, &inputs, &args)
            .await?
        {
            attome_ai::ActionOutcome::Completed { .. } => {}
            _ => tracing::info!(
                action = %action,
                record = %payload.record_id,
                "transition action waits on a person's confirmation or approval"
            ),
        }
    }
    Ok(())
}

/// M8-T1: every minute, committed transitions whose actions are due.
pub fn spawn_transition_actions_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(STATE_TRANSITION_ACTIONS_SWEEP.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "transition actions: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_TRANSITION_ACTIONS_SWEEP,
        "transition actions",
    );
}

/// M8-T3: the automatic transitions passes: `interval` after each write
/// (every minute) and `daily_interval` for conditions that come true with
/// time.
pub fn spawn_auto_transitions_schedulers(
    db: DbPool,
    interval: std::time::Duration,
    daily_interval: std::time::Duration,
) {
    register_job_types();
    for (job_type, key, interval, label) in [
        (
            STATE_AUTO_TRANSITIONS,
            DEDUP_KEY_AUTO_TRANSITIONS,
            interval,
            "automatic transitions",
        ),
        (
            STATE_AUTO_TRANSITIONS_DAILY,
            DEDUP_KEY_AUTO_TRANSITIONS_DAILY,
            daily_interval,
            "automatic transitions (daily)",
        ),
    ] {
        match attome_core::jobs::JOB_TYPES.job(job_type.name, &()) {
            Ok(job) => {
                spawn_dedup_scheduler(db.clone(), interval, EngineJob::Registered(job), key, label)
            }
            Err(error) => tracing::error!(%error, label, "not scheduled"),
        }
    }
}

/// D17-T1: every minute, the contacts who answered a sequence leave it.
pub fn spawn_sequence_exits_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(WORKFLOW_SEQUENCE_EXITS.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "sequence exits: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_SEQUENCE_EXITS,
        "sequence exits",
    );
}

/// F11-T9: nightly, loyalty points deferred and recognised.
pub fn spawn_revrec_loyalty_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(REVREC_LOYALTY.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "loyalty revenue: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_REVREC_LOYALTY,
        "loyalty revenue",
    );
}

/// G17-T10: nightly, yesterday's adherence roll-up.
pub fn spawn_wfm_adherence_day_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(WFM_ADHERENCE_DAY.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "adherence roll-up: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_WFM_ADHERENCE_DAY,
        "adherence roll-up",
    );
}

/// E15-T1: nightly, attribution credit for won opportunities.
pub fn spawn_marketing_attribution_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(MARKETING_ATTRIBUTION.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "marketing attribution: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_MARKETING_ATTRIBUTION,
        "marketing attribution",
    );
}

/// E17-T1: every five minutes, due social posts and their metrics.
pub fn spawn_social_publish_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(SOCIAL_PUBLISH.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "social publish: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_SOCIAL_PUBLISH,
        "social publish",
    );
}

/// E18-T1: every 30 minutes, new Brandwatch mentions.
pub fn spawn_social_mentions_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(SOCIAL_MENTIONS_SYNC.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "social mentions sync: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_SOCIAL_MENTIONS_SYNC,
        "social mentions sync",
    );
}

/// J8-T1: every 15 minutes, new Google reviews.
pub fn spawn_social_reviews_scheduler(db: DbPool, interval: std::time::Duration) {
    register_job_types();
    let job = match attome_core::jobs::JOB_TYPES.job(SOCIAL_REVIEWS_SYNC.name, &()) {
        Ok(job) => EngineJob::Registered(job),
        Err(error) => {
            tracing::error!(%error, "social reviews sync: not scheduled");
            return;
        }
    };
    spawn_dedup_scheduler(
        db,
        interval,
        job,
        DEDUP_KEY_SOCIAL_REVIEWS_SYNC,
        "social reviews sync",
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

/// F11-T3: every minute, revenue contracts for confirmed orders and active
/// subscriptions.
pub fn spawn_revrec_contract_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::RevrecContractSweep,
        DEDUP_KEY_REVREC_CONTRACT_SWEEP,
        "revenue contracts",
    );
}

/// L2-T3: every minute, quality scores for the records that changed.
pub fn spawn_quality_incremental_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::QualityIncrementalSweep,
        DEDUP_KEY_QUALITY_INCREMENTAL_SWEEP,
        "data quality incremental",
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

/// Q10-T9: once a day, the unused-privilege proposals.
pub fn spawn_privilege_usage_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::PrivilegeUsageDaily,
        DEDUP_KEY_PRIVILEGE_USAGE_DAILY,
        "privilege usage daily",
    );
}

/// Q10-T9: every five minutes, this node's privilege-use counts into
/// `privilege_usage_daily`. Per node, not a job: the counts live in this
/// process. Losing one interval on a crash loses analytics, never access.
pub fn spawn_privilege_usage_flush(db: DbPool, interval: std::time::Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(error) = attome_server::privilege_usage::flush(&db).await {
                tracing::warn!(%error, "privilege usage: flush failed; the counts wait for the next one");
            }
        }
    });
}

/// Q15-T5: every ten seconds, this node's buffered full reads of Financial
/// and Health values into `field_view_log`. Per node, like the privilege-use
/// flush: the buffer lives in this process.
pub fn spawn_view_log_flush(db: DbPool, interval: std::time::Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(error) = attome_security::view_log::flush(&db).await {
                tracing::error!(%error, "view log: flush failed; the entries stay buffered for the next one");
            }
        }
    });
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

/// F3-T11: every minute, subscription events handed to revenue and churn.
pub fn spawn_billing_handoff_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingHandoffSweep,
        DEDUP_KEY_BILLING_HANDOFF_SWEEP,
        "billing hand-offs",
    );
}

/// F3-T8: once a day, subscription charges planned.
pub fn spawn_billing_charges_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingGenerateCharges,
        DEDUP_KEY_BILLING_GENERATE_CHARGES,
        "billing charges",
    );
}

/// F3-T9: once a day, renewals and trials.
pub fn spawn_billing_renewal_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::BillingRenewalSweep,
        DEDUP_KEY_BILLING_RENEWAL_SWEEP,
        "billing renewals",
    );
}

/// B15-T1: every five minutes, changed addresses geocoded.
pub fn spawn_geocode_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::GeocodeSweep,
        DEDUP_KEY_GEOCODE_SWEEP,
        "geocode",
    );
}

/// W1-T13: every quarter hour, contracts drafted from their sources.
pub fn spawn_contract_link_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ContractLinkSweep,
        DEDUP_KEY_CONTRACT_LINK_SWEEP,
        "contract links",
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

/// AH6-T3 / AH8-T9 — hourly: compare trial decisions, then propose raises.
pub fn spawn_ai_trial_compare_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AiTrialCompare,
        DEDUP_KEY_AI_TRIAL_COMPARE,
        "trial compare",
    );
}

/// AH8-T8 — once a day: the summary of what agents ran on their own.
pub fn spawn_ai_autonomy_summary_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AiAutonomySummary,
        DEDUP_KEY_AI_AUTONOMY_SUMMARY,
        "autonomy summary",
    );
}

/// AH8 (V2-D693) — sibling of the schedulers above. A seconds-scale
/// interval: an undo window is a wall-clock promise to the person who can
/// cancel it, so the action should run close to its `run_at`.
pub fn spawn_ai_deferred_action_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::AiDeferredActionSweep,
        DEDUP_KEY_AI_DEFERRED_ACTION_SWEEP,
        "deferred action sweep",
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

/// A3-T8 — see `EngineJob::ValidationScoreSweep`'s doc comment. Once/day:
/// a validity score is a nightly snapshot.
pub fn spawn_validation_score_sweep_scheduler(db: DbPool, interval: std::time::Duration) {
    spawn_dedup_scheduler(
        db,
        interval,
        EngineJob::ValidationScoreSweep,
        DEDUP_KEY_VALIDATION_SCORE_SWEEP,
        "validation score sweep",
    );
}

/// Z7-T3: writes the job kinds' concurrency caps before this process's
/// workers start claiming. A failure is logged and the workers start anyway:
/// the caps already in the table (from an earlier start) still apply.
pub async fn install_job_concurrency_caps(db: &DbPool) {
    use attome_jobs::Job as _;
    let caps = EngineJob::concurrency_caps();
    if let Err(e) = attome_jobs::install_concurrency_caps(db, caps).await {
        tracing::error!(error = %e, "job concurrency caps could not be written; the previous caps stay");
    } else {
        tracing::info!(caps = caps.len(), "job concurrency caps installed");
    }
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
    // A1-T10: the history tables of entities with time travel on.
    attome_records::entity_crud::time_travel::maintain(db).await?;
    // A1-T6: the monthly partitions of high-volume entities.
    attome_metadata::provision::storage::maintain_partitions(db).await?;
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
mod schedule_module_tests {
    use super::SCHEDULE_MODULES;

    /// Y4-T2: every mapped schedule names a real module and a real schedule
    /// key of this file, and appears once.
    #[test]
    fn schedule_modules_name_real_modules_and_keys() {
        let source = include_str!("jobs.rs");
        let mut seen = std::collections::HashSet::new();
        for (key, module) in SCHEDULE_MODULES {
            assert!(attome_modules::module_by_name(module).is_some(), "{module}");
            assert!(seen.insert(*key), "{key} is mapped twice");
            assert!(
                source.contains(&format!("&str = \"{key}\";")),
                "{key} is not a schedule key in jobs.rs"
            );
        }
    }
}

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
