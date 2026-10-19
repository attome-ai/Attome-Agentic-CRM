//! M56 Content Management Phase 1 (scheduled publishing) — the periodic
//! sweep that transitions a page between `draft` and `published` once
//! `publish_at`/`unpublish_at` (migration `0230`) has passed `NOW()`.
//! Same bounded-batch, re-derive-current-state shape as
//! `attome_workflow::sla_sweep::sweep`/`attome_security::admin::sweep_due_campaigns`:
//! a crash-and-retry tick just re-scans the same indexed predicate rather
//! than replaying an enqueue-time snapshot, and a row a concurrent admin
//! edit already moved out from under the sweep (lost the `row_version` CAS)
//! is silently skipped, not forced — the next tick re-evaluates it from
//! whatever state it's actually in.
//!
//! Driven by `EngineJob::ContentScheduledPublishSweep`
//! (`crates/server/src/jobs.rs`'s `spawn_content_scheduled_publish_sweep_scheduler`).

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, AuditUserContext,
    audit_service,
};
use attome_core::EngineState;
use attome_types::AppError;
use chrono::Utc;
use uuid::Uuid;

use crate::blocks;
use crate::model::Block;

const SWEEP_BATCH_SIZE: i64 = 500;

/// The system principal recorded as the actor for every sweep-driven
/// transition — never a real `user_account` row, same nil-UUID
/// "policy"/"workflow-engine" idiom `attome_approval::POLICY_ACTOR_ID` and
/// `attome_workflow::scheduler`'s checkpoint audit already use for an automated
/// actor, so the trail reads as "the scheduler did this" rather than a blank
/// name next to a human-looking id.
const SCHEDULER_ACTOR_ID: Uuid = Uuid::nil();

fn scheduler_user_context() -> AuditUserContext {
    AuditUserContext {
        user_id: SCHEDULER_ACTOR_ID,
        user_name: "content-scheduler".to_string(),
        user_display_name: "Content Scheduler (automatic)".to_string(),
        user_email: String::new(),
        user_job_ref: None,
        user_job_name: None,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub published: u64,
    pub unpublished: u64,
    /// A due draft whose current `blocks_draft` fails `blocks::validate_blocks`
    /// (the registry can change between when a draft was saved and when its
    /// `publish_at` arrives — same re-validation `admin::publish_page`
    /// already does at manual publish time). Left in `draft` with
    /// `publish_at` untouched, so a fixed draft saved before the next tick
    /// still goes out, and an operator scanning for "why didn't this page
    /// publish" finds it still in draft rather than missing entirely.
    pub publish_validation_failed: u64,
}

impl SweepStats {
    pub fn total_transitions(&self) -> u64 {
        self.published + self.unpublished
    }
}

#[derive(sqlx::FromRow)]
struct DueDraft {
    id: Uuid,
    blocks_draft: sqlx::types::Json<Vec<Block>>,
    row_version: i64,
}

#[derive(sqlx::FromRow)]
struct DuePublished {
    id: Uuid,
    row_version: i64,
}

/// Re-derives every currently-due transition and applies it. Safe to call
/// repeatedly and concurrently: each row is claimed with an optimistic
/// `row_version` CAS, so two overlapping ticks (or a tick racing an admin's
/// manual publish/edit) never double-apply — the loser's `UPDATE` simply
/// matches zero rows and is skipped.
pub async fn sweep_scheduled_transitions(state: &EngineState) -> Result<SweepStats, AppError> {
    let mut stats = SweepStats::default();

    let due_drafts: Vec<DueDraft> = sqlx::query_as(
        "SELECT id, blocks_draft, row_version FROM content_page p \
         WHERE is_deleted = FALSE AND status = 'draft' \
           AND publish_at IS NOT NULL AND publish_at <= NOW() \
           AND NOT EXISTS (SELECT 1 FROM content_space s \
                            WHERE s.id = p.content_space_id AND s.require_approval) \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for draft in due_drafts {
        if let Err(e) = blocks::validate_blocks(&draft.blocks_draft.0) {
            tracing::warn!(
                page_id = %draft.id,
                error = %e,
                "content scheduled publish sweep: draft fails block validation, skipped"
            );
            stats.publish_validation_failed += 1;
            continue;
        }

        // Same `blocks_published = blocks_draft, status = 'published'`
        // transition `admin::publish_page` performs on a manual publish —
        // this is that same transition, just triggered by the sweep instead
        // of an admin click. `publish_at` is cleared on consumption: left
        // set, a later unpublish (manual or via `unpublish_at`) followed by
        // any future status flip back through this same predicate would
        // silently re-fire a publish the editor never asked for a second
        // time.
        // K5-T1: the publish and its version commit together. A space that
        // requires approval is left out above: its publishes go through
        // approval, never the clock.
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let published: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE content_page \
             SET blocks_published = blocks_draft, status = 'published', published_at = NOW(), \
                 publish_at = NULL, row_version = row_version + 1, updated_at = NOW(), \
                 updated_by = $2 \
             WHERE id = $1 AND is_deleted = FALSE AND status = 'draft' AND row_version = $3 \
             RETURNING id",
        )
        .bind(draft.id)
        .bind(SCHEDULER_ACTOR_ID)
        .bind(draft.row_version)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if published.is_some() {
            crate::versions::record_version_in_tx(&mut tx, draft.id, SCHEDULER_ACTOR_ID, None)
                .await?;
        }
        tx.commit().await.map_err(AppError::internal)?;

        if published.is_some() {
            stats.published += 1;
            write_transition_audit(
                state,
                draft.id,
                "content.page.scheduled_publish",
                "scheduled publish_at reached; page auto-published",
            )
            .await;
        }
    }

    let due_unpublishes: Vec<DuePublished> = sqlx::query_as(
        "SELECT id, row_version FROM content_page \
         WHERE is_deleted = FALSE AND status = 'published' \
           AND unpublish_at IS NOT NULL AND unpublish_at <= NOW() \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for page in due_unpublishes {
        // Reverts to `draft` — `content_public.rs`'s view query only ever
        // selects `status = 'published'`, so this alone drops the page out
        // of public view. `blocks_published` is left in place (not cleared):
        // same "history stays, the live-view predicate is what actually
        // hides it" behavior every other status flip in this schema already
        // relies on; a later republish overwrites it from `blocks_draft`
        // again. `unpublish_at` is cleared on consumption, same reasoning as
        // `publish_at` above — otherwise a later manual republish would be
        // silently auto-unpublished again on the very next tick.
        let unpublished: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE content_page \
             SET status = 'draft', unpublish_at = NULL, row_version = row_version + 1, \
                 updated_at = NOW(), updated_by = $2 \
             WHERE id = $1 AND is_deleted = FALSE AND status = 'published' AND row_version = $3 \
             RETURNING id",
        )
        .bind(page.id)
        .bind(SCHEDULER_ACTOR_ID)
        .bind(page.row_version)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;

        if unpublished.is_some() {
            stats.unpublished += 1;
            // G11-T1: an unpublished article leaves the knowledge index.
            if let Err(e) = crate::article::enqueue_sync(&state.base.db, page.id).await {
                tracing::warn!(page_id = %page.id, error = ?e, "could not queue the article's index update");
            }
            write_transition_audit(
                state,
                page.id,
                "content.page.scheduled_unpublish",
                "scheduled unpublish_at reached; page auto-unpublished",
            )
            .await;
        }
    }

    Ok(stats)
}

async fn write_transition_audit(
    state: &EngineState,
    page_id: Uuid,
    event_name: &str,
    comment: &str,
) {
    let event = AuditEvent {
        organization_ref: attome_core::ROOT_ORGANIZATION_ID,
        category: AuditCategory::Entity,
        entity_name: Some("content_page".to_string()),
        record_id: Some(page_id),
        operation: AuditOperation::Update,
        version_before: None,
        version_after: None,
        user_context: scheduler_user_context(),
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event_name.to_string()),
        event_comment: Some(comment.to_string()),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    if let Err(e) = audit_service(state).write(event).await {
        tracing::error!(
            page_id = %page_id,
            error = %e,
            "content scheduled publish sweep: failed to write audit event"
        );
    }
}
