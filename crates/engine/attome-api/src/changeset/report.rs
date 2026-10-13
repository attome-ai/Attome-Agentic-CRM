//! Solution 7 Phase 2 (D-788 Topic 14; `SOLUTION-7-PHASE-2-DESIGN.md` §7.1
//! post-apply, §10.3, §10.5) — the release report's lifecycle around an apply
//! run.
//!
//! - [`begin_run`]: before the first operation, the run's report (`building`)
//!   — reused when a resumed run's rows already point at a building one — and
//!   every row of the run gets `report_ref` and, when it carries a
//!   `backup_ref`, `backup_retain_until` = now + 30 days (§7.2, 0542).
//! - The run executes inside `release_report::scope`; executors write their
//!   items into it as their effects commit (built async: nothing waits for
//!   the report, and nothing pauses for a decision).
//! - [`finish_run`]: after the last row succeeded, `building -> ready` with
//!   exact counts and, when the run produced items, **one** notification to
//!   the deployment's administrators through attome-notification's
//!   `create_dispatch_in_tx` **in the ready transaction** (`notified_at` set
//!   there): the flip happens once, so the notification is sent once. A
//!   dispatch failure is logged at `error` and the report is still marked
//!   ready (the report is the durable record; the notification is a pointer
//!   to it). The `attome-api -> attome-notification` crate edge already exists.
//!
//! A run that fails leaves its report `building`: the retry resumes into the
//! same report (`begin_run` finds it through `report_ref`).
//!
//! Recipients ([`notify_recipients`]): by default the active users holding
//! `system.admin` directly or through a role (the admin role's holders). When
//! `metadata.release_report.notify_roles` is set (design §10.5), the active
//! holders of those roles (by name) instead; when none of them has an active
//! holder, the admin holders (logged at `warn`), so a stale role name never
//! silences the notification. At most [`MAX_RECIPIENTS`] either way.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_core::release_report::{self as rr, ReadyReport, ReportSource};
use attome_types::AppError;
use uuid::Uuid;

use crate::bundle::PLATFORM_VERSION;

/// `(id, ref, source, backup_ref)` of one ledger row.
type LedgerBrief = (Uuid, String, String, Option<String>);

/// The notification preference category of the post-apply notification.
pub const NOTIFY_CATEGORY: &str = "release_report";

/// Most administrators one report notifies.
const MAX_RECIPIENTS: i64 = 100;

/// Longest `release` label stored.
const MAX_RELEASE_CHARS: usize = 2_000;

/// The report page a notification links to (the report-page lane builds it).
pub fn report_route(report_id: Uuid) -> String {
    format!("/admin/release-reports/{report_id}")
}

/// `"<platform version>: <ref>, <ref>, ..."`, bounded.
fn release_label(refs: &[String]) -> String {
    let mut label = format!("{PLATFORM_VERSION}: {}", refs.join(", "));
    if label.chars().count() > MAX_RELEASE_CHARS {
        label = label.chars().take(MAX_RELEASE_CHARS - 1).collect();
        label.push('…');
    }
    label
}

/// The report source of a ledger row's source (`adopt` never runs; it maps to
/// `admin` for completeness).
fn source_of(ledger_source: &str) -> ReportSource {
    ReportSource::parse(ledger_source).unwrap_or(ReportSource::Admin)
}

/// The run's report: the building report these rows already point at (a
/// resumed run), else a new one. Stamps `report_ref` and
/// `backup_retain_until` on the rows not yet done. The ledger's
/// `row_version`/`updated_at` are left alone: they drive the claim CAS and
/// its takeover timeout. `None` when every row is already done (a
/// re-delivered job): there is nothing to report.
pub async fn begin_run(state: &EngineState, apply_ids: &[Uuid]) -> Result<Option<Uuid>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM changeset_apply \
         WHERE id = ANY($1) AND status NOT IN ('succeeded', 'adopted')",
    )
    .bind(apply_ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if pending == 0 {
        return Ok(None);
    }
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT r.id FROM changeset_apply a \
         JOIN release_report r ON r.id = a.report_ref \
         WHERE a.id = ANY($1) AND r.status = 'building' \
         ORDER BY r.created_at DESC LIMIT 1",
    )
    .bind(apply_ids)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let report_id = match existing {
        Some(id) => id,
        None => {
            let rows: Vec<LedgerBrief> = sqlx::query_as(
                "SELECT id, ref, source, backup_ref FROM changeset_apply \
                 WHERE id = ANY($1)",
            )
            .bind(apply_ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            // In the run's order, not the table's.
            let by_id: HashMap<Uuid, &LedgerBrief> = rows.iter().map(|r| (r.0, r)).collect();
            let ordered: Vec<&LedgerBrief> = apply_ids
                .iter()
                .filter_map(|id| by_id.get(id).copied())
                .collect();
            let refs: Vec<String> = ordered.iter().map(|r| r.1.clone()).collect();
            let source = ordered
                .first()
                .map_or(ReportSource::Admin, |r| source_of(&r.2));
            let backup_ref = ordered.iter().find_map(|r| r.3.clone());
            rr::create_report(
                &mut tx,
                apply_ids,
                &release_label(&refs),
                source,
                backup_ref.as_deref(),
            )
            .await?
        }
    };
    sqlx::query(
        "UPDATE changeset_apply \
            SET report_ref = $1, \
                backup_retain_until = CASE WHEN backup_ref IS NULL THEN backup_retain_until \
                    ELSE COALESCE(backup_retain_until, now() + interval '30 days') END \
          WHERE id = ANY($2) AND status NOT IN ('succeeded', 'adopted') \
            AND report_ref IS DISTINCT FROM $1",
    )
    .bind(report_id)
    .bind(apply_ids)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(report_id))
}

/// Active users holding `system.admin` directly or through a role.
async fn admin_recipients(conn: &mut sqlx::PgConnection) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT u.id FROM user_account u \
         WHERE u.is_active = true AND ( \
             EXISTS (SELECT 1 FROM user_account_mm_privilege up \
                     JOIN privilege p ON p.id = up.privilege_ref \
                     WHERE up.user_ref = u.id AND up.is_active = true \
                       AND p.is_active = true AND p.key = $1) \
          OR EXISTS (SELECT 1 FROM user_account_mm_role ur \
                     JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
                     JOIN privilege p ON p.id = rp.privilege_ref \
                     WHERE ur.user_ref = u.id AND ur.is_deleted = false \
                       AND rp.is_deleted = false AND p.is_active = true AND p.key = $1)) \
         ORDER BY u.id LIMIT $2",
    )
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .bind(MAX_RECIPIENTS)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Active users holding one of the named roles (`role.name`).
async fn role_recipients(
    conn: &mut sqlx::PgConnection,
    roles: &[String],
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT u.id FROM user_account u \
         WHERE u.is_active = true AND EXISTS ( \
             SELECT 1 FROM user_account_mm_role ur \
             JOIN role r ON r.id = ur.role_ref AND r.is_deleted = false \
             WHERE ur.user_ref = u.id AND ur.is_deleted = false AND r.name = ANY($1)) \
         ORDER BY u.id LIMIT $2",
    )
    .bind(roles)
    .bind(MAX_RECIPIENTS)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// The notification's recipients (module doc): the configured roles'
/// holders, else (unset, or none of them held) the administrators.
async fn notify_recipients(
    conn: &mut sqlx::PgConnection,
    notify_roles: Option<&[String]>,
) -> Result<Vec<Uuid>, AppError> {
    if let Some(roles) = notify_roles {
        let users = role_recipients(conn, roles).await?;
        if !users.is_empty() {
            return Ok(users);
        }
        tracing::warn!(
            ?roles,
            "release report: no active user holds any role in \
             metadata.release_report.notify_roles; notifying the administrators instead"
        );
    }
    admin_recipients(conn).await
}

/// `"2 conflict, 1 field deleted"`.
fn kinds_text(by_kind: &[(String, i64)]) -> String {
    by_kind
        .iter()
        .map(|(kind, n)| format!("{n} {}", kind.replace('_', " ")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One dispatch per administrator, in the ready transaction; then
/// `notified_at`. Returns the recipients notified.
async fn notify(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    ready: &ReadyReport,
) -> Result<usize, AppError> {
    let recipients = notify_recipients(
        tx,
        state
            .base
            .config
            .metadata
            .release_report
            .notify_roles
            .as_deref(),
    )
    .await?;
    let by_kind = rr::counts_by_kind(tx, ready.id).await?;
    let subject = format!(
        "Release report: {} item(s) to review ({} open)",
        ready.items_total, ready.items_open
    );
    let body = format!(
        "The release {} was applied. Its report lists {}. Open the report to review it; \
         nothing is blocked while items stay open.",
        ready.release,
        kinds_text(&by_kind)
    );
    for user in &recipients {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(*user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(report_route(ready.id)),
            variables: HashMap::new(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch_in_tx(
            tx,
            &state.base.config.notification,
            req,
            Some(NOTIFY_CATEGORY),
        )
        .await?;
    }
    rr::set_notified(tx, ready.id).await?;
    Ok(recipients.len())
}

/// Post-apply: `building -> ready` and the one notification (module doc).
/// Idempotent: a report already ready is left as it is.
pub async fn finish_run(state: &EngineState, report_id: Uuid) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(ready) = rr::mark_ready(&mut tx, report_id).await? else {
        return attome_db::tx::commit(tx).await;
    };
    if ready.items_total == 0 || !ready.source.notifies() {
        attome_db::tx::commit(tx).await?;
        tracing::info!(report_id = %ready.id, items = ready.items_total,
            "release report ready (no notification)");
        return Ok(());
    }
    match notify(&mut tx, state, &ready).await {
        Ok(recipients) => {
            attome_db::tx::commit(tx).await?;
            tracing::info!(report_id = %ready.id, items = ready.items_total,
                open = ready.items_open, recipients,
                "release report ready; administrators notified");
            Ok(())
        }
        Err(error) => {
            tx.rollback().await.map_err(AppError::internal)?;
            tracing::error!(report_id = %ready.id, %error,
                "release report: the post-apply notification failed; the report is marked \
                 ready without it (open it from the release-report list)");
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            rr::mark_ready(&mut tx, report_id).await?;
            attome_db::tx::commit(tx).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_release_label_names_the_version_and_changesets_and_is_bounded() {
        let label = release_label(&[
            "product/crm/0003-accounts".into(),
            "project/x/0001-a".into(),
        ]);
        assert!(label.starts_with(PLATFORM_VERSION));
        assert!(label.ends_with("product/crm/0003-accounts, project/x/0001-a"));
        let long: Vec<String> = (0..500).map(|i| format!("project/x/{i:04}-name")).collect();
        assert_eq!(release_label(&long).chars().count(), MAX_RELEASE_CHARS);
    }

    #[test]
    fn ledger_sources_map_to_report_sources() {
        assert_eq!(source_of("boot"), ReportSource::Boot);
        assert_eq!(source_of("admin"), ReportSource::Admin);
        assert_eq!(source_of("replay"), ReportSource::Replay);
        assert_eq!(source_of("adopt"), ReportSource::Admin);
    }

    #[test]
    fn the_notification_names_the_counts_by_kind() {
        let text = kinds_text(&[("conflict".into(), 2), ("field_deleted".into(), 1)]);
        assert_eq!(text, "2 conflict, 1 field deleted");
        assert_eq!(
            report_route(Uuid::nil()),
            format!("/admin/release-reports/{}", Uuid::nil())
        );
    }
}
