//! AA10-T9: the person who started a background mass operation is told once
//! when it ends, done or failed, with its counts and a link to it.
//!
//! [`notify_finished`] runs after the chunk that ended the operation has
//! committed, never inside it. It claims the operation's `notified_at` and
//! writes the in-app notification in one short transaction of its own, so
//! a retried job, or two workers, tell the person once. The text is in the
//! person's language; no template is needed (the dispatch carries it).

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// What the notice says about an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub kind: String,
    pub entity: String,
    pub status: String,
    pub done: i64,
    pub skipped: i64,
    pub conflicts: i64,
}

/// The subject and text of the notice, in `locale` (`ar…` is Arabic,
/// anything else English). Pure.
pub fn notice_text(ended: &Ended, locale: &str) -> (String, String) {
    let failed = ended.status == "failed";
    if locale.starts_with("ar") {
        let kind = match ended.kind.as_str() {
            "update" => "التحديث",
            "delete" => "الحذف",
            "reassign" => "إعادة الإسناد",
            "restore" => "الاستعادة",
            _ => "العملية",
        };
        let subject = if failed {
            format!("تعذّر إكمال {kind} الجماعي على {}", ended.entity)
        } else {
            format!("اكتمل {kind} الجماعي على {}", ended.entity)
        };
        let text = format!(
            "تم: {}، تُخطّي لعدم الصلاحية: {}، تعارض: {}.",
            ended.done, ended.skipped, ended.conflicts
        );
        (subject, text)
    } else {
        let subject = if failed {
            format!("Mass {} of {} failed", ended.kind, ended.entity)
        } else {
            format!("Mass {} of {} finished", ended.kind, ended.entity)
        };
        let text = format!(
            "Done: {}, skipped (no access): {}, conflicts: {}.",
            ended.done, ended.skipped, ended.conflicts
        );
        (subject, text)
    }
}

/// Tells the starter of `operation` that it ended, when it is done or
/// failed and they have not been told yet. Answers whether a notice was
/// written.
pub async fn notify_finished(state: &EngineState, operation: Uuid) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let claimed: Option<(Uuid, String, String, String, i64, i64, i64)> = sqlx::query_as(
        "UPDATE heavy_operation SET notified_at = now() \
          WHERE id = $1 AND notified_at IS NULL AND status IN ('done', 'failed') \
          RETURNING started_by, kind, entity_logicalname, status, rows_done, \
                    rows_skipped_permission, rows_conflict",
    )
    .bind(operation)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((starter, kind, entity, status, done, skipped, conflicts)) = claimed else {
        return Ok(false);
    };
    let ended = Ended {
        kind,
        entity,
        status,
        done,
        skipped,
        conflicts,
    };
    let locale = state.user_locale(starter);
    let (subject, text) = notice_text(&ended, &locale);
    let req = crate::dispatch::DispatchRequest {
        template_key: None,
        locale: if locale.starts_with("ar") { "ar" } else { "en" }.to_owned(),
        recipient_user_ref: Some(starter),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned()]),
        subject: Some(subject),
        body_html: None,
        body_text: Some(text),
        route: Some(format!("/xrm/operations/{operation}")),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    crate::dispatch::create_dispatch_in_tx(
        &mut tx,
        &state.base.config.notification,
        req,
        Some("mass.operation"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(status: &str) -> Ended {
        Ended {
            kind: "update".into(),
            entity: "account".into(),
            status: status.into(),
            done: 498,
            skipped: 1,
            conflicts: 1,
        }
    }

    #[test]
    fn notice_names_the_counts_in_the_persons_language() {
        let (subject, text) = notice_text(&ended("done"), "en-US");
        assert_eq!(subject, "Mass update of account finished");
        assert!(text.contains("Done: 498") && text.contains("conflicts: 1"));
        let (subject, _) = notice_text(&ended("failed"), "en");
        assert!(subject.ends_with("failed"));
        let (subject, text) = notice_text(&ended("done"), "ar-SA");
        assert!(subject.contains("التحديث"));
        assert!(text.contains("498"));
    }
}
