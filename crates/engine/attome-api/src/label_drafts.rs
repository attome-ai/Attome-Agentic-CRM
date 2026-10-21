//! A20-T2: agent-drafted translations of metadata labels, for a person to
//! review.
//!
//! For each language in `i18n.draft_locales` (none by default, so nothing
//! happens until an administrator names one), the job [`DRAFT_JOB`] takes the
//! entity, attribute and choice labels that have no translation in it, and
//! the earlier drafts whose source text changed since, and translates up to
//! [`MAX_PER_RUN`] of them through `text.translate` (the glossary, the
//! cache, the model approval and the budget apply as for any call). Each is
//! written with status `draft` and the source's hash, so the workbench
//! (A20-T3) lists it as a draft for review. A person's reviewed translation
//! is never replaced, even when its source changed: the workbench shows it as
//! stale for the person to redo. Drafts are this deployment's own (customer
//! layer) and are not recorded into a changeset; a person's review is.

use std::sync::Arc;

use attome_core::{EngineState, acquire_label_write_lock, append_label_change_log};
use attome_types::AppError;
use uuid::Uuid;

/// The registered job that drafts missing translations.
pub const DRAFT_JOB: &str = "label_translation_drafts";
/// Most labels one run drafts per language.
pub const MAX_PER_RUN: usize = 100;

/// Whether a label in a language should get an agent draft: it has no
/// translation, or its translation is an earlier draft (not reviewed) whose
/// source changed. Pure.
pub fn draftable(has_target: bool, reviewed: bool, stale: bool) -> bool {
    !has_target || (stale && !reviewed)
}

/// The languages to draft into, from `i18n.draft_locales`.
pub fn draft_locales(state: &EngineState) -> Vec<String> {
    let store = state.settings.load();
    let registry = attome_core::setting_registry();
    registry
        .get("i18n.draft_locales")
        .map(|d| store.resolve(d, None, None).0)
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .filter(|l| attome_core::is_valid_locale_tag(l))
        .collect()
}

/// Writes one draft, unless a person's translation is there.
async fn write_draft(
    state: &EngineState,
    kind: &str,
    object_ref: &str,
    locale: &str,
    text: &str,
    source: &str,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    acquire_label_write_lock(&mut tx, kind, object_ref, locale).await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO metadata_label \
             (object_kind, object_ref, locale, display_name, owner_layer, source_hash, status) \
         VALUES ($1, $2, $3, $4, $5, $6, 'draft') \
         ON CONFLICT (object_kind, object_ref, locale) WHERE is_deleted = FALSE \
         DO UPDATE SET display_name = EXCLUDED.display_name, \
             source_hash = EXCLUDED.source_hash, updated_at = NOW(), \
             row_version = metadata_label.row_version + 1 \
           WHERE metadata_label.status = 'draft' \
         RETURNING id",
    )
    .bind(kind)
    .bind(object_ref)
    .bind(locale)
    .bind(text)
    .bind(attome_core::changeset::Layer::Customer.as_str())
    .bind(crate::metadata_label_admin::text_hash(source))
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if id.is_none() {
        return Ok(false);
    }
    append_label_change_log(&mut tx, kind, object_ref, locale, false).await?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// One run: drafts up to [`MAX_PER_RUN`] labels per configured language.
/// Returns how many it drafted.
pub async fn draft_missing(state: &EngineState) -> Result<usize, AppError> {
    let locales = draft_locales(state);
    if locales.is_empty() {
        return Ok(0);
    }
    let security = attome_records::entity_crud::admin_security_context(Uuid::nil());
    let ctx = attome_ai::context::ActionContext::user(Arc::new(security));
    let mut drafted = 0;
    for locale in &locales {
        let rows = crate::metadata_label_admin::workbench_rows(state, locale).await?;
        let to_draft = rows
            .into_iter()
            .filter(|(r, reviewed)| draftable(r.target.is_some(), *reviewed, r.status == "stale"))
            .take(MAX_PER_RUN);
        for (row, _) in to_draft {
            let Some((kind, object_ref)) = row.key.split_once(':') else {
                continue;
            };
            let text = match attome_ai::actions::translate::translate(
                state,
                &ctx,
                &row.source,
                None,
                locale,
            )
            .await
            {
                Ok(text) if !text.trim().is_empty() => text,
                Ok(_) => continue,
                Err(error) => {
                    tracing::warn!(%error, locale, key = %row.key, "label draft: not translated");
                    break;
                }
            };
            if write_draft(state, kind, object_ref, locale, text.trim(), &row.source).await? {
                drafted += 1;
            }
        }
    }
    if drafted > 0 {
        crate::metadata_label_admin::refresh_labels(state).await;
        tracing::info!(drafted, "label translations drafted for review");
    }
    Ok(drafted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_drafts_fill_gaps_and_redo_stale_drafts_only() {
        assert!(draftable(false, true, false), "untranslated");
        assert!(draftable(true, false, true), "a stale draft is redone");
        assert!(!draftable(true, true, true), "a person's work is left");
        assert!(!draftable(true, false, false), "a current draft waits");
    }
}
