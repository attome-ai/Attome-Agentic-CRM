//! Owner-scoped record payload projection (M62 plan §5 "Security" — "a
//! subscription must never be a permission bypass"). Re-reads the record
//! fresh from its physical table at delivery time, respecting the
//! subscription owner's `SecurityContext` at both the entity level (the
//! owner must hold `{entity}.read`) and the field level (an `is_sensitive`
//! column the owner lacks a field-security read grant for is never even
//! SELECTed) — the same two checks `attome_api::entity_crud`'s interactive
//! read path applies, reimplemented here against `attome_core::
//! fetch_entity_snapshot` (the same DB-direct metadata read `attome-api`'s
//! own background-job/bundle-plan paths use) rather than shared with
//! `attome-api` directly: `attome-events` is a peer `xrm-*` engine crate and may
//! not depend on `attome-api`, which sits above the engine layer
//! (guidelines §1).

use attome_core::{fetch_entity_snapshot, quote_ident};
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// Builds the `data` object a webhook payload carries for one changed
/// record, scoped to what `owner_ctx` may see. `Ok(None)` — not an error —
/// whenever there is nothing safe/possible to include:
///
/// * the owner lacks entity-level `{entity}.read` — no field-level detail
///   leaks through for an entity the owner cannot read at all;
/// * the entity no longer exists/is inactive (deleted since the event was
///   recorded);
/// * the record itself is not currently live (a delete/purge event's record
///   has `is_active = false` by definition — the delivery still carries
///   `entity`/`record_id`/`operation` regardless, just no `data`; see
///   `dispatch`/`delivery`'s payload assembly).
///
/// Field-level scoping within a readable entity is `select_columns_
/// filtered`'s job (same predicate `entity_crud::build_response` uses on the
/// interactive read path) — an `is_sensitive` column the owner lacks a
/// field-security read grant for is never even SELECTed, so it cannot appear
/// in the JSON regardless of what a caller does with the result afterward.
///
/// Deliberately does NOT re-apply record-level (business-unit/team/share)
/// scoping the way an interactive `GET /api/v1/{entity}/{id}` would — doing
/// so exactly would mean re-deriving the full `rls_predicate` WHERE clause
/// here, a materially larger scope than M62 Phase 1. Entity- and
/// field-level scoping are what the plan's §5 and the test suite's
/// "owner-scoped payload" case actually specify; full row-level scoping is
/// flagged as a Phase 2+ hardening item, not silently assumed equivalent.
pub async fn owner_scoped_record_data(
    db: &DbPool,
    owner_ctx: &SecurityContext,
    entity_logicalname: &str,
    record_id: Uuid,
) -> Result<Option<Value>, AppError> {
    if owner_ctx.require(entity_logicalname, "read").is_err() {
        return Ok(None);
    }

    let entity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(entity_id) = entity_id else {
        return Ok(None);
    };

    let Some(meta) = fetch_entity_snapshot(db, entity_id).await? else {
        return Ok(None);
    };

    let table = quote_ident(entity_logicalname);
    // D-589: webhook payloads are a bulk surface.
    let cols = attome_security::field_gate::bulk_columns(
        owner_ctx,
        entity_logicalname,
        &meta.attrs,
        meta.primary_name_attribute.as_deref(),
    );
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    );

    let row: Option<Value> = sqlx::query_scalar::<_, Value>(&sql)
        .bind(record_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;

    Ok(row)
}

/// M13-T1: the shape of a subscription's webhook body
/// (`event_subscription.payload_shape`, migration 0204).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadShape {
    /// Entity, record id, operation and event name; no `data`, no `changes`.
    Id,
    /// Plus `changes`: each changed attribute the owner may read, with its
    /// old and new value from the outbox row.
    Changes,
    /// Plus `data`: the record as the owner may read it now.
    Full,
}

impl PayloadShape {
    pub const ALL: [&'static str; 3] = ["id", "changes", "full"];

    pub fn as_str(self) -> &'static str {
        match self {
            PayloadShape::Id => "id",
            PayloadShape::Changes => "changes",
            PayloadShape::Full => "full",
        }
    }

    /// `None` for a value the CHECK constraint would refuse.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "id" => Some(PayloadShape::Id),
            "changes" => Some(PayloadShape::Changes),
            "full" => Some(PayloadShape::Full),
            _ => None,
        }
    }

    /// The stored value of an older row or a future shape this build does
    /// not know falls back to `full`, the shape every subscription had
    /// before 0204; the owner scoping is the same either way.
    pub fn from_stored(value: &str) -> Self {
        Self::parse(value).unwrap_or(PayloadShape::Full)
    }
}

/// `{attribute: {"old": .., "new": ..}}` for every attribute in `changed`
/// that `readable` admits, in `changed` order. A value missing from
/// `before`/`after` (a create has no `before`) is `null`. Pure, so the field
/// filter is tested without a database.
pub fn changes_view(
    changed: &[String],
    before: Option<&Value>,
    after: Option<&Value>,
    readable: impl Fn(&str) -> bool,
) -> Value {
    let pick = |side: Option<&Value>, name: &str| {
        side.and_then(|v| v.get(name))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let mut out = serde_json::Map::new();
    for name in changed {
        if !readable(name) {
            continue;
        }
        out.insert(
            name.clone(),
            serde_json::json!({ "old": pick(before, name), "new": pick(after, name) }),
        );
    }
    Value::Object(out)
}

/// The `changes` object of a `changes`-shaped delivery, scoped like
/// [`owner_scoped_record_data`]: `Ok(None)` when the owner cannot read the
/// entity or it is gone; an attribute the owner may not read on the bulk
/// surface (D-589), or one the entity no longer has, is left out. A
/// sensitive value is already `{"ref": true}` on the outbox row (Y7-T1), so
/// even an attribute the owner may read never carries a secret here.
pub async fn owner_scoped_changes(
    db: &DbPool,
    owner_ctx: &SecurityContext,
    entity_logicalname: &str,
    changed: &[String],
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<Option<Value>, AppError> {
    if owner_ctx.require(entity_logicalname, "read").is_err() {
        return Ok(None);
    }
    let entity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(entity_id) = entity_id else {
        return Ok(None);
    };
    let Some(meta) = fetch_entity_snapshot(db, entity_id).await? else {
        return Ok(None);
    };
    let primary = meta.primary_name_attribute.as_deref();
    Ok(Some(changes_view(changed, before, after, |name| {
        meta.attrs.iter().any(|attr| {
            attr.logicalname == name
                && attome_security::field_gate::readable(
                    owner_ctx,
                    entity_logicalname,
                    attr,
                    primary,
                    attome_security::field_gate::Surface::Bulk,
                )
        })
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn payload_shapes_round_trip_and_unknown_falls_back_to_full() {
        for s in PayloadShape::ALL {
            assert_eq!(PayloadShape::parse(s).map(PayloadShape::as_str), Some(s));
        }
        assert_eq!(PayloadShape::parse("everything"), None);
        assert_eq!(PayloadShape::from_stored("everything"), PayloadShape::Full);
    }

    #[test]
    fn payload_shapes_changes_pairs_old_and_new_values() {
        let before = json!({"stage": "open", "amount": 10});
        let after = json!({"stage": "won", "amount": 12});
        let view = changes_view(
            &names(&["stage", "amount"]),
            Some(&before),
            Some(&after),
            |_| true,
        );
        assert_eq!(
            view,
            json!({
                "stage": {"old": "open", "new": "won"},
                "amount": {"old": 10, "new": 12},
            })
        );
    }

    #[test]
    fn payload_shapes_changes_leaves_out_unreadable_attributes() {
        let after = json!({"stage": "won", "salary": 9000});
        let view = changes_view(&names(&["stage", "salary"]), None, Some(&after), |n| {
            n != "salary"
        });
        assert_eq!(view, json!({"stage": {"old": null, "new": "won"}}));
    }

    #[test]
    fn payload_shapes_changes_keeps_a_sensitive_reference_as_written() {
        let after = json!({"national_id": {"ref": true}});
        let view = changes_view(&names(&["national_id"]), None, Some(&after), |_| true);
        assert_eq!(
            view,
            json!({"national_id": {"old": null, "new": {"ref": true}}})
        );
    }
}
