//! L6-T5: profile drift, scheduled profiles and snapshot retention.
//!
//! Every completed profile is a snapshot. After one completes, it is compared
//! with the entity's previous completed profile, field by field:
//! - the null share rose by [`NULL_JUMP_POINTS`] points or more;
//! - the most frequent value is one the previous profile did not list;
//! - the most common pattern shape changed (L6-T3).
//!
//! The drift found is stored on the profile (`data_profile.drift`, migration
//! 0220) and sent once per entity per run to the data stewards. L3 stewards
//! are not built yet, so system administrators receive it (the plan's
//! fallback).
//!
//! The deployment setting `data_profile.schedule` maps an entity to a cron in
//! the deployment's time zone (`{"contact": "0 2 * * *"}`; none by default).
//! Every five minutes the [`SCHEDULE_JOB`] sweep claims each entity's due
//! slot once (`data_profile_schedule_slot`) and starts its profile as an
//! administrator. The same sweep deletes snapshots older than
//! `data_profile.retention_days` (365 by default).

use attome_core::EngineState;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// The registered job type of the schedule and retention sweep.
pub const SCHEDULE_JOB: &str = "data_profile_schedule";

/// A null share rise, in percentage points, that counts as drift.
pub const NULL_JUMP_POINTS: f64 = 10.0;

/// Snapshots kept by default, in days.
pub const DEFAULT_RETENTION_DAYS: i64 = 365;

/// One field's drift between two snapshots.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Drift {
    pub field: String,
    /// `null_jump`, `new_top_value` or `top_shape_changed`.
    pub kind: &'static str,
    pub before: Value,
    pub after: Value,
}

fn by_field(fields: &[Value]) -> std::collections::HashMap<&str, &Value> {
    fields
        .iter()
        .filter_map(|f| f["field"].as_str().map(|name| (name, f)))
        .collect()
}

/// The drift from `previous` to `current` snapshot fields. Pure.
pub fn compare(previous: &[Value], current: &[Value]) -> Vec<Drift> {
    let before = by_field(previous);
    let mut out = Vec::new();
    for field in current {
        let Some(name) = field["field"].as_str() else {
            continue;
        };
        let Some(prev) = before.get(name) else {
            continue;
        };
        let (old_null, new_null) = (prev["null_pct"].as_f64(), field["null_pct"].as_f64());
        if let (Some(old), Some(new)) = (old_null, new_null)
            && new - old >= NULL_JUMP_POINTS
        {
            out.push(Drift {
                field: name.to_owned(),
                kind: "null_jump",
                before: json!(old),
                after: json!(new),
            });
        }
        let new_top = &field["top_values"][0]["value"];
        if !new_top.is_null() {
            let listed = prev["top_values"]
                .as_array()
                .is_some_and(|values| values.iter().any(|v| &v["value"] == new_top));
            if !listed {
                out.push(Drift {
                    field: name.to_owned(),
                    kind: "new_top_value",
                    before: prev["top_values"][0]["value"].clone(),
                    after: new_top.clone(),
                });
            }
        }
        let (old_shape, new_shape) = (
            &prev["patterns"]["top_shapes"][0]["shape"],
            &field["patterns"]["top_shapes"][0]["shape"],
        );
        if !old_shape.is_null() && !new_shape.is_null() && old_shape != new_shape {
            out.push(Drift {
                field: name.to_owned(),
                kind: "top_shape_changed",
                before: old_shape.clone(),
                after: new_shape.clone(),
            });
        }
    }
    out
}

fn setting(state: &EngineState, key: &str) -> Option<Value> {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
}

/// Compares `profile_id` with its entity's previous completed profile,
/// stores the drift and alerts the stewards once. Best effort for the
/// alert: a failed dispatch is logged.
pub async fn after_run(
    state: &EngineState,
    entity: &str,
    profile_id: Uuid,
) -> Result<usize, AppError> {
    let snapshots: Vec<(Uuid, Value)> = sqlx::query_as(
        "SELECT id, fields FROM data_profile \
          WHERE entity_logicalname = $1 AND status = 'completed' AND NOT is_deleted \
            AND import_job_ref IS NULL \
          ORDER BY completed_at DESC, id DESC LIMIT 2",
    )
    .bind(entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let [(current_id, current), (_, previous)] = snapshots.as_slice() else {
        return Ok(0);
    };
    if *current_id != profile_id {
        return Ok(0);
    }
    let empty = Vec::new();
    let drift = compare(
        previous.as_array().unwrap_or(&empty),
        current.as_array().unwrap_or(&empty),
    );
    if drift.is_empty() {
        return Ok(0);
    }
    sqlx::query("UPDATE data_profile SET drift = $2 WHERE id = $1")
        .bind(profile_id)
        .bind(serde_json::to_value(&drift).map_err(AppError::internal)?)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let summary = drift
        .iter()
        .map(|d| format!("{} ({})", d.field, d.kind))
        .collect::<Vec<_>>()
        .join(", ");
    let recipients = crate::quality_score::admin_recipients(&state.base.db).await?;
    for user in recipients {
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(format!("Data drift in {entity}")),
            body_html: None,
            body_text: Some(format!(
                "The latest profile of {entity} differs from the one before: {summary}."
            )),
            route: None,
            variables: std::collections::HashMap::new(),
            priority: "normal".to_owned(),
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
            tracing::warn!(%entity, %profile_id, %error, "data profile drift: alert not sent");
        }
    }
    Ok(drift.len())
}

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepSummary {
    pub started: usize,
    pub pruned: u64,
}

/// Starts each entity's due scheduled profile once and prunes old snapshots.
pub async fn schedule_sweep(state: &EngineState) -> Result<SweepSummary, AppError> {
    let mut summary = SweepSummary::default();
    let days = setting(state, "data_profile.retention_days")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_RETENTION_DAYS);
    summary.pruned = sqlx::query(
        "DELETE FROM data_profile \
          WHERE status IN ('completed', 'failed') AND created_at < now() - make_interval(days => $1)",
    )
    .bind(i32::try_from(days).unwrap_or(i32::MAX))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    let schedule = setting(state, "data_profile.schedule").unwrap_or(Value::Null);
    let Some(entries) = schedule.as_object().filter(|m| !m.is_empty()) else {
        return Ok(summary);
    };
    let now = attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    let offset = *now.offset();
    let local_now = now.naive_local();
    let admin = crate::quality_score::admin_recipients(&state.base.db)
        .await?
        .into_iter()
        .min();
    let Some(admin) = admin else {
        tracing::warn!("data profile schedule: no administrator to run scheduled profiles as");
        return Ok(summary);
    };
    for (entity, cron) in entries {
        let Some(cron) = cron.as_str() else {
            continue;
        };
        if state.entities.load().get(entity).is_none() {
            continue;
        }
        let Ok(spec) = attome_workflow::schedule_trigger::parse_schedule(
            &json!({ "schedule": { "cron": cron } }),
        ) else {
            tracing::warn!(%entity, cron, "data profile schedule: not a cron; skipped");
            continue;
        };
        let Some(slot) = attome_workflow::schedule_trigger::latest_slot(
            &spec,
            local_now,
            local_now - chrono::Duration::hours(24),
        ) else {
            continue;
        };
        let Some(slot_at) = slot
            .and_local_timezone(offset)
            .single()
            .map(|at| at.with_timezone(&chrono::Utc))
        else {
            continue;
        };
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let claimed = sqlx::query(
            "INSERT INTO data_profile_schedule_slot (entity_logicalname, slot_at) \
             VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(entity)
        .bind(slot_at)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if claimed == 0 {
            continue;
        }
        let profile_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO data_profile (id, entity_logicalname, status, created_by) \
             VALUES ($1, $2, 'pending', $3)",
        )
        .bind(profile_id)
        .bind(entity)
        .bind(admin)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::DataProfile(attome_core::jobs::DataProfilePayload {
                profile_id,
                entity_logicalname: entity.clone(),
                user_id: admin,
                full_scan: false,
                import_job_id: None,
            }),
        )
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        summary.started += 1;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, null_pct: f64, top: &str, shape: &str) -> Value {
        json!({
            "field": name, "null_pct": null_pct,
            "top_values": [{ "value": top, "count": 5 }, { "value": "other", "count": 1 }],
            "patterns": { "top_shapes": [{ "shape": shape, "count": 5 }] },
        })
    }

    #[test]
    fn null_jump_alerts_steward_once() {
        let before = vec![field("email", 2.0, "a@x.sa", "A@A.AA")];
        let after = vec![field("email", 15.0, "a@x.sa", "A@A.AA")];
        let drift = compare(&before, &after);
        assert_eq!(drift.len(), 1, "one null jump, nothing else");
        assert_eq!(drift[0].kind, "null_jump");
        assert!(compare(&after, &after).is_empty(), "no change, no drift");
    }

    #[test]
    fn profile_drift_sees_new_values_and_shapes() {
        let before = vec![field("phone", 0.0, "0501234567", "9999999999")];
        let after = vec![field("phone", 3.0, "+966501234567", "+999999999999")];
        let kinds: Vec<&str> = compare(&before, &after).iter().map(|d| d.kind).collect();
        assert_eq!(kinds, vec!["new_top_value", "top_shape_changed"]);
        let after_known = vec![field("phone", 0.0, "other", "9999999999")];
        assert!(
            compare(&before, &after_known).is_empty(),
            "a value already listed is not new"
        );
    }
}
