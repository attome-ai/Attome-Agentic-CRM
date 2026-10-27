//! Leavers (roadmap D7-T6, the leaver half): when a user's account is
//! disabled while they still own open deals, the people above them hear about
//! it once, with the deals to reassign.
//!
//! - Access ends with the account (the auth layer refuses a disabled user);
//!   nothing here changes a deal, a team or a split. Splits stay with the
//!   person who earned them; reassigning a deal goes through the owner-change
//!   route, which moves them only when asked.
//! - "Above them" is the position hierarchy: the active users holding the
//!   parent of any position the leaver held. A leaver with no position above
//!   them is reported to the administrators instead.
//! - Each disable is reported once: `sales_leaver_notice` keys a report by the
//!   user and the account's `auth_epoch`, which every disable moves on, so a
//!   user disabled again later is reported again. The notice row and the
//!   notifications are written in one transaction.
//! - A sweep reports at most [`SWEEP_BATCH`] leavers and lists at most
//!   [`LISTED_DEALS`] deals in a notification (with the full count).

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// Leavers one sweep reports at most.
pub const SWEEP_BATCH: i64 = 50;

/// Deals named in one notification; the count covers the rest.
pub const LISTED_DEALS: i64 = 20;

/// The text of one leaver report.
pub fn report_text(leaver: &str, total: i64, deals: &[String]) -> String {
    let mut text = format!(
        "{leaver}'s account was disabled and they still own {total} open deal{}. \
         Reassign them with Change owner on each deal.",
        if total == 1 { "" } else { "s" }
    );
    for name in deals {
        text.push_str("\n- ");
        text.push_str(name);
    }
    let listed = i64::try_from(deals.len()).unwrap_or(i64::MAX);
    if total > listed {
        text.push_str(&format!("\n… and {} more", total - listed));
    }
    text
}

type LeaverRow = (Uuid, i32, Option<String>, String);

/// Reports the disabled users who still own open deals and were not reported
/// for this disable yet; the number reported.
pub async fn sweep_leavers(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('opportunity') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let leavers: Vec<LeaverRow> = sqlx::query_as(
        "SELECT u.id, u.auth_epoch, u.user_name, u.email FROM user_account u \
         WHERE u.is_active = false \
           AND EXISTS (SELECT 1 FROM opportunity o WHERE o.owner_ref = u.id \
                 AND (o.is_active IS NULL OR o.is_active = true) \
                 AND COALESCE(o.stage, '') NOT IN ('closed_won', 'closed_lost')) \
           AND NOT EXISTS (SELECT 1 FROM sales_leaver_notice n \
                 WHERE n.user_ref = u.id AND n.auth_epoch = u.auth_epoch) \
         ORDER BY u.id LIMIT $1",
    )
    .bind(SWEEP_BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut reported = 0;
    for (leaver, epoch, name, email) in leavers {
        if report_one(state, leaver, epoch, name.as_deref().unwrap_or(&email)).await? {
            reported += 1;
        }
    }
    Ok(reported)
}

/// The active users above `leaver` in the position hierarchy, else the
/// administrators.
pub async fn managers(db: &attome_db::DbPool, leaver: Uuid) -> Result<Vec<Uuid>, AppError> {
    let above: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT m.user_ref FROM user_account_mm_position mine \
         JOIN position p ON p.id = mine.position_ref AND p.is_deleted = false \
         JOIN user_account_mm_position m ON m.position_ref = p.parent_position_ref \
              AND m.is_deleted = false \
         JOIN user_account u ON u.id = m.user_ref AND u.is_active = true \
         WHERE mine.user_ref = $1 AND mine.is_deleted = false AND m.user_ref <> $1 \
         ORDER BY m.user_ref",
    )
    .bind(leaver)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if !above.is_empty() {
        return Ok(above);
    }
    sqlx::query_scalar(
        "SELECT DISTINCT up.user_ref FROM user_account_mm_privilege up \
         JOIN privilege p ON p.id = up.privilege_ref AND p.key = 'system.admin' \
         JOIN user_account u ON u.id = up.user_ref AND u.is_active = true \
         WHERE (up.is_active IS NULL OR up.is_active = true) ORDER BY up.user_ref",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Reports one leaver; false when another node reported them first.
async fn report_one(
    state: &EngineState,
    leaver: Uuid,
    epoch: i32,
    leaver_name: &str,
) -> Result<bool, AppError> {
    let db = &state.base.db;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM opportunity WHERE owner_ref = $1 \
           AND (is_active IS NULL OR is_active = true) \
           AND COALESCE(stage, '') NOT IN ('closed_won', 'closed_lost')",
    )
    .bind(leaver)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let deals: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT name FROM opportunity WHERE owner_ref = $1 \
           AND (is_active IS NULL OR is_active = true) \
           AND COALESCE(stage, '') NOT IN ('closed_won', 'closed_lost') \
         ORDER BY close_date NULLS LAST, id LIMIT $2",
    )
    .bind(leaver)
    .bind(LISTED_DEALS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let deals: Vec<String> = deals
        .into_iter()
        .map(|n| n.unwrap_or_else(|| "(no name)".to_owned()))
        .collect();
    let recipients = managers(db, leaver).await?;
    let body = report_text(leaver_name, total, &deals);

    let mut tx = attome_db::tx::begin(db).await?;
    let claimed = sqlx::query(
        "INSERT INTO sales_leaver_notice (user_ref, auth_epoch, open_deals) VALUES ($1, $2, $3) \
         ON CONFLICT (user_ref, auth_epoch) DO NOTHING",
    )
    .bind(leaver)
    .bind(epoch)
    .bind(total)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if claimed == 0 {
        return Ok(false);
    }
    for recipient in recipients {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(recipient),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(format!("Deals to reassign from {leaver_name}")),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some("/xrm/entity/opportunity/list".to_owned()),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch_in_tx(
            &mut tx,
            &state.base.config.notification,
            req,
            Some("sales.leaver"),
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_the_deals_and_counts_the_rest() {
        let text = report_text("Sara", 3, &["Big deal".into(), "Renewal".into()]);
        assert!(text.contains("Sara"));
        assert!(text.contains("3 open deals"));
        assert!(text.contains("- Big deal"));
        assert!(text.contains("… and 1 more"));
        let one = report_text("Ali", 1, &["Only".into()]);
        assert!(one.contains("1 open deal."));
        assert!(!one.contains("more"));
    }
}
