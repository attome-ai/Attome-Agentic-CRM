//! D21-T8: a shared call list is someone's own; anyone else needs
//! `call_list.share` to fill it or call from it. A list that is not shared
//! answers to the caller's ordinary record access. Checked by the build and
//! claim handlers before they touch the list.

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

/// The privilege to use and edit another person's shared list.
pub const SHARE_KEY: &str = "call_list.share";

/// Whether `user` may use the list. Pure.
pub fn may_use_list(is_shared: bool, owner: Option<Uuid>, user: Uuid, can_share: bool) -> bool {
    !is_shared || owner == Some(user) || can_share
}

/// `Forbidden` when the list is someone else's shared list and `ctx` lacks
/// [`SHARE_KEY`]; `NotFound` when there is no such list.
pub async fn require_list_use(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
) -> Result<(), AppError> {
    let row: Option<(Option<bool>, Option<Uuid>)> = sqlx::query_as(
        "SELECT is_shared, owner_ref FROM call_list \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (is_shared, owner) = row.ok_or(AppError::NotFound)?;
    let can_share = ctx.is_admin || ctx.privileges.contains(SHARE_KEY);
    if may_use_list(is_shared == Some(true), owner, ctx.user_id, can_share) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_list_needs_share_privilege() {
        let me = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        assert!(
            may_use_list(false, Some(other), me, false),
            "a list that is not shared"
        );
        assert!(
            may_use_list(true, Some(me), me, false),
            "my own shared list"
        );
        assert!(
            !may_use_list(true, Some(other), me, false),
            "someone else's shared list"
        );
        assert!(
            may_use_list(true, Some(other), me, true),
            "with call_list.share"
        );
        assert!(
            !may_use_list(true, None, me, false),
            "an unowned shared list"
        );
    }
}
