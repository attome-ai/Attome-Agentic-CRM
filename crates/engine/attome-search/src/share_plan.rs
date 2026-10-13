//! Choosing between the two visibility shapes (TODO-053).
//!
//! ## The caller this exists for
//!
//! The organization fast tier (TODO-003) helps a BusinessUnit-level caller and
//! nobody else. A caller whose visibility comes from **share rows** gets no
//! tier at all, so the standard fragment's `EXISTS` runs once per candidate the
//! text scan produces — §8.1 puts that at roughly 4 µs/row, and a broad query
//! can produce ~50k candidates to fill one page. That is ~200 ms of pure
//! permission checking, on typeahead too, for precisely the narrowed users the
//! whole design exists to protect. v1 offered them nothing.
//!
//! Meanwhile the *answer* is usually small: a few hundred shared records, and
//! `record_share` is already indexed by principal
//! (`core_record_share_principal_idx`, migration 0051). Driving from the share
//! table into the text match turns a 50k-row filter into a semi-join against a
//! few hundred rows.
//!
//! ## The estimate decides *whether*, never *what*
//!
//! [`plan_visibility_shape`] runs a bounded count and inverts only below a
//! threshold. A stale or wrong estimate must therefore be a *performance*
//! mistake and never a correctness one — which is why the emitted SQL carries
//! no `LIMIT` on the share side, and why
//! `PolymorphicVisibility::share_inversion_eligible` is an exact structural
//! check rather than part of this heuristic. Get the estimate wrong and a query
//! is slow; get the eligibility wrong and a caller silently stops seeing
//! records they are entitled to.
//!
//! ## Why a threshold at all
//!
//! Above it, the share set stops being the small side. A caller reachable
//! through 200k shares would have the planner build a hash from 200k rows to
//! filter a text scan that might return 40 — strictly worse than the per-row
//! form, which at least starts from the text index. The standard shape is
//! correct for everyone, so falling back to it is always safe.

use attome_security::visibility::PolymorphicVisibility;
use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

use crate::legs::VisibilityShape;

/// Above this many reachable shares, the share set is no longer the small side
/// and the standard shape wins.
///
/// Chosen as the point where a hash build over the share set costs about what
/// the per-row `EXISTS` costs over a full candidate ceiling (500 rows/leg × 4
/// legs, several ceilings deep on a broad query). It is a starting point, and
/// the kind of number that should be re-derived from the load test rather than
/// argued about — `search.js` is where that measurement lives.
pub const SHARE_INVERSION_MAX: i64 = 5_000;

/// Picks the visibility shape for this request.
///
/// Never fails a search: an estimate error falls back to
/// [`VisibilityShape::PerRow`], which is correct for every caller. Being unable
/// to *optimize* is not a reason to refuse to answer.
pub async fn plan_visibility_shape(
    db: &PgPool,
    visibility: &PolymorphicVisibility<'_>,
    user_id: Uuid,
    team_ids: &[Uuid],
    subordinate_user_ids: &[Uuid],
) -> VisibilityShape {
    if !visibility.share_inversion_eligible() {
        return VisibilityShape::PerRow;
    }

    match count_reachable_shares(db, user_id, team_ids, subordinate_user_ids).await {
        Ok(n) if n <= SHARE_INVERSION_MAX => VisibilityShape::ShareSemiJoin,
        Ok(_) => VisibilityShape::PerRow,
        Err(e) => {
            tracing::warn!(error = %e, "share-count estimate failed; using the standard shape");
            VisibilityShape::PerRow
        }
    }
}

/// How far the bounded count looks.
///
/// One past the threshold, necessarily: a count capped *at* the threshold can
/// never distinguish "exactly at the limit" from "far above it", so the
/// optimization would apply to every caller above it — the population it exists
/// to exclude.
const COUNT_BOUND: i64 = SHARE_INVERSION_MAX + 1;

/// A **bounded** count of the caller's reachable shares.
///
/// `LIMIT` inside the subquery, so a caller with a million shares costs the
/// same as one with five thousand and one. An unbounded `COUNT(*)` here would
/// make the optimization's own decision the expensive part of the request —
/// and it would be most expensive for exactly the callers it is deciding
/// against.
async fn count_reachable_shares(
    db: &PgPool,
    user_id: Uuid,
    team_ids: &[Uuid],
    subordinate_user_ids: &[Uuid],
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM ( \
           SELECT 1 FROM record_share s \
            WHERE s.capability BETWEEN 0 AND 1 \
              AND ( (s.principal_type = 0 AND s.principal_id = $1) \
                 OR (s.principal_type = 1 AND s.principal_id = ANY($2::uuid[])) \
                 OR (s.principal_type = 0 AND s.principal_id = ANY($3::uuid[])) ) \
            LIMIT $4 ) x",
    )
    .bind(user_id)
    .bind(team_ids)
    .bind(subordinate_user_ids)
    .bind(COUNT_BOUND)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The count must be able to see past the threshold. Capped *at* it, the
    /// comparison `n <= SHARE_INVERSION_MAX` is true for every caller including
    /// the ones with a million shares — the optimization would then apply
    /// exactly where it is worst.
    #[test]
    fn the_bounded_count_looks_past_the_threshold() {
        const _: () = assert!(SHARE_INVERSION_MAX > 0);
        const _: () = assert!(COUNT_BOUND > SHARE_INVERSION_MAX);
    }
}
