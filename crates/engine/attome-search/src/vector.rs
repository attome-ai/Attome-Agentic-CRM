//! pgvector preconditions, asserted at boot (TODO-029).
//!
//! ## Why this is a boot check and not a comment
//!
//! Stage 2's ANN retrieval depends on two things the schema cannot express:
//! pgvector **>= 0.8** (for `hnsw.iterative_scan`) and a bounded
//! `hnsw.max_scan_tuples`. Without the first, a filtered ANN query silently
//! returns fewer results than it should — not an error, just a shorter list,
//! which reads as "the corpus doesn't have much on that". Without the second,
//! the same query for a **narrowed** caller can scan the entire index.
//!
//! Both failures are invisible at the point of use and expensive to diagnose
//! later, so they are checked once, loudly, at startup — the same reasoning
//! that puts config validation at boot rather than at first use.
//!
//! ## The counter-intuitive part, stated because it will be re-derived wrongly
//!
//! Iterative scan keeps pulling candidates until enough survive the permission
//! filter. **The tighter a caller's scope, the longer it scans.** So the worst
//! latency belongs to the most restricted users — the exact population the
//! whole permission design exists to protect, and the exact opposite of the
//! intuition that "fewer visible rows means less work". `MAX_SCAN_TUPLES` is
//! the bound that trades recall for a latency ceiling, and accepting degraded
//! recall for a very narrow scope is the deliberate choice.

use attome_types::AppError;
use sqlx::PgPool;

/// Minimum pgvector version. `hnsw.iterative_scan` arrived in 0.8.
pub const MIN_PGVECTOR: (u32, u32) = (0, 8);

/// The scan bound, in tuples.
///
/// Sized against the 500 ms route budget rather than against recall: 20k
/// candidate tuples is roughly the most a filtered scan can examine and still
/// leave room for fusion and the display read. A deployment whose narrowed
/// callers routinely hit it should widen their access scope, not this number —
/// the bound is doing its job, and raising it moves the cost onto the request.
pub const MAX_SCAN_TUPLES: i64 = 20_000;

/// `relaxed_order` rather than `strict_order`.
///
/// Strict ordering makes iterative scan re-sort as it goes, which costs more
/// for a result set that RRF is about to re-rank anyway — the fused score, not
/// the ANN distance order, decides what a caller sees.
pub const ITERATIVE_SCAN_MODE: &str = "relaxed_order";

/// Applies the per-session GUCs. Called inside the search transaction, next to
/// `statement_timeout`, so all the route-level bounds sit together.
pub async fn apply_scan_bounds(tx: &mut sqlx::PgConnection) -> Result<(), AppError> {
    sqlx::query(&format!(
        "SET LOCAL hnsw.iterative_scan = {ITERATIVE_SCAN_MODE}"
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(&format!(
        "SET LOCAL hnsw.max_scan_tuples = {MAX_SCAN_TUPLES}"
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Parses `x.y[.z]` into `(major, minor)`.
fn parse_version(raw: &str) -> Option<(u32, u32)> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Asserts the extension is installed and new enough.
///
/// Returns an error rather than warning. A deployment that boots with Stage 2
/// configured and pgvector 0.7 would run every semantic query with silently
/// reduced recall — and "search got worse after the upgrade" is a support
/// ticket nobody traces back to an extension version.
pub async fn assert_pgvector_ready(db: &PgPool) -> Result<(), AppError> {
    let installed: Option<String> =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;

    let Some(raw) = installed else {
        return Err(AppError::Validation(
            "semantic retrieval is enabled but the pgvector extension is not \
             installed. The deployment image must be pgvector/pgvector:pg18 — \
             see deploy/UPGRADE-pgvector.md."
                .into(),
        ));
    };

    let Some(version) = parse_version(&raw) else {
        return Err(AppError::Validation(format!(
            "could not parse the installed pgvector version {raw:?}"
        )));
    };

    if version < MIN_PGVECTOR {
        return Err(AppError::Validation(format!(
            "pgvector {raw} is installed but {}.{} or newer is required: \
             hnsw.iterative_scan does not exist before 0.8, and without it a \
             filtered ANN query silently returns fewer results rather than \
             failing.",
            MIN_PGVECTOR.0, MIN_PGVECTOR.1
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_accepts_the_shapes_pg_extension_reports() {
        assert_eq!(parse_version("0.8.0"), Some((0, 8)));
        assert_eq!(parse_version("0.8"), Some((0, 8)));
        assert_eq!(parse_version("1.0.1"), Some((1, 0)));
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(parse_version(""), None);
    }

    /// The comparison is on the tuple, so 0.10 beats 0.8 — a string compare
    /// would put "0.10" before "0.8" and reject a newer version.
    #[test]
    fn version_comparison_is_numeric_not_lexicographic() {
        assert!(parse_version("0.10.0").unwrap() >= MIN_PGVECTOR);
        assert!(parse_version("0.7.4").unwrap() < MIN_PGVECTOR);
        assert!("0.10" < "0.8", "the lexicographic trap this avoids");
    }

    /// The scan bound is set and finite. Unbounded iterative scan for a
    /// narrowed caller can scan the whole index — the tighter the scope, the
    /// longer the scan.
    #[test]
    fn the_scan_bound_is_finite_and_fits_the_route_budget() {
        const _: () = assert!(MAX_SCAN_TUPLES > 0);
        const _: () = assert!(MAX_SCAN_TUPLES <= 50_000);
    }

    /// `relaxed_order`, because RRF re-ranks anyway — paying for strict ANN
    /// ordering buys an order that is then discarded.
    #[test]
    fn iterative_scan_is_relaxed_because_rrf_reranks() {
        assert_eq!(ITERATIVE_SCAN_MODE, "relaxed_order");
    }

    /// The GUCs are interpolated from constants, never from request data —
    /// PostgreSQL rejects bind parameters in `SET`, which is exactly the
    /// exception guidelines §4 permits and exactly where someone would
    /// otherwise reach for a request value.
    #[test]
    fn the_guc_values_come_from_constants_only() {
        let source = include_str!("vector.rs");
        let code = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("test marker");
        assert!(
            code.contains("SET LOCAL hnsw.max_scan_tuples = {MAX_SCAN_TUPLES}"),
            "the bound must come from the constant, not a parameter"
        );
    }
}
