//! Skip-gate for the `seed_for_tests` fixtures (build-loop, 2026-09-24).
//!
//! Every DB-backed test's setup calls one or more `seed_for_tests` functions
//! that walk a platform bundle and `ensure_entity`/`ensure_attribute` each
//! entry. They are idempotent, but on metadata that is already correct each
//! attribute still costs several round trips, and a test boot spent ~1.3 s on
//! ~430 of them. [`run_bundle_fixture`] skips the walk when a content stamp
//! matches and one query confirms every entity, attribute row and table the
//! bundle declares is still live; otherwise the walk runs in full and
//! re-stamps, so a test that deleted something and re-seeds to restore it is
//! unaffected.

use attome_db::DbPool;
use attome_types::AppError;
use std::future::Future;

/// `(entity logicalname, attribute logicalname)` pairs a bundle declares. An
/// entity with no attributes contributes one pair with an empty attribute name.
fn declared_pairs(bundle_json: &str) -> Result<Vec<(String, String)>, AppError> {
    let bundle: serde_json::Value = serde_json::from_str(bundle_json)
        .map_err(|e| AppError::internal(format!("fixture bundle is not valid JSON: {e}")))?;
    let mut pairs = Vec::new();
    for entity in bundle["entities"].as_array().into_iter().flatten() {
        let en = entity["logicalname"].as_str().unwrap_or_default();
        pairs.push((en.to_owned(), String::new()));
        for attr in entity["attributes"].as_array().into_iter().flatten() {
            pairs.push((
                en.to_owned(),
                attr["logicalname"].as_str().unwrap_or_default().to_owned(),
            ));
        }
    }
    Ok(pairs)
}

/// One round trip: is every declared entity live, its table present, and every
/// declared attribute a live row?
async fn declared_state_present(db: &DbPool, pairs: &[(String, String)]) -> Result<bool, AppError> {
    let (entities, attributes): (Vec<&str>, Vec<&str>) =
        pairs.iter().map(|(e, a)| (e.as_str(), a.as_str())).unzip();
    sqlx::query_scalar(
        "SELECT NOT EXISTS ( \
           SELECT 1 FROM unnest($1::text[], $2::text[]) AS x(en, an) \
           WHERE to_regclass(x.en) IS NULL \
              OR NOT EXISTS (SELECT 1 FROM entity_info e \
                             WHERE e.logicalname = x.en \
                               AND (e.is_active IS NULL OR e.is_active = true)) \
              OR (x.an <> '' AND NOT EXISTS ( \
                    SELECT 1 FROM attribute_info a \
                    JOIN entity_info e ON e.id = a.entity_ref \
                    WHERE e.logicalname = x.en AND a.logicalname = x.an \
                      AND (e.is_active IS NULL OR e.is_active = true) \
                      AND (a.is_active IS NULL OR a.is_active = true))))",
    )
    .bind(&entities)
    .bind(&attributes)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Runs `walk` (a fixture's full bundle walk) unless `module` is stamped with
/// this bundle's content and the declared state is verifiably present.
/// `module` is a stamp key of its own (`tests:...`), never one a deployment's
/// boot writes.
pub async fn run_bundle_fixture<F, Fut>(
    db: &DbPool,
    module: &str,
    bundle_json: &str,
    walk: F,
) -> Result<(), AppError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), AppError>>,
{
    let pairs = declared_pairs(bundle_json)?;
    attome_core::seed_gate::run_if_stale_verified(
        db,
        module,
        &attome_core::seed_gate::content_version(bundle_json),
        || declared_state_present(db, &pairs),
        walk,
    )
    .await
}
