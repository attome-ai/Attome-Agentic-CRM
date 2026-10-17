//! A/B variants of a feature flag (roadmap T6-T3). A subject (a user, an
//! account) is placed in a variant by a stable hash of the flag and the
//! subject, so it sees the same variant on every request and node for as
//! long as the split stays the same; changing a weight only moves the
//! subjects near the moved boundary. Outcomes (a conversion, a value) are
//! recorded per event in `experiment_outcome` (migration 0099) and
//! compared per variant by [`summary`].

use uuid::Uuid;

use attome_types::AppError;

/// One variant and its share (any positive numbers; they are normalised).
#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    pub name: String,
    pub weight: f64,
}

/// A number in `[0, 1)` from the flag and subject, the same everywhere.
pub fn bucket(flag_key: &str, subject: Uuid) -> f64 {
    // FNV-1a over "flag:subject": stable across builds and platforms,
    // unlike the standard library's randomly seeded hasher.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in flag_key
        .bytes()
        .chain(*b":")
        .chain(subject.as_bytes().iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    (hash >> 11) as f64 / (1u64 << 53) as f64
}

/// The variant a subject is in; `None` when no variant has weight.
pub fn variant_for<'a>(
    flag_key: &str,
    subject: Uuid,
    variants: &'a [Variant],
) -> Option<&'a Variant> {
    let total: f64 = variants.iter().map(|v| v.weight.max(0.0)).sum();
    if total <= 0.0 {
        return None;
    }
    let point = bucket(flag_key, subject) * total;
    let mut edge = 0.0;
    for variant in variants {
        edge += variant.weight.max(0.0);
        if point < edge {
            return Some(variant);
        }
    }
    variants.iter().rev().find(|v| v.weight > 0.0)
}

/// Records one outcome for a subject's variant.
pub async fn record_outcome(
    db: &attome_db::DbPool,
    flag_key: &str,
    variant: &str,
    subject: Uuid,
    outcome: &str,
    value: Option<f64>,
) -> Result<(), AppError> {
    if outcome.trim().is_empty() {
        return Err(AppError::Validation("outcome is required".into()));
    }
    sqlx::query(
        "INSERT INTO experiment_outcome (flag_key, variant, subject_id, outcome, value) \
         VALUES ($1, $2, $3, $4, $5::float8::numeric)",
    )
    .bind(flag_key)
    .bind(variant)
    .bind(subject)
    .bind(outcome.trim())
    .bind(value)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// One variant's results for an outcome.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct VariantResult {
    pub variant: String,
    /// Distinct subjects with the outcome.
    pub subjects: i64,
    pub events: i64,
    pub total_value: Option<f64>,
}

/// Results per variant for one flag and outcome.
pub async fn summary(
    db: &attome_db::DbPool,
    flag_key: &str,
    outcome: &str,
) -> Result<Vec<VariantResult>, AppError> {
    let rows: Vec<(String, i64, i64, Option<f64>)> = sqlx::query_as(
        "SELECT variant, COUNT(DISTINCT subject_id), COUNT(*), SUM(value)::float8 \
         FROM experiment_outcome WHERE flag_key = $1 AND outcome = $2 \
         GROUP BY variant ORDER BY variant",
    )
    .bind(flag_key)
    .bind(outcome)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(variant, subjects, events, total_value)| VariantResult {
            variant,
            subjects,
            events,
            total_value,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(a: f64, b: f64) -> Vec<Variant> {
        vec![
            Variant {
                name: "control".into(),
                weight: a,
            },
            Variant {
                name: "new".into(),
                weight: b,
            },
        ]
    }

    #[test]
    fn a_subject_always_gets_the_same_variant() {
        let variants = split(50.0, 50.0);
        let subject = Uuid::from_u128(42);
        let first = variant_for("checkout.v2", subject, &variants).map(|v| v.name.clone());
        for _ in 0..10 {
            assert_eq!(
                variant_for("checkout.v2", subject, &variants).map(|v| v.name.clone()),
                first
            );
        }
    }

    #[test]
    fn the_split_follows_the_weights() {
        let variants = split(90.0, 10.0);
        let new = (0..10_000u128)
            .filter(|i| {
                variant_for("checkout.v2", Uuid::from_u128(i * 7919 + 1), &variants)
                    .is_some_and(|v| v.name == "new")
            })
            .count();
        assert!(
            (800..1200).contains(&new),
            "{new} of 10000 in the 10% variant"
        );
        assert!(variant_for("x", Uuid::nil(), &split(0.0, 0.0)).is_none());
        assert!((0.0..1.0).contains(&bucket("flag", Uuid::from_u128(9))));
    }
}
