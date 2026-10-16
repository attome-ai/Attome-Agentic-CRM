//! Forecast cells (roadmap D11-T2): for every open forecast period, each
//! open deal closing in it adds its amount to a cell for its owner and its
//! forecast category (set on the deal, else taken from its stage), and the
//! owner's cells roll up through every position the owner holds and all
//! the positions above it. A cell's node is `user:{id}` or
//! `position:{id}`.
//!
//! [`rollup`] is the pure part. [`run`] recomputes every open period's
//! pipeline amounts (nightly, and on demand), leaves people's adjusted
//! amounts alone (a new cell starts adjusted to its pipeline), and writes a
//! weekly snapshot of each cell once per week.
//!
//! A viewer who cannot read every deal under a node is shown a live sum of
//! the deals they can read instead of the stored cell; that read-time path
//! uses the generic query engine and is not part of this module.

use std::collections::{BTreeMap, HashMap, HashSet};

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use uuid::Uuid;

/// One deal's contribution.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DealAmount {
    pub owner: Uuid,
    pub category: Uuid,
    pub amount: f64,
}

/// `(node_key, category)` to amount.
pub type Cells = BTreeMap<(String, Uuid), f64>;

/// Sums deals per owner and category, then up the position tree.
/// `positions_of` is each user's positions; `parent_of` each position's
/// parent. A cycle in the tree is walked at most once per position.
pub fn rollup(
    deals: &[DealAmount],
    positions_of: &HashMap<Uuid, Vec<Uuid>>,
    parent_of: &HashMap<Uuid, Uuid>,
) -> Cells {
    let mut cells = Cells::new();
    for deal in deals {
        *cells
            .entry((format!("user:{}", deal.owner), deal.category))
            .or_default() += deal.amount;
        let mut seen = HashSet::new();
        for start in positions_of
            .get(&deal.owner)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let mut at = Some(*start);
            while let Some(position) = at {
                if !seen.insert(position) {
                    break;
                }
                *cells
                    .entry((format!("position:{position}"), deal.category))
                    .or_default() += deal.amount;
                at = parent_of.get(&position).copied();
            }
        }
    }
    cells
}

/// The Monday of `day`'s week.
pub fn week_of(day: NaiveDate) -> NaiveDate {
    day - chrono::Duration::days(i64::from(day.weekday().num_days_from_monday()))
}

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForecastRun {
    pub periods: u64,
    pub cells: u64,
    pub snapshots: u64,
}

type PeriodRow = (Uuid, NaiveDate, NaiveDate);

/// Recomputes every open period's cells.
pub async fn run(db: &DbPool, now: DateTime<Utc>) -> Result<ForecastRun, AppError> {
    let mut out = ForecastRun::default();
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'opportunity' AND column_name = 'forecast_category_ref' \
           AND table_schema = ANY (current_schemas(false)))",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(out);
    }
    let positions: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT user_ref, position_ref FROM user_account_mm_position WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut positions_of: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (user, position) in positions {
        positions_of.entry(user).or_default().push(position);
    }
    let parent_of: HashMap<Uuid, Uuid> = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, parent_position_ref FROM position \
         WHERE is_deleted = false AND parent_position_ref IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let periods: Vec<PeriodRow> = sqlx::query_as(
        "SELECT id, starts_on::date, ends_on::date FROM forecast_period \
         WHERE (is_active IS NULL OR is_active = true) AND COALESCE(status, 'open') = 'open' \
           AND starts_on IS NOT NULL AND ends_on IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let week = week_of(now.date_naive());
    for (period, starts, ends) in periods {
        out.periods += 1;
        let deals: Vec<(Uuid, Uuid, f64)> = sqlx::query_as(
            "SELECT o.owner_ref, COALESCE(o.forecast_category_ref, s.forecast_category_ref), \
                    COALESCE(o.amount, 0)::float8 \
             FROM opportunity o \
             LEFT JOIN LATERAL (SELECT st.forecast_category_ref FROM opportunity_stage st \
                 WHERE st.stage = o.stage AND (st.pipeline IS NULL OR st.pipeline = o.pipeline) \
                   AND (st.is_active IS NULL OR st.is_active = true) \
                 ORDER BY st.pipeline NULLS LAST LIMIT 1) s ON true \
             WHERE (o.is_active IS NULL OR o.is_active = true) AND o.owner_ref IS NOT NULL \
               AND o.close_date::date BETWEEN $1 AND $2 \
               AND COALESCE(o.forecast_category_ref, s.forecast_category_ref) IS NOT NULL",
        )
        .bind(starts)
        .bind(ends)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let deals: Vec<DealAmount> = deals
            .into_iter()
            .map(|(owner, category, amount)| DealAmount {
                owner,
                category,
                amount,
            })
            .collect();
        let cells = rollup(&deals, &positions_of, &parent_of);
        let mut tx = attome_db::tx::begin(db).await?;
        // Cells no longer carrying any deal drop to zero rather than keep a
        // stale amount.
        sqlx::query(
            "UPDATE forecast_cell SET pipeline_amount = 0, modified_at = now() \
             WHERE period_ref = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(period)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        for ((node, category), amount) in &cells {
            let owner = node
                .strip_prefix("user:")
                .and_then(|id| Uuid::parse_str(id).ok());
            let cell: Uuid = match sqlx::query_scalar::<_, Uuid>(
                "UPDATE forecast_cell SET pipeline_amount = $4, modified_at = now(), \
                 row_version = row_version + 1 \
                 WHERE period_ref = $1 AND category_ref = $2 AND node_key = $3 \
                   AND (is_active IS NULL OR is_active = true) RETURNING id",
            )
            .bind(period)
            .bind(category)
            .bind(node)
            .bind(amount)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            {
                Some(id) => id,
                None => sqlx::query_scalar(
                    "INSERT INTO forecast_cell \
                       (period_ref, category_ref, node_key, owner_ref, pipeline_amount, adjusted_amount) \
                     VALUES ($1, $2, $3, $4, $5, $5) RETURNING id",
                )
                .bind(period)
                .bind(category)
                .bind(node)
                .bind(owner)
                .bind(amount)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?,
            };
            out.cells += 1;
            let snapped = sqlx::query(
                "INSERT INTO forecast_snapshot (cell_ref, week_of, pipeline_amount, adjusted_amount) \
                 SELECT c.id, $2, c.pipeline_amount, c.adjusted_amount FROM forecast_cell c \
                 WHERE c.id = $1 AND NOT EXISTS (SELECT 1 FROM forecast_snapshot s \
                     WHERE s.cell_ref = c.id AND s.week_of::date = $2 \
                       AND (s.is_active IS NULL OR s.is_active = true))",
            )
            .bind(cell)
            .bind(week)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            out.snapshots += snapped.rows_affected();
        }
        attome_db::tx::commit(tx).await?;
    }
    Ok(out)
}

#[cfg(test)]
mod forecast_rollup {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn deals_roll_up_the_position_tree() {
        // Rep 1 and rep 2 sit under team lead position 20, under VP 30.
        let commit = u(500);
        let best = u(501);
        let deals = [
            DealAmount {
                owner: u(1),
                category: commit,
                amount: 100.0,
            },
            DealAmount {
                owner: u(1),
                category: best,
                amount: 40.0,
            },
            DealAmount {
                owner: u(2),
                category: commit,
                amount: 60.0,
            },
        ];
        let positions = HashMap::from([(u(1), vec![u(10)]), (u(2), vec![u(11)])]);
        let parents = HashMap::from([(u(10), u(20)), (u(11), u(20)), (u(20), u(30))]);
        let cells = rollup(&deals, &positions, &parents);
        let get = |node: String, cat| cells.get(&(node, cat)).copied();
        assert_eq!(get(format!("user:{}", u(1)), commit), Some(100.0));
        assert_eq!(get(format!("position:{}", u(20)), commit), Some(160.0));
        assert_eq!(get(format!("position:{}", u(30)), commit), Some(160.0));
        assert_eq!(get(format!("position:{}", u(30)), best), Some(40.0));
    }

    #[test]
    fn a_cycle_or_two_positions_counts_each_once() {
        let cat = u(500);
        let deals = [DealAmount {
            owner: u(1),
            category: cat,
            amount: 10.0,
        }];
        // The user holds 10 and 11, both under 20; 20 and 21 point at each other.
        let positions = HashMap::from([(u(1), vec![u(10), u(11)])]);
        let parents = HashMap::from([
            (u(10), u(20)),
            (u(11), u(20)),
            (u(20), u(21)),
            (u(21), u(20)),
        ]);
        let cells = rollup(&deals, &positions, &parents);
        assert_eq!(
            cells.get(&(format!("position:{}", u(20)), cat)),
            Some(&10.0)
        );
        assert_eq!(
            cells.get(&(format!("position:{}", u(21)), cat)),
            Some(&10.0)
        );
        assert_eq!(
            week_of(NaiveDate::from_ymd_opt(2026, 10, 16).unwrap_or_default()),
            NaiveDate::from_ymd_opt(2026, 10, 12).unwrap_or_default()
        );
    }
}
