//! F6-T4: the sourcing rule table. The setting [`SETTING`] lists rules
//! tried in order; each has a `condition` (an attome-rules expression over
//! the order's fields, empty for every order), a `strategy` and, for
//! `fixed`, a `location_id`. The first rule whose condition holds decides
//! where each line ships from ([`crate::sourcing::source`]); with none, the
//! default location ships everything. The decision's reason (an i18n key and
//! the rule's number) is stored on each fulfilment order, and a person with
//! `fulfilment_order.override_sourcing` may change the location before the
//! order is released ([`override_sourcing`]).
//!
//! `nearest_with_stock` measures the great-circle distance from the order's
//! `delivery_latitude`/`delivery_longitude` to each location's
//! `latitude`/`longitude`; when either is missing every location counts as
//! equally near, so the rule picks the first location with the stock.

use std::collections::HashMap;

use attome_core::{AttrInfo, EngineState};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::sourcing::{Line, Location, Rule};

/// The setting holding the rule table.
pub const SETTING: &str = "fulfilment.sourcing.rules";
/// The reason key prefix (`fulfilment.sourcing.reason.<strategy>`).
pub const REASON_PREFIX: &str = "fulfilment.sourcing.reason.";
/// The most locations sourcing compares.
const MAX_LOCATIONS: i64 = 200;

/// A sourcing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Fixed,
    NearestWithStock,
    FewestShipments,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::Fixed => "fixed",
            Strategy::NearestWithStock => "nearest_with_stock",
            Strategy::FewestShipments => "fewest_shipments",
        }
    }
}

/// One row of the rule table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcingRule {
    #[serde(default)]
    pub condition: String,
    pub strategy: Strategy,
    #[serde(default)]
    pub location_id: Option<Uuid>,
}

impl SourcingRule {
    /// The sourcing rule it applies; `None` for a `fixed` rule naming no
    /// location.
    pub fn rule(&self) -> Option<Rule> {
        match self.strategy {
            Strategy::Fixed => self.location_id.map(Rule::Fixed),
            Strategy::NearestWithStock => Some(Rule::NearestWithStock),
            Strategy::FewestShipments => Some(Rule::FewestShipments),
        }
    }
}

/// The rule table in the setting's value; rows that do not parse are left
/// out (the setting's schema refuses them on save).
pub fn parse_rules(value: &Value) -> Vec<SourcingRule> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| serde_json::from_value(row.clone()).ok())
        .collect()
}

/// True when `source` holds for the order; an empty condition always holds,
/// one that does not compile never does (and says so in the log).
fn holds(source: &str, attrs: &[AttrInfo], order: &Map<String, Value>) -> bool {
    let source = source.trim();
    if source.is_empty() {
        return true;
    }
    let schema = attome_records::rule_engine::schema_for_entity(attrs);
    match attome_rules::compile(source, &schema) {
        Ok(compiled) => {
            let ctx = attome_records::rule_engine::context_for_record(Utc::now(), attrs, order);
            compiled
                .eval(&ctx)
                .is_ok_and(|v| matches!(v, attome_rules::Value::Bool(true)))
        }
        Err(e) => {
            tracing::warn!(error = %e, "sourcing rule condition does not compile; not met");
            false
        }
    }
}

/// The first rule (with its one-based number) whose condition holds and
/// that names a usable rule. Pure apart from the log line.
pub fn first_match<'a>(
    rules: &'a [SourcingRule],
    attrs: &[AttrInfo],
    order: &Map<String, Value>,
) -> Option<(usize, &'a SourcingRule, Rule)> {
    rules.iter().enumerate().find_map(|(i, r)| {
        let rule = r.rule()?;
        holds(&r.condition, attrs, order).then_some((i + 1, r, rule))
    })
}

/// The great-circle distance between two points, in kilometres. Pure.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = (lat2 - lat1).to_radians();
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().asin()
}

/// Where an order's lines ship from, and why.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourcingDecision {
    /// The location of each sourced line.
    pub by_line: HashMap<Uuid, Uuid>,
    /// Where every other line ships from (services, lines no location had).
    pub fallback: Option<Uuid>,
    /// `fulfilment.sourcing.reason.<strategy>:<rule number>`, or
    /// `fulfilment.sourcing.reason.default`.
    pub reason: String,
}

impl SourcingDecision {
    /// The location `line` ships from.
    pub fn location_of(&self, line: Uuid) -> Option<Uuid> {
        self.by_line.get(&line).copied().or(self.fallback)
    }
}

/// A goods line as sourcing reads it: id, product, quantity.
pub type GoodsLine = (Uuid, Uuid, f64);

/// The decision for an order whose first matching rule is `matched` (or
/// none), from `plan`'s allocations. Pure.
pub fn decision_of(
    matched: Option<(usize, Strategy)>,
    plan: Option<&crate::sourcing::Plan>,
    default_location: Option<Uuid>,
) -> SourcingDecision {
    let Some((number, strategy)) = matched else {
        return SourcingDecision {
            by_line: HashMap::new(),
            fallback: default_location,
            reason: format!("{REASON_PREFIX}default"),
        };
    };
    let mut by_line = HashMap::new();
    if let Some(plan) = plan {
        // A line split across locations ships from its first (nearest) one;
        // the promise date covers the rest.
        for a in &plan.allocations {
            by_line.entry(a.line).or_insert(a.location);
        }
    }
    let fallback = plan
        .and_then(|p| p.allocations.first().map(|a| a.location))
        .or(default_location);
    SourcingDecision {
        by_line,
        fallback,
        reason: format!("{REASON_PREFIX}{}:{number}", strategy.as_str()),
    }
}

/// Decides where `order`'s goods `lines` ship from; see the module doc.
pub async fn decide(
    state: &EngineState,
    order: Uuid,
    lines: &[GoodsLine],
    default_location: Option<Uuid>,
) -> Result<SourcingDecision, AppError> {
    let rules = attome_core::setting_registry()
        .get(SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .map(|v| parse_rules(&v))
        .unwrap_or_default();
    if rules.is_empty() {
        return Ok(decision_of(None, None, default_location));
    }
    let record: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(o) FROM \"order\" o WHERE o.id = $1 AND (o.is_active IS NULL OR o.is_active = true)",
    )
    .bind(order)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(Value::Object(record)) = record else {
        return Ok(decision_of(None, None, default_location));
    };
    let attrs = state
        .entities
        .load()
        .get("order")
        .map(|m| m.attrs.clone())
        .unwrap_or_default();
    let Some((number, matched, rule)) = first_match(&rules, &attrs, &record) else {
        return Ok(decision_of(None, None, default_location));
    };
    let goods: Vec<Line> = lines
        .iter()
        .map(|(id, product, quantity)| Line {
            id: *id,
            product: *product,
            quantity: quantity.max(0.0).ceil() as u32,
        })
        .collect();
    let locations = locations(state, &record, &goods).await?;
    let plan = crate::sourcing::source(rule, &goods, &locations);
    Ok(decision_of(
        Some((number, matched.strategy)),
        Some(&plan),
        default_location,
    ))
}

/// A location row: id, latitude, longitude.
type LocationRow = (Uuid, Option<f64>, Option<f64>);

/// The enabled locations, with their distance from the order's delivery
/// point and, when inventory is wired, their free stock of each product.
async fn locations(
    state: &EngineState,
    order: &Map<String, Value>,
    goods: &[Line],
) -> Result<Vec<Location>, AppError> {
    let rows: Vec<LocationRow> = sqlx::query_as(
        "SELECT id, latitude::float8, longitude::float8 FROM stock_location \
          WHERE COALESCE(is_enabled, true) AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $1",
    )
    .bind(MAX_LOCATIONS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let coordinate = |key: &str| order.get(key).and_then(Value::as_f64);
    let delivery = coordinate("delivery_latitude").zip(coordinate("delivery_longitude"));
    let mut out = Vec::with_capacity(rows.len());
    for (id, lat, lon) in rows {
        let distance_km = match (delivery, lat.zip(lon)) {
            (Some((dlat, dlon)), Some((llat, llon))) => haversine_km(dlat, dlon, llat, llon),
            _ => 0.0,
        };
        let stock = match &state.stock_source {
            Some(source) => {
                let mut per_product = std::collections::BTreeMap::new();
                for line in goods {
                    let free = source
                        .available(line.product, id)
                        .await?
                        .map(|a| a.free())
                        .unwrap_or_default();
                    let free = free.trunc().to_string().parse::<u32>().unwrap_or(0);
                    per_product.insert(line.product, free);
                }
                Some(per_product)
            }
            None => None,
        };
        out.push(Location {
            id,
            distance_km,
            stock,
        });
    }
    Ok(out)
}

/// `fulfilment_order.override_sourcing`: changing where a fulfilment order
/// ships from.
#[derive(Debug)]
pub struct OverrideSourcing;

impl PrivilegeKey for OverrideSourcing {
    const KEY: &'static str = "fulfilment_order.override_sourcing";
}

/// The location to ship from instead.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OverrideBody {
    pub location_id: Uuid,
}

/// The fulfilment order after an override.
#[derive(Debug, Serialize, ToSchema)]
pub struct Overridden {
    pub fulfilment_order_id: Uuid,
    pub location_id: Uuid,
    pub sourcing_reason: String,
}

/// The statuses in which the location may still change.
pub const OVERRIDABLE: [&str; 2] = ["draft", "on_hold"];

/// Sets the fulfilment order's location as `ctx`, through the ordinary
/// update (so its audit, change feed and record access apply), while it is
/// still `draft` or `on_hold`.
pub async fn override_sourcing(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    fulfilment_order: Uuid,
    location: Uuid,
) -> Result<Overridden, AppError> {
    let row: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT status::text, row_version FROM fulfilment_order \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(fulfilment_order)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, row_version)) = row else {
        return Err(AppError::NotFound);
    };
    if !OVERRIDABLE.contains(&status.as_deref().unwrap_or("")) {
        return Err(AppError::Validation(
            "the location can change only before the fulfilment order is released".into(),
        ));
    }
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM stock_location WHERE id = $1 \
                         AND COALESCE(is_enabled, true) AND (is_active IS NULL OR is_active = true))",
    )
    .bind(location)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !live {
        return Err(AppError::Validation(
            "location_id names no enabled stock location".into(),
        ));
    }
    let reason = format!("{REASON_PREFIX}override");
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "fulfilment_order",
        fulfilment_order,
        row_version,
        json!({
            "location_ref": location,
            "sourcing_overridden_by": ctx.user_id,
            "sourcing_reason": reason,
        }),
    )
    .await?;
    Ok(Overridden {
        fulfilment_order_id: fulfilment_order,
        location_id: location,
        sourcing_reason: reason,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/orders/{id}/override-sourcing",
    operation_id = "override_fulfilment_sourcing",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The fulfilment order")),
    request_body = OverrideBody,
    responses(
        (status = 200, description = "The fulfilment order ships from the new location", body = Overridden),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.override_sourcing", body = ErrorResponse),
        (status = 404, description = "No such fulfilment order", body = ErrorResponse),
        (status = 409, description = "The fulfilment order changed meanwhile", body = ErrorResponse),
        (status = 422, description = "The order is already released, or the location is not an enabled stock location", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Override where a fulfilment order ships from
///
/// F6-T4: before the order is released (`draft` or `on_hold`), a person with
/// `fulfilment_order.override_sourcing` names the location instead of the
/// sourcing rules; who did it is kept on the order.
async fn post_override(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OverrideSourcing>>,
    Path(id): Path<Uuid>,
    Json(body): Json<OverrideBody>,
) -> Result<Json<Overridden>, AppError> {
    override_sourcing(&state, &ctx, id, body.location_id)
        .await
        .map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/fulfilment/orders/{id}/override-sourcing",
        post(post_override),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_override), components(schemas(OverrideBody, Overridden)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sourcing::source;

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: attome_core::OnTargetDelete::default(),
            data_classification: attome_core::DataClassification::default(),
            sensitivity: Default::default(),
            options: None,
        }
    }

    fn order(amount: i64) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("amount".into(), json!(amount));
        m
    }

    #[test]
    fn sourcing_fixed_rule_wins() {
        let riyadh = Uuid::now_v7();
        let rules = parse_rules(&json!([
            { "condition": "amount > 1000", "strategy": "fixed", "location_id": riyadh },
            { "condition": "", "strategy": "fewest_shipments" },
            { "strategy": "unknown" }
        ]));
        assert_eq!(rules.len(), 2, "a row that does not parse is left out");
        let attrs = vec![attr("amount", 1)];
        let (number, matched, rule) = first_match(&rules, &attrs, &order(5000)).unwrap();
        assert_eq!((number, matched.strategy), (1, Strategy::Fixed));
        assert_eq!(rule, Rule::Fixed(riyadh));
        let (number, matched, _) = first_match(&rules, &attrs, &order(10)).unwrap();
        assert_eq!((number, matched.strategy), (2, Strategy::FewestShipments));

        let line = Line {
            id: Uuid::now_v7(),
            product: Uuid::now_v7(),
            quantity: 2,
        };
        let plan = source(
            rule,
            &[line],
            &[Location {
                id: riyadh,
                distance_km: 0.0,
                stock: None,
            }],
        );
        let decision = decision_of(Some((1, Strategy::Fixed)), Some(&plan), None);
        assert_eq!(decision.location_of(line.id), Some(riyadh));
        assert_eq!(decision.reason, "fulfilment.sourcing.reason.fixed:1");
    }

    #[test]
    fn sourcing_nearest_uses_distance() {
        // Riyadh to Jeddah is about 850 km; Riyadh to Dammam about 380 km.
        let to_jeddah = haversine_km(24.7136, 46.6753, 21.4858, 39.1925);
        let to_dammam = haversine_km(24.7136, 46.6753, 26.4207, 50.0888);
        assert!((800.0..900.0).contains(&to_jeddah), "{to_jeddah}");
        assert!((350.0..420.0).contains(&to_dammam), "{to_dammam}");

        let (jeddah, dammam) = (Uuid::now_v7(), Uuid::now_v7());
        let line = Line {
            id: Uuid::now_v7(),
            product: Uuid::now_v7(),
            quantity: 1,
        };
        let locations = [
            Location {
                id: jeddah,
                distance_km: to_jeddah,
                stock: None,
            },
            Location {
                id: dammam,
                distance_km: to_dammam,
                stock: None,
            },
        ];
        let plan = source(Rule::NearestWithStock, &[line], &locations);
        let decision = decision_of(Some((3, Strategy::NearestWithStock)), Some(&plan), None);
        assert_eq!(decision.location_of(line.id), Some(dammam));
        assert_eq!(
            decision.reason,
            "fulfilment.sourcing.reason.nearest_with_stock:3"
        );
    }

    #[test]
    fn sourcing_no_rule_uses_default() {
        let default = Uuid::now_v7();
        let attrs = vec![attr("amount", 1)];
        let rules = parse_rules(&json!([
            { "condition": "amount > 1000", "strategy": "nearest_with_stock" },
            { "condition": "amount >", "strategy": "fewest_shipments" },
            { "strategy": "fixed" }
        ]));
        assert!(first_match(&rules, &attrs, &order(5)).is_none());
        let decision = decision_of(None, None, Some(default));
        assert_eq!(decision.location_of(Uuid::now_v7()), Some(default));
        assert_eq!(decision.reason, "fulfilment.sourcing.reason.default");
        assert!(parse_rules(&json!(null)).is_empty());
    }
}
