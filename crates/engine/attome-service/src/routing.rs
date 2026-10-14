//! Rule-driven routing seam (M70 target design §3 "Rule-driven routing") —
//! M45 rules of `kind = routing`, evaluated on work-request create /
//! classification-change, first match wins by `display_order`, producing
//! `{ queue_ref | assignee_ref, priority, sla_policy_ref }`.
//!
//! **M45 Phase 3 (REVIEW-2026-09-02 finding #8): now evaluated, scoped to
//! `queue_ref` only.** `rule` (migration `0400`) is explicit that
//! `target_field` is NULL for a `kind = 'routing'` row — "which reports a
//! pass/fail rather than writing or gating a single field" — so there is no
//! column today to hold a per-rule `assignee_ref`/`priority`/
//! `sla_policy_ref` output; only `queue_ref` (a plain `TEXT`, same type as
//! `service_offering.default_queue_ref`) is expressible as "the value a
//! rule's own expression evaluates to". A routing rule's `expression`
//! therefore evaluates to either `Value::Text(queue)` (this rule fires,
//! route here) or `Value::Null` (this rule does not apply to this context,
//! try the next one) — e.g. `if(category == "billing", "finance-queue",
//! null)`. First non-null result by `display_order` wins, same "first match
//! wins" contract the module doc always specified.  `assignee_ref`,
//! `priority`, and `sla_policy_ref` stay `None` from a matched rule always
//! — a genuine v1 scope limit the schema itself states, not a silent gap;
//! M45 Phase 5's decision tables are the natural place to add richer
//! multi-field routing outcomes without another ad hoc column.
//!
//! Bound to `entity_logicalname = 'service_work_request'` — the only caller
//! (`offering.rs`) is exclusively about work-request intake routing; a
//! second entity wanting this seam is a signal to generalize the query, not
//! a reason to guess at a broader scope now.
use attome_db::DbPool;
use attome_rules::{Context, Schema, Type, Value as RulesValue, compile};
use attome_types::AppError;
use chrono::Utc;
use uuid::Uuid;

/// What a routing rule is evaluated against — the work request's own
/// classification at the moment of create/reclassify.
pub struct RoutingContext<'a> {
    pub request_type: &'a str,
    pub category: Option<&'a str>,
}

impl std::fmt::Debug for RoutingContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingContext").finish_non_exhaustive()
    }
}

/// What a matched `kind = routing` rule produces, per the target design:
/// `{ queue_ref | assignee_ref, priority, sla_policy_ref }`, plus the rule's
/// own id for the audit trail ("audit which rule routed").
pub struct RoutingDecision {
    pub matched_rule_id: Uuid,
    pub queue_ref: Option<String>,
    pub assignee_ref: Option<Uuid>,
    pub priority: Option<String>,
    pub sla_policy_ref: Option<Uuid>,
}

impl std::fmt::Debug for RoutingDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingDecision").finish_non_exhaustive()
    }
}

fn schema_and_context(ctx: &RoutingContext<'_>) -> (Schema, Context) {
    let schema = Schema::new()
        .with_field("request_type", Type::Text)
        .with_field("category", Type::Text);
    let rules_ctx = Context::new(Utc::now())
        .with_field(
            "request_type",
            RulesValue::Text(ctx.request_type.to_owned()),
        )
        .with_field(
            "category",
            ctx.category
                .map(|c| RulesValue::Text(c.to_owned()))
                .unwrap_or(RulesValue::Null),
        );
    (schema, rules_ctx)
}

/// Evaluates `kind = routing` rules against `ctx`, first non-null result by
/// `display_order` wins — see the module doc for exactly what a routing
/// rule's expression evaluates to and why. A rule that fails to compile
/// (e.g. references a field this Context doesn't carry) or evaluates to
/// something other than `Text`/`Null` is logged and skipped, not fatal to
/// the whole write — the same "one bad row doesn't wedge every future
/// intake" posture the offering-defaults fallback already gives every
/// caller when nothing here applies at all.
pub async fn evaluate_routing(
    db: &DbPool,
    ctx: &RoutingContext<'_>,
) -> Result<Option<RoutingDecision>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        expression: String,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, expression FROM rule \
         WHERE entity_logicalname = 'service_work_request' AND kind = 'routing' \
           AND is_active = TRUE AND NOT is_deleted \
         ORDER BY display_order, id",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if rows.is_empty() {
        return Ok(None);
    }

    let (schema, rules_ctx) = schema_and_context(ctx);
    for row in rows {
        let compiled = match compile(&row.expression, &schema) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    rule_id = %row.id,
                    error = %e,
                    "routing rule failed to compile against this context; skipping"
                );
                continue;
            }
        };
        match compiled.eval(&rules_ctx) {
            Ok(RulesValue::Text(queue_ref)) => {
                return Ok(Some(RoutingDecision {
                    matched_rule_id: row.id,
                    queue_ref: Some(queue_ref),
                    assignee_ref: None,
                    priority: None,
                    sla_policy_ref: None,
                }));
            }
            Ok(RulesValue::Null) => continue,
            other => {
                tracing::warn!(
                    rule_id = %row.id,
                    result = ?other,
                    "routing rule did not evaluate to Text or Null; skipping"
                );
                continue;
            }
        }
    }
    Ok(None)
}

/// The final `{priority, queue_ref, sla_policy_ref}` a work request gets:
/// a matched rule's fields win field-by-field (a rule that only computes
/// priority still lets the offering's queue/SLA defaults through), and the
/// offering's own defaults fill in whatever the rule left `None` — including
/// the common case today, where `decision` is always `None` and every field
/// comes straight from the offering.
pub struct EffectiveDefaults {
    pub priority: String,
    pub queue_ref: Option<String>,
    pub sla_policy_ref: Option<Uuid>,
}

impl std::fmt::Debug for EffectiveDefaults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectiveDefaults").finish_non_exhaustive()
    }
}

pub fn resolve_effective_defaults(
    decision: Option<&RoutingDecision>,
    offering_default_priority: &str,
    offering_default_queue_ref: Option<&str>,
    offering_default_sla_policy_ref: Option<Uuid>,
) -> EffectiveDefaults {
    match decision {
        Some(decision) => EffectiveDefaults {
            priority: decision
                .priority
                .clone()
                .unwrap_or_else(|| offering_default_priority.to_owned()),
            queue_ref: decision
                .queue_ref
                .clone()
                .or_else(|| offering_default_queue_ref.map(str::to_owned)),
            sla_policy_ref: decision.sla_policy_ref.or(offering_default_sla_policy_ref),
        },
        None => EffectiveDefaults {
            priority: offering_default_priority.to_owned(),
            queue_ref: offering_default_queue_ref.map(str::to_owned),
            sla_policy_ref: offering_default_sla_policy_ref,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_testkit::skip_if_no_db;
    use sqlx::postgres::PgPoolOptions;

    async fn test_db() -> Option<DbPool> {
        let url = attome_testkit::migrated_db_url()?;
        Some(
            PgPoolOptions::new()
                .max_connections(3)
                .connect(&url)
                .await
                .expect("connect DATABASE_URL"),
        )
    }

    /// Inserts one `kind = 'routing'` row against `service_work_request` — the
    /// only NOT NULL columns `evaluate_routing`'s query reads or that this
    /// table requires beyond defaults.
    async fn seed_routing_rule(db: &DbPool, name: &str, expression: &str, display_order: i32) {
        sqlx::query(
            "INSERT INTO rule \
                (entity_logicalname, name, kind, expression, display_order, owner_layer) \
             VALUES ('service_work_request', $1, 'routing', $2, $3, 'project')",
        )
        .bind(name)
        .bind(expression)
        .bind(display_order)
        .execute(db)
        .await
        .expect("seed routing rule");
    }

    /// The checklist's own required coverage: "no rules configured -> falls
    /// through to offering defaults". Exercises the real `evaluate_routing`
    /// (not a stand-in) against a real, empty table.
    #[tokio::test]
    async fn no_rules_configured_falls_through_to_offering_defaults() {
        let db = skip_if_no_db!(test_db().await);
        let ctx = RoutingContext {
            request_type: &format!("it_request_{}", Uuid::now_v7()),
            category: Some("it"),
        };

        let decision = evaluate_routing(&db, &ctx).await.expect("evaluate_routing");
        assert!(
            decision.is_none(),
            "no matching rule exists for this request_type — must be None"
        );

        let sla_policy_id = Uuid::now_v7();
        let effective = resolve_effective_defaults(
            decision.as_ref(),
            "high",
            Some("placeholder-queue"),
            Some(sla_policy_id),
        );
        assert_eq!(effective.priority, "high");
        assert_eq!(effective.queue_ref.as_deref(), Some("placeholder-queue"));
        assert_eq!(effective.sla_policy_ref, Some(sla_policy_id));
    }

    /// M45 Phase 3 (REVIEW-2026-09-02 finding #8): a routing rule whose
    /// condition holds actually routes now, overriding the offering's own
    /// default queue via `resolve_effective_defaults`.
    #[tokio::test]
    async fn a_matching_rule_routes_to_its_queue() {
        let db = skip_if_no_db!(test_db().await);
        let rule_name = format!("billing-{}", Uuid::now_v7());
        seed_routing_rule(
            &db,
            &rule_name,
            "if(category == \"billing\", \"finance-queue\", null)",
            0,
        )
        .await;

        let ctx = RoutingContext {
            request_type: "invoice_dispute",
            category: Some("billing"),
        };
        let decision = evaluate_routing(&db, &ctx)
            .await
            .expect("evaluate_routing")
            .expect("the billing rule must match");
        assert_eq!(decision.queue_ref.as_deref(), Some("finance-queue"));
        assert!(
            decision.priority.is_none() && decision.sla_policy_ref.is_none(),
            "v1 scope: only queue_ref comes from a matched rule"
        );

        let effective =
            resolve_effective_defaults(Some(&decision), "low", Some("general-queue"), None);
        assert_eq!(effective.queue_ref.as_deref(), Some("finance-queue"));
        assert_eq!(
            effective.priority, "low",
            "queue_ref matched but priority still falls through to the offering default"
        );
    }

    /// A rule whose condition does not hold (`Null`) is skipped, not
    /// treated as a match — falls through exactly like "no rule configured".
    #[tokio::test]
    async fn a_non_matching_rule_falls_through() {
        let db = skip_if_no_db!(test_db().await);
        let rule_name = format!("billing-only-{}", Uuid::now_v7());
        seed_routing_rule(
            &db,
            &rule_name,
            "if(category == \"billing\", \"finance-queue\", null)",
            0,
        )
        .await;

        let ctx = RoutingContext {
            request_type: "password_reset",
            category: Some("it"),
        };
        let decision = evaluate_routing(&db, &ctx).await.expect("evaluate_routing");
        assert!(decision.is_none(), "category is 'it', not 'billing'");
    }

    /// `display_order` is a real ordering, not just a sort key nobody reads
    /// — the first rule (by that order) whose result is non-null wins over
    /// a later, also-matching rule.
    #[tokio::test]
    async fn display_order_picks_the_first_non_null_match() {
        let db = skip_if_no_db!(test_db().await);
        let prefix = Uuid::now_v7();
        // Scoped to this test's own request type: the table is shared with
        // every other test in the binary, and an unconditional rule would
        // route their requests too.
        let only_mine =
            |queue: &str| format!("if(request_type == \"dupe_test_{prefix}\", \"{queue}\", null)");
        seed_routing_rule(
            &db,
            &format!("second-{prefix}"),
            &only_mine("second-queue"),
            10,
        )
        .await;
        seed_routing_rule(
            &db,
            &format!("first-{prefix}"),
            &only_mine("first-queue"),
            0,
        )
        .await;

        let ctx = RoutingContext {
            request_type: &format!("dupe_test_{prefix}"),
            category: None,
        };
        let decision = evaluate_routing(&db, &ctx)
            .await
            .expect("evaluate_routing")
            .expect("both rules match unconditionally");
        assert_eq!(decision.queue_ref.as_deref(), Some("first-queue"));
    }

    /// A rule whose expression can't compile against this Context (e.g. a
    /// stray syntax error, or a field this Context doesn't carry) is
    /// skipped, not fatal — the sweep continues to the next rule/falls
    /// through, same "one bad row doesn't wedge future intake" posture the
    /// module doc states.
    #[tokio::test]
    async fn an_uncompilable_rule_is_skipped_not_fatal() {
        let db = skip_if_no_db!(test_db().await);
        let prefix = Uuid::now_v7();
        seed_routing_rule(&db, &format!("broken-{prefix}"), "amount >>> 1", 0).await;
        seed_routing_rule(
            &db,
            &format!("fallback-{prefix}"),
            &format!("if(request_type == \"broken_test_{prefix}\", \"fallback-queue\", null)"),
            10,
        )
        .await;

        let ctx = RoutingContext {
            request_type: &format!("broken_test_{prefix}"),
            category: None,
        };
        let decision = evaluate_routing(&db, &ctx)
            .await
            .expect("evaluate_routing must not error just because one rule is broken")
            .expect("the second, valid rule must still match");
        assert_eq!(decision.queue_ref.as_deref(), Some("fallback-queue"));
    }

    /// A matched rule's fields win, field-by-field, over the offering's own
    /// defaults — the shape this seam must have the day M45 Phase 2 starts
    /// actually returning `Some`.
    #[test]
    fn a_matched_rule_overrides_the_offering_field_by_field() {
        let rule_sla = Uuid::now_v7();
        let decision = RoutingDecision {
            matched_rule_id: Uuid::now_v7(),
            queue_ref: Some("rule-queue".to_owned()),
            assignee_ref: None,
            priority: Some("critical".to_owned()),
            sla_policy_ref: Some(rule_sla),
        };

        let effective = resolve_effective_defaults(
            Some(&decision),
            "low",
            Some("offering-queue"),
            Some(Uuid::now_v7()),
        );
        assert_eq!(effective.priority, "critical");
        assert_eq!(effective.queue_ref.as_deref(), Some("rule-queue"));
        assert_eq!(effective.sla_policy_ref, Some(rule_sla));
    }

    /// A rule that only computes priority still lets the offering's own
    /// queue/SLA defaults through for the fields it left `None`.
    #[test]
    fn a_partial_rule_only_overrides_the_fields_it_sets() {
        let decision = RoutingDecision {
            matched_rule_id: Uuid::now_v7(),
            queue_ref: None,
            assignee_ref: None,
            priority: Some("critical".to_owned()),
            sla_policy_ref: None,
        };
        let offering_sla = Uuid::now_v7();

        let effective = resolve_effective_defaults(
            Some(&decision),
            "low",
            Some("offering-queue"),
            Some(offering_sla),
        );
        assert_eq!(effective.priority, "critical");
        assert_eq!(effective.queue_ref.as_deref(), Some("offering-queue"));
        assert_eq!(effective.sla_policy_ref, Some(offering_sla));
    }
}
