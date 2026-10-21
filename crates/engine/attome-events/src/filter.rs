//! Subscription filter matching (M62 plan §3/§4 "Event filtering").
//!
//! M45 Phase 3 (REVIEW-2026-09-02 finding #8): `filter_expression` is now
//! evaluated, but only against the [`ChangeEvent`]'s own fields
//! (`entity_logicalname`, `operation`, `event_name`, `record_id`) — NOT the
//! record's business field values, which would need a fetch this crate's
//! `matches`/`matches_audit` deliberately do not perform (this module's
//! whole design keeps matching pure and I/O-free, and a per-event record
//! fetch on the dispatch tick's hot loop, for every subscription, before
//! even knowing the event matches, is exactly the cost that design avoids —
//! see `dispatch.rs`'s own module doc for the same reasoning applied to
//! payload building). A condition like `event_name == "sla.breached" and
//! operation == "update"` is fully expressible; one referencing a business
//! field on the record is rejected at compile time as `UnknownField` — a
//! stated Phase 3 scope, not a silent drop, same convention this file's
//! predecessor comment used for Phase 1.

use attome_core::change_feed::ChangeEvent;

/// Parsed form of `event_subscription`'s `filter_entity_
/// logicalnames`/`filter_operations`/`filter_event_names` (migration
/// `0441`, REVIEW-2026-09-02 finding #3) columns. `None` on any side means
/// "match every value" (NULL in Postgres, mirrored here rather than an empty
/// `Vec` — an empty `Vec` would mean "matches nothing", a materially
/// different and easy-to-misread policy).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionFilter {
    pub entities: Option<Vec<String>>,
    pub operations: Option<Vec<String>>,
    /// Matches [`ChangeEvent::event_name`]. An unnamed event (`None`) never
    /// satisfies a `Some(event_names)` filter — a subscription that asks for
    /// specific named events is not asking for "also every ordinary edit".
    pub event_names: Option<Vec<String>>,
    /// `event_subscription.filter_expression` (migration `0143`,
    /// M45 Phase 3) — see this module's doc comment for exactly what fields
    /// it can reference. `None` (the common case) always matches, same as
    /// every other filter dimension here.
    pub filter_expression: Option<String>,
}

/// The `attome_rules::Schema`/`Context` every `filter_expression` compiles and
/// evaluates against — the [`ChangeEvent`]'s own fields only, see this
/// module's doc comment. Built once per `matches` call (not cached: a
/// subscription's filter is small, admin-edited config, evaluated at most
/// once per (subscription, event) pair on a dispatch tick, not a per-record
/// hot path — revisit only if measurement says otherwise, guidelines §14).
fn schema_and_context_for_event(
    event: &ChangeEvent,
) -> (attome_rules::Schema, attome_rules::Context) {
    let schema = attome_rules::Schema::new()
        .with_field("entity_logicalname", attome_rules::Type::Text)
        .with_field("operation", attome_rules::Type::Text)
        .with_field("record_id", attome_rules::Type::Lookup)
        // `event_name` is `Text`-typed even though it's `None` on an
        // unnamed event -- `Value::Null` (below) is a valid value of every
        // declared type, same "missing means null" convention
        // `attome_api::rule_engine::rules_value_of` uses.
        .with_field("event_name", attome_rules::Type::Text);
    let ctx = attome_rules::Context::new(event.created_at)
        .with_field(
            "entity_logicalname",
            attome_rules::Value::Text(event.entity_logicalname.clone()),
        )
        .with_field(
            "operation",
            attome_rules::Value::Text(event.operation.clone()),
        )
        .with_field("record_id", attome_rules::Value::Lookup(event.record_id))
        .with_field(
            "event_name",
            event
                .event_name
                .clone()
                .map(attome_rules::Value::Text)
                .unwrap_or(attome_rules::Value::Null),
        );
    (schema, ctx)
}

impl SubscriptionFilter {
    pub fn new(
        entities: Option<Vec<String>>,
        operations: Option<Vec<String>>,
        event_names: Option<Vec<String>>,
        filter_expression: Option<String>,
    ) -> Self {
        Self {
            entities,
            operations,
            event_names,
            filter_expression,
        }
    }

    /// True iff `event` should be delivered to a subscription carrying this
    /// filter. `filter_expression` is checked last (after the cheap
    /// entity/operation/event_names checks already narrowed things down) —
    /// a condition that fails to compile or evaluate is treated as
    /// not-matching (fail closed toward "do not deliver", the opposite
    /// direction from an approval-policy condition, because an over-broad
    /// webhook delivery is the worse mistake here, not an under-broad one).
    pub fn matches(&self, event: &ChangeEvent) -> bool {
        if let Some(entities) = &self.entities
            && !entities.iter().any(|e| e == &event.entity_logicalname)
        {
            return false;
        }
        if let Some(operations) = &self.operations
            && !operations.iter().any(|op| op == &event.operation)
        {
            return false;
        }
        if let Some(event_names) = &self.event_names {
            match &event.event_name {
                Some(name) if event_names.iter().any(|n| n == name) => {}
                _ => return false,
            }
        }
        if let Some(expr) = &self.filter_expression {
            let (schema, ctx) = schema_and_context_for_event(event);
            let matched = attome_rules::compile(expr, &schema)
                .ok()
                .and_then(|compiled| compiled.eval(&ctx).ok())
                .is_some_and(|v| v == attome_rules::Value::Bool(true));
            if !matched {
                return false;
            }
        }
        true
    }

    /// Same matching rules as [`Self::matches`], for `kind = 'audit'`
    /// subscriptions (`crate::audit_dispatch`) — the source there is
    /// `audit_header`, not a `ChangeEvent`, so this takes the two
    /// fields directly rather than borrowing that type. `entity_name` is
    /// `None` for a security/business-event header (no entity involved):
    /// an entity filter cannot be satisfied by "no entity", so `None` never
    /// matches a `Some(entities)` filter, same as an entity that just isn't
    /// in the list.
    pub fn matches_audit(&self, entity_name: Option<&str>, operation_name: &str) -> bool {
        if let Some(entities) = &self.entities {
            match entity_name {
                Some(name) if entities.iter().any(|e| e == name) => {}
                _ => return false,
            }
        }
        if let Some(operations) = &self.operations
            && !operations.iter().any(|op| op == operation_name)
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn event(entity: &str, operation: &str) -> ChangeEvent {
        ChangeEvent {
            id: Uuid::now_v7(),
            entity_logicalname: entity.to_string(),
            record_id: Uuid::now_v7(),
            operation: operation.to_string(),
            event_name: None,
            created_at: Utc::now(),
            changed_attributes: Vec::new(),
            quiet: false,
        }
    }

    fn named_event(entity: &str, operation: &str, event_name: &str) -> ChangeEvent {
        ChangeEvent {
            event_name: Some(event_name.to_string()),
            ..event(entity, operation)
        }
    }

    #[test]
    fn empty_filter_matches_every_event() {
        let filter = SubscriptionFilter::default();
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(filter.matches(&event("anything", "purge")));
    }

    #[test]
    fn entity_filter_rejects_a_non_matching_entity() {
        let filter = SubscriptionFilter::new(Some(vec!["service_ticket".into()]), None, None, None);
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(!filter.matches(&event("service_work_request", "create")));
    }

    #[test]
    fn operation_filter_rejects_a_non_matching_operation() {
        let filter = SubscriptionFilter::new(
            None,
            Some(vec!["create".into(), "update".into()]),
            None,
            None,
        );
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(filter.matches(&event("service_ticket", "update")));
        assert!(!filter.matches(&event("service_ticket", "delete")));
    }

    #[test]
    fn both_filters_must_match_together() {
        let filter = SubscriptionFilter::new(
            Some(vec!["service_ticket".into()]),
            Some(vec!["create".into()]),
            None,
            None,
        );
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(!filter.matches(&event("service_ticket", "update")));
        assert!(!filter.matches(&event("service_work_request", "create")));
    }

    #[test]
    fn an_empty_vec_filter_matches_nothing_distinct_from_none() {
        // Deliberately distinct from `SubscriptionFilter::default()`: an
        // explicit empty list (as opposed to NULL/None) means "no entity is
        // eligible," not "every entity is eligible."
        let filter = SubscriptionFilter::new(Some(vec![]), None, None, None);
        assert!(!filter.matches(&event("service_ticket", "create")));
    }

    // REVIEW-2026-09-02 finding #3 — the M62 filter previously had no way to
    // match a named change-feed event (e.g. M73's `sla.breached`) at all.
    #[test]
    fn event_name_filter_matches_only_a_named_event_in_the_list() {
        let filter = SubscriptionFilter::new(None, None, Some(vec!["sla.breached".into()]), None);
        assert!(filter.matches(&named_event("service_ticket", "update", "sla.breached")));
        assert!(!filter.matches(&named_event("service_ticket", "update", "sla.warning")));
    }

    #[test]
    fn event_name_filter_rejects_an_unnamed_event() {
        // An ordinary entity-change event (no `event_name`) never satisfies
        // a `Some(event_names)` filter, even though it would pass the
        // entity/operation filters on its own.
        let filter = SubscriptionFilter::new(None, None, Some(vec!["sla.breached".into()]), None);
        assert!(!filter.matches(&event("service_ticket", "update")));
    }

    #[test]
    fn no_event_name_filter_matches_a_named_event_too() {
        // `None` still means "match every event name, named or not" — the
        // same NULL-means-everything convention the other two filters use.
        let filter = SubscriptionFilter::default();
        assert!(filter.matches(&named_event("service_ticket", "update", "sla.breached")));
    }

    // REVIEW-2026-09-02 finding #8 (M45 Phase 3) — `filter_expression` is
    // now evaluated against the event's own fields.
    #[test]
    fn filter_expression_matches_on_event_name() {
        let filter = SubscriptionFilter::new(
            None,
            None,
            None,
            Some("event_name == \"sla.breached\"".into()),
        );
        assert!(filter.matches(&named_event("service_ticket", "update", "sla.breached")));
        assert!(!filter.matches(&named_event("service_ticket", "update", "sla.warning")));
    }

    #[test]
    fn filter_expression_can_combine_entity_and_operation() {
        let filter = SubscriptionFilter::new(
            None,
            None,
            None,
            Some("entity_logicalname == \"service_ticket\" and operation == \"create\"".into()),
        );
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(!filter.matches(&event("service_ticket", "update")));
        assert!(!filter.matches(&event("service_work_request", "create")));
    }

    #[test]
    fn filter_expression_treats_a_null_event_name_correctly() {
        let filter = SubscriptionFilter::new(None, None, None, Some("is_null(event_name)".into()));
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(!filter.matches(&named_event("service_ticket", "create", "sla.breached")));
    }

    #[test]
    fn an_unresolvable_filter_expression_fails_closed_to_no_match() {
        // References a field with no counterpart in this event's Context
        // (the record's own business fields aren't loaded here, see this
        // module's doc comment) -> compile fails -> fails closed to "does
        // not match" (the safer direction for a webhook delivery filter).
        let filter = SubscriptionFilter::new(None, None, None, Some("amount > 100".into()));
        assert!(!filter.matches(&event("service_ticket", "create")));
    }

    #[test]
    fn filter_expression_is_checked_last_alongside_the_other_dimensions() {
        let filter = SubscriptionFilter::new(
            Some(vec!["service_ticket".into()]),
            None,
            None,
            Some("operation == \"create\"".into()),
        );
        assert!(filter.matches(&event("service_ticket", "create")));
        assert!(!filter.matches(&event("service_ticket", "update")));
        assert!(!filter.matches(&event("service_work_request", "create")));
    }
}
