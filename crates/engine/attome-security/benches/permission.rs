//! AA14-T1: the record-access check every scoped read builds: a user with
//! three roles (one conditional grant each) reading one entity's records at
//! team depth, with the owner arm on.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_debug_implementations,
    reason = "a benchmark: a failed setup step should panic with its message"
)]

use attome_core::AttrInfo;
use attome_security::{RecordAction, rls_predicate_with_conditions};
use attome_server::security::{AccessLevel, SecurityContext};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;
use std::hint::black_box;
use uuid::Uuid;

fn context() -> SecurityContext {
    let roles: Vec<Uuid> = (0..3).map(|_| Uuid::now_v7()).collect();
    serde_json::from_value(json!({
        "user_id": Uuid::now_v7(),
        "is_admin": false,
        "privileges": ["account.read", "account.update", "contact.read"],
        "team_ids": [Uuid::now_v7(), Uuid::now_v7()],
        "accessible_org_ids": [Uuid::now_v7()],
        "role_ids": roles,
        "condition_grants": {
            "account.read": [
                [{ "field_logicalname": "region", "operator": "Eq", "value": "riyadh" }],
                [{ "field_logicalname": "tier", "operator": "In", "value": ["gold", "silver"] }],
                [{ "field_logicalname": "revenue", "operator": "Gte", "value": 100000 }]
            ]
        }
    }))
    .unwrap()
}

fn attrs() -> Vec<AttrInfo> {
    [
        ("region", 1),
        ("tier", 1),
        ("revenue", 3),
        ("owner_ref", 11),
    ]
    .into_iter()
    .map(|(name, kind)| {
        serde_json::from_value(json!({
            "logicalname": name,
            "field_type_int": kind,
            "is_sensitive": false,
            "is_sortable": true,
            "is_filterable": true,
        }))
        .unwrap()
    })
    .collect()
}

fn permission(c: &mut Criterion) {
    let ctx = context();
    let attrs = attrs();
    let entity = Uuid::now_v7();
    c.bench_function("record_access_predicate_three_roles", |b| {
        b.iter(|| {
            black_box(rls_predicate_with_conditions(
                black_box(&ctx),
                entity,
                "t",
                AccessLevel::Team,
                RecordAction::Read.share_capability(),
                "account.read",
                &attrs,
                true,
                1,
            ))
        })
    });
}

criterion_group!(benches, permission);
criterion_main!(benches);
