//! M38 Phase 1 — the graph traversal walk (`attome_search::graph`), run against
//! a real PostgreSQL. `graph::tests` (unit tests, in-crate) covers the pure
//! edge-catalogue logic; this covers what only a real database can prove:
//! that the generated SQL executes, and — the critical property — that a
//! caller never sees a record through the graph that they could not read
//! directly.
//!
//! Exercises [`attome_search::graph::test_support::walk_for_test`] rather than
//! the full [`attome_search::graph::traverse`] entry point, mirroring
//! `harness::run_query`'s pattern in this same crate: `traverse` adds only
//! `EngineState`-specific plumbing (loading the registry snapshot, resolving the
//! access map from real privilege tables, pool selection) on top of the walk
//! itself, and each of those is independently covered elsewhere
//! (`access_cache`'s own tests, `resolve_all_entity_access_levels`'s DB
//! tests in `attome-security`). What is unique to this file is the walk's own
//! SQL and its permission behaviour.
//!
//! Every entity here is a throwaway physical table created directly with
//! `CREATE TABLE`, not through runtime provisioning — squarely inside
//! guidelines §4's "tests against a throwaway database" exemption, the same
//! one `legs_execute.rs`/`harness::seed` already use to write rows straight
//! into `search_index`. The `EntityMetaRegistry` describing them is
//! built by hand (`EntityMetaRegistry::from_entities`) rather than read back
//! from `entity_info` — the registry is the one input `walk` truly
//! needs, and building it directly keeps this suite from depending on
//! `attome-metadata`'s provisioning machinery.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test graph_traverse
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::{AttrInfo, EntityMeta, EntityMetaRegistry, OnTargetDelete};
use attome_db::DbPool;
use attome_search::graph::test_support::walk_for_test;
use attome_search::graph::{Direction, NodeRefInput, TraverseRequest};
use attome_security::visibility::PolymorphicVisibility;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn ctx(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

fn attr(logicalname: &str, lookup_entity_ref: Uuid) -> AttrInfo {
    AttrInfo {
        logicalname: logicalname.to_owned(),
        field_type_int: 11, // lookup
        is_required: false,
        max_length: None,
        is_sensitive: false,
        is_write_restricted: false,
        is_sortable: false,
        is_filterable: false,
        lookup_entity_ref: Some(lookup_entity_ref),
        on_target_delete: OnTargetDelete::Orphan,
        data_classification: Default::default(),
        options: None,
    }
}

fn meta(id: Uuid, name: &str, attrs: Vec<AttrInfo>) -> EntityMeta {
    EntityMeta {
        entity_id: id,
        logicalname: name.to_owned(),
        attrs,
        is_append_only: false,
        primary_name_attribute: None,
    }
}

/// A minimal entity table: `id`, `is_active`, `organization_ref` (the fast
/// tier's own column, referenced unconditionally by the visibility fragment
/// `walk` always builds with `Some(FastTierColumns { .. })`-equivalent
/// wiring), plus whatever lookup columns the caller names.
async fn create_entity_table(db: &DbPool, name: &str, lookup_cols: &[&str]) {
    let extra: String = lookup_cols
        .iter()
        .map(|c| format!(", \"{c}\" UUID"))
        .collect();
    sqlx::query(&format!(
        "CREATE TABLE \"{name}\" (id UUID PRIMARY KEY, is_active BOOLEAN, \
         organization_ref UUID{extra})"
    ))
    .execute(db)
    .await
    .unwrap_or_else(|e| panic!("create test entity table {name}: {e}"));
}

/// `record_relationship` is created by runtime provisioning
/// (`relationship_seed::seed`, `attome-api`), not by a migration — so a
/// database that only ran `sqlx::migrate!` (this crate's own test databases
/// never boot the full `attome-api` system) may not have it yet. Every test
/// here that runs `Direction::Both`/`Outbound`/`Inbound` reaches
/// `graph::relationship_candidates`, which queries it, so this makes the
/// minimal shape that query needs exist idempotently — a no-op if the real
/// seed already ran against this database, compatible with it either way
/// since the real seed's `from_record_id`/`to_record_id` are `text` too.
async fn ensure_relationship_table(db: &DbPool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS record_relationship ( \
            id UUID PRIMARY KEY, \
            from_entity_name TEXT, \
            from_record_id TEXT, \
            to_entity_name TEXT, \
            to_record_id TEXT, \
            relationship_type TEXT, \
            is_active BOOLEAN DEFAULT true \
         )",
    )
    .execute(db)
    .await
    .expect("ensure record_relationship exists for the test");
}

struct Row<'a> {
    id: Uuid,
    cols: &'a [(&'a str, Uuid)],
}

async fn insert_row(db: &DbPool, table: &str, row: Row<'_>) {
    let mut names = vec!["id".to_string(), "is_active".to_string()];
    let mut placeholders = vec!["$1".to_string(), "true".to_string()];
    for (i, (col, _)) in row.cols.iter().enumerate() {
        names.push(format!("\"{col}\""));
        placeholders.push(format!("${}", i + 2));
    }
    let sql = format!(
        "INSERT INTO \"{table}\" ({}) VALUES ({})",
        names.join(", "),
        placeholders.join(", ")
    );
    let mut q = sqlx::query(&sql).bind(row.id);
    for (_, v) in row.cols {
        q = q.bind(*v);
    }
    q.execute(db)
        .await
        .unwrap_or_else(|e| panic!("insert into {table}: {e}"));
}

/// **The critical security test.** A graph where the only path to an
/// otherwise-visible node (`w`) goes through a node the caller cannot read
/// at all (`h`, deliberately absent from the access map — the same
/// "entity absent from `access_by_entity`" technique
/// `legs_execute.rs::a_caller_with_no_privilege_gets_nothing_from_any_leg`
/// uses). `c` is a second, directly-reachable visible node, included so this
/// test also proves the walk isn't merely failing everything — it finds a
/// real path and specifically excludes the hidden one and everything beyond
/// it.
///
///   a --(h_ref)--> h [HIDDEN] --(w_ref)--> w [visible, unreachable]
///   a --(c_ref)--> c [visible, directly reachable]
#[tokio::test]
async fn a_hidden_intermediate_node_never_leaks_itself_or_what_lies_beyond_it() {
    let db = skip_if_no_db!(test_db().await);
    ensure_relationship_table(&db).await;
    let suffix = Uuid::now_v7().simple().to_string();
    let a_name = format!("gk_a_{suffix}");
    let h_name = format!("gk_h_{suffix}");
    let w_name = format!("gk_w_{suffix}");
    let c_name = format!("gk_c_{suffix}");

    create_entity_table(&db, &a_name, &["h_ref", "c_ref"]).await;
    create_entity_table(&db, &h_name, &["w_ref"]).await;
    create_entity_table(&db, &w_name, &[]).await;
    create_entity_table(&db, &c_name, &[]).await;

    let a_id = Uuid::now_v7();
    let h_id = Uuid::now_v7();
    let w_id = Uuid::now_v7();
    let c_id = Uuid::now_v7();

    insert_row(
        &db,
        &a_name,
        Row {
            id: a_id,
            cols: &[("h_ref", h_id), ("c_ref", c_id)],
        },
    )
    .await;
    insert_row(
        &db,
        &h_name,
        Row {
            id: h_id,
            cols: &[("w_ref", w_id)],
        },
    )
    .await;
    insert_row(
        &db,
        &w_name,
        Row {
            id: w_id,
            cols: &[],
        },
    )
    .await;
    insert_row(
        &db,
        &c_name,
        Row {
            id: c_id,
            cols: &[],
        },
    )
    .await;

    let a_entity_id = Uuid::now_v7();
    let h_entity_id = Uuid::now_v7();
    let w_entity_id = Uuid::now_v7();
    let c_entity_id = Uuid::now_v7();
    let registry = EntityMetaRegistry::from_entities(vec![
        meta(
            a_entity_id,
            &a_name,
            vec![attr("h_ref", h_entity_id), attr("c_ref", c_entity_id)],
        ),
        meta(h_entity_id, &h_name, vec![attr("w_ref", w_entity_id)]),
        meta(w_entity_id, &w_name, vec![]),
        meta(c_entity_id, &c_name, vec![]),
    ]);

    // The caller's access map deliberately has NO entry for `h_name` — the
    // exact mechanism that makes `PolymorphicVisibility::push`'s
    // `m.pos IS NOT NULL` guard reject every row of that entity, structural
    // metadata notwithstanding.
    let mut access_map = HashMap::new();
    access_map.insert(a_name.clone(), (Uuid::now_v7(), AccessLevel::Global));
    access_map.insert(w_name.clone(), (Uuid::now_v7(), AccessLevel::Global));
    access_map.insert(c_name.clone(), (Uuid::now_v7(), AccessLevel::Global));

    let c = ctx(Uuid::now_v7());
    let visibility = PolymorphicVisibility::new(
        &c,
        &access_map,
        &HashSet::new(),
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    let req = TraverseRequest {
        start: NodeRefInput {
            entity: a_name.clone(),
            id: a_id,
        },
        edge_types: None,
        direction: Direction::Both,
        max_depth: 4,
        limit: 100,
    };

    let outcome = walk_for_test(&db, &registry, &c, &visibility, &req)
        .await
        .expect("the walk must execute");

    assert!(
        outcome.nodes.iter().any(|n| n.record_id == a_id),
        "the start node must always be present"
    );
    assert!(
        outcome.nodes.iter().any(|n| n.record_id == c_id),
        "a directly-visible node must be found — the walk must not merely \
         fail everything: {:?}",
        outcome
            .nodes
            .iter()
            .map(|n| n.record_id)
            .collect::<Vec<_>>()
    );

    assert!(
        !outcome.nodes.iter().any(|n| n.record_id == h_id),
        "the hidden node itself must never appear in the result, even as a \
         pass-through hop"
    );
    assert!(
        !outcome.nodes.iter().any(|n| n.record_id == w_id),
        "a node reachable ONLY through the hidden node must never appear — \
         its only path was blocked at the hidden hop"
    );
    assert!(
        !outcome
            .edges
            .iter()
            .any(|e| e.from_id == h_id || e.to_id == h_id),
        "the hidden node must not appear as an edge endpoint either — an \
         edge referencing it would prove its existence without listing it \
         as a node"
    );
    assert!(
        !outcome
            .edges
            .iter()
            .any(|e| e.from_id == w_id || e.to_id == w_id),
        "no edge may reference the unreachable node"
    );
    assert!(
        !outcome.truncated,
        "nothing here hit a bound — the missing nodes are a permission \
         decision, not a truncation, and the flag must not conflate the two"
    );
}

/// The depth bound actually stops the walk, and the response says so.
#[tokio::test]
async fn depth_bound_is_enforced_and_reported_truncated() {
    let db = skip_if_no_db!(test_db().await);
    ensure_relationship_table(&db).await;
    let suffix = Uuid::now_v7().simple().to_string();
    // A chain of five entities, each with a lookup to the next: n0 -> n1 ->
    // n2 -> n3 -> n4. max_depth = 2 must reach n0 (depth 0), n1 (depth 1),
    // n2 (depth 2), and stop — n3/n4 must never appear.
    let names: Vec<String> = (0..5).map(|i| format!("gk_chain{i}_{suffix}")).collect();
    let ids: Vec<Uuid> = (0..5).map(|_| Uuid::now_v7()).collect();
    let entity_ids: Vec<Uuid> = (0..5).map(|_| Uuid::now_v7()).collect();

    for (i, name) in names.iter().enumerate() {
        let cols: &[&str] = if i + 1 < names.len() {
            &["next_ref"]
        } else {
            &[]
        };
        create_entity_table(&db, name, cols).await;
    }
    for i in 0..names.len() {
        let cols: Vec<(&str, Uuid)> = if i + 1 < names.len() {
            vec![("next_ref", ids[i + 1])]
        } else {
            vec![]
        };
        insert_row(
            &db,
            &names[i],
            Row {
                id: ids[i],
                cols: &cols,
            },
        )
        .await;
    }

    let metas: Vec<EntityMeta> = (0..names.len())
        .map(|i| {
            let attrs = if i + 1 < names.len() {
                vec![attr("next_ref", entity_ids[i + 1])]
            } else {
                vec![]
            };
            meta(entity_ids[i], &names[i], attrs)
        })
        .collect();
    let registry = EntityMetaRegistry::from_entities(metas);

    let mut access_map = HashMap::new();
    for name in &names {
        access_map.insert(name.clone(), (Uuid::now_v7(), AccessLevel::Global));
    }
    let c = ctx(Uuid::now_v7());
    let visibility = PolymorphicVisibility::new(
        &c,
        &access_map,
        &HashSet::new(),
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    let req = TraverseRequest {
        start: NodeRefInput {
            entity: names[0].clone(),
            id: ids[0],
        },
        edge_types: None,
        direction: Direction::Outbound,
        max_depth: 2,
        limit: 100,
    };

    let outcome = walk_for_test(&db, &registry, &c, &visibility, &req)
        .await
        .expect("the walk must execute");

    for &included in &[0usize, 1, 2] {
        assert!(
            outcome.nodes.iter().any(|n| n.record_id == ids[included]),
            "node at depth {included} must be present"
        );
    }
    for &excluded in &[3usize, 4] {
        assert!(
            !outcome.nodes.iter().any(|n| n.record_id == ids[excluded]),
            "node at depth {excluded} is beyond max_depth and must be absent"
        );
    }
    assert!(
        outcome.truncated,
        "stopping at the depth cap with more reachable beyond it must set truncated"
    );
}

/// The per-hop fan-out bound caps how many newly-admitted nodes one hop may
/// contribute, and reports truncation when it does.
#[tokio::test]
async fn fanout_bound_is_enforced_and_reported_truncated() {
    let db = skip_if_no_db!(test_db().await);
    ensure_relationship_table(&db).await;
    let suffix = Uuid::now_v7().simple().to_string();
    let parent_name = format!("gk_parent_{suffix}");
    let child_name = format!("gk_child_{suffix}");

    create_entity_table(&db, &parent_name, &[]).await;
    create_entity_table(&db, &child_name, &["parent_ref"]).await;

    let parent_id = Uuid::now_v7();
    insert_row(
        &db,
        &parent_name,
        Row {
            id: parent_id,
            cols: &[],
        },
    )
    .await;

    // More children than MAX_FANOUT_PER_HOP, all pointing at the parent —
    // an inbound hop from `parent` must admit at most the bound.
    let over_the_bound = (attome_search::graph::MAX_FANOUT_PER_HOP + 50) as usize;
    let child_ids: Vec<Uuid> = (0..over_the_bound).map(|_| Uuid::now_v7()).collect();
    let active: Vec<bool> = vec![true; over_the_bound];
    sqlx::query(&format!(
        "INSERT INTO \"{child_name}\" (id, is_active, parent_ref) \
         SELECT c.id, c.active, $3 FROM UNNEST($1::uuid[], $2::boolean[]) AS c(id, active)"
    ))
    .bind(&child_ids)
    .bind(&active)
    .bind(parent_id)
    .execute(&db)
    .await
    .expect("seed many children");

    let parent_entity_id = Uuid::now_v7();
    let child_entity_id = Uuid::now_v7();
    let registry = EntityMetaRegistry::from_entities(vec![
        meta(parent_entity_id, &parent_name, vec![]),
        meta(
            child_entity_id,
            &child_name,
            vec![attr("parent_ref", parent_entity_id)],
        ),
    ]);

    let mut access_map = HashMap::new();
    access_map.insert(parent_name.clone(), (Uuid::now_v7(), AccessLevel::Global));
    access_map.insert(child_name.clone(), (Uuid::now_v7(), AccessLevel::Global));
    let c = ctx(Uuid::now_v7());
    let visibility = PolymorphicVisibility::new(
        &c,
        &access_map,
        &HashSet::new(),
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    let req = TraverseRequest {
        start: NodeRefInput {
            entity: parent_name.clone(),
            id: parent_id,
        },
        edge_types: None,
        direction: Direction::Inbound,
        max_depth: 1,
        limit: attome_search::graph::MAX_TOTAL_NODES,
    };

    let outcome = walk_for_test(&db, &registry, &c, &visibility, &req)
        .await
        .expect("the walk must execute");

    let admitted_children = outcome
        .nodes
        .iter()
        .filter(|n| n.entity_logicalname == child_name)
        .count() as i64;
    assert!(
        admitted_children <= attome_search::graph::MAX_FANOUT_PER_HOP,
        "one hop admitted {admitted_children} nodes, past the {} bound",
        attome_search::graph::MAX_FANOUT_PER_HOP
    );
    assert!(
        outcome.truncated,
        "a hop that had more candidates than the fan-out bound must report truncated"
    );
}
