// ── Tests (D-021 — the shared validator both provision.rs and admin.rs call) ──
use super::{
    ATTRIBUTE_INDEX_CONNECTION_LIMIT, MAX_IDENTIFIER_LEN, ReconcilePolicy, RowStatus, WriteStep,
    attribute_index_name, decide_step, default_display_query_sql, managed_value,
    reject_unsafe_default_query_sql, seeded_view_sql, valid_identifier,
};

// ── P-environment-promotion: the pure reconcile policy matrix ────────────────
//
// `decide_step` is the one place the ownership rule ("a seed updates a row it
// seeds unless that row is customized, and reports every skip") is encoded;
// these pin every cell of policy × {missing, live, retired} × {customized,
// not} × {differs, same} without a database.

const PRISTINE_LIVE: Option<RowStatus> = Some(RowStatus {
    is_customized: false,
    is_live: true,
});
const CUSTOMIZED_LIVE: Option<RowStatus> = Some(RowStatus {
    is_customized: true,
    is_live: true,
});
const PRISTINE_RETIRED: Option<RowStatus> = Some(RowStatus {
    is_customized: false,
    is_live: false,
});
const CUSTOMIZED_RETIRED: Option<RowStatus> = Some(RowStatus {
    is_customized: true,
    is_live: false,
});

#[test]
fn decide_step_creates_when_no_row_exists_under_every_policy() {
    for policy in [
        ReconcilePolicy::Seed,
        ReconcilePolicy::Admin,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
        ReconcilePolicy::Bundle {
            is_customized: true,
        },
    ] {
        assert_eq!(decide_step(policy, None, false), WriteStep::Create);
        assert_eq!(decide_step(policy, None, true), WriteStep::Create);
    }
}

#[test]
fn decide_step_seed_is_unchanged_when_identical_and_updates_when_drifted() {
    assert_eq!(
        decide_step(ReconcilePolicy::Seed, PRISTINE_LIVE, false),
        WriteStep::Unchanged,
        "the steady-state boot reseed must take no lock and write nothing"
    );
    assert_eq!(
        decide_step(ReconcilePolicy::Seed, PRISTINE_LIVE, true),
        WriteStep::Update
    );
}

#[test]
fn decide_step_seed_skips_customized_rows_even_when_they_differ() {
    // §6 "Ownership (c)": a seeded row that differs *because* an admin
    // customized it must be skipped, never "fixed".
    assert_eq!(
        decide_step(ReconcilePolicy::Seed, CUSTOMIZED_LIVE, true),
        WriteStep::SkippedCustomized
    );
    assert_eq!(
        decide_step(ReconcilePolicy::Seed, CUSTOMIZED_LIVE, false),
        WriteStep::SkippedCustomized
    );
    // A customized row the admin soft-deleted stays deleted under a seed —
    // reactivating it would undo exactly the change they made.
    assert_eq!(
        decide_step(ReconcilePolicy::Seed, CUSTOMIZED_RETIRED, false),
        WriteStep::SkippedCustomized
    );
}

#[test]
fn decide_step_seed_reactivates_a_pristine_retired_row() {
    // Reactivate-over-insert: a retired, non-customized row with the same key
    // is brought back rather than a second row being inserted.
    assert_eq!(
        decide_step(ReconcilePolicy::Seed, PRISTINE_RETIRED, false),
        WriteStep::Update
    );
}

#[test]
fn decide_step_admin_always_writes_customized_rows_and_marks_pristine_ones() {
    // An admin write applies regardless of the marker…
    assert_eq!(
        decide_step(ReconcilePolicy::Admin, CUSTOMIZED_LIVE, true),
        WriteStep::Update
    );
    assert_eq!(
        decide_step(ReconcilePolicy::Admin, CUSTOMIZED_LIVE, false),
        WriteStep::Unchanged,
        "identical row already marked customized: nothing to write"
    );
    // …and an admin write that changes nothing else still marks a pristine
    // row as customized ("any admin write that touches the row").
    assert_eq!(
        decide_step(ReconcilePolicy::Admin, PRISTINE_LIVE, false),
        WriteStep::Update
    );
    assert_eq!(
        decide_step(ReconcilePolicy::Admin, CUSTOMIZED_RETIRED, false),
        WriteStep::Update,
        "admin re-creating a soft-deleted key reactivates it"
    );
}

#[test]
fn decide_step_bundle_applies_the_carried_marker_exactly() {
    let keep_pristine = ReconcilePolicy::Bundle {
        is_customized: false,
    };
    let carry_customized = ReconcilePolicy::Bundle {
        is_customized: true,
    };
    assert_eq!(
        decide_step(keep_pristine, PRISTINE_LIVE, false),
        WriteStep::Unchanged
    );
    assert_eq!(
        decide_step(carry_customized, PRISTINE_LIVE, false),
        WriteStep::Update,
        "a promoted customization lands with its marker (§4)"
    );
    assert_eq!(
        decide_step(keep_pristine, CUSTOMIZED_LIVE, false),
        WriteStep::Update,
        "a bundle that says 'not customized' clears the marker — exact desired state"
    );
    assert_eq!(
        decide_step(carry_customized, CUSTOMIZED_LIVE, false),
        WriteStep::Unchanged
    );
    assert_eq!(
        decide_step(keep_pristine, CUSTOMIZED_LIVE, true),
        WriteStep::Update
    );
}

#[test]
fn managed_value_seed_none_means_leave_as_is_and_everything_else_is_exact() {
    // Seed + None = "this seed does not manage the column".
    assert_eq!(
        managed_value(ReconcilePolicy::Seed, None, Some(42)),
        Some(42)
    );
    assert_eq!(
        managed_value::<i32>(ReconcilePolicy::Seed, None, None),
        None
    );
    // Seed + Some = managed, exact.
    assert_eq!(
        managed_value(ReconcilePolicy::Seed, Some(7), Some(42)),
        Some(7)
    );
    // Admin/Bundle: the description is the exact desired state, None = NULL.
    assert_eq!(managed_value(ReconcilePolicy::Admin, None, Some(42)), None);
    assert_eq!(
        managed_value(
            ReconcilePolicy::Bundle {
                is_customized: false
            },
            None,
            Some(42)
        ),
        None
    );
    assert_eq!(
        managed_value(ReconcilePolicy::Admin, Some(7), Some(42)),
        Some(7)
    );
}

#[test]
fn accepts_lowercase_letters_digits_and_underscore() {
    assert!(valid_identifier("api_key"));
    assert!(valid_identifier("_leading_underscore"));
    assert!(valid_identifier("entity123"));
}

#[test]
fn rejects_leading_digit_or_all_digit_names() {
    assert!(!valid_identifier("1entity"));
    assert!(!valid_identifier("123"));
}

#[test]
fn rejects_empty_and_uppercase() {
    assert!(!valid_identifier(""));
    assert!(!valid_identifier("Entity"));
}

// P-provisioning-hardening item (a) — D-101.
#[test]
fn accepts_identifier_at_cap() {
    let name: String = "a".repeat(MAX_IDENTIFIER_LEN);
    assert_eq!(name.len(), MAX_IDENTIFIER_LEN);
    assert!(valid_identifier(&name));
}

#[test]
fn rejects_identifier_over_cap() {
    let name: String = "a".repeat(MAX_IDENTIFIER_LEN + 1);
    assert!(!valid_identifier(&name));
}

#[test]
fn attribute_index_name_at_63_ok() {
    // "idx_" (4) + entity + "_" (1) + field + "_sf" (3) == 63
    // entity + field == 55 bytes; split so both individually pass
    // valid_identifier's 48-byte cap.
    let entity = "a".repeat(30);
    let field = "b".repeat(25);
    let name = attribute_index_name(&entity, &field).expect("63 bytes must be accepted");
    assert_eq!(name.len(), 63);
}

#[test]
fn attribute_index_name_past_63_is_hashed_to_fit() {
    let entity = "a".repeat(30);
    let field = "b".repeat(26);
    let name = attribute_index_name(&entity, &field).expect("a long pair still gets a name");
    assert_eq!(name.len(), 63, "{name}");
    assert!(
        name.starts_with("idx_aaaa") && name.ends_with("_sf"),
        "{name}"
    );
    assert_eq!(
        attribute_index_name(&entity, &field).unwrap(),
        name,
        "stable"
    );
    let other = attribute_index_name(&entity, &"c".repeat(26)).unwrap();
    assert_ne!(other, name, "another pair, another name");
}

// Item 28 — bounds `sync_attribute_index`'s direct migrator-connection
// creation. Exercises the semaphore itself (no DB, no async runtime
// needed — `try_acquire` is synchronous): proves the configured limit
// actually refuses a permit once exhausted, and that a release frees a
// slot — rather than a bug silently making the bound a no-op (e.g. an
// unbounded `Semaphore::new(usize::MAX)`). Uses `try_acquire`, never
// `.acquire().await`, so a regression fails fast instead of deadlocking
// this test.
#[test]
fn attribute_index_connection_limit_bounds_concurrent_permits() {
    let mut held = Vec::new();
    while let Ok(permit) = ATTRIBUTE_INDEX_CONNECTION_LIMIT.try_acquire() {
        held.push(permit);
    }
    assert!(
        !held.is_empty(),
        "expected at least one permit to be available at test start"
    );
    assert!(
        ATTRIBUTE_INDEX_CONNECTION_LIMIT.try_acquire().is_err(),
        "acquiring beyond the configured limit must be refused, not silently allowed"
    );

    held.pop();
    assert!(
        ATTRIBUTE_INDEX_CONNECTION_LIMIT.try_acquire().is_ok(),
        "releasing a held permit must free a slot for the next acquire"
    );
}

// P-stored-query-containment addendum §11(a).
#[test]
fn default_display_query_sql_matches_the_strict_single_table_template() {
    let sql = default_display_query_sql("contact", "last_name");
    assert_eq!(
        sql,
        r#"SELECT id, "last_name" FROM "contact" WHERE is_active = true"#
    );
    // Regex-equivalent shape check requested by the addendum: exactly one
    // FROM, no JOIN/UNION/second statement, quoted identifiers only.
    assert!(reject_unsafe_default_query_sql(&sql).is_ok());
}

// The Active/Inactive view pair every runtime-created entity is seeded with.
// `set_default_query_display_column` upgrades the Inactive view by matching
// the *exact* string `ensure_entity_list_views` wrote at create time, so
// these four variants must stay byte-stable relative to each other — a stray
// space in one of them silently turns that upgrade into a no-op and the
// Inactive view renders id-only forever.
#[test]
fn seeded_view_sql_covers_both_views_at_both_lifecycle_stages() {
    // At create time no attribute exists yet, so both views are id-only.
    assert_eq!(
        seeded_view_sql("contact", None, true),
        r#"SELECT id FROM "contact" WHERE is_active = true"#
    );
    assert_eq!(
        seeded_view_sql("contact", None, false),
        r#"SELECT id FROM "contact" WHERE is_active = false"#
    );
    // Once the primary_name_attribute is created, both gain the display column.
    assert_eq!(
        seeded_view_sql("contact", Some("last_name"), true),
        r#"SELECT id, "last_name" FROM "contact" WHERE is_active = true"#
    );
    assert_eq!(
        seeded_view_sql("contact", Some("last_name"), false),
        r#"SELECT id, "last_name" FROM "contact" WHERE is_active = false"#
    );
    // The Active variant is exactly what default_display_query_sql produces —
    // the two must not drift apart now that one delegates to the other.
    assert_eq!(
        seeded_view_sql("contact", Some("last_name"), true),
        default_display_query_sql("contact", "last_name")
    );
    for sql in [
        seeded_view_sql("contact", None, false),
        seeded_view_sql("contact", Some("last_name"), false),
    ] {
        assert!(reject_unsafe_default_query_sql(&sql).is_ok());
    }
}

#[test]
fn reject_unsafe_default_query_sql_accepts_every_current_call_site() {
    // Literal copies of the seven real ensure_default_query call sites
    // (attome-notification, attome-s2s x3, attome-audit, attome-server::license_seed,
    // server::apikey_seed) plus admin.rs's quote_ident-templated one —
    // pins that the guard doesn't false-positive on real, already-
    // shipped traffic.
    let real_call_sites = [
        "SELECT id, template_key, locale, subject, body_html, body_text, \
         default_channels, escalate_after_minutes, escalate_channels, \
         row_version, created_at, modified_at \
         FROM notification_template WHERE is_active = TRUE",
        "SELECT id, name, client_id, description, status, service_user_ref, \
         rate_limit_rpm, max_concurrent, allowed_cidrs, max_payload_bytes, \
         auto_disable_days, last_used_at, row_version, created_at, updated_at \
         FROM s2s_client WHERE is_deleted = FALSE AND is_active IS NOT FALSE",
        "SELECT id, client_ref, entity_name, can_read, can_create, can_update, \
         can_delete, can_export, can_bulk, row_version, created_at, updated_at \
         FROM s2s_permission WHERE is_deleted = FALSE AND is_active IS NOT FALSE",
        "SELECT id, client_ref, client_name, method, path, status_code, response_time_ms, \
         bytes_received, bytes_sent, correlation_id, ip_address, nonce, error_code, created_at \
         FROM s2s_access_log",
        "SELECT id, created_at, organization_ref, is_active, category, entity_name, record_id, \
         operation, version_before, version_after, user_id, user_name, user_display_name, \
         user_email, user_job_ref, user_job_name, changed_on, source, ip_address, browser, \
         device_type, correlation_id, batch_id, event_name, event_comment \
         FROM audit_header",
        "SELECT id, created_at, deployment_id, domain, tier, max_users, expiry, modules, issued_at \
         FROM license",
        "SELECT id, user_ref, name, public_key, created_at, last_used_at, is_active FROM api_key WHERE is_active IS NOT FALSE",
        r#"SELECT id FROM "some_entity" WHERE is_active = true"#,
    ];
    for sql in real_call_sites {
        assert!(
            reject_unsafe_default_query_sql(sql).is_ok(),
            "guard falsely rejected a real call site: {sql}"
        );
    }
}

#[test]
fn reject_unsafe_default_query_sql_rejects_a_second_statement() {
    assert!(
        reject_unsafe_default_query_sql(
            "SELECT id FROM contact; SELECT password_hash FROM user_account"
        )
        .is_err()
    );
}

#[test]
fn reject_unsafe_default_query_sql_rejects_a_join() {
    assert!(
        reject_unsafe_default_query_sql(
            "SELECT c.id, u.password_hash FROM contact c JOIN user_account u ON u.id = c.owner_ref"
        )
        .is_err()
    );
}

#[test]
fn reject_unsafe_default_query_sql_rejects_a_union() {
    assert!(
        reject_unsafe_default_query_sql("SELECT id FROM contact UNION SELECT id FROM api_key")
            .is_err()
    );
}

#[test]
fn reject_unsafe_default_query_sql_rejects_inner_ordering() {
    // D-350 / finding H-9: the exact three strings that used to ship, in the
    // shape they shipped in. query/execute wraps a stored query as a subquery,
    // and PostgreSQL will not flatten one that carries a sortClause — so the
    // sort ran over the whole relation before the outer LIMIT could take a
    // page. Ordering belongs to the caller's order_by/order_dir, applied
    // outside the subquery.
    for sql in [
        "SELECT id, created_at, organization_ref FROM audit_header ORDER BY created_at DESC",
        "SELECT id, client_ref, created_at FROM s2s_access_log ORDER BY created_at DESC",
        "SELECT id, domain, created_at FROM license ORDER BY created_at DESC",
        // Lower-case and mixed-case spellings are the same defect.
        "SELECT id FROM contact order by created_at asc",
    ] {
        assert!(
            reject_unsafe_default_query_sql(sql).is_err(),
            "guard accepted a seeded query carrying its own ORDER BY: {sql}"
        );
    }
}

#[test]
fn reject_unsafe_default_query_sql_rejects_a_second_from() {
    assert!(
        reject_unsafe_default_query_sql(
            "SELECT id FROM contact WHERE id IN (SELECT owner_ref FROM user_account)"
        )
        .is_err()
    );
}

#[test]
fn reject_unsafe_default_query_sql_accepts_extract_and_substring_from_syntax() {
    // EXTRACT(field FROM source) and SUBSTRING(str FROM start [FOR len]) use
    // FROM as standard SQL function-call syntax, not a table clause — a
    // naive " FROM " count previously miscounted either as a second table
    // and rejected an otherwise single-table query. Verified live,
    // 2026-09-02: attome-service's SLA mean-time-to-resolve seed uses exactly
    // this EXTRACT shape and failed boot until this was fixed.
    for sql in [
        "SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60.0) AS value \
         FROM service_ticket WHERE resolved_at IS NOT NULL",
        "SELECT SUBSTRING(name FROM 1 FOR 3) AS prefix FROM contact",
        // A genuine second table FROM alongside one of these must still be
        // rejected — the fix only discounts the function-syntax FROM, it
        // does not disable multi-table detection entirely.
    ] {
        assert!(
            reject_unsafe_default_query_sql(sql).is_ok(),
            "guard wrongly rejected a single-table query using EXTRACT/SUBSTRING FROM syntax: {sql}"
        );
    }
    assert!(
        reject_unsafe_default_query_sql(
            "SELECT AVG(EXTRACT(EPOCH FROM (a.resolved_at - a.created_at))) \
             FROM service_ticket a WHERE a.id IN (SELECT owner_ref FROM user_account)"
        )
        .is_err(),
        "guard must still reject a genuine second table FROM alongside an EXTRACT(...FROM...)"
    );
}
