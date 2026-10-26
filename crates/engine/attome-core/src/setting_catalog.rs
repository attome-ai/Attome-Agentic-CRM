//! The closed catalogue of registered [`SettingDescriptor`]s (M02 §5, D-412).
//!
//! Mirrors `attome-ai`'s `actions/mod.rs::all()` — a hand-written `Vec`, not
//! distributed registration, so the set of valid keys is a code review, not a
//! runtime surprise. Add a new setting by adding it to `core_settings()` (or a
//! new `fn` grouped by owning concern, pushed into `all()` below) — never by
//! constructing a row directly, and never by inventing a key at write time
//! (`attome-server::settings_admin` rejects anything `registry().get(key)` can't
//! find).
//!
//! Two groups today:
//! - `core_settings()` — real, runtime-editable examples covering all three
//!   scopes, so the resolution-order test (`setting_store.rs`) has something
//!   genuine to resolve against.
//! - `reserved_boot_time_examples()` — a single illustrative descriptor
//!   proving the boot-time-only guard actually rejects a write (M02 §6's
//!   required test). It is deliberately not wired to any real `auth.*`
//!   config value — see its own doc comment.

use serde_json::json;

use crate::setting_descriptor::{SettingDescriptor, SettingScope};

pub(crate) fn all() -> Vec<SettingDescriptor> {
    let mut all = core_settings();
    all.extend(personal_settings());
    all.extend(reserved_boot_time_examples());
    all.extend(feature_flag_settings());
    all.extend(action_settings());
    all.extend(ai_settings());
    all.extend(omnichannel_settings());
    all.extend(ops_settings());
    all.extend(commission_settings());
    all.extend(billing_settings());
    all.extend(records_settings());
    all.extend(limit_settings());
    all.extend(service_settings());
    all.extend(marketing_settings());
    all
}

/// E16-T1: SMS campaigns. The price makes the cost estimate (0: no estimate
/// in money, segments only); quiet hours hold messages until the recipient's
/// morning, per country with `*` for the rest, in the country's own time.
fn marketing_settings() -> Vec<SettingDescriptor> {
    const DEPLOYMENT: &[SettingScope] = &[SettingScope::Deployment];
    vec![
        SettingDescriptor::new(
            "marketing.sms_price_per_segment",
            "What one SMS segment costs, in the deployment's base currency, for \
             the estimate shown before an SMS campaign is sent. 0: segments only.",
            || json!({"type": "number", "minimum": 0}),
            DEPLOYMENT,
            false,
            || json!(0),
        ),
        SettingDescriptor::new(
            "marketing.form_intake.user",
            "The service account marketing form submissions are filed as (E10-T1). \
             It needs create and update on lead or contact and create on \
             marketing_form_submission; never a person's account. Empty: forms \
             take no submissions.",
            || {
                json!({
                    "type": "string",
                    "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})?$"
                })
            },
            DEPLOYMENT,
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "marketing.profile_event_retention_months",
            "Months profile events are kept (E23-T1); older months are dropped \
             whole, nightly.",
            || json!({"type": "integer", "minimum": 1, "maximum": 120}),
            DEPLOYMENT,
            false,
            || json!(13),
        ),
        SettingDescriptor::new(
            "marketing.sms_quiet_hours",
            "Hours (HH:MM, recipient's local time) when campaign SMS are held, \
             by country code with \"*\" for every other country, e.g. \
             {\"*\": {\"start\": \"21:00\", \"end\": \"08:00\"}}.",
            || {
                json!({
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {
                            "start": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"},
                            "end": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"}
                        }
                    }
                })
            },
            DEPLOYMENT,
            false,
            || json!({"*": {"start": "21:00", "end": "08:00"}}),
        ),
        SettingDescriptor::new(
            "marketing.blocklist_zones",
            "DNS blocklists this deployment may query (E6-T8), each {name, zone, \
             kind: domain|ip, licence_note}: only lists whose terms allow your use, \
             such as your own Spamhaus DQS zone. None by default.",
            || {
                json!({
                    "type": "array",
                    "maxItems": 20,
                    "items": {
                        "type": "object",
                        "required": ["name", "zone", "kind"],
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                            "zone": {"type": "string", "minLength": 3, "maxLength": 253},
                            "kind": {"type": "string", "enum": ["domain", "ip"]},
                            "licence_note": {"type": "string", "maxLength": 500}
                        }
                    }
                })
            },
            DEPLOYMENT,
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "marketing.social_post_approval",
            "Social posts publish only once someone approved them \
             (approved_by set) (E17-T1). Off: a scheduled post publishes at its time.",
            || json!({"type": "boolean"}),
            DEPLOYMENT,
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "marketing.blocklist_ips",
            "The sending IPs the daily blocklist check looks up (E6-T8); the \
             sending domains come from the deliverability rollup.",
            || json!({"type": "array", "maxItems": 100, "items": {"type": "string", "maxLength": 45}}),
            DEPLOYMENT,
            false,
            || json!([]),
        ),
    ]
}

/// G2-T1: anonymous requests from a public web form. Both settings must be
/// set before any offering takes one: the offerings that accept them, and
/// the service account they are filed as (it needs
/// `service_work_request.create`). Off until then.
fn service_settings() -> Vec<SettingDescriptor> {
    const DEPLOYMENT: &[SettingScope] = &[SettingScope::Deployment];
    vec![
        SettingDescriptor::new(
            "service.anonymous_intake.offerings",
            "Ids of the public service offerings that accept anonymous requests \
             from a web form (POST /api/v1/service-portal/offerings/{id}/requests). \
             Empty: none do.",
            || {
                json!({
                    "type": "array",
                    "maxItems": 200,
                    "items": {
                        "type": "string",
                        "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
                    }
                })
            },
            DEPLOYMENT,
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "service.anonymous_intake.user",
            "The service account anonymous requests are filed as and by. It needs \
             service_work_request.create; never a person's account. Empty: no \
             anonymous requests.",
            || {
                json!({
                    "type": "string",
                    "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})?$"
                })
            },
            DEPLOYMENT,
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "service.email_thread_days",
            "An inbound email with no case number in its subject and no reply \
             headers joins its sender's most recent open case updated within this \
             many days (G1-T2). 0: only the case number or the reply headers join.",
            || json!({"type": "integer", "minimum": 0, "maximum": 90}),
            DEPLOYMENT,
            false,
            || json!(7),
        ),
        SettingDescriptor::new(
            "service.presence",
            "The person's presence on the service desk (G5-T3): available, busy \
             or away. Round-robin and least-loaded queues route new work only to \
             available members; picking work by hand is not affected.",
            || json!({"type": "string", "enum": ["available", "busy", "away"]}),
            &[SettingScope::User, SettingScope::Deployment],
            false,
            || json!("available"),
        ),
    ]
}

/// AA9-T3: the limits an operator may change at run time (the
/// `RuntimeSetting` entries of `attome_config::limits`), as `limits.{key}`.
/// Deployment scope only. The schema's bounds are the limit's floor and
/// ceiling; a stored value wins over the boot configuration, and with none
/// stored the boot value (or the code default) applies.
fn limit_settings() -> Vec<SettingDescriptor> {
    const DEPLOYMENT: &[SettingScope] = &[SettingScope::Deployment];
    vec![
        SettingDescriptor::new(
            "limits.bulk.max_records_per_request",
            "Records one bulk request may carry; a larger set goes through a \
             staged import. 1 to 10,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 10_000 }),
            DEPLOYMENT,
            false,
            || json!(500),
        ),
        // AA10-T2: the rows a heavy operation changes in the request.
        SettingDescriptor::new(
            "limits.heavy_op.inline_max_rows",
            "Rows an update or delete over a filtered set changes in the request; a larger set \
             runs as a background job with progress. 1 to 100,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 100_000 }),
            DEPLOYMENT,
            false,
            || json!(500),
        ),
        // AA10-T9: the measured speed of a mass update, written by each one.
        SettingDescriptor::new(
            "limits.heavy_op.measured_rps.update",
            "Records per second a background mass update changed, a moving average each finished \
             one updates; estimates use it. 1 to 1,000,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 1_000_000 }),
            DEPLOYMENT,
            false,
            || json!(2000),
        ),
        // AA10-T9: the measured speed of a mass delete, written by each one.
        SettingDescriptor::new(
            "limits.heavy_op.measured_rps.delete",
            "Records per second a background mass delete changed, a moving average each finished \
             one updates; estimates use it. 1 to 1,000,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 1_000_000 }),
            DEPLOYMENT,
            false,
            || json!(2000),
        ),
        // AA10-T9: the measured speed of a mass reassign, written by each one.
        SettingDescriptor::new(
            "limits.heavy_op.measured_rps.reassign",
            "Records per second a background mass reassign changed, a moving average each finished \
             one updates; estimates use it. 1 to 1,000,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 1_000_000 }),
            DEPLOYMENT,
            false,
            || json!(2000),
        ),
        // AA10-T9: the measured speed of a mass restore, written by each one.
        SettingDescriptor::new(
            "limits.heavy_op.measured_rps.restore",
            "Records per second a background mass restore changed, a moving average each finished \
             one updates; estimates use it. 1 to 1,000,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 1_000_000 }),
            DEPLOYMENT,
            false,
            || json!(2000),
        ),
        // AA10-T5: how long a finished mass operation can still be undone.
        SettingDescriptor::new(
            "limits.heavy_op.undo_retention_days",
            "Days a finished mass operation keeps the values it replaced, so it can be undone; \
             a daily job clears older ones. 1 to 3,650.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 3_650 }),
            DEPLOYMENT,
            false,
            || json!(30),
        ),
        SettingDescriptor::new(
            "limits.query.timeout_ms.interactive",
            "Milliseconds an ordinary list or view query may run before it is \
             cancelled. 100 to 3,600,000.",
            || json!({ "type": "integer", "minimum": 100, "maximum": 3_600_000 }),
            DEPLOYMENT,
            false,
            || json!(5_000),
        ),
        SettingDescriptor::new(
            "limits.query.timeout_ms.report",
            "Milliseconds a stored query flagged as a report may run before it \
             is cancelled. 100 to 3,600,000.",
            || json!({ "type": "integer", "minimum": 100, "maximum": 3_600_000 }),
            DEPLOYMENT,
            false,
            || json!(60_000),
        ),
        SettingDescriptor::new(
            "limits.query.timeout_ms.export",
            "Milliseconds an export's query may run before it is cancelled. \
             100 to 3,600,000.",
            || json!({ "type": "integer", "minimum": 100, "maximum": 3_600_000 }),
            DEPLOYMENT,
            false,
            || json!(60_000),
        ),
        // M1-T4: a flow run's bounds.
        SettingDescriptor::new(
            "limits.workflow.max_steps_per_run",
            "Node executions one flow run may make, retries included; the run fails when it would make more. 10 to 100,000.",
            || json!({ "type": "integer", "minimum": 10, "maximum": 100_000 }),
            DEPLOYMENT,
            false,
            || json!(1_000),
        ),
        SettingDescriptor::new(
            "limits.workflow.max_loop_items",
            "Items one for-each step may go through; a longer list fails the step. 1 to 1,000,000.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 1_000_000 }),
            DEPLOYMENT,
            false,
            || json!(10_000),
        ),
        SettingDescriptor::new(
            "limits.workflow.max_nesting",
            "Levels of sub-flows and for-each runs one run may nest inside each other. 1 to 50.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 50 }),
            DEPLOYMENT,
            false,
            || json!(20),
        ),
        SettingDescriptor::new(
            "limits.workflow.max_run_minutes",
            "Minutes a flow run may last, waits included; an older run fails on its next step. 1 to 525,600.",
            || json!({ "type": "integer", "minimum": 1, "maximum": 525_600 }),
            DEPLOYMENT,
            false,
            || json!(43_200),
        ),
        // AA9-T7: not a limit itself, the share of one at which the daily
        // check warns the administrators.
        SettingDescriptor::new(
            "limits.warn_at_percent",
            "Percent of a limit at which administrators are warned that callers \
             come close to it. 50 to 99.",
            || json!({ "type": "integer", "minimum": 50, "maximum": 99 }),
            DEPLOYMENT,
            false,
            || json!(80),
        ),
    ]
}

/// B5-T3: record settings.
fn records_settings() -> Vec<SettingDescriptor> {
    vec![
        // L6-T5: scheduled profiles and snapshot retention.
        SettingDescriptor::new(
            "data_profile.schedule",
            "Entities profiled on a schedule, each with a cron in the deployment's time zone, as \
             {\"contact\": \"0 2 * * *\"}; a profile that drifts from the one before alerts the \
             data stewards. None by default (L6-T5).",
            || json!({"type": "object", "additionalProperties": {"type": "string", "minLength": 9, "maxLength": 100}}),
            &[SettingScope::Deployment],
            false,
            || json!({}),
        ),
        SettingDescriptor::new(
            "data_profile.retention_days",
            "Days a data profile snapshot is kept before it is deleted (L6-T5). 1 to 3650.",
            || json!({"type": "integer", "minimum": 1, "maximum": 3650}),
            &[SettingScope::Deployment],
            false,
            || json!(365),
        ),
        // M12-T3: hours heavy scheduled work waits out.
        SettingDescriptor::new(
            "jobs.quiet_windows",
            "Quiet windows in the deployment's time, as [{\"start\": \"08:00\", \"end\": \"18:00\"}] \
             (an end before the start runs past midnight): heavy scheduled work (a flow run over \
             a view's records, a report delivery) does not start in one, and starts once when \
             it closes (M12-T3).",
            || {
                json!({
                    "type": "array",
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {
                            "start": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"},
                            "end": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"},
                        },
                        "additionalProperties": false,
                    },
                })
            },
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
        // M9-T3: emailed approval links.
        SettingDescriptor::new(
            "approval.email_links",
            "Whether the approvers of each step of a pending approval request get an email \
             with a one-time link to it (M9-T3).",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(true),
        ),
        SettingDescriptor::new(
            "approval.email_decide_actions",
            "Approval action types low-risk enough to approve or reject straight from the \
             emailed link; any other request's link opens the request page, which needs \
             sign-in (M9-T3).",
            || json!({"type": "array", "items": {"type": "string", "minLength": 1}, "maxItems": 100}),
            &[SettingScope::Deployment],
            false,
            || json!(["approval_process", "approval_process.change"]),
        ),
        SettingDescriptor::new(
            "records.bulk_edit_approval_count",
            "A bulk edit changing more records than this waits on an approval before it runs; \
         0 never asks.",
            || json!({"type": "integer", "minimum": 0}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        // B1-T1: the related records each entity's timeline rolls in.
        SettingDescriptor::new(
            "records.timeline_roll_in",
            "The related records whose entries a record's timeline also shows, by entity: each a \
         child entity and its lookup to this one, such as {\"account\": [{\"entity\": \"contact\", \
         \"via\": \"account_id\"}]}. Only children the person may read roll in, the newest 200 \
         per relationship. Empty by default: a timeline shows its own record only.",
            || {
                json!({
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "maxItems": 10,
                        "items": {
                            "type": "object",
                            "required": ["entity", "via"],
                            "properties": {
                                "entity": {"type": "string"},
                                "via": {"type": "string"}
                            }
                        }
                    }
                })
            },
            &[SettingScope::Deployment],
            false,
            || json!({}),
        ),
        // B5-T4: a person's saved bulk edits.
        SettingDescriptor::new(
            "records.bulk_actions",
            "The person's saved bulk edits, by entity: each a name and the operations it applies, rerun from the bulk edit dialog.",
            || {
                json!({
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "maxItems": 50,
                        "items": {
                            "type": "object",
                            "required": ["name", "operations"],
                            "properties": {
                                "name": {"type": "string", "minLength": 1, "maxLength": 100},
                                "operations": {"type": "array", "maxItems": 50}
                            }
                        }
                    }
                })
            },
            &[SettingScope::User],
            false,
            || json!({}),
        ),
        // P4-T1: exports write formula-like text as text.
        SettingDescriptor::new(
            "records.export_formula_guard",
            "Whether CSV, XLSX and slide exports write a text cell that starts with =, +, -, @, \
         a tab or a carriage return as text (prefixed with '), so a spreadsheet does not run it \
         as a formula.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(true),
        ),
        // F6-T3: where a confirmed order ships from until sourcing does it.
        SettingDescriptor::new(
            "fulfilment.default_location_id",
            "The stock location a confirmed order's fulfilment orders ship from (F6-T3). Unset, \
         the deployment's only stock location is used; with several and none named, orders are \
         not split.",
            || json!({"type": ["string", "null"], "format": "uuid"}),
            &[SettingScope::Deployment],
            false,
            || json!(null),
        ),
        // A25-T2: the country a local phone number belongs to.
        SettingDescriptor::new(
            "core.default_country",
            "The country (ISO 3166-1 alpha-2) a phone number written without its country code \
         belongs to, such as SA: search matches `0501234567` with `+966501234567` (A25-T2).",
            || json!({"type": "string", "pattern": "^[A-Z]{2}$"}),
            &[SettingScope::Deployment],
            false,
            || json!("SA"),
        ),
        // L4-T3: whether the catalogue names attributes a person may not read.
        SettingDescriptor::new(
            "catalog.show_hidden_existence",
            "Whether the data catalogue lists an attribute the person may not read by its name only, \
         marked hidden so they can ask for access (L4-T3). Off by default: a hidden attribute is \
         never named.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "catalog.export_enabled",
            "Whether GET /api/v1/catalog/export answers: the catalogue's metadata (no record values) \
         as JSON for a harvester such as Purview or Collibra (L4-T4). Off by default.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        // P13-T1: the entities the warehouse export writes; none by default.
        SettingDescriptor::new(
            "integration.warehouse_entities",
            "The entities whose record changes are exported every few minutes as Parquet files \
         under `warehouse/{entity}/` in object storage, one per hour of change, with a manifest \
         (P13-T1). Empty by default: the export is off. Sensitive attributes are never exported.",
            || json!({"type": "array", "items": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"}, "maxItems": 200}),
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
        // A25-T3: personal ranking, off until a deployment sets weights.
        SettingDescriptor::new(
            "search.personal_weights",
            "Small additions to a search result's score for a record the person owns (`owner`), \
         one they opened from a search in the last 30 days (`opened`) and one a team of theirs \
         owns (`team`), each 0 to 1; all 0 by default (A25-T3). It only re-orders records the \
         person can already see.",
            || {
                json!({"type": "object", "additionalProperties": false, "properties": {
                    "owner": {"type": "number", "minimum": 0, "maximum": 1},
                    "opened": {"type": "number", "minimum": 0, "maximum": 1},
                    "team": {"type": "number", "minimum": 0, "maximum": 1}
                }})
            },
            &[SettingScope::Deployment],
            false,
            || json!({"owner": 0, "opened": 0, "team": 0}),
        ),
        // F6-T14: when an order counts as stuck.
        SettingDescriptor::new(
            "fulfilment.stuck_hours",
            "How many hours a fulfilment order may stay in one open status before it is raised as \
         a stuck exception (F6-T14). 48 by default.",
            || json!({"type": "integer", "minimum": 1, "maximum": 720}),
            &[SettingScope::Deployment],
            false,
            || json!(48),
        ),
        // F6-T11: a one-time code at delivery.
        SettingDescriptor::new(
            "fulfilment.delivery.otp",
            "Whether a delivery by the deployment's own drivers needs a one-time code: when a \
         shipment goes out for delivery, a six-digit code is texted to the order's delivery \
         phone (else its account's phone), and the driver enters it to prove the delivery \
         (F6-T11). Off by default.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        // F11-T4: the SSP fallbacks.
        SettingDescriptor::new(
            "revrec.ssp_list_discount_percent",
            "Percent taken off a product's list price to give its standalone selling price, when \
         it has no entered SSP and too few sales on its own to observe one (F11-T4). 0 by \
         default.",
            || json!({"type": "number", "minimum": 0, "maximum": 100}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        SettingDescriptor::new(
            "revrec.ssp_cost_margin_percent",
            "Percent added to a product's cost to give its standalone selling price, when it has \
         no entered SSP, too few sales on its own and no list price (F11-T4). 0 by default.",
            || json!({"type": "number", "minimum": 0, "maximum": 1000}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        // L2-T3: the quality scoring's issue caps.
        SettingDescriptor::new(
            "quality.max_issues_per_run",
            "The most data quality issue rows one scoring run writes across all entities \
         (L2-T3). Scores are written regardless; only the issue detail is capped.",
            || json!({"type": "integer", "minimum": 0, "maximum": 1000000}),
            &[SettingScope::Deployment],
            false,
            || json!(2000),
        ),
        // L2-T7: a sudden drop in an entity's overall quality score.
        SettingDescriptor::new(
            "quality.drop_alert_points",
            "How many points an entity's overall data quality score must fall since yesterday \
         for its stewards to be alerted, besides falling below its target (L2-T7).",
            || json!({"type": "number", "minimum": 0, "maximum": 100}),
            &[SettingScope::Deployment],
            false,
            || json!(10),
        ),
        // R11-T1: the evidence collectors' administrator ceiling.
        SettingDescriptor::new(
            "grc.max_admins",
            "The most active administrators the admin_count evidence collector accepts; more, or \
         none, opens a finding (R11-T1).",
            || json!({"type": "integer", "minimum": 1, "maximum": 1000}),
            &[SettingScope::Deployment],
            false,
            || json!(5),
        ),
        // L1-T7: golden-record changes sent only once certified.
        SettingDescriptor::new(
            "master.certified_only",
            "Master entities whose golden-record changes are sent to subscribers only while the \
         golden record is certified; a draft or retired one's changes are not sent (L1-T7).",
            || json!({"type": "array", "maxItems": 200, "items": {"type": "string", "maxLength": 63}}),
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "quality.max_issues_per_entity",
            "The most data quality issue rows one entity gets in a scoring run, so one entity \
         cannot use the whole run's issues (L2-T3).",
            || json!({"type": "integer", "minimum": 0, "maximum": 1000000}),
            &[SettingScope::Deployment],
            false,
            || json!(200),
        ),
        // L5-T6: the lineage graph's OpenLineage export.
        SettingDescriptor::new(
            "lineage.export_enabled",
            "Whether administrators may pull the lineage graph as OpenLineage events          (GET /api/v1/lineage/export/openlineage): names of definitions, entities and          attributes only, never record values. Off by default (L5-T6).",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "customer_tests.require_pass_before_publish",
            "Before a changeset apply or a model publish, run every active blocking customer test \
         and refuse the publish when one fails.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "billing.renewal.lead_days",
            "Days before a subscription ends that it is renewed (auto mode, after \
             any contract notice deadline) or gets a renewal opportunity (F3-T9).",
            || json!({"type": "integer", "minimum": 0, "maximum": 365}),
            &[SettingScope::Deployment],
            false,
            || json!(60),
        ),
        SettingDescriptor::new(
            "billing.renewal.uplift_percent",
            "Percent added to each line's price when a subscription renews \
             automatically (F3-T9); 0 keeps the prices.",
            || json!({"type": "number", "minimum": 0, "maximum": 100}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        SettingDescriptor::new(
            "billing.trial.reminder_days",
            "Days before a trial ends that its owner is reminded (F3-T9).",
            || json!({"type": "integer", "minimum": 0, "maximum": 90}),
            &[SettingScope::Deployment],
            false,
            || json!(3),
        ),
        SettingDescriptor::new(
            "billing.trial.convert",
            "Whether a trial becomes an active subscription on its end date \
             (F3-T9); off ends it instead.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(true),
        ),
        SettingDescriptor::new(
            "billing.seller_name",
            "The deployment's legal name, printed as the seller on every invoice.",
            || json!({"type": "string", "maxLength": 200}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_vat_number",
            "The deployment's VAT registration number, printed as the seller's on every invoice.",
            || json!({"type": "string", "maxLength": 30}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_crn",
            "The deployment's commercial registration number, printed as the seller's identifier on e-invoices.",
            || json!({"type": "string", "maxLength": 30}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_street",
            "The seller's street (national address), on e-invoices.",
            || json!({"type": "string", "maxLength": 200}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_building_number",
            "The seller's four-digit building number (national address).",
            || json!({"type": "string", "maxLength": 10}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_district",
            "The seller's district (national address).",
            || json!({"type": "string", "maxLength": 100}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_city",
            "The seller's city (national address).",
            || json!({"type": "string", "maxLength": 100}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.seller_postal_zone",
            "The seller's five-digit postal code (national address).",
            || json!({"type": "string", "maxLength": 10}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "billing.write_off_approval_threshold",
            "Write-offs larger than this wait for an approval before they are applied; \
         zero writes off without one.",
            || json!({"type": "number", "minimum": 0}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
    ]
}

/// F4: billing settings.
fn billing_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "billing.seller_country",
            "The deployment's own country, as an ISO 3166 two-letter code: the seller \
         side of VAT on every invoice line.",
            || json!({"type": "string", "pattern": "^[A-Z]{2}$"}),
            &[SettingScope::Deployment],
            false,
            || json!("SA"),
        ),
        SettingDescriptor::new(
            "billing.refund.approval_threshold",
            "Refunds larger than this amount wait for a finance manager's approval (0 = never).",
            || json!({"type": "number", "minimum": 0}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        SettingDescriptor::new(
            "billing.saved_methods.enabled",
            "Charge due invoices to the customer's default saved card each day, with retries.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "billing.retry.days",
            "Days to wait after each failed saved-card charge before the next try; after the \
             last, the invoice goes to collections.",
            || json!({"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 90}}),
            &[SettingScope::Deployment],
            false,
            || json!([1, 3, 7]),
        ),
        SettingDescriptor::new(
            "billing.gateway.rules",
            "Which payment gateway takes a payment: rules in order, the first whose currency, \
             country and amount range match wins.",
            || json!({"type": "array", "items": {"type": "object", "required": ["system_id"]}}),
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "billing.issue_approval_threshold",
            "Invoices whose grand total is above this wait for an approval before          they are issued; zero issues every invoice without one.",
            || json!({"type": "number", "minimum": 0}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        SettingDescriptor::new(
            "billing.credit.block_overdue",
            "Refuse new sales on credit to an account with an overdue invoice, even within its \
             credit limit (F5-T12).",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "billing.credit.auto_hold",
            "Each night, put on credit hold every account with an invoice overdue by more than \
             billing.credit.hold_after_days (F5-T12).",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "billing.credit.hold_after_days",
            "Days past its due date an invoice may be before the nightly sweep puts its account \
             on credit hold (F5-T12).",
            || json!({"type": "integer", "minimum": 0, "maximum": 365}),
            &[SettingScope::Deployment],
            false,
            || json!(30),
        ),
    ]
}

/// F10: commission settings.
fn commission_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "commission.adjustment_approval_amount",
            "Manual commission adjustments larger than this (either way, in the \
         deployment's base currency) are written only after an approval.",
            || json!({"type": "number", "minimum": 0}),
            &[SettingScope::Deployment],
            false,
            || json!(1000),
        ),
        SettingDescriptor::new(
            "commission.clawback_days",
            "Days after a commission credit that a credit note or refund still \
         takes it back (F10-T3); an older credit stands.",
            || json!({"type": "integer", "minimum": 0, "maximum": 3650}),
            &[SettingScope::Deployment],
            false,
            || json!(180),
        ),
        // F2-T1: the discount policy quotes are submitted under.
        SettingDescriptor::new(
            "sales.discount_policy",
            "Discount thresholds a quote is checked against when it is submitted, as \
             [{\"family\": <product family id or null>, \"role\": <role name or null>, \
             \"min_deal_total\": \"0\", \"max_line_discount_pct\": \"10\", \
             \"max_total_discount_pct\": \"10\", \"approval_process\": \"Manager discount\", \
             \"level\": 1}]. A quote over a threshold goes to the approval process the strictest \
             one names (an active process for quotes that starts on submit); within all of them \
             it is sent. None by default (F2-T1).",
            || {
                json!({
                    "type": "array",
                    "maxItems": 200,
                    "items": {
                        "type": "object",
                        "required": ["max_line_discount_pct", "max_total_discount_pct", "approval_process"],
                        "properties": {
                            "family": {"type": ["string", "null"], "format": "uuid"},
                            "role": {"type": ["string", "null"], "maxLength": 200},
                            "min_deal_total": {"type": ["string", "number"]},
                            "max_line_discount_pct": {"type": ["string", "number"]},
                            "max_total_discount_pct": {"type": ["string", "number"]},
                            "approval_process": {"type": "string", "minLength": 1, "maxLength": 200},
                            "level": {"type": "integer", "minimum": 1, "maximum": 100}
                        }
                    }
                })
            },
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
    ]
}

/// AB5-T6: operating switches.
fn ops_settings() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "ops.read_only",
        "Read-only mode: while true, every write answers 503 `read_only`; reading, \
         signing in and this switch keep working. Every server follows it within \
         the read-only refresh interval.",
        || json!({"type": "boolean"}),
        &[SettingScope::Deployment],
        false,
        || json!(false),
    )]
}

fn core_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "i18n.draft_locales",
            "Languages (BCP-47 tags such as ar-SA) whose missing metadata label translations an \
             agent drafts for review each hour (A20-T2); none by default.",
            || json!({"type": "array", "items": {"type": "string", "pattern": "^[a-z]{2}(-[A-Z]{2})?$"}}),
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "core.locale",
            "Preferred BCP-47 locale tag used for date/number formatting and \
             (future) localized content. Inheritable at every scope: a user's \
             own choice wins, then their organization's, then the \
             deployment-wide default, then \"en-US\".",
            || {
                json!({
                    "type": "string",
                    "pattern": "^[a-z]{2}(-[A-Z]{2})?$",
                })
            },
            &[
                SettingScope::User,
                SettingScope::Organization,
                SettingScope::Deployment,
            ],
            false,
            || json!("en-US"),
        ),
        SettingDescriptor::new(
            "core.list_page_size",
            "Default page size for admin list views. Deployment- or \
             organization-scoped only — deliberately not user-overridable in \
             this first slice, so a single descriptor still demonstrates a \
             narrower `allowed_scopes` set than core.locale's.",
            || {
                json!({
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 200,
                })
            },
            &[SettingScope::Organization, SettingScope::Deployment],
            false,
            || json!(25),
        ),
        SettingDescriptor::new(
            "core.dark_mode_default",
            "Deployment-wide default for whether new users start in dark \
             mode. A user's own theme preference (client-local today, see \
             sidebar-preferences.service.ts) always wins if set; this is only \
             the fallback shown before they ever choose.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "core.country",
            "The country this deployment serves, as an ISO 3166 alpha-2 code \
             (SA, AE, EG). Set by the first-run wizard (X12-T3), which also \
             installs the regions pack and the matching locale, time zone and \
             calendar. Empty until then.",
            || json!({"type": "string", "pattern": "^([A-Z]{2})?$"}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "email.tracking.enabled",
            "Whether outgoing record email carries tracked links and an open \
             pixel (D16-T1). A contact, lead or account who withdrew the \
             email_tracking consent purpose is never tracked.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "compliance.double_opt_in_countries",
            "Countries (ISO 3166 alpha-2 codes) where a marketing consent \
             captured from a public form counts only once the person confirms \
             it from an email (E27-T3). A form that names no country uses \
             core.country. Empty: consent counts when given.",
            || json!({"type": "array", "items": {"type": "string", "pattern": "^[A-Za-z]{2}$"}, "maxItems": 250}),
            &[SettingScope::Deployment],
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "compliance.consent_expiry_days",
            "Days a marketing consent lasts before it lapses and must be given \
             again (E27-T3); 0 means it does not lapse.",
            || json!({"type": "integer", "minimum": 0, "maximum": 3650}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
        SettingDescriptor::new(
            "compliance.dsr_response_days",
            "Days a data-subject request (access, erasure, restriction, \
             rectification and the rest) must be answered within, counted from \
             when it is recorded (R1-T1). 0 uses the law of core.country where \
             the platform knows it (30 days under Saudi PDPL), else 30.",
            || json!({"type": "integer", "minimum": 0, "maximum": 365}),
            &[SettingScope::Deployment],
            false,
            || json!(0),
        ),
    ]
}

/// Every scope a personal setting may be stored at: the person's own choice
/// wins, then their organization's, then the deployment's, then the code
/// default (B11-T1). `SettingScope` has no role level; an organization is the
/// group default.
const PERSONAL: &[SettingScope] = &[
    SettingScope::User,
    SettingScope::Organization,
    SettingScope::Deployment,
];

/// B11-T1 / AG1-T7: how one person sees the product. The web app applies them
/// at once, and server rendering (exports, emails) reads the same values.
/// `core.locale` above is the language.
fn personal_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "core.time_zone",
            "IANA time zone dates and times are shown in, e.g. Asia/Riyadh.",
            || {
                json!({
                    "type": "string",
                    "pattern": "^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$",
                    "maxLength": 64,
                })
            },
            PERSONAL,
            false,
            || json!("UTC"),
        ),
        SettingDescriptor::new(
            "notification.quiet_hours",
            "Your quiet hours, in your own time zone, as {\"start\": \"22:00\", \"end\": \"07:00\"}: low and normal priority notifications sent then wait until they end; high and urgent ones arrive at once. Empty: no quiet hours (M15-T1/T2).",
            || {
                json!({
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"},
                        "end": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"},
                    },
                    "additionalProperties": false,
                })
            },
            PERSONAL,
            false,
            || json!({}),
        ),
        SettingDescriptor::new(
            "notification.digest",
            "How low-priority notifications reach you: off (each on its own), hourly or daily (one message at 08:00 your time listing them all) (M15-T2).",
            || json!({"type": "string", "enum": ["off", "hourly", "daily"]}),
            PERSONAL,
            false,
            || json!("off"),
        ),
        SettingDescriptor::new(
            "mail_capture.enabled",
            "Whether emails in your connected mailbox with known contacts and \
             leads are captured onto their records (D15-T2).",
            || json!({"type": "boolean"}),
            PERSONAL,
            false,
            || json!(true),
        ),
        SettingDescriptor::new(
            "mail_capture.excluded_domains",
            "Domains whose addresses are never captured, typically your \
             organization's own, comma separated (D15-T2).",
            || json!({"type": "string", "maxLength": 2000}),
            PERSONAL,
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "voice.agent_number",
            "Your own phone number (E.164) or PBX extension: a call placed \
             from Attome rings it first, then the customer (J6-T1).",
            || json!({"type": "string", "maxLength": 40}),
            PERSONAL,
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "scan.record_location",
            "Whether a scan action records where the device was, when the \
             device sends it (B16-T8). Off: the location is dropped.",
            || json!({"type": "boolean"}),
            PERSONAL,
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "core.calendar",
            "Calendar dates are shown in: gregorian, hijri (Umm al-Qura), or \
             both. A date attribute's own display_calendar option wins.",
            || json!({"type": "string", "enum": ["gregorian", "hijri", "both"]}),
            PERSONAL,
            false,
            || json!("gregorian"),
        ),
        SettingDescriptor::new(
            "core.digits",
            "Digits numbers and dates are written with: latn (0-9) or arab \
             (Arabic-Indic).",
            || json!({"type": "string", "enum": ["latn", "arab"]}),
            PERSONAL,
            false,
            || json!("latn"),
        ),
        SettingDescriptor::new(
            "core.date_format",
            "Order of day, month and year in a short date: dmy, mdy or ymd.",
            || json!({"type": "string", "enum": ["dmy", "mdy", "ymd"]}),
            PERSONAL,
            false,
            || json!("dmy"),
        ),
        SettingDescriptor::new(
            "core.start_page",
            "The page opened after signing in, as an app route starting with /.",
            || json!({"type": "string", "pattern": "^/[^\\s]*$", "maxLength": 200}),
            PERSONAL,
            false,
            || json!("/"),
        ),
        SettingDescriptor::new(
            "core.theme",
            "Colour theme: light, dark, or auto (follow the device).",
            || json!({"type": "string", "enum": ["light", "dark", "auto"]}),
            PERSONAL,
            false,
            || json!("auto"),
        ),
        SettingDescriptor::new(
            "core.text_size",
            "Text size: normal or large.",
            || json!({"type": "string", "enum": ["normal", "large"]}),
            PERSONAL,
            false,
            || json!("normal"),
        ),
        SettingDescriptor::new(
            "core.reduced_motion",
            "Turn off animations and transitions.",
            || json!({"type": "boolean"}),
            PERSONAL,
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "core.tours_seen",
            "B14-T1: the guided tours this person has finished or skipped, by tour \
             id, so a tour that starts by itself does so once. Replaying a tour \
             does not change it.",
            || {
                json!({
                    "type": "array",
                    "maxItems": 500,
                    "items": { "type": "string", "maxLength": 64 }
                })
            },
            PERSONAL,
            false,
            || json!([]),
        ),
        SettingDescriptor::new(
            "core.simple_mode",
            "Simple mode (AK6-T2): hide advanced actions such as duplicating, sharing \
             and changesets, for people who only need the everyday ones.",
            || json!({"type": "boolean"}),
            PERSONAL,
            false,
            || json!(false),
        ),
    ]
}

/// A single illustrative descriptor in a reserved namespace, existing only to
/// prove `SettingRegistry::new`'s boot-time-only assertion and the write
/// handler's 422 both actually fire (M02 §6). Deliberately NOT wired to the
/// real `config.auth` section — `attome-config`'s session TTL stays the sole
/// source of truth for that value; registering it here as `boot_time_only`
/// only demonstrates the guard, it does not expose or shadow the real config.
fn reserved_boot_time_examples() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "auth.session_ttl_minutes",
        "Illustrative only. Session lifetime is boot-time config \
         (`config.json`'s auth section, D-038) precisely because a malformed \
         value must fail the process at boot rather than take effect quietly \
         mid-flight. This descriptor is registered solely so the runtime \
         settings API has a real key to reject a write against — it does not \
         read or influence the actual session TTL.",
        || json!({"type": "integer"}),
        &[SettingScope::Deployment],
        true,
        || serde_json::Value::Null,
    )]
}

/// One `SettingDescriptor` per registered [`crate::feature_flag_descriptor::FeatureFlag`]
/// (M95, D-430) — the storage half of the flag catalogue in
/// `feature_flag_catalog.rs`. `FeatureFlagRegistry::new()` asserts every flag
/// there has a matching entry here, so the two lists can't silently drift
/// apart.
///
/// Each descriptor is deliberately `Deployment`-scope only: per-user/role
/// targeting and the progressive-rollout percentage live *inside* the stored
/// JSON value (`feature_flag_store::FeatureFlagPolicy`), not as additional
/// `setting` rows at other scopes — `SettingScope` has no `Role`
/// variant and adding one (plus the DB `CHECK` it would need) is out of
/// scope for a change that rides entirely on the existing store. The schema
/// only pins the top-level shape (`validate_against_schema`'s minimal
/// subset has no nested-property support); `features_admin`'s write handler
/// does the deeper structural/dependency validation before ever calling the
/// shared `write_setting` path.
fn feature_flag_settings() -> Vec<SettingDescriptor> {
    let scan = |key: &'static str, description: &'static str| {
        SettingDescriptor::new(
            key,
            description,
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        )
    };
    vec![
        scan(
            "feature.revrec.basic",
            "Stored policy value for the revrec.basic feature flag (F11-T11).",
        ),
        scan(
            "feature.revrec.contracts",
            "Stored policy value for the revrec.contracts feature flag (F11-T11).",
        ),
        scan(
            "feature.revrec.ssp_allocation",
            "Stored policy value for the revrec.ssp_allocation feature flag (F11-T11).",
        ),
        scan(
            "feature.revrec.usage_completion",
            "Stored policy value for the revrec.usage_completion feature flag (F11-T11).",
        ),
        scan(
            "feature.revrec.change_rules",
            "Stored policy value for the revrec.change_rules feature flag (F11-T11).",
        ),
        scan(
            "feature.revrec.disclosure",
            "Stored policy value for the revrec.disclosure feature flag (F11-T11).",
        ),
        scan(
            "feature.scan.enabled",
            "Stored policy value for the scan.enabled feature flag (B16-T9), same shape as \
             feature.core.beta_ui.",
        ),
        scan(
            "feature.scan.actions_enabled",
            "Stored policy value for the scan.actions_enabled feature flag (B16-T9).",
        ),
        scan(
            "feature.scan.continuous_enabled",
            "Stored policy value for the scan.continuous_enabled feature flag (B16-T9).",
        ),
        scan(
            "feature.content.seo_audit",
            "Stored policy value for the content.seo_audit feature flag (E13-T2).",
        ),
        scan(
            "feature.content.seo_clusters",
            "Stored policy value for the content.seo_clusters feature flag (E13-T2).",
        ),
        scan(
            "feature.content.search_console",
            "Stored policy value for the content.search_console feature flag (E13-T2).",
        ),
        scan(
            "feature.content.instant_indexing",
            "Stored policy value for the content.instant_indexing feature flag (E13-T2).",
        ),
        scan(
            "feature.content.seo_arabic_paths",
            "Stored policy value for the content.seo_arabic_paths feature flag (E13-T2).",
        ),
        scan(
            "feature.content.seo_agent",
            "Stored policy value for the content.seo_agent feature flag (E13-T2).",
        ),
        scan(
            "feature.marketing.tracking",
            "Stored policy value for the marketing.tracking feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_external_sites",
            "Stored policy value for the marketing.tracking_external_sites feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_identify",
            "Stored policy value for the marketing.tracking_identify feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_company",
            "Stored policy value for the marketing.tracking_company feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_custom_events",
            "Stored policy value for the marketing.tracking_custom_events feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_alerts",
            "Stored policy value for the marketing.tracking_alerts feature flag (E14-T1).",
        ),
        scan(
            "feature.sales.opportunity_lines",
            "Stored policy value for the sales.opportunity_lines feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.recurring_lines",
            "Stored policy value for the sales.recurring_lines feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.schedules",
            "Stored policy value for the sales.schedules feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.quote_sync",
            "Stored policy value for the sales.quote_sync feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.product_suggestions",
            "Stored policy value for the sales.product_suggestions feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.deal_teams",
            "Stored policy value for the sales.deal_teams feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.splits",
            "Stored policy value for the sales.splits feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.line_splits",
            "Stored policy value for the sales.line_splits feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.partner_members",
            "Stored policy value for the sales.partner_members feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.team_suggestions",
            "Stored policy value for the sales.team_suggestions feature flag (D7-T10).",
        ),
        SettingDescriptor::new(
            "feature.core.beta_ui",
            "Stored policy value for the core.beta_ui feature flag (M95, D-430): \
             {deployment: bool, user_overrides: {\"<user_id>\": bool}, \
             role_overrides: {\"<privilege_key>\": bool}, percentage: 0-100}.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        ),
        SettingDescriptor::new(
            "feature.core.beta_ui_advanced_panels",
            "Stored policy value for the core.beta_ui_advanced_panels feature \
             flag (M95, D-430) — same shape as feature.core.beta_ui.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        ),
        SettingDescriptor::new(
            "feature.project.gantt_v2_preview",
            "Stored policy value for the project.gantt_v2_preview feature flag \
             (M95, D-430) — same shape as feature.core.beta_ui. Gated on \
             MODULE_PROJECT: this flag can never evaluate true for a \
             deployment whose licence doesn't hold that module, regardless of \
             this stored value.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        ),
    ]
}

/// M98 Phase 1 (`record.update_field`, D-448) — the deployment-configured
/// allow-list of `(entity, field)` pairs the action may write. The action's
/// `RiskTier::Reversible` descriptor gates *whether* a caller may reach the
/// action at all; this setting gates *what it may touch* once reached — a
/// second, narrower boundary the static descriptor cannot express because it
/// has no notion of `args`. `attome-ai`'s executor resolves this at
/// `Deployment` scope only (no per-user override — an admin, not each agent
/// session's owner, decides the blast radius) and refuses any `(entity,
/// field)` pair not listed, for every caller, not only an agent — the action
/// is scoped by descriptor to this set, full stop.
///
/// Shape: `{"<entity_logicalname>": ["<field_logicalname>", ...], ...}`.
/// Default `{}` — nothing is writable until an admin opts fields in, the
/// same fail-closed posture `feature.*`'s `{"deployment": false}` default
/// uses. The minimal schema validator has no nested-property support (see
/// `setting_store.rs`'s header), so — same trade-off `feature_flag_settings`
/// already accepts — only the top-level `object` shape is schema-checked;
/// `attome-ai`'s executor is the one place that actually walks the map.
fn action_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "ai.record_update_field_allowlist",
            "Deployment-wide allow-list of entity/field pairs the \
             record.update_field AI action may write: \
             {\"<entity>\": [\"<field>\", ...]}. A pair not listed here is \
             refused regardless of caller, risk ceiling, or approval — this is \
             the action's own scope, not a privilege check.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({}),
        ),
        mcp_entity_admission(),
    ]
}

/// MCP entity admission (plan item M3.4, `mcp-excellence-10-10.md`; owner
/// decision 2026-09-28, a runtime setting rather than an entity metadata
/// flag). Which entities an **external agent on the MCP surface** may reach
/// through the `record.*` tools, and with which verbs.
///
/// Shape: `{"<entity_logicalname>": ["read" | "create" | "update" | "delete", ...]}`.
/// Default `{}` — **nothing is admitted** (default-deny, invariant MI-3): an
/// MCP `record.*` call on an entity not listed, or with a verb not listed, is
/// refused darkly. Admission only narrows: the caller's own privileges and
/// record-level security still apply on top. `attome-ai` also refuses a
/// code-owned set of security, identity, audit and licence entities even when
/// this setting names them (`attome_ai::mcp::admission`).
///
/// Deployment scope only, same reasoning as the allow-list above: an admin,
/// not each session owner, decides what an external agent may touch. Only the
/// top-level `object` shape is schema-checked (the minimal validator has no
/// nested support); `attome-ai` is the one place that walks the map, and an
/// unrecognised verb there admits nothing.
fn mcp_entity_admission() -> SettingDescriptor {
    SettingDescriptor::new(
        "ai.mcp_entity_admission",
        "Entities an external MCP agent may reach through the record.* tools, \
         and with which verbs: {\"<entity>\": [\"read\", \"create\", \
         \"update\", \"delete\"]}. Default {} admits nothing. Security, \
         identity, audit and licence entities are refused even if listed. \
         The caller's own privileges still apply.",
        || json!({"type": "object"}),
        &[SettingScope::Deployment],
        false,
        || json!({}),
    )
}

/// M35 (AI Memory, D-451). Deployment-scope only — memory retention is a
/// deployment-wide policy question, not a per-user preference, matching
/// `core.dark_mode_default`'s own reasoning for the same scope restriction.
/// Read by `attome-compliance::retention::propose_retention_actions` (via
/// `SettingsSnapshot::resolve`, `user_id`/`organization_ref` both `None`)
/// exactly like every other runtime-editable setting — no separate config
/// table, per M02/D-412.
fn ai_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "ai.memory_retention_days",
            "How many days a memory row (`memory`, M35) is kept after \
         creation before the retention sweep proposes it for deletion. \
         Applies uniformly across every scope_kind in v1. A deployment that \
         wants to keep memory indefinitely should set a very large value \
         rather than relying on an unset default — this key always has an \
         effective value (the code default below).",
            || {
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3650,
                })
            },
            &[SettingScope::Deployment],
            false,
            || json!(365),
        ),
        // AI6-T3: briefs made an hour before a meeting. A person may turn
        // their own off; the deployment's value is everyone else's.
        SettingDescriptor::new(
            "ai.meeting_briefs",
            "Whether the AI writes a brief an hour before each meeting, for the \
         meeting's owner (`meeting.brief`). A user's own choice wins over \
         the deployment's.",
            || json!({"type": "boolean"}),
            &[SettingScope::User, SettingScope::Deployment],
            false,
            || json!(true),
        ),
    ]
}

/// M53 Phase 1 (Omnichannel, web chat only, D-474). Deployment-scope only —
/// same "policy question, not a per-user preference" reasoning
/// `ai_settings` above already gives for its own single-scope setting. Read
/// by `attome_server::omnichannel_public` via `SettingsSnapshot::resolve`
/// (`user_id`/`organization_ref` both `None`), same established pattern as
/// every other runtime-editable setting.
///
/// Genuine conditional routing (which queue a given request goes to, by
/// content/category) needs M45 rule authoring, which does not exist yet
/// (`attome_service::routing`'s own doc comment documents the identical gap for
/// M70) — `web_chat_default_queue_ref` is deliberately the simple,
/// hardcoded-but-admin-configurable stand-in the module plan calls for: every
/// new web-chat handoff routes to this one queue, full stop, until M45 Phase
/// 2 ships a real rule table.
fn omnichannel_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "omnichannel.web_chat_default_queue_ref",
            "The `service_work_queue.id` every new web-chat handoff's work \
             request is routed to (`work_queue_ref`). Empty string (the \
             default) means no default queue is configured — a handoff still \
             creates the work request, just with no queue set, exactly as if \
             an admin had not configured M84 queue routing for this channel \
             at all.",
            || json!({"type": "string"}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "omnichannel.web_chat_offline_message",
            "Fixed auto-reply text shown to a web-chat visitor when \
             `web_chat_calendar_ref` is configured and the current instant \
             falls outside that calendar's business hours (`attome-calendar`, \
             D-404). Not M45-conditional — a single fixed message for v1, \
             same scope cut every other module this session has taken for a \
             genuine M45 gap.",
            || json!({"type": "string"}),
            &[SettingScope::Deployment],
            false,
            || {
                json!(
                    "Our team is currently offline. We've received your \
                     message and will follow up as soon as we're back."
                )
            },
        ),
        SettingDescriptor::new(
            "omnichannel.web_chat_calendar_ref",
            "Optional `calendar.id` (D-404/M83) whose business \
             hours gate the web chat widget. Empty string (the default) \
             means no business-hours check applies — the widget behaves as \
             if it were always open, the same opt-in-by-configuration \
             posture `service_sla_policy.calendar_ref`/`service_work_queue.calendar_ref` \
             already establish. Plain string, not a `lookup` — calendars are \
             a dedicated admin object, not a generic XRM entity (see either \
             of those two attributes' own doc comments).",
            || json!({"type": "string"}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B11-T1: every personal setting is the person's to set, its default
    /// passes its own schema, and a value outside it is refused.
    #[test]
    fn personal_settings_resolve_with_defaults() {
        use crate::setting_store::validate_against_schema;
        let personal = personal_settings();
        assert!(personal.iter().any(|d| d.key == "core.calendar"));
        for d in &personal {
            assert!(d.allows_scope(SettingScope::User), "{}", d.key);
            assert!(d.allows_scope(SettingScope::Deployment), "{}", d.key);
            validate_against_schema(&(d.default)(), &(d.schema)())
                .unwrap_or_else(|e| panic!("{}: default fails its schema: {e}", d.key));
        }
        let schema = |key: &str| (personal.iter().find(|d| d.key == key).unwrap().schema)();
        assert!(validate_against_schema(&json!("hijri"), &schema("core.calendar")).is_ok());
        assert!(validate_against_schema(&json!("julian"), &schema("core.calendar")).is_err());
        assert!(validate_against_schema(&json!("Asia/Riyadh"), &schema("core.time_zone")).is_ok());
        assert!(validate_against_schema(&json!("no zone"), &schema("core.time_zone")).is_err());
        assert!(
            validate_against_schema(&json!("/xrm/dashboard"), &schema("core.start_page")).is_ok()
        );
        assert!(validate_against_schema(&json!("https://x"), &schema("core.start_page")).is_err());
    }

    /// MCP entity admission is default-deny (plan item M3.4): the code
    /// default admits nothing, and only an admin's deployment-scope row can
    /// change that — no per-user or per-organization override.
    #[test]
    fn mcp_entity_admission_defaults_to_nothing_admitted_at_deployment_scope_only() {
        let descriptor = all()
            .into_iter()
            .find(|d| d.key == "ai.mcp_entity_admission")
            .expect("ai.mcp_entity_admission must be registered");
        assert_eq!((descriptor.default)(), json!({}));
        assert_eq!(descriptor.allowed_scopes, &[SettingScope::Deployment]);
        assert!(!descriptor.boot_time_only);
        assert_eq!((descriptor.schema)(), json!({"type": "object"}));
    }
}
