//! The plain-language review summary of an `attome-changeset/v1` document
//! (ruling 0.8: JSON is stored, a generated summary is what the owner reads).
//!
//! A line-for-line port of `scripts/changesets/summarize.mjs`: the same
//! sentence per operation, the same "Look closely" risks, the same layout, so
//! the close response and `summarize.mjs` over the written file say the same
//! thing. `tests::fixture_summaries_match_summarize_mjs` holds the Node output
//! for both committed fixtures. Change the two together.

use attome_core::changeset::Op;
use serde_json::{Map, Value};

use super::jcs;

/// JavaScript's template-literal rendering of a value (`${v}`): a string as
/// itself, `undefined` for a missing member, arrays joined with `,`.
fn js(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => {
            jcs::canonicalize(&Value::Number(n.clone())).unwrap_or_else(|_| n.to_string())
        }
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::Null => String::new(),
                other => js(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// `JSON.stringify(v)` (insertion order is the map's order; used only for
/// business-key values, which are scalars in practice).
fn json_stringify(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn q(value: Option<&Value>) -> String {
    format!("\"{}\"", js(value))
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// `a ?? b` over two optional values.
fn coalesce<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    match a {
        None | Some(Value::Null) => b,
        some => some,
    }
}

struct Ctx<'a> {
    t: &'a Map<String, Value>,
    a: &'a Map<String, Value>,
}

impl Ctx<'_> {
    fn t(&self, key: &str) -> Option<&Value> {
        self.t.get(key)
    }

    fn a(&self, key: &str) -> Option<&Value> {
        self.a.get(key)
    }

    fn def(&self, key: &str) -> Option<&Value> {
        self.a.get("definition").and_then(|d| d.get(key))
    }

    fn qt(&self, key: &str) -> String {
        q(self.t(key))
    }

    fn fld(&self) -> String {
        format!("\"{}.{}\"", js(self.t("entity")), js(self.t("field")))
    }

    /// ` (a, b)` from `args.changed`, or nothing.
    fn changed(&self) -> String {
        match self.a("changed") {
            Some(Value::Array(items)) if !items.is_empty() => format!(
                " ({})",
                items
                    .iter()
                    .map(|v| js(Some(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => String::new(),
        }
    }

    fn entries(&self, key: &str) -> String {
        match self.a(key) {
            Some(Value::Object(map)) => map
                .iter()
                .map(|(k, v)| format!("{k}={}", js(Some(v))))
                .collect::<Vec<_>>()
                .join(", "),
            _ => String::new(),
        }
    }
}

/// One sentence for one operation; an unknown op falls back to a generic
/// line so a summary never hides an operation.
fn sentence(op_name: &str, target: &Map<String, Value>, args: &Map<String, Value>) -> String {
    let c = Ctx { t: target, a: args };
    let Some(op) = Op::parse(op_name) else {
        return format!(
            "{op_name} on {}.",
            json_stringify(&Value::Object(target.clone()))
        );
    };
    let e = || c.qt("entity");
    match op {
        Op::CreateEntity => format!(
            "Create the table {} ({}).",
            e(),
            js(coalesce(c.def("display_name"), c.t("entity")))
        ),
        Op::UpdateEntity => format!("Update the table {}{}.", e(), c.changed()),
        Op::RetireEntity => format!("Retire the table {} (hidden, data kept).", e()),
        Op::ReactivateEntity => format!("Bring back the retired table {}.", e()),
        Op::SetEntityMasterData => {
            if truthy(c.a("is_master")) {
                format!(
                    "Make the table {} master data ({}).",
                    e(),
                    c.a("hub_style")
                        .and_then(Value::as_str)
                        .unwrap_or("no hub style")
                )
            } else {
                format!("The table {} is no longer master data.", e())
            }
        }
        Op::SetEntityDomain => {
            if truthy(c.a("domain")) {
                format!(
                    "Put the table {} in the data domain {}.",
                    e(),
                    q(c.a("domain"))
                )
            } else {
                format!("Take the table {} out of its data domain.", e())
            }
        }
        Op::AddField => {
            let mut extra = Vec::new();
            if truthy(c.def("field_type")) {
                extra.push(format!("type {}", js(c.def("field_type"))));
            }
            if truthy(c.def("is_required")) {
                extra.push("required".to_owned());
            }
            if truthy(c.def("lookup_entity")) {
                extra.push(format!("looks up {}", js(c.def("lookup_entity"))));
            }
            let extra = extra.join(", ");
            format!(
                "Add the field {} ({}{}).",
                c.fld(),
                js(coalesce(c.def("display_name"), c.t("field"))),
                if extra.is_empty() {
                    String::new()
                } else {
                    format!(", {extra}")
                }
            )
        }
        Op::UpdateField => format!("Update the field {}{}.", c.fld(), c.changed()),
        Op::RetireField => format!("Retire the field {} (hidden, data kept).", c.fld()),
        Op::ReactivateField => format!("Bring back the retired field {}.", c.fld()),
        Op::UpsertRelationship => format!(
            "Create or update the relationship {}.",
            c.qt("relationship")
        ),
        Op::RetireRelationship => format!("Retire the relationship {}.", c.qt("relationship")),
        Op::SetLabel => format!(
            "Set the {} name of {} {} to {}.",
            js(c.t("locale")),
            js(c.t("object_kind")),
            c.qt("object_key"),
            q(c.a("display_name"))
        ),
        Op::ClearLabel => format!(
            "Remove the {} name of {} {}.",
            js(c.t("locale")),
            js(c.t("object_kind")),
            c.qt("object_key")
        ),
        Op::UpsertQuery => format!(
            "Create or update the saved query {} on {}.",
            c.qt("query"),
            e()
        ),
        Op::RetireQuery => format!("Remove the saved query {} from {}.", c.qt("query"), e()),
        Op::UpsertView => format!("Create or update the view {} on {}.", c.qt("view"), e()),
        Op::RetireView => format!("Remove the view {} from {}.", c.qt("view"), e()),
        Op::UpsertRule => format!(
            "Create or update the business rule {} on {}.",
            c.qt("rule"),
            e()
        ),
        Op::PublishRule => format!("Publish the business rule {} on {}.", c.qt("rule"), e()),
        Op::RetireRule => format!("Remove the business rule {} from {}.", c.qt("rule"), e()),
        Op::UpsertStateModel => format!("Create or update the status model of {}.", e()),
        Op::RetireStateModel => format!("Remove the status model of {}.", e()),
        Op::UpsertStateTransition => format!(
            "Create or update the status change {} on {}.",
            c.qt("transition"),
            e()
        ),
        Op::RetireStateTransition => format!(
            "Remove the status change {} from {}.",
            c.qt("transition"),
            e()
        ),
        Op::UpsertWorkflow => format!("Create or update the workflow {}.", c.qt("workflow")),
        Op::SetWorkflowDraft => {
            format!("Save a new draft of the workflow {}.", c.qt("workflow"))
        }
        Op::PublishWorkflow => format!(
            "Publish the current draft of the workflow {}.",
            c.qt("workflow")
        ),
        Op::RetireWorkflow => format!("Remove the workflow {}.", c.qt("workflow")),
        Op::UpsertCaseDef => format!("Create or update the case type {}.", c.qt("case_def")),
        Op::RetireCaseDef => format!("Remove the case type {}.", c.qt("case_def")),
        Op::UpsertSidebarItem => format!("Create or update the menu item {}.", c.qt("path")),
        Op::RetireSidebarItem => format!("Remove the menu item {}.", c.qt("path")),
        Op::UpsertApp => format!("Create or update the app {}.", c.qt("app")),
        Op::RetireApp => format!("Remove the app {}.", c.qt("app")),
        Op::UpsertTheme => format!("Create or update the theme of {}.", c.qt("theme_scope")),
        Op::PublishTheme => format!("Publish the theme of {}.", c.qt("theme_scope")),
        Op::RetireTheme => format!("Retire the published theme of {}.", c.qt("theme_scope")),
        Op::UpsertCalendar => format!("Create or update the calendar {}.", c.qt("calendar")),
        Op::RetireCalendar => format!("Remove the calendar {}.", c.qt("calendar")),
        Op::AddCalendarHoliday => format!(
            "Add the holiday {} to the calendar {}.",
            js(c.t("date")),
            c.qt("calendar")
        ),
        Op::RemoveCalendarHoliday => format!(
            "Remove the holiday {} from the calendar {}.",
            js(c.t("date")),
            c.qt("calendar")
        ),
        Op::AddCalendarException => format!(
            "Add the exception {} to the calendar {}.",
            c.qt("exception"),
            c.qt("calendar")
        ),
        Op::RemoveCalendarException => format!(
            "Remove the exception {} from the calendar {}.",
            c.qt("exception"),
            c.qt("calendar")
        ),
        Op::UpsertCalendarRule => format!(
            "Create or update the holiday rule {} of the calendar {}.",
            c.qt("rule"),
            c.qt("calendar")
        ),
        Op::RetireCalendarRule => format!(
            "Remove the holiday rule {} from the calendar {}.",
            c.qt("rule"),
            c.qt("calendar")
        ),
        Op::UpsertCalendarSeason => format!(
            "Create or update the season {} of the calendar {}.",
            c.qt("season"),
            c.qt("calendar")
        ),
        Op::RetireCalendarSeason => format!(
            "Remove the season {} from the calendar {}.",
            c.qt("season"),
            c.qt("calendar")
        ),
        Op::EnsurePrivilege => format!("Make sure the privilege {} exists.", c.qt("privilege")),
        Op::UpsertRole => format!("Create or update the role {}.", c.qt("role")),
        Op::GrantRolePrivilege => format!(
            "Give the role {} the privilege {} ({}).",
            c.qt("role"),
            c.qt("privilege"),
            js(c.a("depth"))
        ),
        Op::RevokeRolePrivilege => format!(
            "Take the privilege {} away from the role {}.",
            c.qt("privilege"),
            c.qt("role")
        ),
        Op::AddRoleGrantCondition => format!(
            "Limit the role {}'s privilege {} with the condition {}.",
            c.qt("role"),
            c.qt("privilege"),
            c.qt("condition")
        ),
        Op::RemoveRoleGrantCondition => format!(
            "Remove the condition {} from the role {}'s privilege {}.",
            c.qt("condition"),
            c.qt("role"),
            c.qt("privilege")
        ),
        Op::SetRoleEntityAccess => format!(
            "Set what the role {} may do on {}: {}.",
            c.qt("role"),
            e(),
            c.entries("access")
        ),
        Op::ClearRoleEntityAccess => {
            format!("Remove the role {}'s access to {}.", c.qt("role"), e())
        }
        Op::SetRoleBulkFields => format!(
            "Set the bulk-editable fields of the role {} ({}).",
            c.qt("role"),
            match c.a("fields") {
                Some(Value::Array(f)) => f.len(),
                _ => 0,
            }
        ),
        Op::SetEntityDefaultShare => {
            format!("Set the default sharing {} on {}.", c.qt("share"), e())
        }
        Op::RemoveEntityDefaultShare => {
            format!("Remove the default sharing {} from {}.", c.qt("share"), e())
        }
        Op::UpsertFieldProfile => format!(
            "Create or update the field security profile {}.",
            c.qt("profile")
        ),
        Op::SetFieldProfileField => format!(
            "In the field security profile {}, set \"{}.{}\" to {}.",
            c.qt("profile"),
            js(c.t("entity")),
            js(c.t("field")),
            c.entries("permissions")
        ),
        Op::AssignFieldProfile => format!(
            "Give the role {} the field security profile {}.",
            c.qt("role"),
            c.qt("profile")
        ),
        Op::UnassignFieldProfile => format!(
            "Take the field security profile {} away from the role {}.",
            c.qt("profile"),
            c.qt("role")
        ),
        Op::UpsertDataDomain => format!("Create or update the data domain {}.", c.qt("domain")),
        Op::UpsertRecord => format!(
            "Create or update the {} record with {}.",
            e(),
            match c.t("key") {
                Some(Value::Object(key)) => key
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", json_stringify(v)))
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            }
        ),
        Op::RenameField => format!(
            "Rename the field {} to {} in place (data kept; every reference follows, customer \
             objects included; integrations that use the old name break at this release).",
            c.fld(),
            q(c.a("new_name"))
        ),
        Op::ChangeFieldType => {
            let from = c.a("conversion").and_then(|v| v.get("from_type"));
            format!(
                "Change the type of {}{} to {} in place (values that do not convert become empty \
                 and are kept 30 days in the recovery archive; runs without business rules or \
                 workflows).",
                c.fld(),
                if truthy(from) {
                    format!(" from {}", js(from))
                } else {
                    String::new()
                },
                js(c.a("field_type"))
            )
        }
        Op::AddChoiceValue => format!(
            "Add the choice {} ({}) to {}.",
            q(c.a("label")),
            js(c.a("value")),
            c.fld()
        ),
        Op::RemoveChoiceValue => format!(
            "Remove the choice value {} from {} (records that have it keep it and show it empty).",
            js(c.a("value")),
            c.fld()
        ),
        Op::DeleteField => format!(
            "Delete the field {} (the column is dropped at this release; its values are kept 30 \
             days in the recovery archive; integrations that use it break).",
            c.fld()
        ),
        Op::SetViewColumns => {
            let cols = match c.a("columns") {
                Some(Value::Array(cols)) => cols
                    .iter()
                    .map(|col| js(col.get("name")))
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            };
            let sort = match c.a("sort") {
                Some(Value::Array(sort)) if !sort.is_empty() => format!(
                    ", sorted by {}",
                    sort.iter()
                        .map(|x| format!("{} {}", js(x.get("field")), js(x.get("direction"))))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => String::new(),
            };
            format!(
                "Set the columns of the view {} on {} to {cols}{sort}.",
                c.qt("view"),
                e()
            )
        }
        Op::DataStep => data_step_sentence(&c),
    }
}

/// `data_step` in `summarize.mjs`, per kind.
fn data_step_sentence(c: &Ctx<'_>) -> String {
    let f = |name: Option<&Value>| format!("\"{}.{}\"", js(c.t("entity")), js(name));
    const BYPASS: &str = "(runs without business rules or workflows)";
    match c.a("kind").and_then(Value::as_str) {
        Some("copy") => format!(
            "Copy {} into {}{} {BYPASS}.",
            f(c.a("from")),
            f(c.a("to")),
            if c.a("only_empty") == Some(&Value::Bool(false)) {
                " (overwriting existing values)"
            } else {
                " (only where it is empty)"
            }
        ),
        Some("convert") => format!(
            "Convert {} ({}) into {} ({}{}); values that do not convert leave the target empty \
             and are counted {BYPASS}.",
            f(c.a("from")),
            js(c.a("from_type")),
            f(c.a("to")),
            js(c.a("to_type")),
            if truthy(c.a("format")) {
                format!(", format {}", js(c.a("format")))
            } else {
                String::new()
            }
        ),
        Some("map_values") => {
            let to = c.a("to");
            let into = if truthy(to) && to != c.a("field") {
                format!(" into {}", f(to))
            } else {
                String::new()
            };
            let map = match c.a("map") {
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| format!("\"{k}\" to {}", q(Some(v))))
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            };
            format!(
                "Change the values of {}{into}: {map} {BYPASS}.",
                f(c.a("field"))
            )
        }
        Some("set_default") => format!(
            "Fill the empty values of {} with {} {BYPASS}.",
            f(c.a("field")),
            c.a("value")
                .map(json_stringify)
                .unwrap_or_else(|| "undefined".into())
        ),
        _ => format!(
            "Run a {} data step on {} {BYPASS}.",
            js(c.a("kind")),
            c.qt("entity")
        ),
    }
}

fn empty() -> Map<String, Value> {
    Map::new()
}

fn obj(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => empty(),
    }
}

/// Things a reviewer must look at twice (`risks` in `summarize.mjs`).
fn risks(ops: &[Value]) -> Vec<String> {
    let op_of = |o: &Value| o.get("op").and_then(Value::as_str).map(str::to_owned);
    let count = |name: &str| {
        ops.iter()
            .filter(|o| o.get("op").and_then(Value::as_str) == Some(name))
            .count()
    };
    let changed_has = |o: &Value, key: &str| {
        o.get("args")
            .and_then(|a| a.get("changed"))
            .and_then(Value::as_array)
            .is_some_and(|c| c.iter().any(|v| v.as_str() == Some(key)))
    };
    let mut out = Vec::new();
    let contract = ops
        .iter()
        .filter(|o| o.get("phase").and_then(Value::as_str) == Some("contract"))
        .count();
    if contract > 0 {
        out.push(format!(
            "{contract} contract operation(s) — removals; they run in the same apply, after the \
             expand operations and the health check, so check nothing of ours still uses what \
             they remove."
        ));
    }
    let required = ops
        .iter()
        .filter(|o| {
            let name = op_of(o);
            let becomes_required = o
                .get("args")
                .and_then(|a| a.get("definition"))
                .and_then(|d| d.get("is_required"))
                == Some(&Value::Bool(true));
            (name.as_deref() == Some("add_field")
                || (name.as_deref() == Some("update_field") && changed_has(o, "is_required")))
                && becomes_required
        })
        .count();
    if required > 0 {
        out.push(format!(
            "{required} field(s) are or become required — required is checked by the \
             application; existing empty records stay empty (D-788)."
        ));
    }
    let types = count("change_field_type");
    if types > 0 {
        out.push(format!(
            "{types} type change(s) — values that do not convert become empty and are kept 30 \
             days in the recovery archive; the release report lists them with Restore."
        ));
    }
    let deletes = count("delete_field");
    if deletes > 0 {
        out.push(format!(
            "{deletes} field delete(s) — the column is dropped at this release; values are kept \
             30 days in the recovery archive."
        ));
    }
    let steps = count("data_step") + types;
    if steps > 0 {
        out.push(format!(
            "{steps} step(s) change record values without business rules or workflows; large \
             tables run in batches inside the apply."
        ));
    }
    let keys = ops
        .iter()
        .filter(|o| {
            matches!(op_of(o).as_deref(), Some("update_entity" | "create_entity"))
                && changed_has(o, "business_key")
        })
        .count();
    if keys > 0 {
        out.push(format!(
            "{keys} business key(s) declared or changed — existing duplicate records block the \
             apply; the plan counts them first."
        ));
    }
    let future = ops
        .iter()
        .filter(|o| {
            o.get("op")
                .and_then(Value::as_str)
                .and_then(Op::parse)
                .is_some_and(|op| op.stage() == 2)
        })
        .count();
    if future > 0 {
        out.push(format!(
            "{future} Phase 2 operation(s) — the target server must run a release with Phase 2 \
             (older releases refuse them)."
        ));
    }
    let breaking: Vec<String> = ops
        .iter()
        .filter_map(|o| {
            let name = op_of(o)?;
            let t = o.get("target");
            let f = format!(
                "{}.{}",
                js(t.and_then(|t| t.get("entity"))),
                js(t.and_then(|t| t.get("field")))
            );
            let a = o.get("args");
            match name.as_str() {
                "rename_field" => Some(format!(
                    "{f} renamed to {}",
                    js(a.and_then(|a| a.get("new_name")))
                )),
                "delete_field" => Some(format!("{f} removed")),
                "change_field_type" => Some(format!(
                    "{f} now {}",
                    js(a.and_then(|a| a.get("field_type")))
                )),
                _ => None,
            }
        })
        .collect();
    if !breaking.is_empty() {
        out.push(format!(
            "Breaking changes for API users ({}): {}.",
            breaking.len(),
            breaking.join("; ")
        ));
    }
    out
}

/// `refOf` in `lib.mjs`: `<layer>/<scope>/<NNNN>-<name>`.
pub fn ref_of(document: &Value) -> String {
    let seq = document.get("seq").and_then(Value::as_i64).unwrap_or(0);
    format!(
        "{}/{}/{seq:04}-{}",
        js(document.get("layer")),
        js(document.get("scope")),
        js(document.get("name"))
    )
}

/// The Markdown summary of a changeset document (`summarize` in
/// `summarize.mjs`).
pub fn summarize(document: &Value) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# {}", js(document.get("title"))));
    lines.push(String::new());
    lines.push(format!(
        "`{}` · layer **{}** · by {} · closed {}",
        ref_of(document),
        js(document.get("layer")),
        js(document.get("author")),
        js(document.get("closed_at"))
    ));
    if truthy(document.get("description")) {
        lines.push(String::new());
        lines.push(js(document.get("description")));
    }
    lines.push(String::new());
    let requires = obj(document.get("requires"));
    let mut req = vec![format!("platform {}", js(requires.get("platform")))];
    if let Some(Value::Array(after)) = requires.get("after")
        && !after.is_empty()
    {
        req.push(format!(
            "after {}",
            after
                .iter()
                .map(|v| js(Some(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(Value::Array(modules)) = requires.get("modules")
        && !modules.is_empty()
    {
        req.push(format!(
            "modules {}",
            modules
                .iter()
                .map(|v| js(Some(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines.push(format!("Requires: {}.", req.join("; ")));

    let ops: Vec<Value> = document
        .get("operations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (phase, heading) in [
        ("expand", "## First (expand)"),
        ("contract", "## Then, after the health check (contract)"),
    ] {
        let in_phase: Vec<&Value> = ops
            .iter()
            .filter(|o| o.get("phase").and_then(Value::as_str) == Some(phase))
            .collect();
        if in_phase.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(heading.to_owned());
        lines.push(String::new());
        for o in in_phase {
            let text = sentence(
                o.get("op").and_then(Value::as_str).unwrap_or_default(),
                &obj(o.get("target")),
                &obj(o.get("args")),
            );
            lines.push(format!("{}. {text}", js(o.get("seq"))));
        }
    }
    let r = risks(&ops);
    if !r.is_empty() {
        lines.push(String::new());
        lines.push("## Look closely".to_owned());
        lines.push(String::new());
        for x in r {
            lines.push(format!("- {x}"));
        }
    }
    lines.push(String::new());
    lines.push(format!("Checksum: `{}`", js(document.get("checksum"))));
    format!("{}\n", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ACME: &str = include_str!(
        "../../../../../scripts/changesets/fixtures/valid/project/acme/0001-acme-contracts.json"
    );
    const PLATFORM: &str = include_str!(
        "../../../../../scripts/changesets/fixtures/valid/platform/0001-service-desk-priority.json"
    );
    const PHASE2: &str = include_str!(
        "../../../../../scripts/changesets/fixtures/valid/project/acme/0002-acme-contract-evolution.json"
    );

    /// `node scripts/changesets/summarize.mjs` over the Phase 2 fixture (D-788).
    const PHASE2_SUMMARY: &str = "# Acme: contract value as money, renewal renamed

`project/acme/0002-acme-contract-evolution` · layer **project** · by dev@attome.local · closed 2026-09-30T09:30:00Z

Phase 2 example (D-788): renames the renewal date in place, converts the free-text contract value to currency in place, adds and removes status choices, sets the list view columns, seeds a contract type by business key, and deletes a legacy field.

Requires: platform >=4.3.0; after project/acme/0001-acme-contracts.

## First (expand)

1. Rename the field \"contract.renewal_date\" to \"renewal_on\" in place (data kept; every reference follows, customer objects included; integrations that use the old name break at this release).
2. Change the type of \"contract.contract_value\" from text to currency in place (values that do not convert become empty and are kept 30 days in the recovery archive; runs without business rules or workflows).
3. Add the choice \"On hold\" (on_hold) to \"contract.status\".
4. Change the values of \"contract.status\": \"draft_legacy\" to \"draft\" (runs without business rules or workflows).
5. Fill the empty values of \"contract.currency_code\" with \"BHD\" (runs without business rules or workflows).
6. Set the columns of the view \"active_contracts\" on \"contract\" to name, renewal_on, contract_value, sorted by renewal_on asc.
7. Update the table \"contract_type\" (business_key, is_reference_data).
8. Create or update the \"contract_type\" record with code = \"SVC\".

## Then, after the health check (contract)

9. Remove the choice value draft_legacy from \"contract.status\" (records that have it keep it and show it empty).
10. Delete the field \"contract.value_text\" (the column is dropped at this release; its values are kept 30 days in the recovery archive; integrations that use it break).

## Look closely

- 2 contract operation(s) — removals; they run in the same apply, after the expand operations and the health check, so check nothing of ours still uses what they remove.
- 1 type change(s) — values that do not convert become empty and are kept 30 days in the recovery archive; the release report lists them with Restore.
- 1 field delete(s) — the column is dropped at this release; values are kept 30 days in the recovery archive.
- 3 step(s) change record values without business rules or workflows; large tables run in batches inside the apply.
- 1 business key(s) declared or changed — existing duplicate records block the apply; the plan counts them first.
- 8 Phase 2 operation(s) — the target server must run a release with Phase 2 (older releases refuse them).
- Breaking changes for API users (3): contract.renewal_date renamed to renewal_on; contract.contract_value now currency; contract.value_text removed.

Checksum: `sha256:0763674fc4a69e557f80188c5babab991670f106623490d6989bc85b5279b481`
";

    /// `node scripts/changesets/summarize.mjs <fixture>` output, verbatim.
    const ACME_SUMMARY: &str = "# Acme: contract renewal date

`project/acme/0001-acme-contracts` · layer **project** · by dev@attome.local · closed 2026-09-29T10:20:00Z

Adds a renewal date to contracts for Acme, names it in Arabic, and retires the old free-text renewal note.

Requires: platform >=4.2.0; after platform/platform/0001-service-desk-priority.

## First (expand)

1. Add the field \"contract.renewal_date\" (Renewal date, type date).
2. Set the ar name of attribute \"contract.renewal_date\" to \"تاريخ التجديد\".

## Then, after the health check (contract)

3. Retire the field \"contract.renewal_note\" (hidden, data kept).

## Look closely

- 1 contract operation(s) — removals; they run in the same apply, after the expand operations and the health check, so check nothing of ours still uses what they remove.

Checksum: `sha256:d94fb2394f9fc6d208e93735488e2a45afda45716df78e3550fff477766ff44c`
";

    const PLATFORM_SUMMARY: &str = "# Service desk: ticket priority and triage view

`platform/platform/0001-service-desk-priority` · layer **platform** · by dev@attome.local · closed 2026-09-29T09:30:00Z

Adds a priority to service tickets, a triage view sorted by it, access for the Service Desk Agent role, and the Hardware category.

Requires: platform >=4.2.0; modules service.

## First (expand)

1. Add the field \"service_ticket.priority\" (Priority, type choice).
2. Create or update the view \"Triage\" on \"service_ticket\".
3. Set what the role \"Service Desk Agent\" may do on \"service_ticket\": read=organization, write=user.
4. Create or update the \"service_category\" record with code = \"HW\".

Checksum: `sha256:33bf590a327b275250efd035255ce0ae353c6b3f81e860e80b08f965a25b4623`
";

    #[test]
    fn fixture_summaries_match_summarize_mjs() {
        for (text, expected) in [
            (ACME, ACME_SUMMARY),
            (PLATFORM, PLATFORM_SUMMARY),
            (PHASE2, PHASE2_SUMMARY),
        ] {
            let document: Value = serde_json::from_str(text).expect("fixture parses");
            assert_eq!(summarize(&document), expected);
        }
    }

    #[test]
    fn every_op_has_a_sentence_and_risks_are_counted() {
        for op in Op::ALL {
            let text = sentence(op.as_str(), &Map::new(), &Map::new());
            assert!(text.ends_with('.'), "{}: {text}", op.as_str());
        }
        assert_eq!(
            sentence("no_such_op", &obj(Some(&json!({"a": 1}))), &Map::new()),
            "no_such_op on {\"a\":1}."
        );
        let ops = vec![
            json!({"op": "add_field", "phase": "expand",
                   "args": {"definition": {"is_required": true}}}),
            json!({"op": "update_field", "phase": "expand",
                   "args": {"changed": ["is_required"], "definition": {"is_required": true}}}),
            json!({"op": "update_field", "phase": "expand",
                   "args": {"changed": ["display_name"], "definition": {"is_required": true}}}),
            json!({"op": "retire_view", "phase": "contract"}),
            json!({"op": "data_step", "phase": "expand"}),
        ];
        let r = risks(&ops);
        assert_eq!(r.len(), 4);
        assert!(r[0].starts_with("1 contract"));
        assert!(r[1].starts_with("2 field(s)"));
        assert!(r[2].starts_with("1 step(s)"));
        assert!(r[3].starts_with("1 Phase 2 operation(s)"));
    }

    #[test]
    fn update_sentences_name_what_changed() {
        let target = obj(Some(&json!({"entity": "account", "field": "name"})));
        let args = obj(Some(&json!({"changed": ["display_name", "max_length"]})));
        assert_eq!(
            sentence("update_field", &target, &args),
            "Update the field \"account.name\" (display_name, max_length)."
        );
        assert_eq!(
            sentence(
                "set_entity_domain",
                &obj(Some(&json!({"entity": "a"}))),
                &obj(Some(&json!({"domain": null})))
            ),
            "Take the table \"a\" out of its data domain."
        );
    }
}
