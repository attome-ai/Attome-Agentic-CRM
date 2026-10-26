//! The changeset types: owner layers, operation phases, the v1 operation
//! catalogue, and the operation a writer hands the recorder.
//!
//! The catalogue of record is `OPS` in `scripts/changesets/lib.mjs`; the
//! schema `schemas/attome-changeset-v1.schema.json` is generated from it.
//! [`Op`] mirrors it name for name, phase for phase, stage for stage and
//! target key for target key, and `tests::op_catalogue_matches_the_schema`
//! fails when the two drift.

use serde_json::Value;
use uuid::Uuid;

pub use attome_config::{ChangesetLayer as Layer, ChangesetMode as RecordingMode};

/// When an operation may run (D-785 rule 5): `expand` is safe before the
/// release that needs it, `contract` only after that release is verified.
/// v1 fixes the phase per op: every removal is `contract`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpPhase {
    Expand,
    Contract,
}

impl OpPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expand => "expand",
            Self::Contract => "contract",
        }
    }
}

/// How a changeset came to be (`changeset.origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Opened explicitly through the admin API.
    Authored,
    /// One request's writes on an `auto`-mode server.
    Auto,
    /// One request's writes admitted through a break-glass window.
    BreakGlass,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authored => "authored",
            Self::Auto => "auto",
            Self::BreakGlass => "break_glass",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Authored, Self::Auto, Self::BreakGlass]
            .into_iter()
            .find(|o| o.as_str() == value)
    }

    /// Automatic changesets are closed by the recorder and sealed later.
    pub fn is_automatic(self) -> bool {
        matches!(self, Self::Auto | Self::BreakGlass)
    }
}

/// `changeset.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangesetStatus {
    Open,
    Closed,
    Abandoned,
}

impl ChangesetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Abandoned => "abandoned",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Open, Self::Closed, Self::Abandoned]
            .into_iter()
            .find(|s| s.as_str() == value)
    }
}

macro_rules! op_catalogue {
    ($( $variant:ident => $name:literal, $phase:ident, $stage:literal, [$($key:literal),*]; )*) => {
        /// The attome-changeset/v1 operation catalogue (design §3).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Op { $( $variant, )* }

        impl Op {
            /// Every op, in catalogue order.
            pub const ALL: &'static [Op] = &[ $( Op::$variant, )* ];

            /// The wire and column name.
            pub fn as_str(self) -> &'static str {
                match self { $( Op::$variant => $name, )* }
            }

            /// The only phase this op may carry in v1.
            pub fn phase(self) -> OpPhase {
                match self { $( Op::$variant => OpPhase::$phase, )* }
            }

            /// 1: executable in Phase 1. 2: a Phase 2 operation (D-788); a
            /// binary whose [`SUPPORTED_STAGE`] is below it refuses it
            /// (`op_not_supported`).
            pub fn stage(self) -> u8 {
                match self { $( Op::$variant => $stage, )* }
            }

            /// The keys `target` must carry, exactly.
            pub fn target_keys(self) -> &'static [&'static str] {
                match self { $( Op::$variant => &[$($key),*], )* }
            }

            pub fn parse(value: &str) -> Option<Op> {
                match value { $( $name => Some(Op::$variant), )* _ => None }
            }
        }
    };
}

op_catalogue! {
    CreateEntity => "create_entity", Expand, 1, ["entity"];
    UpdateEntity => "update_entity", Expand, 1, ["entity"];
    RetireEntity => "retire_entity", Contract, 1, ["entity"];
    ReactivateEntity => "reactivate_entity", Expand, 1, ["entity"];
    SetEntityDomain => "set_entity_domain", Expand, 1, ["entity"];
    SetEntityMasterData => "set_entity_master_data", Expand, 1, ["entity"];
    AddField => "add_field", Expand, 1, ["entity", "field"];
    UpdateField => "update_field", Expand, 1, ["entity", "field"];
    RetireField => "retire_field", Contract, 1, ["entity", "field"];
    ReactivateField => "reactivate_field", Expand, 1, ["entity", "field"];
    UpsertRelationship => "upsert_relationship", Expand, 1, ["relationship"];
    RetireRelationship => "retire_relationship", Contract, 1, ["relationship"];
    SetLabel => "set_label", Expand, 1, ["object_kind", "object_key", "locale"];
    ClearLabel => "clear_label", Expand, 1, ["object_kind", "object_key", "locale"];
    UpsertQuery => "upsert_query", Expand, 1, ["entity", "query"];
    RetireQuery => "retire_query", Contract, 1, ["entity", "query"];
    UpsertView => "upsert_view", Expand, 1, ["entity", "view"];
    RetireView => "retire_view", Contract, 1, ["entity", "view"];
    UpsertRule => "upsert_rule", Expand, 1, ["entity", "rule"];
    PublishRule => "publish_rule", Expand, 1, ["entity", "rule"];
    RetireRule => "retire_rule", Contract, 1, ["entity", "rule"];
    UpsertStateModel => "upsert_state_model", Expand, 1, ["entity"];
    RetireStateModel => "retire_state_model", Contract, 1, ["entity"];
    UpsertStateTransition => "upsert_state_transition", Expand, 1, ["entity", "transition"];
    RetireStateTransition => "retire_state_transition", Contract, 1, ["entity", "transition"];
    UpsertWorkflow => "upsert_workflow", Expand, 1, ["workflow"];
    SetWorkflowDraft => "set_workflow_draft", Expand, 1, ["workflow"];
    PublishWorkflow => "publish_workflow", Expand, 1, ["workflow"];
    RetireWorkflow => "retire_workflow", Contract, 1, ["workflow"];
    UpsertCaseDef => "upsert_case_def", Expand, 1, ["case_def"];
    RetireCaseDef => "retire_case_def", Contract, 1, ["case_def"];
    UpsertSidebarItem => "upsert_sidebar_item", Expand, 1, ["path"];
    RetireSidebarItem => "retire_sidebar_item", Contract, 1, ["path"];
    UpsertApp => "upsert_app", Expand, 1, ["app"];
    RetireApp => "retire_app", Contract, 1, ["app"];
    UpsertCalendar => "upsert_calendar", Expand, 1, ["calendar"];
    RetireCalendar => "retire_calendar", Contract, 1, ["calendar"];
    AddCalendarHoliday => "add_calendar_holiday", Expand, 1, ["calendar", "date"];
    RemoveCalendarHoliday => "remove_calendar_holiday", Contract, 1, ["calendar", "date"];
    AddCalendarException => "add_calendar_exception", Expand, 1, ["calendar", "exception"];
    RemoveCalendarException => "remove_calendar_exception", Contract, 1, ["calendar", "exception"];
    UpsertCalendarRule => "upsert_calendar_rule", Expand, 1, ["calendar", "rule"];
    RetireCalendarRule => "retire_calendar_rule", Contract, 1, ["calendar", "rule"];
    UpsertCalendarSeason => "upsert_calendar_season", Expand, 1, ["calendar", "season"];
    RetireCalendarSeason => "retire_calendar_season", Contract, 1, ["calendar", "season"];
    EnsurePrivilege => "ensure_privilege", Expand, 1, ["privilege"];
    UpsertRole => "upsert_role", Expand, 1, ["role"];
    GrantRolePrivilege => "grant_role_privilege", Expand, 1, ["role", "privilege"];
    RevokeRolePrivilege => "revoke_role_privilege", Contract, 1, ["role", "privilege"];
    AddRoleGrantCondition => "add_role_grant_condition", Expand, 1, ["role", "privilege", "condition"];
    RemoveRoleGrantCondition => "remove_role_grant_condition", Contract, 1, ["role", "privilege", "condition"];
    SetRoleEntityAccess => "set_role_entity_access", Expand, 1, ["role", "entity"];
    ClearRoleEntityAccess => "clear_role_entity_access", Contract, 1, ["role", "entity"];
    SetRoleBulkFields => "set_role_bulk_fields", Expand, 1, ["role"];
    SetEntityDefaultShare => "set_entity_default_share", Expand, 1, ["entity", "share"];
    RemoveEntityDefaultShare => "remove_entity_default_share", Contract, 1, ["entity", "share"];
    UpsertFieldProfile => "upsert_field_profile", Expand, 1, ["profile"];
    SetFieldProfileField => "set_field_profile_field", Expand, 1, ["profile", "entity", "field"];
    AssignFieldProfile => "assign_field_profile", Expand, 1, ["profile", "role"];
    UnassignFieldProfile => "unassign_field_profile", Contract, 1, ["profile", "role"];
    UpsertDataDomain => "upsert_data_domain", Expand, 1, ["domain"];
    UpsertRecord => "upsert_record", Expand, 1, ["entity", "key"];
    RenameField => "rename_field", Expand, 2, ["entity", "field"];
    ChangeFieldType => "change_field_type", Expand, 2, ["entity", "field"];
    AddChoiceValue => "add_choice_value", Expand, 2, ["entity", "field"];
    RemoveChoiceValue => "remove_choice_value", Contract, 2, ["entity", "field"];
    SetViewColumns => "set_view_columns", Expand, 2, ["entity", "view"];
    DataStep => "data_step", Expand, 2, ["entity"];
    DeleteField => "delete_field", Contract, 2, ["entity", "field"];
    // B13-T7: brand themes, by scope (`deployment`, or `<kind>:<ref>`).
    UpsertTheme => "upsert_theme", Expand, 1, ["theme_scope"];
    PublishTheme => "publish_theme", Expand, 1, ["theme_scope"];
    RetireTheme => "retire_theme", Contract, 1, ["theme_scope"];
}

/// The highest op stage this binary records and applies (design §4.1): stage 2
/// ops are the Phase 2 operations (D-788).
pub const SUPPORTED_STAGE: u8 = 2;

/// One operation a writer hands [`super::Recording::record`], built from the
/// row it just wrote.
#[derive(Debug, Clone)]
pub struct RecordedOp {
    pub op: Op,
    /// `"entity"`, `"attribute"`, `"view"`, … — diagnostics and translation.
    pub object_kind: &'static str,
    /// The live row id, for diagnostics; never exported.
    pub object_ref: Option<Uuid>,
    /// The object's logical key (never a UUID): an object with exactly
    /// [`Op::target_keys`].
    pub target: Value,
    /// The post-write row, enumerated columns; UUIDs allowed.
    pub snapshot: Value,
    /// The properties an update changed, for the review summary.
    pub changed: Vec<&'static str>,
}

fn is_uuid_like(value: &str) -> bool {
    value.len() == 36 && Uuid::parse_str(value).is_ok()
}

impl RecordedOp {
    /// Shape check before anything is written. A failure is a defect in the
    /// hook that built the op, not bad client input, so the caller maps it to
    /// a masked internal error.
    pub fn check(&self) -> Result<(), String> {
        let name = self.op.as_str();
        if self.op.stage() > SUPPORTED_STAGE {
            return Err(format!(
                "{name} is a stage {} operation and cannot be recorded by this release",
                self.op.stage()
            ));
        }
        let Some(target) = self.target.as_object() else {
            return Err(format!("{name}: target must be an object"));
        };
        let expected = self.op.target_keys();
        if target.len() != expected.len() || !expected.iter().all(|k| target.contains_key(*k)) {
            return Err(format!(
                "{name}: target keys must be exactly {expected:?}, got {:?}",
                target.keys().collect::<Vec<_>>()
            ));
        }
        for (key, value) in target {
            match value {
                // upsert_record's business key: field -> value.
                Value::Object(map) if key == "key" && !map.is_empty() => {}
                Value::String(s) if !s.is_empty() && !is_uuid_like(s) => {}
                _ => {
                    return Err(format!(
                        "{name}: target.{key} must be a non-empty logical name, never a UUID"
                    ));
                }
            }
        }
        if !self.snapshot.is_object() {
            return Err(format!("{name}: snapshot must be an object"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCHEMA: &str = include_str!("../../../../../schemas/attome-changeset-v1.schema.json");

    /// The Rust catalogue equals the generated schema: every op's name, phase,
    /// stage and target keys, and nothing extra on either side.
    #[test]
    fn op_catalogue_matches_the_schema() {
        let schema: Value = serde_json::from_str(SCHEMA).expect("schema parses");
        let names: Vec<&str> = schema["$defs"]["operation"]["properties"]["op"]["enum"]
            .as_array()
            .expect("op enum")
            .iter()
            .map(|v| v.as_str().expect("op name"))
            .collect();
        let ours: Vec<&str> = Op::ALL.iter().map(|op| op.as_str()).collect();
        assert_eq!(
            ours, names,
            "Op::ALL must equal the schema's op enum, in order"
        );
        assert_eq!(Op::ALL.len(), 69);
        assert_eq!(Op::ALL.iter().filter(|op| op.stage() == 1).count(), 62);
        assert_eq!(Op::ALL.iter().filter(|op| op.stage() == 2).count(), 7);

        for op in Op::ALL {
            let def = &schema["$defs"][format!("op_{}", op.as_str())];
            assert_eq!(
                def["properties"]["phase"]["const"].as_str(),
                Some(op.phase().as_str()),
                "{} phase",
                op.as_str()
            );
            let mut keys: Vec<&str> = def["properties"]["target"]["required"]
                .as_array()
                .expect("target.required")
                .iter()
                .map(|v| v.as_str().expect("key"))
                .collect();
            let mut expected = op.target_keys().to_vec();
            keys.sort_unstable();
            expected.sort_unstable();
            assert_eq!(keys, expected, "{} target keys", op.as_str());
            let description = def["description"].as_str().expect("description");
            assert!(
                description.contains(&format!("(stage {}", op.stage())),
                "{} stage: {description}",
                op.as_str()
            );
            assert_eq!(Op::parse(op.as_str()), Some(*op));
        }
        assert_eq!(
            Op::parse("drop_field"),
            None,
            "the delete op is delete_field (D-788)"
        );
        for gone in [
            "add_form_section",
            "move_form_field",
            "remove_form_field",
            "retire_choice_value",
        ] {
            assert_eq!(Op::parse(gone), None, "{gone} left the catalogue (D-788)");
        }
        for gone in ["upsert_form", "retire_form"] {
            assert_eq!(
                Op::parse(gone),
                None,
                "{gone} left the catalogue: forms are code (D-790)"
            );
        }
    }

    #[test]
    fn every_removal_is_a_contract_op() {
        for op in Op::ALL {
            let name = op.as_str();
            let removal = [
                "retire_",
                "remove_",
                "revoke_",
                "clear_",
                "unassign_",
                "delete_",
            ]
            .iter()
            .any(|p| name.starts_with(p));
            // clear_label is expand (a label reset is not structural).
            if removal && *op != Op::ClearLabel {
                assert_eq!(op.phase(), OpPhase::Contract, "{name}");
            }
        }
    }

    fn op(op: Op, target: Value) -> RecordedOp {
        RecordedOp {
            op,
            object_kind: "view",
            object_ref: Some(Uuid::now_v7()),
            target,
            snapshot: json!({ "name": "x" }),
            changed: vec![],
        }
    }

    #[test]
    fn a_well_formed_op_passes_the_check() {
        assert!(
            op(
                Op::UpsertView,
                json!({ "entity": "account", "view": "active_accounts" })
            )
            .check()
            .is_ok()
        );
        assert!(
            op(
                Op::UpsertRecord,
                json!({ "entity": "country", "key": { "code": "BH" } })
            )
            .check()
            .is_ok()
        );
    }

    #[test]
    fn a_malformed_op_is_refused() {
        let uuid = Uuid::now_v7().to_string();
        for bad in [
            op(Op::UpsertView, json!({ "entity": "account" })),
            op(
                Op::UpsertView,
                json!({ "entity": "account", "view": "v", "x": "y" }),
            ),
            op(Op::UpsertView, json!({ "entity": "account", "view": uuid })),
            op(Op::UpsertView, json!({ "entity": "account", "view": "" })),
            op(Op::UpsertView, json!(["account"])),
            op(Op::UpsertRecord, json!({ "entity": "country", "key": {} })),
        ] {
            assert!(bad.check().is_err(), "{:?} must be refused", bad.target);
        }
        let mut no_snapshot = op(Op::RetireView, json!({ "entity": "a", "view": "b" }));
        no_snapshot.snapshot = Value::Null;
        assert!(no_snapshot.check().is_err());
    }

    #[test]
    fn phase_two_ops_are_recordable() {
        for p2 in [Op::RenameField, Op::DeleteField, Op::ChangeFieldType] {
            assert!(
                op(p2, json!({ "entity": "account", "field": "name" }))
                    .check()
                    .is_ok(),
                "{} must be recordable (SUPPORTED_STAGE = 2)",
                p2.as_str()
            );
        }
    }

    #[test]
    fn origin_and_status_round_trip() {
        for o in [Origin::Authored, Origin::Auto, Origin::BreakGlass] {
            assert_eq!(Origin::parse(o.as_str()), Some(o));
        }
        assert!(Origin::BreakGlass.is_automatic() && !Origin::Authored.is_automatic());
        for s in [
            ChangesetStatus::Open,
            ChangesetStatus::Closed,
            ChangesetStatus::Abandoned,
        ] {
            assert_eq!(ChangesetStatus::parse(s.as_str()), Some(s));
        }
    }
}
