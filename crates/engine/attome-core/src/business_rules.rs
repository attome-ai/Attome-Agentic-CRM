//! Business rules (D-789, amended by D-791; `document/general/BUSINESS-RULES-DESIGN.md`):
//! the model of an `rule` row of kind `business` — the structured
//! condition tree, the policies, the audience, the lock precedence — plus the
//! pure functions every consumer shares:
//!
//! - [`compile_condition`] validates a condition against an entity's
//!   attributes and compiles it to **one** `attome-rules` program (D-399: one
//!   evaluator). Every literal in a structured leaf becomes a typed parameter
//!   (`__p0`, `__p1`, …) declared in the [`Schema`] and supplied in the
//!   [`Context`]; no value is ever spliced into program text.
//! - [`validate_rule`] checks a whole rule (audience, condition, policies)
//!   the way the admin API does before it stores one; the checks that need
//!   the database or the caller (role liveness, field read access, rule
//!   limits across an entity, warnings) stay with the admin routes.
//!
//! Pure: no I/O, no clock of its own (the caller passes `now`), no cache. The
//! compiled-program cache and the write pipeline live in `attome-records`.

use std::collections::{BTreeMap, BTreeSet};

use attome_rules::{Compiled, Context, Expr, RulesError, Schema, Type, Value as RulesValue};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AttrInfo, FieldType};

/// `rule.kind` of a business rule.
pub const BUSINESS_KIND: &str = "business";

/// Admin-validated limits (design §1.1). The per-entity active-rule limit is
/// checked by the admin route, which can count rows.
pub const MAX_ACTIVE_RULES_PER_ENTITY: usize = 200;
pub const MAX_POLICIES_PER_RULE: usize = 50;
pub const MAX_ROLES_PER_RULE: usize = 20;
/// Nesting of `all`/`any` groups, the root group included.
pub const MAX_TREE_DEPTH: usize = 4;
/// Structured and advanced leaves together.
pub const MAX_LEAVES: usize = 20;
/// Values in one `in`/`not_in` list.
pub const MAX_LIST_VALUES: usize = 50;
/// `rule_policy.message` is `VARCHAR(500)`.
pub const MAX_POLICY_MESSAGE_CHARS: usize = 500;

/// System columns a condition may read (as lookups). Every other system
/// column (`id`, `created_at`, `is_active`, …) is refused; the state field is
/// an ordinary attribute and is accepted as one.
pub const CONDITION_SYSTEM_FIELDS: [&str; 2] = ["owner_ref", "organization_ref"];

/// Prefix of the parameter identifiers [`compile_condition`] declares. Field
/// logical names start with a letter, so they cannot collide; an advanced
/// expression may not name an identifier with this prefix.
pub const PARAM_PREFIX: &str = "__p";

// ── The condition tree ──────────────────────────────────────────────────────

/// A condition: `{"all": [...]}` (AND), `{"any": [...]}` (OR), a structured
/// leaf `{"field", "op", "value"?}`, or an advanced leaf `{"expression"}`
/// holding a `attome-rules` boolean. The root `{"all": []}` means "always".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum ConditionTree {
    All(ConditionAll),
    Any(ConditionAny),
    Expression(ConditionExpression),
    Leaf(ConditionLeaf),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionAll {
    /// The tree nests, so utoipa must not expand it inline (the recursion
    /// would overflow the stack while building the OpenAPI document).
    #[schema(no_recursion)]
    pub all: Vec<ConditionTree>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionAny {
    #[schema(no_recursion)]
    pub any: Vec<ConditionTree>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionExpression {
    /// A `attome-rules` expression over the entity's own fields that types as
    /// `bool`. A rule with an advanced leaf may not carry `hidden` or
    /// `disabled` policies (the client cannot mirror it).
    pub expression: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionLeaf {
    pub field: String,
    pub op: BusinessRuleOp,
    /// Absent for `is_empty`/`is_not_empty`; an array for `in`/`not_in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl ConditionTree {
    /// `{"all": []}` — the condition of a rule that always applies.
    pub fn always() -> Self {
        ConditionTree::All(ConditionAll { all: Vec::new() })
    }

    pub fn is_always(&self) -> bool {
        matches!(self, ConditionTree::All(a) if a.all.is_empty())
    }

    /// True when the tree holds an advanced (`expression`) leaf anywhere.
    pub fn has_expression(&self) -> bool {
        match self {
            ConditionTree::All(g) => g.all.iter().any(Self::has_expression),
            ConditionTree::Any(g) => g.any.iter().any(Self::has_expression),
            ConditionTree::Expression(_) => true,
            ConditionTree::Leaf(_) => false,
        }
    }

    /// The fields named by structured leaves (advanced leaves not included:
    /// their references come from parsing, see [`CompiledCondition::fields`]).
    pub fn leaf_fields(&self) -> BTreeSet<&str> {
        let mut out = BTreeSet::new();
        self.collect_leaf_fields(&mut out);
        out
    }

    fn collect_leaf_fields<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            ConditionTree::All(g) => g.all.iter().for_each(|c| c.collect_leaf_fields(out)),
            ConditionTree::Any(g) => g.any.iter().for_each(|c| c.collect_leaf_fields(out)),
            ConditionTree::Expression(_) => {}
            ConditionTree::Leaf(l) => {
                out.insert(l.field.as_str());
            }
        }
    }
}

/// Leaf operators (string serde). `eq … in` keep `ConditionOperator`'s
/// meaning; the per-type table is [`ConditionFieldKind::allows`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BusinessRuleOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Contains,
    StartsWith,
    IsEmpty,
    IsNotEmpty,
}

impl BusinessRuleOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::In => "in",
            Self::NotIn => "not_in",
            Self::Contains => "contains",
            Self::StartsWith => "starts_with",
            Self::IsEmpty => "is_empty",
            Self::IsNotEmpty => "is_not_empty",
        }
    }

    fn takes_value(self) -> bool {
        !matches!(self, Self::IsEmpty | Self::IsNotEmpty)
    }

    fn takes_list(self) -> bool {
        matches!(self, Self::In | Self::NotIn)
    }
}

/// How a field behaves inside a condition. `None` from [`Self::of_attr`] means
/// the field cannot be a leaf (file, image, rich text).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionFieldKind {
    Text,
    Number,
    Date,
    Bool,
    Choice,
    MultiChoice,
    Lookup,
}

impl ConditionFieldKind {
    /// A formula field is its result type (D-604).
    pub fn of_attr(attr: &AttrInfo) -> Option<Self> {
        if matches!(
            attr.field_type(),
            FieldType::RichText
                | FieldType::File
                | FieldType::Image
                | FieldType::Time
                | FieldType::Geolocation
                | FieldType::Json
        ) {
            return None;
        }
        Some(match attr.storage_type() {
            FieldType::Text | FieldType::Icon | FieldType::Color | FieldType::Formula => Self::Text,
            FieldType::Number | FieldType::Currency | FieldType::Rollup => Self::Number,
            FieldType::Date | FieldType::DateTime => Self::Date,
            FieldType::Bool => Self::Bool,
            FieldType::Choice => {
                if FieldType::Choice.is_multi_valued(attr.options.as_ref().unwrap_or(&Value::Null))
                {
                    Self::MultiChoice
                } else {
                    Self::Choice
                }
            }
            FieldType::Lookup => Self::Lookup,
            FieldType::File
            | FieldType::Image
            | FieldType::RichText
            | FieldType::Time
            | FieldType::Geolocation
            | FieldType::Json => {
                return None;
            }
        })
    }

    /// The `attome-rules` type the field is declared as in a condition's schema.
    /// A multi-choice field is a list of choices (its stored JSON array).
    pub fn rules_type(self) -> Type {
        match self {
            Self::Text => Type::Text,
            Self::Number => Type::Number,
            Self::Date => Type::Date,
            Self::Bool => Type::Bool,
            Self::Choice => Type::Choice,
            Self::MultiChoice => Type::List(Box::new(Type::Choice)),
            Self::Lookup => Type::Lookup,
        }
    }

    /// The operator table of design §2.
    pub fn allows(self, op: BusinessRuleOp) -> bool {
        use BusinessRuleOp as O;
        match self {
            Self::Text => matches!(
                op,
                O::Eq
                    | O::Ne
                    | O::In
                    | O::NotIn
                    | O::Contains
                    | O::StartsWith
                    | O::IsEmpty
                    | O::IsNotEmpty
            ),
            Self::Number | Self::Date if op == O::In || op == O::NotIn => self == Self::Number,
            Self::Number | Self::Date => matches!(
                op,
                O::Eq | O::Ne | O::Gt | O::Gte | O::Lt | O::Lte | O::IsEmpty | O::IsNotEmpty
            ),
            Self::Bool => matches!(op, O::Eq | O::IsEmpty | O::IsNotEmpty),
            Self::Choice | Self::Lookup => matches!(
                op,
                O::Eq | O::Ne | O::In | O::NotIn | O::IsEmpty | O::IsNotEmpty
            ),
            Self::MultiChoice => matches!(op, O::Contains | O::In | O::IsEmpty | O::IsNotEmpty),
        }
    }
}

// ── Policies ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    Hidden,
    Disabled,
    Error,
    SetValue,
    /// A11-T1: the field is required while the condition holds.
    Required,
    /// A11-T1: the field takes only the codes in `value` (a list) while the
    /// condition holds.
    AllowedValues,
    /// B4-T3: the record gets the shared tag named in `value`.
    AddTag,
    /// B4-T3: the record loses the shared tag named in `value`.
    RemoveTag,
}

impl PolicyType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Disabled => "disabled",
            Self::Error => "error",
            Self::SetValue => "set_value",
            Self::Required => "required",
            Self::AllowedValues => "allowed_values",
            Self::AddTag => "add_tag",
            Self::RemoveTag => "remove_tag",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "hidden" => Self::Hidden,
            "disabled" => Self::Disabled,
            "error" => Self::Error,
            "set_value" => Self::SetValue,
            "required" => Self::Required,
            "allowed_values" => Self::AllowedValues,
            "add_tag" => Self::AddTag,
            "remove_tag" => Self::RemoveTag,
            _ => return None,
        })
    }

    pub fn is_lock(self) -> bool {
        matches!(self, Self::Hidden | Self::Disabled)
    }
}

/// A3-T4: how a refusing check (`error`, `required`, `allowed_values`) is
/// rolled out. `Report` only logs a failure, `Warn` lets the write through
/// with a warning, `Enforce` refuses it — from `enforce_from` when set, and
/// as a warning before that date.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Report,
    Warn,
    Enforce,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Warn => "warn",
            Self::Enforce => "enforce",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "report" => Some(Self::Report),
            "warn" => Some(Self::Warn),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// A3-T4: what a failing check does to the write today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enforcement {
    /// Logged only; the caller hears nothing.
    Report,
    /// The write goes through with a warning.
    Warn,
    /// The write is refused (unless overridden with a reason).
    Enforce,
}

/// A3-T4: the privilege that lets a staff user save a record a check
/// refuses, with a reason; each override is a security event.
pub const OVERRIDE_PRIVILEGE: &str = "record.override_rules";

/// Severity of an `error` policy. `Error` fails the write (422
/// `rule_violation`); `Warning` never blocks: the write succeeds and the
/// warning is returned to the caller (D-791 rule 6) and logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "error" => Some(Self::Error),
            "warning" => Some(Self::Warning),
            _ => None,
        }
    }

    /// Whether a firing policy of this severity refuses the write.
    pub fn blocks(self) -> bool {
        self == Self::Error
    }
}

/// When a `set_value` policy writes: on every write, or on create only when
/// the field is still empty (after the body, state initial value and
/// autovalue).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetMode {
    Always,
    Default,
}

impl SetMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Default => "default",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "always" => Some(Self::Always),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
}

/// Who a rule applies to (`rule.applies_to`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppliesTo {
    #[default]
    All,
    Roles,
}

impl AppliesTo {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Roles => "roles",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "roles" => Some(Self::Roles),
            _ => None,
        }
    }
}

/// One policy, in the wire shape `{ type, field?, message?, severity?,
/// value?, expression?, mode? }` (one `rule_policy` row). Its shape
/// is checked by [`validate_rule`] (and by the table's CHECK); use
/// [`PolicyDef::effect`] for the typed view.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDef {
    #[serde(rename = "type")]
    pub policy_type: PolicyType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// A `set_value` literal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// A `set_value` `attome-rules` expression over the entity's own fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SetMode>,
    /// A3-T4: how this check is rolled out; absent means its severity decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<Stage>,
    /// A3-T4: with `stage: enforce`, the first day the check refuses writes;
    /// before it the check warns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforce_from: Option<chrono::NaiveDate>,
    /// `rule_policy.ordinal` — the policy's position in its rule
    /// (the admin API stores the list index). Not on the wire: order is the
    /// list order.
    #[serde(skip)]
    pub ordinal: i32,
}

/// The effect of a lock policy. Ordered: `Hidden` is more restrictive than
/// `Disabled`, and the most restrictive wins across rules and roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockEffect {
    Disabled,
    Hidden,
}

impl LockEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Hidden => "hidden",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SetValueSource<'a> {
    Literal(&'a Value),
    Expression(&'a str),
}

/// The typed view of a well-formed [`PolicyDef`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PolicyEffect<'a> {
    Lock {
        field: &'a str,
        effect: LockEffect,
    },
    Error {
        field: Option<&'a str>,
        message: Option<&'a str>,
        severity: Severity,
    },
    SetValue {
        field: &'a str,
        source: SetValueSource<'a>,
        mode: SetMode,
    },
    /// A11-T1: the write fails when `field` is empty.
    Required {
        field: &'a str,
        message: Option<&'a str>,
    },
    /// A11-T1: the write fails when `field` holds a value (or, for a
    /// multi-choice, any value) not in `values`.
    AllowedValues {
        field: &'a str,
        values: &'a [Value],
        message: Option<&'a str>,
    },
    /// B4-T3: the written record gets (`add`) or loses the shared tag `name`.
    Tag {
        add: bool,
        name: &'a str,
    },
}

/// A11-T1: whether `value` is allowed by an `allowed_values` list. Empty is
/// allowed (that is `required`'s business); a list must hold allowed items
/// only. Codes compare by their text, so `1` and `"1"` are the same code.
pub fn value_allowed(value: Option<&Value>, allowed: &[Value]) -> bool {
    fn code(v: &Value) -> String {
        match v {
            Value::String(s) => s.trim().to_owned(),
            other => other.to_string(),
        }
    }
    let one = |v: &Value| allowed.iter().any(|a| code(a) == code(v));
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) if s.trim().is_empty() => true,
        Some(Value::Array(items)) => items.iter().all(one),
        Some(v) => one(v),
    }
}

impl PolicyDef {
    /// A3-T4: a check that refuses a write, and so can be staged.
    pub fn is_staged_type(&self) -> bool {
        matches!(
            self.policy_type,
            PolicyType::Error | PolicyType::Required | PolicyType::AllowedValues
        )
    }

    /// A3-T4: what this check does to a write today, given the severity it
    /// would have unstaged.
    pub fn enforcement(&self, severity: Severity, today: chrono::NaiveDate) -> Enforcement {
        match self.stage {
            None if severity.blocks() => Enforcement::Enforce,
            None | Some(Stage::Warn) => Enforcement::Warn,
            Some(Stage::Report) => Enforcement::Report,
            Some(Stage::Enforce) => match self.enforce_from {
                Some(from) if today < from => Enforcement::Warn,
                _ => Enforcement::Enforce,
            },
        }
    }

    /// `None` for a malformed policy (one [`validate_rule`] refuses).
    pub fn effect(&self) -> Option<PolicyEffect<'_>> {
        match self.policy_type {
            PolicyType::Hidden | PolicyType::Disabled => Some(PolicyEffect::Lock {
                field: self.field.as_deref()?,
                effect: if self.policy_type == PolicyType::Hidden {
                    LockEffect::Hidden
                } else {
                    LockEffect::Disabled
                },
            }),
            PolicyType::Error => Some(PolicyEffect::Error {
                field: self.field.as_deref(),
                message: self.message.as_deref(),
                severity: self.severity?,
            }),
            PolicyType::SetValue => {
                let source = match (&self.value, &self.expression) {
                    (Some(v), None) => SetValueSource::Literal(v),
                    (None, Some(e)) => SetValueSource::Expression(e),
                    _ => return None,
                };
                Some(PolicyEffect::SetValue {
                    field: self.field.as_deref()?,
                    source,
                    mode: self.mode?,
                })
            }
            PolicyType::Required => Some(PolicyEffect::Required {
                field: self.field.as_deref()?,
                message: self.message.as_deref(),
            }),
            PolicyType::AllowedValues => Some(PolicyEffect::AllowedValues {
                field: self.field.as_deref()?,
                values: self.value.as_ref()?.as_array()?.as_slice(),
                message: self.message.as_deref(),
            }),
            PolicyType::AddTag | PolicyType::RemoveTag => Some(PolicyEffect::Tag {
                add: self.policy_type == PolicyType::AddTag,
                name: self.value.as_ref()?.as_str()?,
            }),
        }
    }
}

// ── The loaded rule and its audience ────────────────────────────────────────

/// The writer a rule set is evaluated for (design §3.1, D-791 rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAudience<'a> {
    /// A staff principal and the roles it holds (direct and through teams).
    /// `interactive` is true for a session user and false for an API-key or
    /// S2S principal, which skips `hidden`/`disabled` (D-791 rule 3).
    Staff {
        role_ids: &'a [Uuid],
        interactive: bool,
    },
    /// A portal user and their one portal role (D-579).
    Portal { role_id: Uuid },
    /// A system context (workflow scheduler, bundle record sets, …): all-users
    /// rules' `error` and `set_value` only.
    System,
}

impl RuleAudience<'_> {
    /// Whether `hidden`/`disabled` policies restrict this writer.
    pub fn subject_to_locks(&self) -> bool {
        matches!(
            self,
            RuleAudience::Staff {
                interactive: true,
                ..
            } | RuleAudience::Portal { .. }
        )
    }
}

/// One business rule as the registry holds it: its row, live role
/// associations (soft-deleted staff roles are not loaded) and its policies in
/// `ordinal` order.
#[derive(Clone, Debug, PartialEq)]
pub struct BusinessRuleDef {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub name: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub display_order: i32,
    pub version: i32,
    pub row_version: i64,
    pub applies_to: AppliesTo,
    pub role_ids: Vec<Uuid>,
    pub portal_role_ids: Vec<Uuid>,
    pub condition: ConditionTree,
    pub policies: Vec<PolicyDef>,
}

impl BusinessRuleDef {
    /// The name shown to users (lock tooltips, error details).
    pub fn label(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.name)
    }

    /// Whether the rule's audience includes `audience` (activity not
    /// considered; see [`crate::RuleEntry::business_rules_for`]).
    pub fn applies_to_audience(&self, audience: &RuleAudience<'_>) -> bool {
        match (self.applies_to, audience) {
            (AppliesTo::All, _) => true,
            (AppliesTo::Roles, RuleAudience::Staff { role_ids, .. }) => {
                self.role_ids.iter().any(|r| role_ids.contains(r))
            }
            (AppliesTo::Roles, RuleAudience::Portal { role_id }) => {
                self.portal_role_ids.contains(role_id)
            }
            (AppliesTo::Roles, RuleAudience::System) => false,
        }
    }

    /// The policies that bind `audience` (lock policies dropped for a writer
    /// not subject to locks), in order. Empty when the rule does not apply.
    pub fn policies_for<'a>(
        &'a self,
        audience: &RuleAudience<'_>,
    ) -> impl Iterator<Item = &'a PolicyDef> + 'a {
        let applies = self.is_active && self.applies_to_audience(audience);
        let locks = audience.subject_to_locks();
        self.policies
            .iter()
            .filter(move |p| applies && (locks || !p.policy_type.is_lock()))
    }

    pub fn has_lock_policy(&self) -> bool {
        self.policies.iter().any(|p| p.policy_type.is_lock())
    }
}

/// The lock on one field after combining every firing rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldLock {
    pub effect: LockEffect,
    pub rule_id: Uuid,
    pub rule_name: String,
}

/// Combines the lock policies of the rules whose condition holds (true or
/// unknown, design §3.2) for one writer: per field the most restrictive
/// effect wins (`hidden` > `disabled`); among equal effects the first rule in
/// the given order (display order) names the lock. Several roles never loosen
/// each other. The caller has already filtered by audience (for example with
/// [`BusinessRuleDef::policies_for`]'s rules), so this looks at lock policies
/// only.
pub fn combine_locks<'a>(
    fired: impl IntoIterator<Item = &'a BusinessRuleDef>,
) -> BTreeMap<String, FieldLock> {
    let mut out: BTreeMap<String, FieldLock> = BTreeMap::new();
    for rule in fired {
        for policy in &rule.policies {
            let Some(PolicyEffect::Lock { field, effect }) = policy.effect() else {
                continue;
            };
            match out.get(field) {
                Some(existing) if existing.effect >= effect => {}
                _ => {
                    out.insert(
                        field.to_owned(),
                        FieldLock {
                            effect,
                            rule_id: rule.id,
                            rule_name: rule.label().to_owned(),
                        },
                    );
                }
            }
        }
    }
    out
}

// ── Conflicts (A11-T4) ──────────────────────────────────────────────────────

/// The `field = value` pairs a condition requires to hold: a single `eq`
/// leaf, or the `eq` leaves of an `all`. Anything else requires nothing
/// that can rule an overlap out.
fn required_equalities(tree: &ConditionTree) -> Vec<(&str, &Value)> {
    match tree {
        ConditionTree::Leaf(leaf) if leaf.op == BusinessRuleOp::Eq => leaf
            .value
            .as_ref()
            .map(|v| vec![(leaf.field.as_str(), v)])
            .unwrap_or_default(),
        ConditionTree::All(all) => all.all.iter().flat_map(required_equalities).collect(),
        _ => Vec::new(),
    }
}

/// Whether two conditions can hold at once. Conservative: only two
/// conditions that require the same field to equal different values are
/// known to exclude each other; everything else may overlap. Pure.
pub fn may_overlap(a: &ConditionTree, b: &ConditionTree) -> bool {
    let left = required_equalities(a);
    let right = required_equalities(b);
    !left
        .iter()
        .any(|(f, v)| right.iter().any(|(g, w)| f == g && v != w))
}

/// One conflict between two business rules on one field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleConflict {
    /// `required_and_hidden` or `two_set_values`.
    pub code: &'static str,
    pub field: String,
}

fn fields_of(policies: &[PolicyDef], kind: PolicyType) -> Vec<&str> {
    policies
        .iter()
        .filter(|p| p.policy_type == kind)
        .filter_map(|p| p.field.as_deref())
        .collect()
}

/// A11-T4: the conflicts between a rule (`condition`, `policies`) and
/// another (`other_condition`, `other_policies`) when their conditions may
/// hold together: a field one makes required while the other hides it, and
/// a field both set. Pass the same rule twice to check it against itself
/// (only `required_and_hidden` applies then). Pure.
pub fn conflicts_between(
    condition: &ConditionTree,
    policies: &[PolicyDef],
    other_condition: &ConditionTree,
    other_policies: &[PolicyDef],
    same_rule: bool,
) -> Vec<RuleConflict> {
    if !may_overlap(condition, other_condition) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let required = fields_of(policies, PolicyType::Required);
    let hidden = fields_of(policies, PolicyType::Hidden);
    let other_required = fields_of(other_policies, PolicyType::Required);
    let other_hidden = fields_of(other_policies, PolicyType::Hidden);
    for field in &required {
        if other_hidden.contains(field) {
            out.push(RuleConflict {
                code: "required_and_hidden",
                field: (*field).to_owned(),
            });
        }
    }
    if !same_rule {
        for field in &hidden {
            if other_required.contains(field) {
                out.push(RuleConflict {
                    code: "required_and_hidden",
                    field: (*field).to_owned(),
                });
            }
        }
        let sets = fields_of(policies, PolicyType::SetValue);
        let other_sets = fields_of(other_policies, PolicyType::SetValue);
        for field in &sets {
            if other_sets.contains(field) {
                out.push(RuleConflict {
                    code: "two_set_values",
                    field: (*field).to_owned(),
                });
            }
        }
    }
    out.sort_by(|a, b| (a.code, &a.field).cmp(&(b.code, &b.field)));
    out.dedup();
    out
}

// ── Issues ──────────────────────────────────────────────────────────────────

/// One validation problem, addressed by a path into the rule body
/// (`condition.all[1].value`, `policies[0].field`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleIssue {
    pub path: String,
    pub code: String,
    pub message: String,
}

impl RuleIssue {
    fn new(path: impl Into<String>, code: &str, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

// ── Schema and context for conditions ───────────────────────────────────────

/// The kind of a field a condition may name, or the issue code explaining why
/// it may not.
fn condition_field_kind(
    attrs: &[AttrInfo],
    name: &str,
) -> Result<ConditionFieldKind, (&'static str, String)> {
    if CONDITION_SYSTEM_FIELDS.contains(&name) {
        return Ok(ConditionFieldKind::Lookup);
    }
    if crate::ALL_SYSTEM_COLS.contains(&name) {
        return Err((
            "field_not_eligible",
            format!("system column '{name}' cannot be used in a condition"),
        ));
    }
    let attr = attrs
        .iter()
        .find(|a| a.logicalname == name)
        .ok_or_else(|| {
            (
                "field_unknown",
                format!("'{name}' is not a field of this entity"),
            )
        })?;
    ConditionFieldKind::of_attr(attr).ok_or_else(|| {
        (
            "field_not_eligible",
            format!(
                "field '{name}' ({}) cannot be used in a condition",
                attr.field_type().as_str()
            ),
        )
    })
}

/// The `attome-rules` schema of an entity's own fields for business rules:
/// every condition-eligible attribute ([`ConditionFieldKind::rules_type`]; a
/// multi-choice field is `list<choice>`), rich text readable as text by
/// expressions, and the [`CONDITION_SYSTEM_FIELDS`] as lookups. Parameters of
/// a compiled condition are added by [`CompiledCondition::schema`].
pub fn condition_schema(attrs: &[AttrInfo]) -> Schema {
    let mut schema = Schema::new();
    for attr in attrs {
        if crate::ALL_SYSTEM_COLS.contains(&attr.logicalname.as_str()) {
            continue;
        }
        if let Some(kind) = ConditionFieldKind::of_attr(attr) {
            schema = schema.with_field(attr.logicalname.clone(), kind.rules_type());
        } else if attr.field_type() == FieldType::RichText {
            schema = schema.with_field(attr.logicalname.clone(), Type::Text);
        }
    }
    for name in CONDITION_SYSTEM_FIELDS {
        schema = schema.with_field(name, Type::Lookup);
    }
    schema
}

// ── Related records (A11-T2) ────────────────────────────────────────────────

/// A11-T2: the most lookups a rule follows to reach a value.
pub const MAX_RELATED_HOPS: usize = 3;
/// A11-T2: the most related values one expression reads.
pub const MAX_RELATED_REFS: usize = 20;

/// A11-T2: one value an expression reads through lookups:
/// `account.name` (one hop) or `account.owner.region` (up to
/// [`MAX_RELATED_HOPS`]).
#[derive(Debug, Clone, PartialEq)]
pub struct RelatedRef {
    /// The lookup fields followed, then the field read.
    pub segments: Vec<String>,
    /// The entity each lookup reaches, in order.
    pub entities: Vec<String>,
    /// The kind of the field read.
    pub kind: ConditionFieldKind,
}

fn collect_related(expr: &Expr, params: &mut Vec<String>, out: &mut BTreeSet<Vec<String>>) {
    match expr {
        Expr::FieldRef(r) => {
            if let Some(hop) = &r.hop
                && !params.contains(&r.base)
            {
                out.insert(vec![r.base.clone(), hop.clone()]);
            }
        }
        Expr::Path(segments) => {
            if !segments.first().is_some_and(|s| params.contains(s)) {
                out.insert(segments.clone());
            }
        }
        Expr::Unary { expr, .. } => collect_related(expr, params, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_related(lhs, params, out);
            collect_related(rhs, params, out);
        }
        Expr::Call { args, .. } | Expr::ListLit(args) => {
            for a in args {
                collect_related(a, params, out);
            }
        }
        Expr::Lambda { param, body } => {
            params.push(param.clone());
            collect_related(body, params, out);
            params.pop();
        }
        Expr::NullLit | Expr::BoolLit(_) | Expr::NumberLit(_) | Expr::StringLit(_) => {}
    }
}

/// A11-T2: the related values `src` reads that resolve through `attrs`'
/// lookups in `registry`, at most [`MAX_RELATED_REFS`]. A reference that
/// does not resolve (not a lookup, unknown target, field without a rule
/// type, too deep) is left out, so the compiler names it as unknown.
pub fn related_refs(
    src: &str,
    attrs: &[AttrInfo],
    registry: &crate::EntityMetaRegistry,
) -> Vec<RelatedRef> {
    related_refs_within(src, attrs, registry, MAX_RELATED_HOPS)
}

/// [`related_refs`] following at most `max_hops` lookups (A9-T2: formulas
/// follow up to [`crate::formula::MAX_FORMULA_HOPS`]).
pub fn related_refs_within(
    src: &str,
    attrs: &[AttrInfo],
    registry: &crate::EntityMetaRegistry,
    max_hops: usize,
) -> Vec<RelatedRef> {
    let Ok(expr) = attome_rules::parse(src) else {
        return Vec::new();
    };
    let mut found = BTreeSet::new();
    collect_related(&expr, &mut Vec::new(), &mut found);
    let mut out = Vec::new();
    'refs: for segments in found {
        if segments.len() < 2 || segments.len() > max_hops + 1 {
            continue;
        }
        let mut current: &[AttrInfo] = attrs;
        let mut entities = Vec::new();
        for lookup in &segments[..segments.len() - 1] {
            let Some(target) = current
                .iter()
                .find(|a| &a.logicalname == lookup && a.field_type() == FieldType::Lookup)
                .and_then(|a| a.lookup_entity_ref)
                .and_then(|id| registry.get_by_id(id))
            else {
                continue 'refs;
            };
            entities.push(target.logicalname.clone());
            current = &target.attrs;
        }
        let last = &segments[segments.len() - 1];
        let Some(kind) = current
            .iter()
            .find(|a| &a.logicalname == last && !a.is_read_gated())
            .and_then(ConditionFieldKind::of_attr)
        else {
            continue;
        };
        out.push(RelatedRef {
            segments,
            entities,
            kind,
        });
        if out.len() == MAX_RELATED_REFS {
            break;
        }
    }
    out
}

/// A11-T2: `schema` with the related values declared: one hop as the
/// lookup's related fields, longer ones as optional paths.
pub fn with_related_schema(mut schema: Schema, refs: &[RelatedRef]) -> Schema {
    let mut one_hop: BTreeMap<&str, std::collections::HashMap<String, Type>> = BTreeMap::new();
    for r in refs {
        if r.segments.len() == 2 {
            one_hop
                .entry(r.segments[0].as_str())
                .or_default()
                .insert(r.segments[1].clone(), r.kind.rules_type());
        } else {
            let path: Vec<&str> = r.segments.iter().map(String::as_str).collect();
            schema = schema.with_optional_path(&path, r.kind.rules_type());
        }
    }
    for (lookup, fields) in one_hop {
        schema = schema.with_related(lookup, fields);
    }
    schema
}

/// The value one field of a record has inside a condition. Absent, JSON
/// `null` and a value of the wrong JSON type are `Null` (the entity engine's
/// "missing means null" posture). A multi-choice value is its JSON array of
/// keys; a date accepts RFC 3339 or `YYYY-MM-DD` (midnight UTC).
pub fn condition_value(kind: ConditionFieldKind, v: Option<&Value>) -> RulesValue {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return RulesValue::Null;
    };
    let out = match kind {
        ConditionFieldKind::Text => v.as_str().map(|s| RulesValue::Text(s.to_owned())),
        ConditionFieldKind::Number => v.as_f64().filter(|n| n.is_finite()).map(RulesValue::Number),
        ConditionFieldKind::Date => v.as_str().and_then(parse_date).map(RulesValue::Date),
        ConditionFieldKind::Bool => v.as_bool().map(RulesValue::Bool),
        ConditionFieldKind::Choice => v.as_str().map(|s| RulesValue::Choice(s.to_owned())),
        ConditionFieldKind::MultiChoice => v.as_array().map(|items| {
            RulesValue::List(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| RulesValue::Choice(s.to_owned()))
                    .collect(),
            )
        }),
        ConditionFieldKind::Lookup => v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .map(RulesValue::Lookup),
    };
    out.unwrap_or(RulesValue::Null)
}

/// The evaluation context for a record: every field [`condition_schema`]
/// declares, taken from `record` (absent means null). Parameters are added by
/// [`CompiledCondition::context`].
pub fn condition_context(
    attrs: &[AttrInfo],
    record: &serde_json::Map<String, Value>,
    now: DateTime<Utc>,
) -> Context {
    let mut ctx = Context::new(now);
    for attr in attrs {
        if crate::ALL_SYSTEM_COLS.contains(&attr.logicalname.as_str()) {
            continue;
        }
        let value = record.get(&attr.logicalname);
        if let Some(kind) = ConditionFieldKind::of_attr(attr) {
            ctx = ctx.with_field(attr.logicalname.clone(), condition_value(kind, value));
        } else if attr.field_type() == FieldType::RichText {
            ctx = ctx.with_field(
                attr.logicalname.clone(),
                condition_value(ConditionFieldKind::Text, value),
            );
        }
    }
    for name in CONDITION_SYSTEM_FIELDS {
        ctx = ctx.with_field(
            name,
            condition_value(ConditionFieldKind::Lookup, record.get(name)),
        );
    }
    ctx
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
}

// ── Compilation ─────────────────────────────────────────────────────────────

/// One typed parameter of a compiled condition.
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionParam {
    pub name: String,
    pub ty: Type,
    pub value: RulesValue,
}

/// A condition compiled to one `attome-rules` program. Holds the type-checked
/// program (cheap to clone) so the caller can cache it.
#[derive(Clone, Debug)]
pub struct CompiledCondition {
    /// The generated program text. Holds field names, parameter identifiers
    /// and the fixed operators only — never a leaf value.
    pub program: String,
    pub params: Vec<ConditionParam>,
    /// Every field the condition reads (structured leaves and advanced
    /// expressions).
    pub fields: BTreeSet<String>,
    pub has_expression: bool,
    pub compiled: Compiled,
}

impl CompiledCondition {
    /// [`condition_schema`] plus the parameters.
    pub fn schema(&self, attrs: &[AttrInfo]) -> Schema {
        with_params_schema(condition_schema(attrs), &self.params)
    }

    /// [`condition_context`] plus the parameters.
    pub fn context(
        &self,
        attrs: &[AttrInfo],
        record: &serde_json::Map<String, Value>,
        now: DateTime<Utc>,
    ) -> Context {
        let mut ctx = condition_context(attrs, record, now);
        for p in &self.params {
            ctx = ctx.with_field(p.name.clone(), p.value.clone());
        }
        ctx
    }

    /// Evaluates the condition for `record`.
    pub fn evaluate(
        &self,
        attrs: &[AttrInfo],
        record: &serde_json::Map<String, Value>,
        now: DateTime<Utc>,
    ) -> ConditionOutcome {
        ConditionOutcome::from_result(self.compiled.eval(&self.context(attrs, record, now)))
    }
}

fn with_params_schema(mut schema: Schema, params: &[ConditionParam]) -> Schema {
    for p in params {
        schema = schema.with_field(p.name.clone(), p.ty.clone());
    }
    schema
}

/// The outcome of evaluating a condition (design §3.2).
#[derive(Clone, Debug, PartialEq)]
pub enum ConditionOutcome {
    True,
    False,
    /// `null`, a non-boolean, or a permanent evaluation error. Counts as true
    /// for `hidden`, `disabled` and `error` (fail closed) and fails the write
    /// for `set_value`. Carries the `attome-rules` error code when there was
    /// one (never a value).
    Unknown {
        code: Option<&'static str>,
    },
    /// The wall-clock breaker tripped ([`RulesError::is_transient`]): a
    /// blocking policy answers 503, retryable.
    Transient,
}

impl ConditionOutcome {
    pub fn from_result(result: Result<RulesValue, RulesError>) -> Self {
        match result {
            Ok(RulesValue::Bool(true)) => Self::True,
            Ok(RulesValue::Bool(false)) => Self::False,
            Ok(_) => Self::Unknown { code: None },
            Err(e) if e.is_transient() => Self::Transient,
            Err(e) => Self::Unknown {
                code: Some(e.code()),
            },
        }
    }

    /// Whether `hidden`/`disabled`/`error` policies apply (true or unknown).
    pub fn holds_fail_closed(&self) -> bool {
        matches!(self, Self::True | Self::Unknown { .. })
    }
}

/// Validates `tree` against the entity's attributes and compiles it (design
/// §2): shape, depth, leaf count, field eligibility, the operator/type table,
/// value types, choice values present in `options.choices`, and every
/// advanced leaf parsed, restricted to the entity's own eligible fields and
/// typed `bool`. Issue paths start at `condition`.
pub fn compile_condition(
    tree: &ConditionTree,
    attrs: &[AttrInfo],
) -> Result<CompiledCondition, Vec<RuleIssue>> {
    let mut c = Compiler {
        attrs,
        params: Vec::new(),
        issues: Vec::new(),
        leaves: 0,
        fields: BTreeSet::new(),
        has_expression: false,
    };
    let program = c.node(tree, "condition", 0, true);
    if c.leaves > MAX_LEAVES {
        c.issues.push(RuleIssue::new(
            "condition",
            "condition_too_many_leaves",
            format!("a condition may hold at most {MAX_LEAVES} leaves"),
        ));
    }
    if !c.issues.is_empty() {
        return Err(c.issues);
    }
    let schema = with_params_schema(condition_schema(attrs), &c.params);
    let compiled = attome_rules::compile(&program, &schema).map_err(|e| {
        vec![RuleIssue::new(
            "condition",
            e.code(),
            format!("condition does not compile: {e}"),
        )]
    })?;
    if *compiled.result_type() != Type::Bool {
        return Err(vec![RuleIssue::new(
            "condition",
            "expression_not_boolean",
            format!(
                "condition must be a boolean, got {}",
                compiled.result_type()
            ),
        )]);
    }
    Ok(CompiledCondition {
        program,
        params: c.params,
        fields: c.fields,
        has_expression: c.has_expression,
        compiled,
    })
}

/// [`compile_condition`] without keeping the result.
pub fn validate_condition(tree: &ConditionTree, attrs: &[AttrInfo]) -> Result<(), Vec<RuleIssue>> {
    compile_condition(tree, attrs).map(|_| ())
}

struct Compiler<'a> {
    attrs: &'a [AttrInfo],
    params: Vec<ConditionParam>,
    issues: Vec<RuleIssue>,
    leaves: usize,
    fields: BTreeSet<String>,
    has_expression: bool,
}

/// Returned in place of a fragment once an issue is recorded; the program is
/// discarded whenever there is an issue.
const INVALID: &str = "false";

impl Compiler<'_> {
    fn node(&mut self, node: &ConditionTree, path: &str, depth: usize, is_root: bool) -> String {
        match node {
            ConditionTree::All(g) => self.group(&g.all, "all", " and ", path, depth, is_root),
            ConditionTree::Any(g) => self.group(&g.any, "any", " or ", path, depth, is_root),
            ConditionTree::Expression(e) => self.expression(&e.expression, path),
            ConditionTree::Leaf(l) => self.leaf(l, path),
        }
    }

    fn group(
        &mut self,
        children: &[ConditionTree],
        key: &str,
        joiner: &str,
        path: &str,
        depth: usize,
        is_root: bool,
    ) -> String {
        let depth = depth + 1;
        if depth > MAX_TREE_DEPTH {
            self.issues.push(RuleIssue::new(
                path,
                "condition_too_deep",
                format!("groups may nest at most {MAX_TREE_DEPTH} deep"),
            ));
            return INVALID.to_owned();
        }
        if children.is_empty() {
            if is_root && key == "all" {
                return "true".to_owned();
            }
            self.issues.push(RuleIssue::new(
                path,
                "condition_empty_group",
                format!("'{key}' needs at least one condition"),
            ));
            return INVALID.to_owned();
        }
        let parts: Vec<String> = children
            .iter()
            .enumerate()
            .map(|(i, child)| self.node(child, &format!("{path}.{key}[{i}]"), depth, false))
            .collect();
        format!("({})", parts.join(joiner))
    }

    fn expression(&mut self, src: &str, path: &str) -> String {
        self.leaves += 1;
        self.has_expression = true;
        let path = format!("{path}.expression");
        // Parsed on its own first: a source that parses standalone is a
        // complete expression, so wrapping it in parentheses cannot change
        // how its neighbours combine.
        let expr = match attome_rules::parse(src) {
            Ok(e) => e,
            Err(e) => {
                self.issues.push(RuleIssue::new(
                    path,
                    "expression_invalid",
                    format!("expression does not parse: {e}"),
                ));
                return INVALID.to_owned();
            }
        };
        let mut refs = Vec::new();
        collect_field_refs(&expr, &mut refs);
        let before = self.issues.len();
        for (base, hop) in refs {
            if base.starts_with("__") {
                self.issues.push(RuleIssue::new(
                    &path,
                    "expression_reserved_identifier",
                    format!("identifier '{base}' is reserved"),
                ));
                continue;
            }
            if hop.is_some() {
                self.issues.push(RuleIssue::new(
                    &path,
                    "expression_lookup_hop",
                    format!("'{base}.…' reads another record; a condition reads the entity's own fields only"),
                ));
                continue;
            }
            let readable = condition_field_kind(self.attrs, &base).is_ok()
                || self
                    .attrs
                    .iter()
                    .any(|a| a.logicalname == base && a.field_type() == FieldType::RichText);
            if readable {
                self.fields.insert(base);
            } else {
                let (code, message) = condition_field_kind(self.attrs, &base)
                    .err()
                    .unwrap_or(("field_not_eligible", format!("'{base}' cannot be read")));
                self.issues.push(RuleIssue::new(&path, code, message));
            }
        }
        if self.issues.len() > before {
            return INVALID.to_owned();
        }
        format!("({src})")
    }

    fn param(&mut self, value: RulesValue) -> String {
        let name = format!("{PARAM_PREFIX}{}", self.params.len());
        self.params.push(ConditionParam {
            name: name.clone(),
            ty: value.ty(),
            value,
        });
        name
    }

    fn leaf(&mut self, leaf: &ConditionLeaf, path: &str) -> String {
        self.leaves += 1;
        let field = leaf.field.as_str();
        let kind = match condition_field_kind(self.attrs, field) {
            Ok(k) => k,
            Err((code, message)) => {
                self.issues
                    .push(RuleIssue::new(format!("{path}.field"), code, message));
                return INVALID.to_owned();
            }
        };
        if !is_safe_identifier(field) {
            self.issues.push(RuleIssue::new(
                format!("{path}.field"),
                "field_not_eligible",
                format!("'{field}' is not a plain identifier"),
            ));
            return INVALID.to_owned();
        }
        let op = leaf.op;
        if !kind.allows(op) {
            self.issues.push(RuleIssue::new(
                format!("{path}.op"),
                "operator_not_allowed",
                format!(
                    "operator '{}' does not apply to field '{field}'",
                    op.as_str()
                ),
            ));
            return INVALID.to_owned();
        }
        self.fields.insert(field.to_owned());
        let value_path = format!("{path}.value");
        let value = match (op.takes_value(), leaf.value.as_ref()) {
            (false, None) | (false, Some(Value::Null)) => None,
            (false, Some(_)) => {
                self.issues.push(RuleIssue::new(
                    value_path,
                    "value_unexpected",
                    format!("operator '{}' takes no value", op.as_str()),
                ));
                return INVALID.to_owned();
            }
            (true, None) | (true, Some(Value::Null)) => {
                self.issues.push(RuleIssue::new(
                    value_path,
                    "value_missing",
                    format!("operator '{}' needs a value", op.as_str()),
                ));
                return INVALID.to_owned();
            }
            (true, Some(v)) => Some(v),
        };

        let f = field;
        let guard = format!("not is_null({f})");
        let norm = format!("lower(trim({f}))");
        match (kind, op, value) {
            // "Empty" is null, a blank string, or an empty list — the same
            // definition the client interpreter uses.
            (_, BusinessRuleOp::IsEmpty, _) => match kind {
                ConditionFieldKind::Text => format!("(is_null({f}) or trim({f}) == \"\")"),
                ConditionFieldKind::Choice => format!("(is_null({f}) or {f} == \"\")"),
                ConditionFieldKind::MultiChoice => format!("(is_null({f}) or len({f}) == 0)"),
                _ => format!("is_null({f})"),
            },
            (_, BusinessRuleOp::IsNotEmpty, _) => match kind {
                ConditionFieldKind::Text => format!("({guard} and trim({f}) != \"\")"),
                ConditionFieldKind::Choice => format!("({guard} and {f} != \"\")"),
                ConditionFieldKind::MultiChoice => format!("({guard} and len({f}) > 0)"),
                _ => guard,
            },
            (_, _, None) => INVALID.to_owned(),
            (ConditionFieldKind::MultiChoice, BusinessRuleOp::Contains, Some(v)) => {
                let Some(val) = self.scalar(field, kind, v, &value_path) else {
                    return INVALID.to_owned();
                };
                let p = self.param(val);
                format!("({guard} and contains({f}, {p}))")
            }
            (ConditionFieldKind::MultiChoice, BusinessRuleOp::In, Some(v)) => {
                let Some(vals) = self.list(field, kind, v, &value_path) else {
                    return INVALID.to_owned();
                };
                let parts: Vec<String> = vals
                    .into_iter()
                    .map(|val| {
                        let p = self.param(val);
                        format!("contains({f}, {p})")
                    })
                    .collect();
                format!("({guard} and ({}))", parts.join(" or "))
            }
            (_, op, Some(v)) if op.takes_list() => {
                let Some(vals) = self.list(field, kind, v, &value_path) else {
                    return INVALID.to_owned();
                };
                let p = self.param(RulesValue::List(vals));
                let lhs = if kind == ConditionFieldKind::Text {
                    norm
                } else {
                    f.to_owned()
                };
                if op == BusinessRuleOp::In {
                    format!("({guard} and in({lhs}, {p}))")
                } else {
                    format!("(is_null({f}) or not in({lhs}, {p}))")
                }
            }
            (_, op, Some(v)) => {
                let Some(val) = self.scalar(field, kind, v, &value_path) else {
                    return INVALID.to_owned();
                };
                let p = self.param(val);
                let lhs = if kind == ConditionFieldKind::Text {
                    norm
                } else {
                    f.to_owned()
                };
                match op {
                    BusinessRuleOp::Eq => format!("({guard} and {lhs} == {p})"),
                    BusinessRuleOp::Ne => format!("(is_null({f}) or {lhs} != {p})"),
                    BusinessRuleOp::Gt => format!("({guard} and {lhs} > {p})"),
                    BusinessRuleOp::Gte => format!("({guard} and {lhs} >= {p})"),
                    BusinessRuleOp::Lt => format!("({guard} and {lhs} < {p})"),
                    BusinessRuleOp::Lte => format!("({guard} and {lhs} <= {p})"),
                    BusinessRuleOp::Contains => format!("({guard} and contains({lhs}, {p}))"),
                    BusinessRuleOp::StartsWith => {
                        format!("({guard} and startswith({lhs}, {p}))")
                    }
                    // In/NotIn/IsEmpty/IsNotEmpty are handled above.
                    _ => INVALID.to_owned(),
                }
            }
        }
    }

    /// One leaf value of `kind`. Text is normalised (trimmed, lower-cased) the
    /// way the program normalises the field.
    fn scalar(
        &mut self,
        field: &str,
        kind: ConditionFieldKind,
        v: &Value,
        path: &str,
    ) -> Option<RulesValue> {
        let out = match kind {
            ConditionFieldKind::Text => v
                .as_str()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .map(RulesValue::Text),
            ConditionFieldKind::Number => {
                v.as_f64().filter(|n| n.is_finite()).map(RulesValue::Number)
            }
            ConditionFieldKind::Date => v.as_str().and_then(parse_date).map(RulesValue::Date),
            ConditionFieldKind::Bool => v.as_bool().map(RulesValue::Bool),
            ConditionFieldKind::Choice | ConditionFieldKind::MultiChoice => {
                match v.as_str().filter(|s| !s.is_empty()) {
                    Some(s) => {
                        if !self.choice_known(field, path, s) {
                            return None;
                        }
                        Some(RulesValue::Choice(s.to_owned()))
                    }
                    None => None,
                }
            }
            ConditionFieldKind::Lookup => v
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .map(RulesValue::Lookup),
        };
        if out.is_none() {
            self.issues.push(RuleIssue::new(
                path,
                "value_type",
                format!("expected {}", expected_value(kind)),
            ));
        }
        out
    }

    fn list(
        &mut self,
        field: &str,
        kind: ConditionFieldKind,
        v: &Value,
        path: &str,
    ) -> Option<Vec<RulesValue>> {
        let Some(items) = v.as_array().filter(|a| !a.is_empty()) else {
            self.issues.push(RuleIssue::new(
                path,
                "value_type",
                format!("expected a non-empty list of {}", expected_value(kind)),
            ));
            return None;
        };
        if items.len() > MAX_LIST_VALUES {
            self.issues.push(RuleIssue::new(
                path,
                "value_list_too_long",
                format!("a list may hold at most {MAX_LIST_VALUES} values"),
            ));
            return None;
        }
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            out.push(self.scalar(field, kind, item, &format!("{path}[{i}]"))?);
        }
        Some(out)
    }

    /// Whether `value` is one of `field`'s `options.choices` (a field without
    /// a choices list accepts any key). A choice removed later keeps the rule
    /// valid: this runs at authoring only (design §8.3).
    fn choice_known(&mut self, field: &str, path: &str, value: &str) -> bool {
        let choices = self
            .attrs
            .iter()
            .find(|a| a.logicalname == field)
            .and_then(|a| a.options.as_ref())
            .and_then(|o| o.get("choices"))
            .and_then(Value::as_array);
        let Some(choices) = choices else {
            return true;
        };
        if choices.iter().any(|c| c.as_str() == Some(value)) {
            return true;
        }
        self.issues.push(RuleIssue::new(
            path,
            "value_not_a_choice",
            format!("'{value}' is not a choice of field '{field}'"),
        ));
        false
    }
}

fn expected_value(kind: ConditionFieldKind) -> &'static str {
    match kind {
        ConditionFieldKind::Text => "a non-blank string",
        ConditionFieldKind::Number => "a number",
        ConditionFieldKind::Date => "an ISO-8601 date or date-time",
        ConditionFieldKind::Bool => "a boolean",
        ConditionFieldKind::Choice | ConditionFieldKind::MultiChoice => "a choice value",
        ConditionFieldKind::Lookup => "a record id (UUID)",
    }
}

/// Every `(base, hop)` field reference in a parsed expression.
fn collect_field_refs(expr: &Expr, out: &mut Vec<(String, Option<String>)>) {
    match expr {
        Expr::FieldRef(r) => out.push((r.base.clone(), r.hop.clone())),
        Expr::ListLit(items) => items.iter().for_each(|i| collect_field_refs(i, out)),
        Expr::Unary { expr, .. } => collect_field_refs(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_field_refs(lhs, out);
            collect_field_refs(rhs, out);
        }
        Expr::Call { args, .. } => args.iter().for_each(|a| collect_field_refs(a, out)),
        // Z11-T3: a lambda's parameter is not a record field; its body may
        // still read the record's own fields.
        Expr::Lambda { param, body } => {
            let mut inner = Vec::new();
            collect_field_refs(body, &mut inner);
            out.extend(inner.into_iter().filter(|(base, _)| base != param));
        }
        // Z11-T7: a path reads its first segment's lookup and beyond.
        Expr::Path(segments) => {
            if let Some((base, rest)) = segments.split_first() {
                out.push((base.clone(), Some(rest.join("."))));
            }
        }
        Expr::NullLit | Expr::BoolLit(_) | Expr::NumberLit(_) | Expr::StringLit(_) => {}
    }
}

/// A name the generated program can carry as a bare identifier: an ASCII
/// letter, then letters, digits or `_`, and not a grammar keyword.
fn is_safe_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !matches!(name, "and" | "or" | "not" | "true" | "false" | "null")
}

// ── Whole-rule validation ───────────────────────────────────────────────────

/// A business rule body as [`validate_rule`] sees it. Role ids are checked
/// for liveness by the admin route; only their counts matter here.
#[derive(Clone, Copy, Debug)]
pub struct BusinessRuleSpec<'a> {
    pub applies_to: AppliesTo,
    pub staff_role_count: usize,
    pub portal_role_count: usize,
    pub condition: &'a ConditionTree,
    pub policies: &'a [PolicyDef],
    /// A11-T2: the entities, so a value expression may read related
    /// records through lookups; `None` checks it against the record alone.
    pub related: Option<&'a crate::EntityMetaRegistry>,
}

/// The pure checks of design §6.2: audience and role count, the condition
/// ([`compile_condition`]), 1..=[`MAX_POLICIES_PER_RULE`] policies of the
/// shape the table's CHECK requires, policy fields that are attributes of the
/// entity (not system columns), `set_value` never on a formula, a literal or
/// expression that fits its field's type, and no `hidden`/`disabled` policy
/// with an advanced condition leaf or a sensitive condition field. Returns
/// the compiled condition when the rule is valid.
///
/// Not checked here (they need the database or the caller): staff roles
/// live and portal roles existing, the per-entity active-rule limit, and
/// `rule_engine::check_field_read_access` on advanced and `set_value`
/// expressions.
pub fn validate_rule(
    spec: &BusinessRuleSpec<'_>,
    attrs: &[AttrInfo],
) -> Result<CompiledCondition, Vec<RuleIssue>> {
    let mut issues = Vec::new();
    let roles = spec.staff_role_count + spec.portal_role_count;
    match spec.applies_to {
        AppliesTo::All if roles > 0 => issues.push(RuleIssue::new(
            "applies_to",
            "roles_not_allowed",
            "a rule that applies to all users takes no roles",
        )),
        AppliesTo::Roles if roles == 0 => issues.push(RuleIssue::new(
            "applies_to",
            "roles_required",
            "a rule that applies to roles needs at least one role",
        )),
        _ => {}
    }
    if roles > MAX_ROLES_PER_RULE {
        issues.push(RuleIssue::new(
            "role_ids",
            "too_many_roles",
            format!("a rule may name at most {MAX_ROLES_PER_RULE} roles"),
        ));
    }
    if spec.policies.is_empty() {
        issues.push(RuleIssue::new(
            "policies",
            "policies_required",
            "a rule needs at least one policy",
        ));
    }
    if spec.policies.len() > MAX_POLICIES_PER_RULE {
        issues.push(RuleIssue::new(
            "policies",
            "too_many_policies",
            format!("a rule may hold at most {MAX_POLICIES_PER_RULE} policies"),
        ));
    }

    let compiled = match compile_condition(spec.condition, attrs) {
        Ok(c) => Some(c),
        Err(mut e) => {
            issues.append(&mut e);
            None
        }
    };

    let expr_schema = condition_schema(attrs);
    for (i, policy) in spec.policies.iter().enumerate() {
        // A11-T2: a value expression may read related records.
        let schema = match (spec.related, policy.expression.as_deref()) {
            (Some(registry), Some(src)) => std::borrow::Cow::Owned(with_related_schema(
                expr_schema.clone(),
                &related_refs(src, attrs, registry),
            )),
            _ => std::borrow::Cow::Borrowed(&expr_schema),
        };
        check_policy(
            policy,
            &format!("policies[{i}]"),
            attrs,
            &schema,
            &mut issues,
        );
    }

    if spec.policies.iter().any(|p| p.policy_type.is_lock()) {
        if spec.condition.has_expression() {
            issues.push(RuleIssue::new(
                "policies",
                "lock_with_advanced_condition",
                "a rule with an advanced expression in its condition cannot hide or lock fields",
            ));
        }
        if let Some(c) = &compiled {
            for field in &c.fields {
                if attrs
                    .iter()
                    .any(|a| &a.logicalname == field && a.is_read_gated())
                {
                    issues.push(RuleIssue::new(
                        "policies",
                        "lock_with_sensitive_condition",
                        format!(
                            "the condition reads sensitive field '{field}'; a rule that hides or locks fields cannot"
                        ),
                    ));
                }
            }
        }
    }

    match compiled {
        Some(c) if issues.is_empty() => Ok(c),
        _ => Err(issues),
    }
}

fn check_policy(
    policy: &PolicyDef,
    path: &str,
    attrs: &[AttrInfo],
    expr_schema: &Schema,
    issues: &mut Vec<RuleIssue>,
) {
    let type_name = policy.policy_type.as_str();
    let mut forbid = |present: bool, key: &str| {
        if present {
            issues.push(RuleIssue::new(
                format!("{path}.{key}"),
                "policy_shape",
                format!("a {type_name} policy takes no '{key}'"),
            ));
        }
    };
    // A3-T4: only a check that refuses a write is staged, and only an
    // enforced one has a start date.
    if policy.is_staged_type() {
        forbid(
            policy.enforce_from.is_some() && policy.stage != Some(Stage::Enforce),
            "enforce_from",
        );
    } else {
        forbid(policy.stage.is_some(), "stage");
        forbid(policy.enforce_from.is_some(), "enforce_from");
    }
    match policy.policy_type {
        PolicyType::Hidden | PolicyType::Disabled => {
            forbid(policy.message.is_some(), "message");
            forbid(policy.severity.is_some(), "severity");
            forbid(policy.value.is_some(), "value");
            forbid(policy.expression.is_some(), "expression");
            forbid(policy.mode.is_some(), "mode");
        }
        PolicyType::Error => {
            forbid(policy.value.is_some(), "value");
            forbid(policy.expression.is_some(), "expression");
            forbid(policy.mode.is_some(), "mode");
        }
        PolicyType::SetValue => {
            forbid(policy.message.is_some(), "message");
            forbid(policy.severity.is_some(), "severity");
        }
        PolicyType::Required => {
            forbid(policy.severity.is_some(), "severity");
            forbid(policy.value.is_some(), "value");
            forbid(policy.expression.is_some(), "expression");
            forbid(policy.mode.is_some(), "mode");
        }
        PolicyType::AllowedValues => {
            forbid(policy.severity.is_some(), "severity");
            forbid(policy.expression.is_some(), "expression");
            forbid(policy.mode.is_some(), "mode");
        }
        PolicyType::AddTag | PolicyType::RemoveTag => {
            forbid(policy.field.is_some(), "field");
            forbid(policy.message.is_some(), "message");
            forbid(policy.severity.is_some(), "severity");
            forbid(policy.expression.is_some(), "expression");
            forbid(policy.mode.is_some(), "mode");
            let name = policy.value.as_ref().and_then(Value::as_str).map(str::trim);
            if !name.is_some_and(|n| !n.is_empty() && n.chars().count() <= 80) {
                issues.push(RuleIssue::new(
                    format!("{path}.value"),
                    "policy_shape",
                    format!("a {type_name} policy needs a tag name of 1 to 80 characters"),
                ));
            }
            return;
        }
    }

    let field_attr = match policy.field.as_deref() {
        Some(name) => match policy_attr(attrs, name) {
            Ok(a) => Some(a),
            Err((code, message)) => {
                issues.push(RuleIssue::new(format!("{path}.field"), code, message));
                return;
            }
        },
        None if policy.policy_type == PolicyType::Error => None,
        None => {
            issues.push(RuleIssue::new(
                format!("{path}.field"),
                "policy_shape",
                format!("a {type_name} policy needs a field"),
            ));
            return;
        }
    };

    match policy.policy_type {
        // Checked, and returned from, above.
        PolicyType::AddTag | PolicyType::RemoveTag => {}
        PolicyType::Hidden | PolicyType::Disabled => {}
        PolicyType::Error => {
            if policy.severity.is_none() {
                issues.push(RuleIssue::new(
                    format!("{path}.severity"),
                    "policy_shape",
                    "an error policy needs a severity ('error' or 'warning')",
                ));
            }
            if policy
                .message
                .as_deref()
                .is_some_and(|m| m.chars().count() > MAX_POLICY_MESSAGE_CHARS)
            {
                issues.push(RuleIssue::new(
                    format!("{path}.message"),
                    "message_too_long",
                    format!("a message may hold at most {MAX_POLICY_MESSAGE_CHARS} characters"),
                ));
            }
        }
        PolicyType::SetValue => {
            if let Some(attr) = field_attr {
                check_set_value(policy, path, attr, expr_schema, issues);
            }
        }
        PolicyType::Required | PolicyType::AllowedValues => {
            if policy
                .message
                .as_deref()
                .is_some_and(|m| m.chars().count() > MAX_POLICY_MESSAGE_CHARS)
            {
                issues.push(RuleIssue::new(
                    format!("{path}.message"),
                    "message_too_long",
                    format!("a message may hold at most {MAX_POLICY_MESSAGE_CHARS} characters"),
                ));
            }
            if policy.policy_type == PolicyType::AllowedValues {
                let codes = policy.value.as_ref().and_then(Value::as_array);
                let well_formed = codes.is_some_and(|c| {
                    !c.is_empty()
                        && c.len() <= MAX_ALLOWED_VALUES
                        && c.iter().all(|v| v.is_string() || v.is_number())
                });
                if !well_formed {
                    issues.push(RuleIssue::new(
                        format!("{path}.value"),
                        "policy_shape",
                        format!(
                            "an allowed_values policy needs a list of 1 to {MAX_ALLOWED_VALUES} codes"
                        ),
                    ));
                }
            }
        }
    }
}

/// The most codes one `allowed_values` policy lists.
pub const MAX_ALLOWED_VALUES: usize = 500;

fn policy_attr<'a>(
    attrs: &'a [AttrInfo],
    name: &str,
) -> Result<&'a AttrInfo, (&'static str, String)> {
    if crate::ALL_SYSTEM_COLS.contains(&name) {
        return Err((
            "field_not_eligible",
            format!("system column '{name}' cannot carry a policy"),
        ));
    }
    attrs.iter().find(|a| a.logicalname == name).ok_or_else(|| {
        (
            "field_unknown",
            format!("'{name}' is not a field of this entity"),
        )
    })
}

fn check_set_value(
    policy: &PolicyDef,
    path: &str,
    attr: &AttrInfo,
    expr_schema: &Schema,
    issues: &mut Vec<RuleIssue>,
) {
    let field = attr.logicalname.as_str();
    if policy.mode.is_none() {
        issues.push(RuleIssue::new(
            format!("{path}.mode"),
            "policy_shape",
            "a set_value policy needs a mode ('always' or 'default')",
        ));
    }
    if attr.is_computed() {
        issues.push(RuleIssue::new(
            format!("{path}.field"),
            "set_value_formula",
            format!("'{field}' is a formula or rollup field and is always computed"),
        ));
        return;
    }
    let Some(kind) = ConditionFieldKind::of_attr(attr) else {
        issues.push(RuleIssue::new(
            format!("{path}.field"),
            "field_not_eligible",
            format!(
                "a set_value policy cannot target a {} field",
                attr.field_type().as_str()
            ),
        ));
        return;
    };
    match (&policy.value, &policy.expression) {
        (Some(v), None) => {
            if !literal_fits(attr, kind, v) {
                issues.push(RuleIssue::new(
                    format!("{path}.value"),
                    "value_type",
                    format!("the value does not fit field '{field}'"),
                ));
            }
        }
        (None, Some(src)) => match attome_rules::compile(src, expr_schema) {
            Ok(compiled) => {
                let target = kind.rules_type();
                let produced = compiled.result_type();
                let fits = produced.unify(&target).is_some()
                    || matches!(
                        (produced, &target),
                        (Type::Choice, Type::Text) | (Type::Text, Type::Choice)
                    );
                if !fits {
                    issues.push(RuleIssue::new(
                        format!("{path}.expression"),
                        "expression_type",
                        format!("the expression produces {produced} but '{field}' holds {target}"),
                    ));
                }
            }
            Err(e) => issues.push(RuleIssue::new(
                format!("{path}.expression"),
                e.code(),
                format!("expression does not compile: {e}"),
            )),
        },
        _ => issues.push(RuleIssue::new(
            path,
            "policy_shape",
            "a set_value policy needs exactly one of 'value' and 'expression'",
        )),
    }
}

fn literal_fits(attr: &AttrInfo, kind: ConditionFieldKind, v: &Value) -> bool {
    let choices: Option<Vec<&str>> = attr
        .options
        .as_ref()
        .and_then(|o| o.get("choices"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect());
    let choice_ok = |s: &str| choices.as_ref().is_none_or(|c| c.contains(&s));
    match kind {
        ConditionFieldKind::Text => v.is_string(),
        ConditionFieldKind::Number => v.as_f64().is_some_and(f64::is_finite),
        ConditionFieldKind::Date => v.as_str().and_then(parse_date).is_some(),
        ConditionFieldKind::Bool => v.is_boolean(),
        ConditionFieldKind::Choice => v.as_str().is_some_and(choice_ok),
        ConditionFieldKind::MultiChoice => v
            .as_array()
            .is_some_and(|a| a.iter().all(|i| i.as_str().is_some_and(choice_ok))),
        ConditionFieldKind::Lookup => v.as_str().is_some_and(|s| Uuid::parse_str(s).is_ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attr(name: &str, ty: &str, options: Option<Value>) -> AttrInfo {
        let field_type_int = FieldType::try_from(ty).expect("field type").to_int();
        serde_json::from_value(json!({
            "logicalname": name,
            "field_type_int": field_type_int,
            "is_sensitive": false,
            "is_sortable": false,
            "is_filterable": false,
            "options": options,
        }))
        .expect("AttrInfo")
    }

    fn lookup(name: &str, target: Uuid) -> AttrInfo {
        let mut a = attr(name, "lookup", None);
        a.lookup_entity_ref = Some(target);
        a
    }

    #[test]
    fn rule_related_refs_resolve_through_lookups() {
        let user = Uuid::now_v7();
        let account = Uuid::now_v7();
        let meta = |id: Uuid, name: &str, attrs: Vec<AttrInfo>| crate::EntityMeta {
            entity_id: id,
            logicalname: name.to_owned(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        };
        let registry = crate::EntityMetaRegistry::from_entities(vec![
            meta(user, "app_user", vec![attr("region", "text", None)]),
            meta(
                account,
                "account",
                vec![attr("name", "text", None), lookup("owner", user)],
            ),
        ]);
        let deal = vec![lookup("account", account), attr("amount", "number", None)];
        let src = "account.name + \" / \" + account.owner.region";
        let refs = related_refs(src, &deal, &registry);
        assert_eq!(refs.len(), 2, "{refs:?}");
        assert_eq!(refs[0].segments, vec!["account", "name"]);
        assert_eq!(refs[0].entities, vec!["account"]);
        assert_eq!(refs[1].segments, vec!["account", "owner", "region"]);
        assert_eq!(refs[1].entities, vec!["account", "app_user"]);
        let schema = with_related_schema(condition_schema(&deal), &refs);
        assert!(attome_rules::compile(src, &schema).is_ok());
        // A field that is not a lookup, and an unknown field, resolve to nothing.
        assert!(related_refs("amount.x", &deal, &registry).is_empty());
        assert!(related_refs("account.missing", &deal, &registry).is_empty());
    }

    fn attrs() -> Vec<AttrInfo> {
        vec![
            attr("title", "text", None),
            attr("amount", "number", None),
            attr("due", "date", None),
            attr("is_vip", "bool", None),
            attr(
                "status",
                "choice",
                Some(json!({ "choices": ["open", "pending", "closed"], "multi": false })),
            ),
            attr(
                "tags",
                "choice",
                Some(json!({ "choices": ["a", "b", "c"], "multi": true })),
            ),
            attr("account", "lookup", None),
            attr("notes", "rich_text", None),
            attr("photo", "image", None),
            attr(
                "total",
                "formula",
                Some(json!({ "result_type": "number", "expression": "amount * 2" })),
            ),
        ]
    }

    fn tree(v: Value) -> ConditionTree {
        serde_json::from_value(v).expect("condition tree")
    }

    fn codes(issues: &[RuleIssue]) -> Vec<&str> {
        issues.iter().map(|i| i.code.as_str()).collect()
    }

    fn record(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().cloned().expect("record object")
    }

    // ── Conformance fixture (shared with the Angular interpreter) ──────────

    const CONFORMANCE: &str = include_str!("../../../../schemas/business-rules-conformance.json");

    #[test]
    fn conformance_fixture_matches_compile_and_base_rules() {
        let fixture: Value = serde_json::from_str(CONFORMANCE).expect("fixture parses");
        let fields: Vec<AttrInfo> = fixture["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|f| {
                let name = f["name"].as_str().expect("name");
                let ty = f["type"].as_str().expect("type");
                let mut options = serde_json::Map::new();
                if let Some(c) = f.get("choices") {
                    options.insert("choices".into(), c.clone());
                }
                if let Some(m) = f.get("multi") {
                    options.insert("multi".into(), m.clone());
                }
                if let Some(r) = f.get("result_type") {
                    options.insert("result_type".into(), r.clone());
                    options.insert("expression".into(), json!("1"));
                }
                attr(
                    name,
                    ty,
                    (!options.is_empty()).then_some(Value::Object(options)),
                )
            })
            .collect();
        let cases = fixture["cases"].as_array().expect("cases");
        assert!(cases.len() >= 50, "the fixture should stay broad");
        let now = Utc::now();
        for case in cases {
            let name = case["name"].as_str().expect("case name");
            let condition: ConditionTree =
                serde_json::from_value(case["condition"].clone()).expect(name);
            let compiled = compile_condition(&condition, &fields)
                .unwrap_or_else(|e| panic!("{name}: does not compile: {e:?}"));
            let outcome = compiled.evaluate(&fields, &record(case["record"].clone()), now);
            let expected = if case["expected"].as_bool().expect("expected") {
                ConditionOutcome::True
            } else {
                ConditionOutcome::False
            };
            assert_eq!(outcome, expected, "{name}: program {}", compiled.program);
        }
    }

    // ── Parameters, never program text ─────────────────────────────────────

    #[test]
    fn leaf_values_are_parameters_never_program_text() {
        let hostile = "x\") or true or (\"";
        let t = tree(json!({ "all": [
            { "field": "title", "op": "eq", "value": hostile },
            { "field": "title", "op": "in", "value": ["zz_marker_one", "zz_marker_two"] },
            { "field": "amount", "op": "gt", "value": 987654 },
            { "field": "account", "op": "eq", "value": "0192a4b0-0000-7000-8000-00000000abcd" },
        ]}));
        let c = compile_condition(&t, &attrs()).expect("compiles");
        for needle in ["zz_marker", "987654", "abcd", "or true"] {
            assert!(
                !c.program.contains(needle),
                "'{needle}' leaked into {}",
                c.program
            );
        }
        assert_eq!(c.params.len(), 4);
        assert!(c.params.iter().all(|p| p.name.starts_with(PARAM_PREFIX)));
        // The hostile text is compared as data: the condition is false for
        // an ordinary record instead of the injected `or true`.
        let out = c.evaluate(
            &attrs(),
            &record(json!({ "title": "zz_marker_one", "amount": 1 })),
            Utc::now(),
        );
        assert_eq!(out, ConditionOutcome::False);
        assert_eq!(
            c.params[1].value,
            RulesValue::List(vec![
                RulesValue::Text("zz_marker_one".into()),
                RulesValue::Text("zz_marker_two".into())
            ])
        );
        assert_eq!(
            c.params[3].value,
            RulesValue::Lookup(Uuid::parse_str("0192a4b0-0000-7000-8000-00000000abcd").unwrap())
        );
    }

    #[test]
    fn an_advanced_leaf_cannot_break_out_of_its_parentheses() {
        let t = tree(json!({ "all": [
            { "field": "amount", "op": "gt", "value": 1 },
            { "expression": "true) or (true" },
        ]}));
        let issues = compile_condition(&t, &attrs()).unwrap_err();
        assert_eq!(codes(&issues), vec!["expression_invalid"]);
    }

    #[test]
    fn advanced_leaf_rules() {
        let a = attrs();
        let ok = tree(json!({ "any": [
            { "expression": "amount > 10 and contains(tags, \"a\")" },
            { "field": "status", "op": "eq", "value": "open" },
        ]}));
        let c = compile_condition(&ok, &a).expect("compiles");
        assert!(c.has_expression);
        assert!(c.fields.contains("amount") && c.fields.contains("tags"));

        let reserved = tree(json!({ "expression": "__p0 == 1" }));
        assert_eq!(
            codes(&compile_condition(&reserved, &a).unwrap_err()),
            vec!["expression_reserved_identifier"]
        );
        let hop = tree(json!({ "expression": "account.name == \"x\"" }));
        assert_eq!(
            codes(&compile_condition(&hop, &a).unwrap_err()),
            vec!["expression_lookup_hop"]
        );
        let not_bool = tree(json!({ "expression": "amount + 1" }));
        assert_eq!(
            codes(&compile_condition(&not_bool, &a).unwrap_err()),
            vec!["expression_not_boolean"]
        );
        let unknown = tree(json!({ "expression": "nope > 1" }));
        assert_eq!(
            codes(&compile_condition(&unknown, &a).unwrap_err()),
            vec!["field_unknown"]
        );
        let system = tree(json!({ "expression": "is_null(created_at)" }));
        assert_eq!(
            codes(&compile_condition(&system, &a).unwrap_err()),
            vec!["field_not_eligible"]
        );
    }

    // ── Tree validation ────────────────────────────────────────────────────

    #[test]
    fn tree_shape_limits() {
        let a = attrs();
        let leaf = json!({ "field": "amount", "op": "gt", "value": 1 });
        // Depth 4 is fine, 5 is not.
        let depth4 = tree(json!({ "all": [ { "any": [ { "all": [ { "any": [ leaf ] } ] } ] } ] }));
        assert!(compile_condition(&depth4, &a).is_ok());
        let depth5 = tree(
            json!({ "all": [ { "any": [ { "all": [ { "any": [ { "all": [ leaf ] } ] } ] } ] } ] }),
        );
        assert_eq!(
            codes(&compile_condition(&depth5, &a).unwrap_err()),
            vec!["condition_too_deep"]
        );
        let many = tree(json!({ "any": vec![leaf.clone(); MAX_LEAVES + 1] }));
        assert_eq!(
            codes(&compile_condition(&many, &a).unwrap_err()),
            vec!["condition_too_many_leaves"]
        );
        let empty_any = tree(json!({ "any": [] }));
        assert_eq!(
            codes(&compile_condition(&empty_any, &a).unwrap_err()),
            vec!["condition_empty_group"]
        );
        let nested_empty = tree(json!({ "all": [ { "all": [] } ] }));
        assert_eq!(
            codes(&compile_condition(&nested_empty, &a).unwrap_err()),
            vec!["condition_empty_group"]
        );
        assert!(ConditionTree::always().is_always());
    }

    #[test]
    fn unknown_keys_and_mixed_nodes_do_not_deserialize() {
        for bad in [
            json!({ "all": [], "any": [] }),
            json!({ "field": "amount", "op": "gt", "value": 1, "extra": true }),
            json!({ "field": "amount", "op": "regex", "value": "x" }),
            json!({ "expression": "true", "field": "amount" }),
            json!([]),
        ] {
            assert!(
                serde_json::from_value::<ConditionTree>(bad.clone()).is_err(),
                "{bad} should be refused"
            );
        }
        let t = tree(json!({ "any": [ { "field": "amount", "op": "is_empty" }, { "all": [] } ] }));
        assert_eq!(
            serde_json::to_value(&t).unwrap(),
            json!({ "any": [ { "field": "amount", "op": "is_empty" }, { "all": [] } ] })
        );
    }

    #[test]
    fn operator_and_value_table() {
        let a = attrs();
        let issue = |v: Value| codes(&compile_condition(&tree(v), &a).unwrap_err()).join(",");
        assert_eq!(
            issue(json!({ "field": "amount", "op": "contains", "value": 1 })),
            "operator_not_allowed"
        );
        assert_eq!(
            issue(json!({ "field": "is_vip", "op": "ne", "value": true })),
            "operator_not_allowed"
        );
        assert_eq!(
            issue(json!({ "field": "due", "op": "in", "value": ["2026-01-01"] })),
            "operator_not_allowed"
        );
        assert_eq!(
            issue(json!({ "field": "tags", "op": "eq", "value": "a" })),
            "operator_not_allowed"
        );
        assert_eq!(
            issue(json!({ "field": "amount", "op": "gt", "value": "10" })),
            "value_type"
        );
        assert_eq!(
            issue(json!({ "field": "amount", "op": "gt" })),
            "value_missing"
        );
        assert_eq!(
            issue(json!({ "field": "amount", "op": "is_empty", "value": 1 })),
            "value_unexpected"
        );
        assert_eq!(
            issue(json!({ "field": "status", "op": "eq", "value": "archived" })),
            "value_not_a_choice"
        );
        assert_eq!(
            issue(json!({ "field": "tags", "op": "in", "value": [] })),
            "value_type"
        );
        assert_eq!(
            issue(json!({ "field": "title", "op": "eq", "value": "   " })),
            "value_type"
        );
        assert_eq!(
            issue(json!({ "field": "account", "op": "eq", "value": "not-a-uuid" })),
            "value_type"
        );
        assert_eq!(
            issue(json!({ "field": "amount", "op": "in", "value": vec![1; MAX_LIST_VALUES + 1] })),
            "value_list_too_long"
        );
        assert_eq!(
            issue(json!({ "field": "notes", "op": "is_empty" })),
            "field_not_eligible"
        );
        assert_eq!(
            issue(json!({ "field": "photo", "op": "is_empty" })),
            "field_not_eligible"
        );
        assert_eq!(
            issue(json!({ "field": "created_at", "op": "is_empty" })),
            "field_not_eligible"
        );
        assert_eq!(
            issue(json!({ "field": "missing", "op": "is_empty" })),
            "field_unknown"
        );
        assert!(
            compile_condition(
                &tree(json!({ "field": "organization_ref", "op": "is_not_empty" })),
                &a
            )
            .is_ok()
        );
    }

    // ── Outcomes ───────────────────────────────────────────────────────────

    #[test]
    fn outcome_is_tri_state_and_transient_is_separate() {
        assert_eq!(
            ConditionOutcome::from_result(Ok(RulesValue::Bool(true))),
            ConditionOutcome::True
        );
        assert_eq!(
            ConditionOutcome::from_result(Ok(RulesValue::Null)),
            ConditionOutcome::Unknown { code: None }
        );
        assert_eq!(
            ConditionOutcome::from_result(Err(RulesError::DivideByZero)),
            ConditionOutcome::Unknown {
                code: Some("rules.eval.divide_by_zero")
            }
        );
        assert_eq!(
            ConditionOutcome::from_result(Err(RulesError::Budget(
                attome_rules::BudgetKind::WallClock
            ))),
            ConditionOutcome::Transient
        );
        assert!(ConditionOutcome::Unknown { code: None }.holds_fail_closed());
        assert!(!ConditionOutcome::False.holds_fail_closed());
    }

    fn rule(name: &str, applies_to: AppliesTo, policies: Vec<PolicyDef>) -> BusinessRuleDef {
        BusinessRuleDef {
            id: Uuid::now_v7(),
            entity_logicalname: "support_case".into(),
            name: name.into(),
            display_name: None,
            is_active: true,
            display_order: 0,
            version: 1,
            row_version: 0,
            applies_to,
            role_ids: Vec::new(),
            portal_role_ids: Vec::new(),
            condition: ConditionTree::always(),
            policies,
        }
    }

    fn lock(field: &str, ty: PolicyType) -> PolicyDef {
        PolicyDef {
            policy_type: ty,
            field: Some(field.into()),
            message: None,
            severity: None,
            value: None,
            expression: None,
            mode: None,
            stage: None,
            enforce_from: None,
            ordinal: 0,
        }
    }

    fn error_policy() -> PolicyDef {
        PolicyDef {
            policy_type: PolicyType::Error,
            field: None,
            message: Some("no".into()),
            severity: Some(Severity::Error),
            value: None,
            expression: None,
            mode: None,
            stage: None,
            enforce_from: None,
            ordinal: 1,
        }
    }

    #[test]
    fn most_restrictive_lock_wins() {
        let a = rule(
            "a",
            AppliesTo::All,
            vec![
                lock("amount", PolicyType::Disabled),
                lock("title", PolicyType::Hidden),
            ],
        );
        let b = rule(
            "b",
            AppliesTo::All,
            vec![
                lock("amount", PolicyType::Hidden),
                lock("title", PolicyType::Disabled),
                lock("due", PolicyType::Disabled),
            ],
        );
        let c = rule("c", AppliesTo::All, vec![lock("due", PolicyType::Disabled)]);
        let locks = combine_locks([&a, &b, &c]);
        assert_eq!(locks["amount"].effect, LockEffect::Hidden);
        assert_eq!(locks["amount"].rule_name, "b");
        assert_eq!(locks["title"].effect, LockEffect::Hidden);
        assert_eq!(locks["title"].rule_name, "a");
        // Equal effects: the first rule names the lock.
        assert_eq!(locks["due"].rule_name, "b");
        assert!(LockEffect::Hidden > LockEffect::Disabled);
    }

    #[test]
    fn audience_decides_which_policies_bind() {
        let staff_role = Uuid::now_v7();
        let other_role = Uuid::now_v7();
        let portal_role = Uuid::now_v7();
        let all = rule(
            "all",
            AppliesTo::All,
            vec![lock("amount", PolicyType::Disabled), error_policy()],
        );
        let mut scoped = rule(
            "scoped",
            AppliesTo::Roles,
            vec![lock("amount", PolicyType::Hidden), error_policy()],
        );
        scoped.role_ids = vec![staff_role];
        scoped.portal_role_ids = vec![portal_role];

        let held = [staff_role];
        let not_held = [other_role];
        let user = RuleAudience::Staff {
            role_ids: &held,
            interactive: true,
        };
        let service = RuleAudience::Staff {
            role_ids: &held,
            interactive: false,
        };
        let outsider = RuleAudience::Staff {
            role_ids: &not_held,
            interactive: true,
        };
        let portal = RuleAudience::Portal {
            role_id: portal_role,
        };
        let other_portal = RuleAudience::Portal {
            role_id: other_role,
        };
        let system = RuleAudience::System;

        let count = |r: &BusinessRuleDef, aud: &RuleAudience<'_>| r.policies_for(aud).count();
        assert_eq!(count(&all, &user), 2);
        assert_eq!(count(&all, &service), 1, "API-key/S2S skip locks (D-791)");
        assert_eq!(count(&all, &system), 1, "system contexts skip locks");
        assert_eq!(count(&all, &portal), 2);
        assert_eq!(count(&scoped, &user), 2);
        assert_eq!(count(&scoped, &service), 1);
        assert_eq!(count(&scoped, &outsider), 0);
        assert_eq!(count(&scoped, &portal), 2);
        assert_eq!(count(&scoped, &other_portal), 0);
        assert_eq!(
            count(&scoped, &system),
            0,
            "role rules never bind a system context"
        );

        let mut inactive = all.clone();
        inactive.is_active = false;
        assert_eq!(count(&inactive, &user), 0);
    }

    // ── Whole-rule validation ──────────────────────────────────────────────

    fn spec<'a>(
        applies_to: AppliesTo,
        roles: usize,
        condition: &'a ConditionTree,
        policies: &'a [PolicyDef],
    ) -> BusinessRuleSpec<'a> {
        BusinessRuleSpec {
            applies_to,
            staff_role_count: roles,
            portal_role_count: 0,
            condition,
            policies,
            related: None,
        }
    }

    #[test]
    fn rule_outcomes_required_and_allowed_values_have_typed_effects() {
        let required = PolicyDef {
            policy_type: PolicyType::Required,
            field: Some("amount".into()),
            message: Some("Amount is needed for large deals".into()),
            severity: None,
            value: None,
            expression: None,
            mode: None,
            stage: None,
            enforce_from: None,
            ordinal: 0,
        };
        assert_eq!(
            required.effect(),
            Some(PolicyEffect::Required {
                field: "amount",
                message: Some("Amount is needed for large deals"),
            })
        );
        let codes = serde_json::json!(["open", 2]);
        let allowed = PolicyDef {
            policy_type: PolicyType::AllowedValues,
            field: Some("status".into()),
            message: None,
            severity: None,
            value: Some(codes.clone()),
            expression: None,
            mode: None,
            stage: None,
            enforce_from: None,
            ordinal: 1,
        };
        let Some(PolicyEffect::AllowedValues { field, values, .. }) = allowed.effect() else {
            panic!("allowed_values has an effect");
        };
        assert_eq!(field, "status");
        assert!(value_allowed(Some(&serde_json::json!("open")), values));
        assert!(value_allowed(Some(&serde_json::json!("2")), values));
        assert!(value_allowed(Some(&serde_json::json!(["open", 2])), values));
        assert!(value_allowed(None, values));
        assert!(!value_allowed(Some(&serde_json::json!("closed")), values));
        assert!(!value_allowed(
            Some(&serde_json::json!(["open", "closed"])),
            values
        ));
        assert_eq!(
            PolicyType::parse("allowed_values"),
            Some(PolicyType::AllowedValues)
        );
        assert_eq!(PolicyType::Required.as_str(), "required");
    }

    #[test]
    fn validate_rule_accepts_a_well_formed_rule() {
        let cond = tree(json!({ "field": "status", "op": "eq", "value": "closed" }));
        let policies = vec![
            lock("amount", PolicyType::Disabled),
            error_policy(),
            PolicyDef {
                policy_type: PolicyType::SetValue,
                field: Some("title".into()),
                message: None,
                severity: None,
                value: Some(json!("Closed")),
                expression: None,
                mode: Some(SetMode::Always),
                stage: None,
                enforce_from: None,
                ordinal: 2,
            },
            PolicyDef {
                policy_type: PolicyType::SetValue,
                field: Some("amount".into()),
                message: None,
                severity: None,
                value: None,
                expression: Some("coalesce(amount, 0) + 1".into()),
                mode: Some(SetMode::Default),
                stage: None,
                enforce_from: None,
                ordinal: 3,
            },
        ];
        validate_rule(&spec(AppliesTo::Roles, 1, &cond, &policies), &attrs()).expect("valid rule");
    }

    #[test]
    fn validate_rule_refusals() {
        let a = attrs();
        let cond = ConditionTree::always();
        let refused = |s: BusinessRuleSpec<'_>| {
            let issues = validate_rule(&s, &a).unwrap_err();
            codes(&issues).join(",")
        };
        let one_lock = [lock("amount", PolicyType::Hidden)];
        assert_eq!(
            refused(spec(AppliesTo::Roles, 0, &cond, &one_lock)),
            "roles_required"
        );
        assert_eq!(
            refused(spec(AppliesTo::All, 2, &cond, &one_lock)),
            "roles_not_allowed"
        );
        assert_eq!(
            refused(spec(AppliesTo::All, 0, &cond, &[])),
            "policies_required"
        );

        let advanced = tree(json!({ "expression": "amount > 1" }));
        assert_eq!(
            refused(spec(AppliesTo::All, 0, &advanced, &one_lock)),
            "lock_with_advanced_condition"
        );
        let mut sensitive_attrs = a.clone();
        if let Some(amount) = sensitive_attrs
            .iter_mut()
            .find(|x| x.logicalname == "amount")
        {
            amount.is_sensitive = true;
        }
        let on_amount = tree(json!({ "field": "amount", "op": "gt", "value": 1 }));
        let title_lock = [lock("title", PolicyType::Disabled)];
        assert_eq!(
            codes(
                &validate_rule(
                    &spec(AppliesTo::All, 0, &on_amount, &title_lock),
                    &sensitive_attrs
                )
                .unwrap_err()
            ),
            vec!["lock_with_sensitive_condition"]
        );

        let bad_shape = [PolicyDef {
            message: Some("x".into()),
            ..lock("amount", PolicyType::Hidden)
        }];
        assert_eq!(
            refused(spec(AppliesTo::All, 0, &cond, &bad_shape)),
            "policy_shape"
        );
        let no_field = [PolicyDef {
            field: None,
            ..lock("amount", PolicyType::Hidden)
        }];
        assert_eq!(
            refused(spec(AppliesTo::All, 0, &cond, &no_field)),
            "policy_shape"
        );
        let system_field = [lock("modified_at", PolicyType::Hidden)];
        assert_eq!(
            refused(spec(AppliesTo::All, 0, &cond, &system_field)),
            "field_not_eligible"
        );
        let no_severity = [PolicyDef {
            severity: None,
            ..error_policy()
        }];
        assert_eq!(
            refused(spec(AppliesTo::All, 0, &cond, &no_severity)),
            "policy_shape"
        );
        let set = |field: &str, value: Option<Value>, expression: Option<&str>| PolicyDef {
            policy_type: PolicyType::SetValue,
            field: Some(field.into()),
            message: None,
            severity: None,
            value,
            expression: expression.map(str::to_owned),
            mode: Some(SetMode::Always),
            stage: None,
            enforce_from: None,
            ordinal: 0,
        };
        assert_eq!(
            refused(spec(
                AppliesTo::All,
                0,
                &cond,
                &[set("total", Some(json!(1)), None)]
            )),
            "set_value_formula"
        );
        assert_eq!(
            refused(spec(
                AppliesTo::All,
                0,
                &cond,
                &[set("amount", Some(json!("x")), None)]
            )),
            "value_type"
        );
        assert_eq!(
            refused(spec(
                AppliesTo::All,
                0,
                &cond,
                &[set("status", Some(json!("gone")), None)]
            )),
            "value_type"
        );
        assert_eq!(
            refused(spec(
                AppliesTo::All,
                0,
                &cond,
                &[set("amount", None, Some("\"text\""))]
            )),
            "expression_type"
        );
        assert_eq!(
            refused(spec(
                AppliesTo::All,
                0,
                &cond,
                &[set("amount", Some(json!(1)), Some("1"))]
            )),
            "policy_shape"
        );
        assert_eq!(
            refused(spec(
                AppliesTo::All,
                0,
                &cond,
                &[set("photo", Some(json!("k")), None)]
            )),
            "field_not_eligible"
        );
    }

    #[test]
    fn policy_wire_shape_round_trips() {
        let p: PolicyDef = serde_json::from_value(json!({
            "type": "error", "message": "m", "severity": "warning", "field": "amount"
        }))
        .expect("policy");
        assert_eq!(
            p.effect(),
            Some(PolicyEffect::Error {
                field: Some("amount"),
                message: Some("m"),
                severity: Severity::Warning
            })
        );
        assert!(!Severity::Warning.blocks());
        assert!(Severity::Error.blocks());
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!({ "type": "error", "message": "m", "severity": "warning", "field": "amount" })
        );
        assert!(
            serde_json::from_value::<PolicyDef>(json!({ "type": "hidden", "field": "a", "x": 1 }))
                .is_err()
        );
    }

    /// A3-T4: an unstaged check follows its severity; a staged one its stage,
    /// and an enforced one warns before its date.
    #[test]
    fn enforcement_follows_stage_and_date() {
        let day = |d: &str| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").expect("date");
        let policy = |extra: Value| {
            let mut v = json!({"type": "required", "field": "status"});
            if let (Some(v), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
                v.extend(extra.clone());
            }
            serde_json::from_value::<PolicyDef>(v).expect("policy")
        };
        let today = day("2026-10-15");
        assert_eq!(
            policy(json!({})).enforcement(Severity::Error, today),
            Enforcement::Enforce
        );
        assert_eq!(
            policy(json!({})).enforcement(Severity::Warning, today),
            Enforcement::Warn
        );
        assert_eq!(
            policy(json!({"stage": "report"})).enforcement(Severity::Error, today),
            Enforcement::Report
        );
        assert_eq!(
            policy(json!({"stage": "warn"})).enforcement(Severity::Error, today),
            Enforcement::Warn
        );
        let from = |d: &str| policy(json!({"stage": "enforce", "enforce_from": d}));
        assert_eq!(
            from("2026-10-16").enforcement(Severity::Error, today),
            Enforcement::Warn
        );
        assert_eq!(
            from("2026-10-15").enforcement(Severity::Error, today),
            Enforcement::Enforce
        );
        assert!(policy(json!({"stage": "warn"})).is_staged_type());
    }

    /// A recursive schema must not expand inline forever (see
    /// `attome-dashboard`'s `building_the_fragment_terminates`).
    #[test]
    fn condition_schema_generation_terminates() {
        use utoipa::PartialSchema;
        let schema = serde_json::to_string(&ConditionTree::schema()).expect("schema");
        assert!(schema.contains("ConditionAll") || schema.contains("oneOf"));
    }

    fn policy(kind: PolicyType, field: &str) -> PolicyDef {
        PolicyDef {
            policy_type: kind,
            field: Some(field.into()),
            message: None,
            severity: None,
            value: None,
            expression: None,
            mode: None,
            stage: None,
            enforce_from: None,
            ordinal: 0,
        }
    }

    fn eq(field: &str, value: &str) -> ConditionTree {
        ConditionTree::Leaf(ConditionLeaf {
            field: field.into(),
            op: BusinessRuleOp::Eq,
            value: Some(serde_json::json!(value)),
        })
    }

    #[test]
    fn conflicting_rules_are_found_and_exclusive_conditions_are_not() {
        let required = [policy(PolicyType::Required, "amount")];
        let hidden = [policy(PolicyType::Hidden, "amount")];
        let open = eq("status", "open");
        let closed = eq("status", "closed");
        let found = conflicts_between(&open, &required, &open, &hidden, false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, "required_and_hidden");
        // status = open and status = closed never hold together.
        assert!(conflicts_between(&open, &required, &closed, &hidden, false).is_empty());
        assert!(!may_overlap(&open, &closed));
        assert!(may_overlap(&open, &ConditionTree::always()));

        let set = [policy(PolicyType::SetValue, "stage")];
        let found = conflicts_between(&open, &set, &ConditionTree::always(), &set, false);
        assert_eq!(found[0].code, "two_set_values");

        // One rule requiring and hiding the same field conflicts with itself.
        let both = [
            policy(PolicyType::Required, "amount"),
            policy(PolicyType::Hidden, "amount"),
        ];
        assert_eq!(conflicts_between(&open, &both, &open, &both, true).len(), 1);
    }
}
