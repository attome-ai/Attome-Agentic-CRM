//! `Context` — the caller-resolved input to `Compiled::eval`, and `Schema` —
//! the caller-declared field types `compile` type-checks a rule against.
//!
//! **BRU-C4 (D-399 ruling 4, amended by this plan's BRU-D4).** A Context
//! optionally carries the caller's IANA time zone (UTC by default, so every
//! existing caller is unchanged). today() is local midnight converted to UTC,
//! and date_add/date_diff by months/years read local calendar fields;
//! day/hour/minute arithmetic stays an exact duration. Which zone a caller
//! picks is the caller's decision: the organisation default for entity rules,
//! the event's zone for event filters, UTC for TRD (BRU-D4).
//!
//! Both are deliberately dumb bags of already-resolved data. The evaluator
//! never queries anything: a one-hop `lookup_field.target_field` reference is
//! satisfied only if the caller pre-populated it via `with_related` (M45 plan
//! §3.3 "Cross-record context" — "the caller resolves ... before evaluation
//! ... bounded and permission-checked via the existing read path"). This is
//! the mechanism that makes "rules are pure and I/O-free" actually true
//! rather than aspirational: there is no code path inside this crate that
//! could hold a transaction, make an HTTP call, or touch Redis.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;

use crate::error::RulesError;
use crate::value::{Type, Value};

/// The field types a rule is checked against at compile time. `fields` are
/// the rule's own entity; `related` maps a lookup field's name to the field
/// types available on the record it points at (one hop, per the grammar).
#[derive(Debug, Clone, Default)]
pub struct Schema {
    fields: HashMap<String, Type>,
    related: HashMap<String, HashMap<String, Type>>,
    /// Z11-T8: the user functions a rule may call.
    functions: Option<std::sync::Arc<crate::functions::FunctionLibrary>>,
}

impl Schema {
    /// Z11-T8: lets rules checked against this schema call `library`'s
    /// functions (see [`crate::compile_with_library`]).
    #[must_use]
    pub fn with_functions(
        mut self,
        library: std::sync::Arc<crate::functions::FunctionLibrary>,
    ) -> Self {
        self.functions = Some(library);
        self
    }

    pub(crate) fn user_function(
        &self,
        name: &str,
    ) -> Option<&std::sync::Arc<crate::functions::CompiledFunction>> {
        self.functions.as_ref()?.get(name)
    }

    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>, ty: Type) -> Self {
        self.fields.insert(name.into(), ty);
        self
    }

    #[must_use]
    pub fn with_related(
        mut self,
        lookup_field: impl Into<String>,
        fields: HashMap<String, Type>,
    ) -> Self {
        self.related.insert(lookup_field.into(), fields);
        self
    }

    /// Z11-T3: a related list `name` whose rows have `fields`; a rule reads
    /// it with the list functions (`sum(lines)`, `any(lines, l => l.qty > 0)`).
    #[must_use]
    pub fn with_related_list(self, name: impl Into<String>, fields: Vec<(String, Type)>) -> Self {
        self.with_field(name, Type::List(Box::new(Type::Record(fields))))
    }

    pub fn field_type(&self, name: &str) -> Option<&Type> {
        self.fields.get(name)
    }

    pub fn related_field_type(&self, lookup_field: &str, target_field: &str) -> Option<&Type> {
        self.related
            .get(lookup_field)
            .and_then(|m| m.get(target_field))
    }

    /// Whether `lookup_field` is declared at all (used to distinguish "no
    /// such lookup field" from "lookup field exists but this hop isn't on
    /// it" in error messages).
    pub fn has_related(&self, lookup_field: &str) -> bool {
        self.related.contains_key(lookup_field)
    }
}

/// The resolved values a rule evaluates against. Mirrors `Schema`'s shape:
/// `fields` for the rule's own record, `related` for one-hop lookups, plus
/// the injected clock (`now`) — the only source of "current time" an
/// expression can see, since the evaluator has no clock access of its own
/// (M45 plan §3.1, "Pure").
#[derive(Debug, Clone)]
pub struct Context {
    pub now: DateTime<Utc>,
    /// BRU-C4: the caller's local zone. UTC unless with_timezone /
    /// with_timezone_name sets it, so the pre-BRU-C4 behaviour is the default.
    timezone: Tz,
    fields: HashMap<String, Value>,
    related: HashMap<String, HashMap<String, Value>>,
    /// Z11-T5: the base currency and, per currency, the value of one unit
    /// in the base currency. Supplied by the caller; never looked up.
    rates: Option<(String, HashMap<String, f64>)>,
}

impl Context {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now,
            timezone: chrono_tz::UTC,
            fields: HashMap::new(),
            related: HashMap::new(),
            rates: None,
        }
    }

    /// Z11-T5: the rates `convert` uses. `rates` gives, per currency, the
    /// value of one unit in `base`; the base itself is 1. Every code must be
    /// a known ISO 4217 code and every rate finite and positive.
    pub fn with_rates(
        mut self,
        base: String,
        rates: Vec<(String, f64)>,
    ) -> Result<Self, RulesError> {
        let base_code = crate::currency::known(&base).ok_or(RulesError::UnknownCurrency(base))?;
        let mut table = HashMap::with_capacity(rates.len() + 1);
        for (code, rate) in rates {
            let known = crate::currency::known(&code).ok_or(RulesError::UnknownCurrency(code))?;
            if !rate.is_finite() || rate <= 0.0 {
                return Err(RulesError::Eval(format!(
                    "the rate for {known} must be a finite positive number"
                )));
            }
            table.insert(known, rate);
        }
        table.insert(base_code.clone(), 1.0);
        self.rates = Some((base_code, table));
        Ok(self)
    }

    /// Z11-T5: the value of one unit of `code` in the base currency.
    pub fn rate(&self, code: &str) -> Result<f64, RulesError> {
        let known = crate::currency::known(code)
            .ok_or_else(|| RulesError::UnknownCurrency(code.to_owned()))?;
        self.rates
            .as_ref()
            .and_then(|(_, table)| table.get(&known).copied())
            .ok_or(RulesError::NoRate(known))
    }

    /// BRU-C4: the zone today() and month/year arithmetic use.
    pub fn timezone(&self) -> Tz {
        self.timezone
    }

    /// BRU-C4: sets the caller's zone (BRU-D4 leaves the choice of zone to the
    /// caller: organisation default for entity rules, the event's zone for
    /// event filters, UTC for TRD).
    #[must_use]
    pub fn with_timezone(mut self, timezone: Tz) -> Self {
        self.timezone = timezone;
        self
    }

    /// BRU-C4: the same as with_timezone from an IANA name ("Asia/Riyadh"),
    /// for callers holding configuration rather than a Tz. An unknown name is
    /// RulesError::UnknownTimezone — never a silent fall-back to UTC, which
    /// would evaluate a rule in the wrong zone.
    pub fn with_timezone_name(mut self, name: &str) -> Result<Self, RulesError> {
        self.timezone = name
            .parse::<Tz>()
            .map_err(|_| RulesError::UnknownTimezone(name.to_owned()))?;
        Ok(self)
    }

    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>, value: Value) -> Self {
        self.fields.insert(name.into(), value);
        self
    }

    /// Z11-T3: the rows of a related list (the schema's
    /// [`Schema::with_related_list`]); more rows than the budgets'
    /// `max_list_len` is refused when a rule reads it.
    #[must_use]
    pub fn with_related_list(
        self,
        name: impl Into<String>,
        rows: Vec<Vec<(String, Value)>>,
    ) -> Self {
        self.with_field(
            name,
            Value::List(rows.into_iter().map(Value::Record).collect()),
        )
    }

    /// Z11-T8: this context's clock, zone and rates with no fields and no
    /// related records, for a user function's body.
    pub(crate) fn without_fields(&self) -> Context {
        Context {
            now: self.now,
            timezone: self.timezone,
            fields: HashMap::new(),
            related: HashMap::new(),
            rates: self.rates.clone(),
        }
    }

    #[must_use]
    pub fn with_related(
        mut self,
        lookup_field: impl Into<String>,
        fields: HashMap<String, Value>,
    ) -> Self {
        self.related.insert(lookup_field.into(), fields);
        self
    }

    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }

    pub fn related_field(&self, lookup_field: &str, target_field: &str) -> Option<&Value> {
        self.related
            .get(lookup_field)
            .and_then(|m| m.get(target_field))
    }

    pub fn has_related(&self, lookup_field: &str) -> bool {
        self.related.contains_key(lookup_field)
    }
}
