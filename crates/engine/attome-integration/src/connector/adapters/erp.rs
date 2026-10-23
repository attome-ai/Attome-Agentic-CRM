//! S12-T2: what the ERP connectors (Odoo, SAP Business One) exchange with
//! Attome, independent of either: customers, products, sales orders and
//! invoices as records of the CRM, sales and finance packs' entities
//! (`account`, `product`, `order`, `invoice`), each keyed by the ERP's id.
//!
//! Pulling is safe in every direction; pushing is limited to customers
//! ([`ErpKind::Customer`]): orders and invoices belong to the ERP's books
//! and are never written back from the CRM.

use serde_json::{Map, Value};

/// The kinds of records an ERP connector moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErpKind {
    Customer,
    Product,
    Order,
    Invoice,
}

impl ErpKind {
    /// The Attome entity a record of this kind lands in.
    pub fn entity(self) -> &'static str {
        match self {
            ErpKind::Customer => "account",
            ErpKind::Product => "product",
            ErpKind::Order => "order",
            ErpKind::Invoice => "invoice",
        }
    }

    /// Whether Attome may write this kind back to the ERP.
    pub fn pushable(self) -> bool {
        matches!(self, ErpKind::Customer)
    }
}

/// One ERP record as an Attome record.
#[derive(Debug, Clone, PartialEq)]
pub struct ErpRecord {
    pub kind: ErpKind,
    /// `<system>:<id>` (`odoo:42`, `sap_b1:C20000`), the external id it is
    /// upserted by.
    pub external_id: String,
    /// The entity's attributes it sets.
    pub fields: Map<String, Value>,
}

/// A non-empty text value.
pub fn text(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Some(Value::String(s.trim().to_owned())),
        _ => None,
    }
}

/// A date (`YYYY-MM-DD`) from a date or date-time text.
pub fn date(v: &Value) -> Option<Value> {
    let s = v.as_str()?.trim();
    (s.len() >= 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-')
        .then(|| Value::String(s[..10].to_owned()))
}

/// Sets `key` when `value` is something.
pub fn put(fields: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(v) = value {
        fields.insert(key.to_owned(), v);
    }
}

/// The email domain of an address.
pub fn email_domain(v: &Value) -> Option<Value> {
    let email = v.as_str()?;
    let domain = email.rsplit_once('@')?.1.trim().to_lowercase();
    (!domain.is_empty()).then_some(Value::String(domain))
}
