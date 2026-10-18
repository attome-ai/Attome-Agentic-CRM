//! Fuzzes the column-filter compiler: arbitrary bytes as a JSON filter list,
//! each filter's dynamic values expanded, then compiled against a fixed
//! whitelist. Every step returns SQL or an error; nothing panics.
#![no_main]

use std::collections::{HashMap, HashSet};

use attome_core::filter::{self, DynamicValues, FieldCastError, Filter, FilterSchema};
use libfuzzer_sys::fuzz_target;

struct Whitelist {
    casts: HashMap<&'static str, &'static str>,
    multi_choice: HashSet<&'static str>,
}

impl FilterSchema for Whitelist {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        self.casts
            .get(field)
            .copied()
            .ok_or(FieldCastError::Unknown)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.multi_choice.contains(field)
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(filters) = serde_json::from_slice::<Vec<Filter>>(data) else {
        return;
    };
    let schema = Whitelist {
        casts: HashMap::from([
            ("amount", "numeric"),
            ("closed_on", "timestamptz"),
            ("due", "date"),
            ("name", "text"),
            ("owner_id", "uuid"),
            ("open", "boolean"),
            ("tags", "text"),
        ]),
        multi_choice: HashSet::from(["tags"]),
    };
    let dynamic = DynamicValues {
        user_id: uuid::Uuid::nil(),
        team_ids: vec![uuid::Uuid::nil()],
        unit_ids: Vec::new(),
        today: chrono::NaiveDate::from_ymd_opt(2026, 10, 18).unwrap_or_default(),
    };
    let mut placeholder = 1;
    for f in filters.iter().take(64) {
        let Ok(expanded) = filter::expand_dynamic(f, &dynamic) else {
            continue;
        };
        for one in expanded {
            if let Ok((_sql, binds)) = filter::compile(&one, &schema, placeholder) {
                placeholder += binds.len();
            }
        }
    }
});
