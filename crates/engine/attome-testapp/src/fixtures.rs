//! Seeded fixture builders (roadmap Z15-T4): a valid record for any entity
//! from its metadata, the same for the same seed, created through the API so
//! rules and validation run.
//!
//! Every required attribute gets a value its field type accepts; optional
//! ones are left out. Text starts with a unique token so reruns never
//! collide on a unique index. A required lookup is left to the caller (create
//! the target first and set its id). Failure messages name the seed.

use attome_core::{AttrInfo, EntityMeta};
use serde_json::{Map, Value, json};

/// A small deterministic generator (SplitMix64): the same seed always gives
/// the same sequence, with no global state.
#[derive(Debug, Clone)]
pub struct Seeded(u64);

impl Seeded {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// A value of `attr`'s field type, or `None` for a type a fixture cannot
/// invent (a lookup, a file, a formula).
pub fn value_for(attr: &AttrInfo, seed: u64, rng: &mut Seeded, token: &str) -> Option<Value> {
    let n = rng.next_u64();
    Some(match attr.field_type_int {
        1 | 4 | 9 | 10 => json!(n % 1000),
        2 => json!((n % 100_000) as f64 / 100.0),
        5 => {
            let day = (seed + n % 28) % 28 + 1;
            json!(format!("2026-01-{day:02}"))
        }
        6 => json!(n.is_multiple_of(2)),
        7 | 8 => {
            let choices = attr
                .options
                .as_ref()
                .and_then(|o| o["choices"].as_array())
                .and_then(|c| c.first())
                .cloned()?;
            if attr.field_type_int == 8 {
                json!([choices])
            } else {
                choices
            }
        }
        11 | 12 | 13 | 16 | 18 => return None,
        14 => json!("las la-star"),
        15 => json!("#336699"),
        _ => {
            let max = attr
                .max_length
                .and_then(|m| usize::try_from(m).ok())
                .unwrap_or(200);
            let text = format!("{token}-{}-{}", attr.logicalname, n % 10_000);
            json!(text.chars().take(max.max(1)).collect::<String>())
        }
    })
}

/// A record body for `meta`: every required attribute set, deterministic in
/// `seed` apart from the leading unique `token`.
pub fn record_for(meta: &EntityMeta, seed: u64, token: &str) -> Map<String, Value> {
    let mut rng = Seeded::new(seed);
    let mut attrs: Vec<&AttrInfo> = meta.attrs.iter().filter(|a| a.is_required).collect();
    attrs.sort_by(|a, b| a.logicalname.cmp(&b.logicalname));
    let mut out = Map::new();
    for attr in attrs {
        if let Some(value) = value_for(attr, seed, &mut rng, token) {
            out.insert(attr.logicalname.clone(), value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str, field_type_int: i32, required: bool) -> AttrInfo {
        serde_json::from_value(json!({
            "logicalname": name, "field_type_int": field_type_int, "is_required": required,
            "is_sensitive": false, "is_sortable": false, "is_filterable": false,
            "options": if field_type_int == 7 { json!({ "choices": ["open", "closed"], "multi": false }) } else { Value::Null }
        }))
        .unwrap()
    }

    fn meta() -> EntityMeta {
        serde_json::from_value(json!({
            "entity_id": uuid::Uuid::nil(), "logicalname": "ticket", "is_append_only": false,
            "attrs": []
        }))
        .map(|mut m: EntityMeta| {
            m.attrs = vec![
                attr("title", 3, true),
                attr("count", 1, true),
                attr("status", 7, true),
                attr("due", 5, true),
                attr("note", 3, false),
                attr("owner", 11, true),
            ];
            m
        })
        .unwrap()
    }

    #[test]
    fn record_for_is_deterministic() {
        let a = record_for(&meta(), 7, "t");
        let b = record_for(&meta(), 7, "t");
        assert_eq!(a, b, "seed=7");
        assert_ne!(a, record_for(&meta(), 8, "t"), "another seed differs");
        assert!(a.contains_key("title") && a.contains_key("count") && a.contains_key("due"));
        assert_eq!(a["status"], "open", "a choice takes its first option");
        assert!(!a.contains_key("note"), "optional attributes are left out");
        assert!(!a.contains_key("owner"), "a lookup is left to the caller");
        assert!(a["title"].as_str().unwrap().starts_with("t-title-"));
    }
}
