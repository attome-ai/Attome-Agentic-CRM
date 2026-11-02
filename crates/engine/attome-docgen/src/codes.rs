//! B16-T12 (V2-D1610 (4)): label codes drawn on the server.
//!
//! A document template names `qr_<field>` or `barcode_<field>` in an
//! `<img src="{{ qr_asset_tag }}">`; [`code_values`] finds those names in
//! the template and draws each from the record's own (permission-filtered)
//! value as an SVG `data:` URI, a QR code through the `qrcode` crate the
//! ZATCA QR already uses, and a Code 128 (set B) barcode through
//! [`code128_svg`]. A field the reader cannot see, or a value Code 128
//! cannot carry, draws nothing (an empty `src`).

use base64::Engine as _;
use serde_json::Value;

/// The prefix that asks for a QR of a field.
pub const QR_PREFIX: &str = "qr_";
/// The prefix that asks for a Code 128 barcode of a field.
pub const BARCODE_PREFIX: &str = "barcode_";
/// The longest value a barcode carries.
const MAX_BARCODE_CHARS: usize = 48;

/// Code 128 bar and space widths for values 0 to 105 (106 is the stop,
/// separate).
const PATTERNS: [&str; 106] = [
    "212222", "222122", "222221", "121223", "121322", "131222", "122213", "122312", "132212",
    "221213", "221312", "231212", "112232", "122132", "122231", "113222", "123122", "123221",
    "223211", "221132", "221231", "213212", "223112", "312131", "311222", "321122", "321221",
    "312212", "322112", "322211", "212123", "212321", "232121", "111323", "131123", "131321",
    "112313", "132113", "132311", "211313", "231113", "231311", "112133", "112331", "132131",
    "113123", "113321", "133121", "313121", "211331", "231131", "213113", "213311", "213131",
    "311123", "311321", "331121", "312113", "312311", "332111", "314111", "221411", "431111",
    "111224", "111422", "121124", "121421", "141122", "141221", "112214", "112412", "122114",
    "122411", "142112", "142211", "241211", "221114", "413111", "241112", "134111", "111242",
    "121142", "121241", "114212", "124112", "124211", "411212", "421112", "421211", "212141",
    "214121", "412121", "111143", "111341", "131141", "114113", "114311", "411113", "411311",
    "113141", "114131", "311141", "411131", "211412", "211214", "211232",
];
const STOP: &str = "2331112";
const START_B: usize = 104;

/// The Code 128 set B symbols of `value` with start, checksum and stop;
/// `None` when a character is outside printable ASCII. Pure.
pub fn code128_symbols(value: &str) -> Option<Vec<usize>> {
    if value.is_empty() || value.chars().count() > MAX_BARCODE_CHARS {
        return None;
    }
    let mut symbols = vec![START_B];
    for c in value.chars() {
        let code = u32::from(c);
        if !(32..=126).contains(&code) {
            return None;
        }
        symbols.push((code - 32) as usize);
    }
    let checksum = symbols
        .iter()
        .enumerate()
        .map(|(i, s)| if i == 0 { *s } else { i * s })
        .sum::<usize>()
        % 103;
    symbols.push(checksum);
    Some(symbols)
}

/// `value` as a Code 128 barcode SVG; `None` when it cannot be encoded.
/// Pure.
pub fn code128_svg(value: &str) -> Option<String> {
    let symbols = code128_symbols(value)?;
    let mut widths: Vec<u32> = Vec::new();
    for s in &symbols {
        widths.extend(PATTERNS[*s].bytes().map(|b| u32::from(b - b'0')));
    }
    widths.extend(STOP.bytes().map(|b| u32::from(b - b'0')));
    let module = 2u32;
    let quiet = 10 * module;
    let height = 60u32;
    let mut x = quiet;
    let mut bars = String::new();
    for (i, w) in widths.iter().enumerate() {
        if i % 2 == 0 {
            bars.push_str(&format!(
                "<rect x=\"{x}\" y=\"0\" width=\"{}\" height=\"{height}\"/>",
                w * module
            ));
        }
        x += w * module;
    }
    let total = x + quiet;
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total}\" height=\"{height}\" \
         viewBox=\"0 0 {total} {height}\"><rect width=\"{total}\" height=\"{height}\" \
         fill=\"#fff\"/><g fill=\"#000\">{bars}</g></svg>"
    ))
}

fn svg_uri(svg: &str) -> String {
    format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())
    )
}

fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The `qr_<field>` and `barcode_<field>` names `source` uses, each with
/// its drawn code (`None` when there is nothing to draw), for the fields of
/// `data`. Pure apart from drawing.
pub fn code_values(
    source: &str,
    data: &serde_json::Map<String, Value>,
) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for (field, value) in data {
        for prefix in [QR_PREFIX, BARCODE_PREFIX] {
            let name = format!("{prefix}{field}");
            if !crate::document_render::mentions(source, &name) || data.contains_key(&name) {
                continue;
            }
            let drawn = text_of(value).and_then(|text| {
                if prefix == QR_PREFIX {
                    crate::document_render::qr_data_uri(&text).ok()
                } else {
                    code128_svg(&text).map(|svg| svg_uri(&svg))
                }
            });
            out.push((name, drawn));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_pattern_is_eleven_modules() {
        for p in PATTERNS {
            assert_eq!(
                p.bytes().map(|b| u32::from(b - b'0')).sum::<u32>(),
                11,
                "{p}"
            );
        }
        assert_eq!(STOP.bytes().map(|b| u32::from(b - b'0')).sum::<u32>(), 13);
    }

    #[test]
    fn code128_checksum_is_the_weighted_sum() {
        // "PJJ123C": the worked example of the Code 128 checksum.
        let symbols = code128_symbols("PJJ123C").unwrap();
        assert_eq!(symbols.first(), Some(&104));
        assert_eq!(symbols.last(), Some(&55));
        assert!(code128_symbols("é").is_none());
        assert!(code128_symbols("").is_none());
    }

    #[test]
    fn qr_placeholder_emits_img_tag() {
        let data = json!({ "asset_tag": "AST-0042", "name": "Pump" });
        let source =
            "<img src=\"{{ qr_asset_tag }}\"><img src=\"{{ barcode_asset_tag }}\">{{ name }}";
        let values = code_values(source, data.as_object().unwrap());
        let names: Vec<&str> = values.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"qr_asset_tag") && names.contains(&"barcode_asset_tag"));
        assert!(values.iter().all(|(_, v)| {
            v.as_deref()
                .is_some_and(|v| v.starts_with("data:image/svg+xml;base64,"))
        }));
    }

    #[test]
    fn code_value_is_escaped() {
        // A value with markup is drawn, never written into the page as text.
        let svg = code128_svg("<b>&\"x\"</b>").unwrap();
        assert!(!svg.contains("<b>") && !svg.contains("&\""));
        let data = json!({ "tag": "<script>" });
        let values = code_values("{{ barcode_tag }}", data.as_object().unwrap());
        let uri = values[0].1.as_deref().unwrap();
        assert!(!uri.contains('<') && !uri.contains('"'));
    }
}
