//! Brand theme tokens and their WCAG contrast check (roadmap B13-T2).
//!
//! A theme is a set of optional tokens, so a narrower scope (a portal, an
//! app) overrides only what it changes ([`merge`]). [`check`] measures the
//! pairs people read: text on its surface (4.5:1, WCAG 2.2 AA for body
//! text), the brand colour and each status colour on the surface (3:1, for
//! large text and UI components), and keeps the four status colours apart
//! from each other (CIE76 ΔE of 20 or more), so success and danger never
//! look alike. A colour the theme leaves out is measured at the product's
//! own default. Pure: no SQL, no HTTP.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A colour as `#RRGGBB`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type = String, example = "#6d28d9")]
pub struct HexColor(String);

impl HexColor {
    /// Accepts exactly `#` and six hex digits.
    pub fn parse(text: &str) -> Result<Self, ThemeError> {
        let valid = text.len() == 7
            && text.starts_with('#')
            && text[1..].chars().all(|c| c.is_ascii_hexdigit());
        if valid {
            Ok(Self(text.to_ascii_lowercase()))
        } else {
            Err(ThemeError::InvalidColor(text.to_owned()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The red, green and blue channels, 0 to 255.
    fn channels(&self) -> [u8; 3] {
        let byte = |i: usize| u8::from_str_radix(&self.0[i..i + 2], 16).unwrap_or(0);
        [byte(1), byte(3), byte(5)]
    }
}

impl TryFrom<String> for HexColor {
    type Error = ThemeError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<HexColor> for String {
    fn from(value: HexColor) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThemeError {
    #[error("'{0}' is not a colour like #RRGGBB")]
    InvalidColor(String),
}

/// How tightly the product packs its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Density {
    Comfortable,
    Compact,
}

/// A theme: every token optional, so a scope overrides only what it sets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ThemeTokens {
    pub primary: Option<HexColor>,
    pub accent: Option<HexColor>,
    pub surface: Option<HexColor>,
    pub surface_dark: Option<HexColor>,
    pub text: Option<HexColor>,
    pub text_dark: Option<HexColor>,
    pub success: Option<HexColor>,
    pub warning: Option<HexColor>,
    pub danger: Option<HexColor>,
    pub info: Option<HexColor>,
    pub font_latin: Option<String>,
    pub font_arabic: Option<String>,
    pub arabic_line_height: Option<f32>,
    pub radius_px: Option<u8>,
    pub density: Option<Density>,
    pub hide_vendor_name: Option<bool>,
}

/// One pair that reads too faintly, or two status colours too alike.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ContrastFailure {
    /// `text/surface`, `primary/surface`, `success/danger`, …
    pub pair: String,
    /// `light`, `dark`, or `distinct` for two status colours.
    pub mode: String,
    /// The measured contrast ratio, or ΔE for `distinct`.
    pub ratio: f64,
    pub required: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ContrastReport {
    pub passed: bool,
    pub failures: Vec<ContrastFailure>,
}

/// The product's own colours (`web/projects/base/src/lib/theme.service.ts`
/// light and dark schemes), used for any token a theme leaves out. Warning
/// and info have no product colour yet; these are the amber and blue the
/// status badges use.
const DEFAULTS: [(&str, &str); 10] = [
    ("primary", "#374151"),
    ("accent", "#6d28d9"),
    ("surface", "#ffffff"),
    ("surface_dark", "#141728"),
    ("text", "#0d1117"),
    ("text_dark", "#e8eaf6"),
    ("success", "#166534"),
    ("warning", "#b45309"),
    ("danger", "#b91c1c"),
    ("info", "#1d4ed8"),
];

fn default_colour(name: &str) -> HexColor {
    let hex = DEFAULTS
        .iter()
        .find(|(n, _)| *n == name)
        .map_or("#000000", |(_, h)| *h);
    HexColor(hex.to_owned())
}

/// The WCAG 2.2 relative luminance of a colour.
pub fn relative_luminance(colour: &HexColor) -> f64 {
    let linear = |c: u8| {
        let s = f64::from(c) / 255.0;
        if s <= 0.040_45 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    let [r, g, b] = colour.channels();
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

/// The WCAG 2.2 contrast ratio, 1 to 21.
pub fn contrast_ratio(a: &HexColor, b: &HexColor) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (light, dark) = if la >= lb { (la, lb) } else { (lb, la) };
    (light + 0.05) / (dark + 0.05)
}

/// CIE L*a*b* of a colour (sRGB, D65).
fn lab(colour: &HexColor) -> [f64; 3] {
    let linear = |c: u8| {
        let s = f64::from(c) / 255.0;
        if s <= 0.040_45 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    let [r, g, b] = colour.channels().map(linear);
    let x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.950_47;
    let y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    let z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.088_83;
    let f = |t: f64| {
        if t > 0.008_856 {
            t.cbrt()
        } else {
            7.787 * t + 16.0 / 116.0
        }
    };
    let (fx, fy, fz) = (f(x), f(y), f(z));
    [116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz)]
}

/// CIE76 ΔE: how different two colours look.
pub fn delta_e(a: &HexColor, b: &HexColor) -> f64 {
    let (p, q) = (lab(a), lab(b));
    ((p[0] - q[0]).powi(2) + (p[1] - q[1]).powi(2) + (p[2] - q[2]).powi(2)).sqrt()
}

/// `base` with every token `over` sets.
pub fn merge(base: &ThemeTokens, over: &ThemeTokens) -> ThemeTokens {
    fn pick<T: Clone>(over: &Option<T>, base: &Option<T>) -> Option<T> {
        over.clone().or_else(|| base.clone())
    }
    ThemeTokens {
        primary: pick(&over.primary, &base.primary),
        accent: pick(&over.accent, &base.accent),
        surface: pick(&over.surface, &base.surface),
        surface_dark: pick(&over.surface_dark, &base.surface_dark),
        text: pick(&over.text, &base.text),
        text_dark: pick(&over.text_dark, &base.text_dark),
        success: pick(&over.success, &base.success),
        warning: pick(&over.warning, &base.warning),
        danger: pick(&over.danger, &base.danger),
        info: pick(&over.info, &base.info),
        font_latin: pick(&over.font_latin, &base.font_latin),
        font_arabic: pick(&over.font_arabic, &base.font_arabic),
        arabic_line_height: over.arabic_line_height.or(base.arabic_line_height),
        radius_px: over.radius_px.or(base.radius_px),
        density: over.density.or(base.density),
        hide_vendor_name: over.hide_vendor_name.or(base.hide_vendor_name),
    }
}

/// Text, brand and status colours measured against their surfaces, and the
/// status colours against each other.
pub fn check(theme: &ThemeTokens) -> ContrastReport {
    let colour = |token: &Option<HexColor>, name: &str| {
        token.clone().unwrap_or_else(|| default_colour(name))
    };
    let surface = colour(&theme.surface, "surface");
    let surface_dark = colour(&theme.surface_dark, "surface_dark");
    let mut failures = Vec::new();
    let mut need = |pair: &str, mode: &str, a: &HexColor, b: &HexColor, required: f64| {
        let ratio = contrast_ratio(a, b);
        if ratio < required {
            failures.push(ContrastFailure {
                pair: pair.to_owned(),
                mode: mode.to_owned(),
                ratio: (ratio * 100.0).round() / 100.0,
                required,
            });
        }
    };
    need(
        "text/surface",
        "light",
        &colour(&theme.text, "text"),
        &surface,
        4.5,
    );
    need(
        "text_dark/surface_dark",
        "dark",
        &colour(&theme.text_dark, "text_dark"),
        &surface_dark,
        4.5,
    );
    need(
        "primary/surface",
        "light",
        &colour(&theme.primary, "primary"),
        &surface,
        3.0,
    );
    let status = [
        ("success", colour(&theme.success, "success")),
        ("warning", colour(&theme.warning, "warning")),
        ("danger", colour(&theme.danger, "danger")),
        ("info", colour(&theme.info, "info")),
    ];
    for (name, c) in &status {
        need(&format!("{name}/surface"), "light", c, &surface, 3.0);
    }
    for (i, (a_name, a)) in status.iter().enumerate() {
        for (b_name, b) in status.iter().skip(i + 1) {
            let distance = delta_e(a, b);
            if distance < 20.0 {
                failures.push(ContrastFailure {
                    pair: format!("{a_name}/{b_name}"),
                    mode: "distinct".into(),
                    ratio: (distance * 100.0).round() / 100.0,
                    required: 20.0,
                });
            }
        }
    }
    ContrastReport {
        passed: failures.is_empty(),
        failures,
    }
}

/// The light-mode CSS variables a theme sets, by the names the web app
/// already uses (`--color-*` in `theme.service.ts`). Tokens with no
/// variable yet (warning, info, the dark pair, fonts, radius, density) are
/// left out until the web app reads them (B13-T8).
pub fn to_css_variables(theme: &ThemeTokens) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |var: &str, value: &Option<HexColor>| {
        if let Some(c) = value {
            out.insert(var.to_owned(), c.as_str().to_owned());
        }
    };
    put("--color-primary", &theme.primary);
    put("--color-accent", &theme.accent);
    put("--color-bg-alt", &theme.surface);
    put("--color-text-primary", &theme.text);
    put("--color-success", &theme.success);
    put("--color-danger", &theme.danger);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> HexColor {
        HexColor::parse(s).unwrap()
    }

    #[test]
    fn black_on_white_is_21() {
        let ratio = contrast_ratio(&hex("#000000"), &hex("#ffffff"));
        assert!((ratio - 21.0).abs() < 1e-9, "{ratio}");
        assert!((contrast_ratio(&hex("#ffffff"), &hex("#ffffff")) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn grey_777_fails_text_contrast() {
        let theme = ThemeTokens {
            text: Some(hex("#777777")),
            ..ThemeTokens::default()
        };
        let report = check(&theme);
        assert!(!report.passed);
        let failure = report
            .failures
            .iter()
            .find(|f| f.pair == "text/surface")
            .expect("text on surface fails");
        assert!(failure.ratio < 4.5 && failure.ratio > 4.0, "{failure:?}");
        assert!(
            check(&ThemeTokens::default()).passed,
            "the product's own colours pass"
        );
    }

    #[test]
    fn invalid_colour_rejected() {
        for bad in ["red", "#fff", "#12345g", "123456", "#1234567"] {
            assert!(HexColor::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(HexColor::parse("#6D28D9").unwrap().as_str(), "#6d28d9");
        assert!(
            serde_json::from_value::<ThemeTokens>(serde_json::json!({"primary": "blue"})).is_err()
        );
    }

    #[test]
    fn identical_status_colours_fail() {
        let same = hex("#b91c1c");
        let theme = ThemeTokens {
            success: Some(same.clone()),
            danger: Some(same),
            ..ThemeTokens::default()
        };
        let report = check(&theme);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.pair == "success/danger" && f.mode == "distinct")
        );
    }

    #[test]
    fn merge_keeps_base_when_override_none() {
        let base = ThemeTokens {
            primary: Some(hex("#111111")),
            radius_px: Some(8),
            ..ThemeTokens::default()
        };
        let over = ThemeTokens {
            accent: Some(hex("#222222")),
            ..ThemeTokens::default()
        };
        let merged = merge(&base, &over);
        assert_eq!(merged.primary, Some(hex("#111111")));
        assert_eq!(merged.accent, Some(hex("#222222")));
        assert_eq!(merged.radius_px, Some(8));
        let vars = to_css_variables(&merged);
        assert_eq!(
            vars.get("--color-primary").map(String::as_str),
            Some("#111111")
        );
        assert!(!vars.contains_key("--color-danger"));
    }
}
