//! `attome slo generate [--check]` (roadmap AA13-T2): one SLO catalogue,
//! `observability/slo-catalogue.json`, is the single source. This writes the
//! three things derived from it and, with `--check`, fails when any of them
//! has drifted from what the catalogue renders:
//!
//! - the `attome-slo` Prometheus rule group in `observability/alerts.yml`,
//!   between its `BEGIN/END GENERATED attome-slo` markers;
//! - `loadtest/k6/lib/slo.js`, the k6 thresholds per class;
//! - the SLO table in `docs/slo.md`, between its `slo-table` markers.
//!
//! Rules and thresholds use the `solo` profile's numbers; a class whose p99
//! is `null` (S8 today) gets thresholds but no burn-rate rules, because the
//! latency rules are built on the p99 bucket.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

/// The catalogue, as far as the generators read it.
#[derive(Debug, Deserialize)]
pub struct Catalogue {
    pub version: u32,
    pub classes: Vec<Class>,
}

/// One SLO class.
#[derive(Debug, Deserialize)]
pub struct Class {
    pub id: String,
    pub name_en: String,
    pub kind: String,
    #[serde(rename = "match")]
    pub matcher: Matcher,
    pub targets: Targets,
    pub error_objective: f64,
    pub status: String,
    pub k6_scenario: Option<String>,
}

/// What a class measures: an HTTP route, or a metric with labels.
#[derive(Debug, Deserialize)]
pub struct Matcher {
    pub method: Option<String>,
    pub endpoint: Option<String>,
}

/// Per-profile latency targets.
#[derive(Debug, Deserialize)]
pub struct Targets {
    pub solo: Latency,
    pub team: Latency,
    pub ha: Latency,
    pub scale: Latency,
}

/// One profile's latency targets, in milliseconds.
#[derive(Debug, Deserialize)]
pub struct Latency {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: Option<f64>,
}

const CATALOGUE: &str = "observability/slo-catalogue.json";
const ALERTS: &str = "observability/alerts.yml";
const K6: &str = "loadtest/k6/lib/slo.js";
const TABLE: &str = "docs/slo.md";

const RULES_BEGIN: &str = "  # BEGIN GENERATED attome-slo (attome slo generate)";
const RULES_END: &str = "  # END GENERATED attome-slo";
const TABLE_BEGIN: &str = "<!-- BEGIN GENERATED slo-table -->";
const TABLE_END: &str = "<!-- END GENERATED slo-table -->";

/// The five class-generic alerts that close the group, kept verbatim.
const GENERIC_ALERTS: &str = include_str!("slo_alerts.yml");

/// Parses the catalogue text.
pub fn parse(text: &str) -> Result<Catalogue, String> {
    serde_json::from_str(text).map_err(|error| format!("{CATALOGUE}: {error}"))
}

/// A millisecond count as written in labels and tables: `60`, `12.5`.
fn ms(value: f64) -> String {
    format!("{value}")
}

/// The class's route, `METHOD /path`, when it is an HTTP class.
fn route(class: &Class) -> Option<(&str, &str)> {
    match (&class.matcher.method, &class.matcher.endpoint) {
        (Some(method), Some(endpoint)) if class.kind == "http" => Some((method, endpoint)),
        _ => None,
    }
}

fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The recording rules for one class: request rates, latency-bad ratios and
/// 5xx ratios over the burn-rate windows. Empty for a non-HTTP class or one
/// without a p99 target.
pub fn render_class_rules(class: &Class) -> String {
    let (Some((method, endpoint)), Some(p99)) = (route(class), class.targets.solo.p99_ms) else {
        return String::new();
    };
    let sel = format!("method=\"{method}\",endpoint=\"{endpoint}\"");
    let le = format!("{}", p99 / 1000.0);
    let labels = format!(
        "        labels:\n          slo_class: {}\n          slo_route: \"{method} {endpoint}\"\n          slo_p99_ms: \"{}\"\n",
        class.id,
        ms(p99)
    );
    let mut out = format!(
        "      # {} — {}; p99 budget {} ms\n",
        class.id,
        lower_first(&class.name_en),
        ms(p99)
    );
    for window in ["5m", "30m"] {
        out.push_str(&format!(
            "      - record: attome:slo_requests:rate{window}\n        expr: sum(rate(axum_http_requests_duration_seconds_count{{{sel}}}[{window}]))\n{labels}"
        ));
    }
    for window in ["5m", "30m", "1h", "6h"] {
        out.push_str(&format!(
            "      - record: attome:slo_latency_bad:ratio_rate{window}\n        expr: |\n          1 - (\n            sum(rate(axum_http_requests_duration_seconds_bucket{{{sel},le=\"{le}\"}}[{window}]))\n            /\n            sum(rate(axum_http_requests_duration_seconds_count{{{sel}}}[{window}]))\n          )\n{labels}"
        ));
    }
    for window in ["5m", "30m", "1h", "6h"] {
        out.push_str(&format!(
            "      - record: attome:slo_errors:ratio_rate{window}\n        expr: |\n          (sum(rate(axum_http_requests_total{{{sel},status=~\"5..\"}}[{window}])) or vector(0))\n          /\n          sum(rate(axum_http_requests_total{{{sel}}}[{window}]))\n{labels}"
        ));
    }
    out
}

/// The whole `attome-slo` group, markers excluded.
pub fn render_rules(catalogue: &Catalogue) -> String {
    let mut out = String::from("  - name: attome-slo\n    rules:\n");
    for class in &catalogue.classes {
        out.push_str(&render_class_rules(class));
    }
    out.push_str(&GENERIC_ALERTS.replace("\r\n", "\n"));
    out
}

/// `loadtest/k6/lib/slo.js`.
pub fn render_k6(catalogue: &Catalogue) -> String {
    let mut out = format!(
        "// GENERATED by `attome slo generate` from {CATALOGUE} (version {}).\n// Do not edit: change the catalogue and regenerate.\n\nconst CLASSES = {{\n",
        catalogue.version
    );
    for class in &catalogue.classes {
        let t = &class.targets.solo;
        let p99 = t.p99_ms.map_or_else(|| "null".to_owned(), ms);
        out.push_str(&format!(
            "  {}: {{ p50: {}, p95: {}, p99: {p99}, errorRate: {} }},\n",
            class.id,
            ms(t.p50_ms),
            ms(t.p95_ms),
            class.error_objective
        ));
    }
    out.push_str(
        "};\n\n\
// k6 thresholds for one class, keyed on the `slo_class` request tag.\n\
export function thresholdsFor(classId) {\n\
  const c = CLASSES[classId];\n\
  if (!c) {\n\
    throw new Error(`unknown SLO class ${classId}`);\n\
  }\n\
  const latency = [`p(50)<${c.p50}`, `p(95)<${c.p95}`];\n\
  if (c.p99 !== null) {\n\
    latency.push(`p(99)<${c.p99}`);\n\
  }\n\
  return {\n\
    [`http_req_duration{slo_class:${classId}}`]: latency,\n\
    [`http_req_failed{slo_class:${classId}}`]: [`rate<${c.errorRate}`],\n\
  };\n\
}\n",
    );
    out
}

/// The markdown rows of the SLO table, header included.
pub fn render_table(catalogue: &Catalogue) -> String {
    let mut out = String::from(
        "| Class | Name | Route | p50 ms | p95 ms | p99 ms | Error objective | Status | k6 scenario |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for class in &catalogue.classes {
        let t = &class.targets.solo;
        let route_text = route(class).map_or_else(|| "—".to_owned(), |(m, e)| format!("`{m} {e}`"));
        out.push_str(&format!(
            "| {} | {} | {route_text} | {} | {} | {} | {} | {} | {} |\n",
            class.id,
            class.name_en,
            ms(t.p50_ms),
            ms(t.p95_ms),
            t.p99_ms.map_or_else(|| "—".to_owned(), ms),
            class.error_objective,
            class.status,
            class
                .k6_scenario
                .as_deref()
                .map_or_else(|| "—".to_owned(), |s| format!("`{s}`")),
        ));
    }
    out
}

/// Replaces the text between `begin` and `end` (each on its own line) with
/// `body`.
pub fn splice(text: &str, begin: &str, end: &str, body: &str) -> Result<String, String> {
    let text = text.replace("\r\n", "\n");
    let start = text
        .find(&format!("{begin}\n"))
        .ok_or_else(|| format!("marker `{begin}` not found"))?
        + begin.len()
        + 1;
    let stop = text[start..]
        .find(end)
        .ok_or_else(|| format!("marker `{end}` not found"))?
        + start;
    Ok(format!("{}{body}{}", &text[..start], &text[stop..]))
}

/// Every generated file and its rendered content.
pub fn render_all(root: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).map_err(|error| format!("{rel}: {error}"))
    };
    let catalogue = parse(&read(CATALOGUE)?)?;
    Ok(vec![
        (
            root.join(ALERTS),
            splice(
                &read(ALERTS)?,
                RULES_BEGIN,
                RULES_END,
                &render_rules(&catalogue),
            )?,
        ),
        (root.join(K6), render_k6(&catalogue)),
        (
            root.join(TABLE),
            splice(
                &read(TABLE)?,
                TABLE_BEGIN,
                TABLE_END,
                &render_table(&catalogue),
            )?,
        ),
    ])
}

/// The generated files whose content on disk differs from the catalogue.
pub fn drift(root: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(render_all(root)?
        .into_iter()
        .filter(|(path, rendered)| {
            std::fs::read_to_string(path)
                .map(|disk| disk.replace("\r\n", "\n") != *rendered)
                .unwrap_or(true)
        })
        .map(|(path, _)| path)
        .collect())
}

/// `attome slo generate [--check]`.
pub fn generate(root: &Path, check: bool) -> ExitCode {
    if check {
        return match drift(root) {
            Ok(stale) if stale.is_empty() => ExitCode::SUCCESS,
            Ok(stale) => {
                for path in stale {
                    eprintln!(
                        "attome slo generate --check: {} is out of date; run `attome slo generate`",
                        path.display()
                    );
                }
                ExitCode::from(2)
            }
            Err(error) => {
                eprintln!("attome slo generate --check: {error}");
                ExitCode::from(2)
            }
        };
    }
    let files = match render_all(root) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("attome slo generate: {error}");
            return ExitCode::from(2);
        }
    };
    for (path, content) in files {
        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            eprintln!("attome slo generate: {}: {error}", parent.display());
            return ExitCode::FAILURE;
        }
        if let Err(error) = std::fs::write(&path, content) {
            eprintln!("attome slo generate: {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOGUE_TEXT: &str = include_str!("../../../../observability/slo-catalogue.json");

    fn catalogue() -> Catalogue {
        parse(CATALOGUE_TEXT).unwrap()
    }

    #[test]
    fn s1_rules_match_current_alerts_yml() {
        let fixture = include_str!("../tests/fixtures/slo_s1_rules.yml").replace("\r\n", "\n");
        let catalogue = catalogue();
        let s1 = catalogue.classes.iter().find(|c| c.id == "S1").unwrap();
        assert_eq!(render_class_rules(s1), fixture);
    }

    #[test]
    fn a_class_without_p99_gets_no_rules_but_thresholds() {
        let catalogue = catalogue();
        let s8 = catalogue.classes.iter().find(|c| c.id == "S8").unwrap();
        assert!(render_class_rules(s8).is_empty());
        assert!(render_k6(&catalogue).contains("S8: { p50: 60, p95: 150, p99: null"));
    }

    #[test]
    fn check_detects_drift() {
        let root = std::env::temp_dir().join(format!("attome-slo-drift-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["observability", "loadtest/k6/lib", "docs"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join(CATALOGUE), CATALOGUE_TEXT).unwrap();
        std::fs::write(
            root.join(ALERTS),
            format!("groups:\n{RULES_BEGIN}\nstale\n{RULES_END}\n"),
        )
        .unwrap();
        std::fs::write(
            root.join(TABLE),
            format!("# SLOs\n\n{TABLE_BEGIN}\n{TABLE_END}\n"),
        )
        .unwrap();
        assert_eq!(drift(&root).unwrap().len(), 3, "everything starts stale");
        assert_eq!(generate(&root, false), ExitCode::SUCCESS);
        assert!(drift(&root).unwrap().is_empty(), "generate leaves no drift");
        std::fs::write(root.join(K6), "// hand edit\n").unwrap();
        assert_eq!(drift(&root).unwrap(), vec![root.join(K6)]);
        assert_eq!(generate(&root, true), ExitCode::from(2));
        let _ = std::fs::remove_dir_all(&root);
    }
}
