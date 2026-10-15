//! Release notes (roadmap AC6-T1): `attome release tag` writes the version's
//! `CHANGELOG.md` section as notes in English and Arabic,
//! `release-notes/v<version>.en.md` and `.ar.md`, breaking changes first and
//! then each area in the changelog's own order.
//!
//! The Arabic notes carry Arabic headings and introduction; each entry keeps
//! its English text, marked for translation, until a reviewed translation
//! replaces it (the translation agent drafts it in the product, N20; the
//! release tool does not call a model).

/// One `### Area` of a changelog section and its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub heading: String,
    pub entries: Vec<String>,
}

/// The `## [version]` section of `changelog`, as areas: `Breaking` first,
/// then the rest in order. Wrapped entry lines are joined.
pub fn sections(changelog: &str, version: &str) -> Result<Vec<Section>, String> {
    let marker = format!("## [{version}]");
    let start = changelog
        .find(&marker)
        .ok_or_else(|| format!("CHANGELOG.md has no {marker} section"))?;
    let after = start + marker.len();
    let end = changelog[after..]
        .find("\n## [")
        .map_or(changelog.len(), |offset| after + offset);
    let mut out: Vec<Section> = Vec::new();
    for line in changelog[after..end].lines().skip(1) {
        if let Some(heading) = line.strip_prefix("### ") {
            out.push(Section {
                heading: heading.trim().to_owned(),
                entries: Vec::new(),
            });
        } else if let Some(entry) = line.strip_prefix("- ") {
            if let Some(section) = out.last_mut() {
                section.entries.push(entry.trim().to_owned());
            }
        } else if !line.trim().is_empty()
            && line.starts_with(' ')
            && let Some(last) = out.last_mut().and_then(|s| s.entries.last_mut())
        {
            last.push(' ');
            last.push_str(line.trim());
        }
    }
    out.retain(|section| !section.entries.is_empty());
    out.sort_by_key(|section| section.heading != "Breaking");
    Ok(out)
}

/// The notes in English.
pub fn english(version: &str, date: &str, sections: &[Section]) -> String {
    let mut out = format!("# Attome {version}\n\nReleased {date}.\n");
    for section in sections {
        out.push_str(&format!("\n## {}\n\n", english_heading(&section.heading)));
        for entry in &section.entries {
            out.push_str(&format!("- {entry}\n"));
        }
    }
    out
}

/// The notes in Arabic: Arabic headings, each entry marked until translated.
pub fn arabic(version: &str, date: &str, sections: &[Section]) -> String {
    let mut out = format!(
        "# أتوم {version}\n\nصدر في {date}.\n\nتبقى البنود أدناه بنصها الإنجليزي إلى أن تُراجَع ترجمتها.\n"
    );
    for section in sections {
        out.push_str(&format!("\n## {}\n\n", arabic_heading(&section.heading)));
        for entry in &section.entries {
            out.push_str(&format!("- {entry} *(بانتظار الترجمة)*\n"));
        }
    }
    out
}

fn english_heading(heading: &str) -> &str {
    match heading {
        "Breaking" => "Breaking changes",
        other => other,
    }
}

fn arabic_heading(heading: &str) -> &str {
    match heading {
        "Breaking" => "تغييرات غير متوافقة مع السابق",
        "Security" => "الأمان",
        "Added" => "الجديد",
        "Changed" => "ما تغيّر",
        "Fixed" => "الإصلاحات",
        "Removed" => "ما أُزيل",
        "Deprecated" => "ما سيُزال",
        "Performance" => "الأداء",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "# Changelog\n\n## [Unreleased]\n\n## [2.1.0] - 2026-10-15\n\n### Added\n- One.\n- Two, wrapped\n  over two lines.\n\n### Breaking\n- Removed `GET /x`.\n\n### Fixed\n\n## [2.0.0] - 2026-09-01\n\n### Added\n- Old.\n";

    #[test]
    fn breaking_comes_first_and_empty_areas_are_dropped() {
        let got = sections(LOG, "2.1.0").expect("section");
        assert_eq!(
            got,
            vec![
                Section {
                    heading: "Breaking".into(),
                    entries: vec!["Removed `GET /x`.".into()],
                },
                Section {
                    heading: "Added".into(),
                    entries: vec!["One.".into(), "Two, wrapped over two lines.".into()],
                },
            ]
        );
    }

    #[test]
    fn a_missing_version_is_an_error() {
        assert!(sections(LOG, "9.9.9").is_err());
    }

    #[test]
    fn both_languages_carry_every_entry() {
        let got = sections(LOG, "2.1.0").expect("section");
        let en = english("2.1.0", "2026-10-15", &got);
        assert!(en.starts_with("# Attome 2.1.0"));
        assert!(en.find("## Breaking changes") < en.find("## Added"));
        assert!(en.contains("- Two, wrapped over two lines."));
        let ar = arabic("2.1.0", "2026-10-15", &got);
        assert!(ar.contains("## تغييرات غير متوافقة مع السابق"));
        assert!(ar.contains("## الجديد"));
        assert!(ar.contains("- One. *(بانتظار الترجمة)*"));
        assert!(!ar.contains("Old."));
    }
}
