//! K6-T5: main-content extraction on saved English and Arabic pages.

use attome_html::main_content::extract_main;

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn main_content_strips_nav_and_footer_en() {
    let m = extract_main(&fixture("page_en.html"));
    assert_eq!(m.title.as_deref(), Some("Returns policy | Example Store"));
    assert!(
        m.text_markdown.starts_with("# Returns policy"),
        "{}",
        m.text_markdown
    );
    assert!(m.text_markdown.contains("- Keep the receipt"));
    for chrome in ["Shop", "cookies", "Popular products", "Copyright"] {
        assert!(
            !m.text_markdown.contains(chrome),
            "{chrome} in {}",
            m.text_markdown
        );
    }
    assert_eq!(m.lang.as_deref(), Some("en"));
    assert_eq!(m.dir, "ltr");
}

#[test]
fn main_content_tags_arabic_page_rtl() {
    let m = extract_main(&fixture("page_ar.html"));
    assert!(
        m.text_markdown.starts_with("# سياسة الإرجاع"),
        "{}",
        m.text_markdown
    );
    assert!(!m.text_markdown.contains("الرئيسية"), "the menu is dropped");
    assert!(
        !m.text_markdown.contains("جميع الحقوق"),
        "the footer is dropped"
    );
    assert_eq!(m.lang.as_deref(), Some("ar"));
    assert_eq!(m.dir, "rtl");
}
