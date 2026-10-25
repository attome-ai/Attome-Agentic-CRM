//! E13-T9: building the sitemaps `GET /api/v1/content/sitemap` serves.
//!
//! A site is a content space with a domain (E12-T2). Its sitemap lists, per
//! language, the space's published public pages that are not `noindex`
//! (an `internal` page is for signed-in people, a draft or preview is not
//! published), each at `https://{domain}{url_path}` with `lastmod` and
//! `hreflang` alternates for its translations. A page with no language is
//! filed under `ar` when its title is in Arabic script, else `en`.
//!
//! Up to [`MAX_URLS`] URLs a language is one `urlset` (part 0). More is
//! split: part 0 is a `sitemapindex` naming parts 1.. by their API address
//! (`/api/v1/content/sitemap?site=…&lang=…&part=N`), each a `urlset` of at
//! most [`MAX_URLS`].
//!
//! [`regenerate_all`] runs from the hourly `content_sitemap` job. It skips a
//! site none of whose pages changed since its sitemap was built, writes only
//! the parts whose XML differs and deletes parts and languages no longer
//! there, so running it twice changes nothing the second time.

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, SecondsFormat, Utc};
use uuid::Uuid;

/// The most URLs one sitemap file may list.
pub const MAX_URLS: usize = 50_000;
/// The job's name.
pub const JOB: &str = "content_sitemap";

/// One published page as the sitemap reads it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PageRow {
    pub id: Uuid,
    pub title: String,
    pub url_path: String,
    pub updated_at: DateTime<Utc>,
    pub language: Option<String>,
    pub translation_of: Option<Uuid>,
}

/// One URL of a sitemap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub loc: String,
    pub lastmod: DateTime<Utc>,
    /// `(hreflang, href)` of every language of the page, itself included,
    /// when it has more than one.
    pub alternates: Vec<(String, String)>,
}

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SitemapCounts {
    pub sites: usize,
    pub skipped: usize,
    pub written: usize,
    pub unchanged: usize,
    pub removed: u64,
}

/// The language a page is listed under. Pure.
pub fn lang_of(language: Option<&str>, title: &str) -> String {
    match language.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => l.to_ascii_lowercase(),
        None if title.chars().any(crate::model::is_arabic_letter) => "ar".to_owned(),
        None => "en".to_owned(),
    }
}

/// A page's address on its site. Pure.
pub fn page_url(domain: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("https://{domain}{path}")
    } else {
        format!("https://{domain}/{path}")
    }
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A site's entries by language, each language's sorted by address; a page
/// and its translations are one family for the alternates. Pure.
pub fn entries_by_lang(domain: &str, pages: &[PageRow]) -> BTreeMap<String, Vec<Entry>> {
    let mut families: BTreeMap<Uuid, Vec<(String, String)>> = BTreeMap::new();
    for page in pages {
        families
            .entry(page.translation_of.unwrap_or(page.id))
            .or_default()
            .push((
                lang_of(page.language.as_deref(), &page.title),
                page_url(domain, &page.url_path),
            ));
    }
    for members in families.values_mut() {
        members.sort();
        members.dedup();
    }
    let mut out: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    for page in pages {
        let lang = lang_of(page.language.as_deref(), &page.title);
        let family = &families[&page.translation_of.unwrap_or(page.id)];
        out.entry(lang).or_default().push(Entry {
            loc: page_url(domain, &page.url_path),
            lastmod: page.updated_at,
            alternates: if family.len() > 1 {
                family.clone()
            } else {
                Vec::new()
            },
        });
    }
    for entries in out.values_mut() {
        entries.sort_by(|a, b| a.loc.cmp(&b.loc));
        entries.dedup_by(|a, b| a.loc == b.loc);
    }
    out
}

/// One `urlset`. Pure.
pub fn urlset(entries: &[Entry]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" \
         xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n",
    );
    for e in entries {
        xml.push_str("<url><loc>");
        xml.push_str(&xml_escape(&e.loc));
        xml.push_str("</loc><lastmod>");
        xml.push_str(&e.lastmod.to_rfc3339_opts(SecondsFormat::Secs, true));
        xml.push_str("</lastmod>");
        for (lang, href) in &e.alternates {
            xml.push_str(&format!(
                "<xhtml:link rel=\"alternate\" hreflang=\"{}\" href=\"{}\"/>",
                xml_escape(lang),
                xml_escape(href)
            ));
        }
        xml.push_str("</url>\n");
    }
    xml.push_str("</urlset>\n");
    xml
}

/// The `sitemapindex` naming parts `1..=parts`. Pure.
pub fn index(domain: &str, lang: &str, parts: usize) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for part in 1..=parts {
        let loc = format!(
            "https://{domain}/api/v1/content/sitemap?site={domain}&lang={lang}&part={part}"
        );
        xml.push_str("<sitemap><loc>");
        xml.push_str(&xml_escape(&loc));
        xml.push_str("</loc></sitemap>\n");
    }
    xml.push_str("</sitemapindex>\n");
    xml
}

/// The stored parts for one language, part 0 first. Pure.
pub fn documents(domain: &str, lang: &str, entries: &[Entry]) -> Vec<String> {
    if entries.len() <= MAX_URLS {
        return vec![urlset(entries)];
    }
    let chunks: Vec<&[Entry]> = entries.chunks(MAX_URLS).collect();
    let mut docs = Vec::with_capacity(chunks.len() + 1);
    docs.push(index(domain, lang, chunks.len()));
    docs.extend(chunks.into_iter().map(urlset));
    docs
}

/// Rebuilds every site's sitemaps that may have changed.
pub async fn regenerate_all(db: &DbPool) -> Result<SitemapCounts, AppError> {
    let sites: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, domain FROM content_space \
          WHERE domain IS NOT NULL AND domain <> '' AND is_deleted = false \
          ORDER BY domain",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut counts = SitemapCounts::default();
    for (space, domain) in sites {
        counts.sites += 1;
        let pages: Vec<PageRow> = sqlx::query_as(
            "SELECT id, title, url_path, updated_at, language, translation_of FROM content_page \
              WHERE content_space_id = $1 AND is_deleted = false AND status = 'published' \
                AND audience = 'public' AND seo_noindex = false",
        )
        .bind(space)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let built: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT min(built_at) FROM content_sitemap WHERE site_key = $1")
                .bind(&domain)
                .fetch_one(db)
                .await
                .map_err(AppError::internal)?;
        // Any page of the space, published or not: an unpublish or a
        // delete moves its updated_at too.
        let newest: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT max(updated_at) FROM content_page WHERE content_space_id = $1",
        )
        .bind(space)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        // Nothing changed since the last build; rebuilt at least daily.
        if let (Some(built), Some(newest)) = (built, newest)
            && newest <= built
            && chrono::Utc::now() - built < chrono::Duration::hours(24)
        {
            counts.skipped += 1;
            continue;
        }
        let mut wanted: Vec<(String, i32, String)> = Vec::new();
        for (lang, entries) in entries_by_lang(&domain, &pages) {
            for (part, xml) in documents(&domain, &lang, &entries).into_iter().enumerate() {
                wanted.push((lang.clone(), i32::try_from(part).unwrap_or(i32::MAX), xml));
            }
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let stored: Vec<(String, i32, String)> =
            sqlx::query_as("SELECT lang, part, xml FROM content_sitemap WHERE site_key = $1")
                .bind(&domain)
                .fetch_all(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        let stored: BTreeMap<(String, i32), String> = stored
            .into_iter()
            .map(|(lang, part, xml)| ((lang, part), xml))
            .collect();
        for (lang, part, xml) in &wanted {
            if stored.get(&(lang.clone(), *part)) == Some(xml) {
                counts.unchanged += 1;
                continue;
            }
            sqlx::query(
                "INSERT INTO content_sitemap (site_key, lang, part, xml, built_at) \
                 VALUES ($1, $2, $3, $4, now()) \
                 ON CONFLICT (site_key, lang, part) DO UPDATE SET xml = EXCLUDED.xml, built_at = now()",
            )
            .bind(&domain)
            .bind(lang)
            .bind(part)
            .bind(xml)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            counts.written += 1;
        }
        let langs: Vec<String> = wanted.iter().map(|(l, _, _)| l.clone()).collect();
        let parts: Vec<i32> = wanted.iter().map(|(_, p, _)| *p).collect();
        counts.removed += sqlx::query(
            "DELETE FROM content_sitemap s WHERE s.site_key = $1 AND NOT EXISTS ( \
               SELECT 1 FROM UNNEST($2::text[], $3::int[]) AS w(lang, part) \
                WHERE w.lang = s.lang AND w.part = s.part)",
        )
        .bind(&domain)
        .bind(&langs)
        .bind(&parts)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        // Unchanged parts are touched so the next run can skip the site.
        sqlx::query("UPDATE content_sitemap SET built_at = now() WHERE site_key = $1")
            .bind(&domain)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str, lang: Option<&str>, of: Option<Uuid>) -> PageRow {
        PageRow {
            id: Uuid::now_v7(),
            title: "Pricing".into(),
            url_path: path.into(),
            updated_at: "2026-10-25T08:00:00Z".parse().unwrap(),
            language: lang.map(str::to_owned),
            translation_of: of,
        }
    }

    #[test]
    fn sitemap_splits_at_50000() {
        let entries: Vec<Entry> = (0..=MAX_URLS)
            .map(|i| Entry {
                loc: format!("https://www.example.sa/p/{i:06}"),
                lastmod: "2026-10-25T08:00:00Z".parse().unwrap(),
                alternates: Vec::new(),
            })
            .collect();
        let docs = documents("www.example.sa", "en", &entries);
        assert_eq!(docs.len(), 3, "an index and two parts");
        assert!(docs[0].contains("<sitemapindex"));
        assert!(docs[0].contains("site=www.example.sa&amp;lang=en&amp;part=2"));
        assert_eq!(docs[1].matches("<url>").count(), MAX_URLS);
        assert_eq!(docs[2].matches("<url>").count(), 1);
        // Exactly the limit is one urlset.
        assert_eq!(
            documents("www.example.sa", "en", &entries[..MAX_URLS]).len(),
            1
        );
    }

    #[test]
    fn sitemap_lists_translations_as_alternates() {
        let en = row("/pricing", Some("en"), None);
        let ar = row("/ar/pricing", Some("ar"), Some(en.id));
        let lone = row("/about", None, None);
        let by_lang = entries_by_lang("www.example.sa", &[en.clone(), ar, lone]);
        assert_eq!(by_lang["en"].len(), 2);
        assert_eq!(by_lang["ar"].len(), 1);
        let pricing = by_lang["en"]
            .iter()
            .find(|e| e.loc.ends_with("/pricing"))
            .unwrap();
        assert_eq!(pricing.alternates.len(), 2);
        let xml = urlset(&by_lang["en"]);
        assert!(xml.contains(
            "<xhtml:link rel=\"alternate\" hreflang=\"ar\" href=\"https://www.example.sa/ar/pricing\"/>"
        ));
        assert!(xml.contains("<lastmod>2026-10-25T08:00:00Z</lastmod>"));
        // The page with no translation carries none.
        let about = by_lang["en"]
            .iter()
            .find(|e| e.loc.ends_with("/about"))
            .unwrap();
        assert!(about.alternates.is_empty());
    }

    #[test]
    fn sitemap_files_untagged_pages_by_script() {
        assert_eq!(lang_of(None, "الأسعار"), "ar");
        assert_eq!(lang_of(None, "Pricing"), "en");
        assert_eq!(lang_of(Some("AR-sa"), "Pricing"), "ar-sa");
        assert_eq!(page_url("x.example", "p"), "https://x.example/p");
        assert_eq!(xml_escape("a&b<c>"), "a&amp;b&lt;c&gt;");
    }
}
