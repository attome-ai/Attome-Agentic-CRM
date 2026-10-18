//! The canonical form ZATCA hashes (XML-C14N 1.1 without comments, as the
//! Fatoora specification names it), for the invoices Attome writes.
//!
//! The invoice hash is taken over the invoice with three parts removed: the
//! `ext:UBLExtensions` (the signature), the `cac:Signature` reference and the
//! `cac:AdditionalDocumentReference` whose `cbc:ID` is `QR`. Removing an
//! element keeps the whitespace around it, exactly as removing the node from
//! a DOM does. The rest is written canonically:
//!
//! - no XML declaration, nothing outside the root element, no comments;
//! - empty elements written as a start and an end tag;
//! - namespace declarations where the source declares them, default first
//!   then by prefix, followed by the attributes sorted by name (Attome's
//!   invoices carry no prefixed attributes);
//! - text escapes `&`, `<`, `>` and carriage return; attribute values escape
//!   `&`, `<`, `"`, tab, line feed and carriage return; line ends are
//!   normalised to line feed first, as an XML parser does.
//!
//! This is the subset of C14N 1.1 that UBL invoices use (no `xml:`
//! attributes, no relative namespace URIs, no document subsets beyond the
//! three removals), implemented in Rust so the binary carries no native XML
//! security library (V2-D471). It parses with quick-xml and checks that the
//! input is well formed.

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

/// Why a document could not be canonicalised.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum C14nError {
    #[error("the invoice XML is not well formed: {0}")]
    Malformed(String),
}

fn malformed(e: impl std::fmt::Display) -> C14nError {
    C14nError::Malformed(e.to_string())
}

/// Which elements the hash leaves out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// Keep everything.
    None,
    /// ZATCA's invoice hash: drop the signature, its reference and the QR.
    InvoiceHash,
}

fn escape_text(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

fn escape_attr(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

fn name_of(e: &BytesStart<'_>) -> Result<String, C14nError> {
    std::str::from_utf8(e.name().as_ref())
        .map(str::to_owned)
        .map_err(malformed)
}

/// The canonical start tag of `e`.
fn start_tag(e: &BytesStart<'_>, out: &mut String) -> Result<(), C14nError> {
    let name = name_of(e)?;
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut attributes: Vec<(String, String)> = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(malformed)?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(malformed)?
            .to_owned();
        // Attribute-value normalisation (whitespace characters become
        // spaces) and entity resolution, as an XML 1.0 parser does.
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(malformed)?
            .into_owned();
        if key == "xmlns" || key.starts_with("xmlns:") {
            namespaces.push((key, value));
        } else {
            attributes.push((key, value));
        }
    }
    namespaces.sort_by(|a, b| (a.0 != "xmlns", &a.0).cmp(&(b.0 != "xmlns", &b.0)));
    attributes.sort();
    out.push('<');
    out.push_str(&name);
    for (key, value) in namespaces.iter().chain(attributes.iter()) {
        out.push(' ');
        out.push_str(key);
        out.push_str("=\"");
        escape_attr(value, out);
        out.push('"');
    }
    out.push('>');
    Ok(())
}

/// A parsed event, owned, so a subtree can be held back and decided later.
enum Piece {
    Start(String, String),
    End(String),
    Text(String),
}

/// Canonicalises `xml`, leaving out what `removal` names.
pub fn canonicalize(xml: &str, removal: Removal) -> Result<String, C14nError> {
    let normalised = xml.replace("\r\n", "\n").replace('\r', "\n");
    let mut reader = Reader::from_str(&normalised);
    {
        let config = reader.config_mut();
        config.trim_text(false);
        config.expand_empty_elements = true;
    }
    let mut out = String::with_capacity(normalised.len());
    // Open element names, to know the depth and the parent.
    let mut stack: Vec<String> = Vec::new();
    // While inside a removed subtree: the depth it started at.
    let mut skipping: Option<usize> = None;
    // A held `cac:AdditionalDocumentReference` (removed when its ID is QR).
    let mut held: Option<(usize, Vec<Piece>)> = None;
    let mut seen_root = false;

    loop {
        let event = reader.read_event().map_err(malformed)?;
        let piece = match event {
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_) => continue,
            Event::Start(e) => {
                let name = name_of(&e)?;
                let mut tag = String::new();
                start_tag(&e, &mut tag)?;
                Piece::Start(name, tag)
            }
            Event::End(e) => Piece::End(
                std::str::from_utf8(e.name().as_ref())
                    .map_err(malformed)?
                    .to_owned(),
            ),
            Event::Text(t) => Piece::Text(t.decode().map_err(malformed)?.into_owned()),
            Event::CData(t) => Piece::Text(t.decode().map_err(malformed)?.into_owned()),
            Event::GeneralRef(r) => {
                let text = match r.resolve_char_ref().map_err(malformed)? {
                    Some(c) => c.to_string(),
                    None => match r.decode().map_err(malformed)?.as_ref() {
                        "amp" => "&".to_owned(),
                        "lt" => "<".to_owned(),
                        "gt" => ">".to_owned(),
                        "quot" => "\"".to_owned(),
                        "apos" => "'".to_owned(),
                        other => {
                            return Err(C14nError::Malformed(format!(
                                "undeclared entity &{other};"
                            )));
                        }
                    },
                };
                Piece::Text(text)
            }
            _ => continue,
        };

        match &piece {
            Piece::Start(name, _) => {
                if stack.is_empty() {
                    if seen_root {
                        return Err(C14nError::Malformed("more than one root element".into()));
                    }
                    seen_root = true;
                }
                stack.push(name.clone());
                let depth = stack.len();
                if skipping.is_none() && removal == Removal::InvoiceHash && depth == 2 {
                    match name.as_str() {
                        "ext:UBLExtensions" | "cac:Signature" => {
                            skipping = Some(depth);
                            continue;
                        }
                        "cac:AdditionalDocumentReference" if held.is_none() => {
                            held = Some((depth, vec![piece]));
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            Piece::End(name) => {
                if stack.pop().as_deref() != Some(name.as_str()) {
                    return Err(C14nError::Malformed(format!("unexpected </{name}>")));
                }
                let depth = stack.len() + 1;
                if skipping == Some(depth) {
                    skipping = None;
                    continue;
                }
                if let Some((held_depth, pieces)) = &mut held
                    && *held_depth == depth
                {
                    pieces.push(piece);
                    let pieces = std::mem::take(pieces);
                    held = None;
                    if !is_qr_reference(&pieces) {
                        for p in &pieces {
                            write_piece(p, &mut out);
                        }
                    }
                    continue;
                }
            }
            Piece::Text(_) => {
                // Nothing outside the root element is canonical.
                if stack.is_empty() {
                    continue;
                }
            }
        }
        if skipping.is_some() {
            continue;
        }
        if let Some((_, pieces)) = &mut held {
            pieces.push(piece);
            continue;
        }
        write_piece(&piece, &mut out);
    }
    if !stack.is_empty() || !seen_root {
        return Err(C14nError::Malformed(
            "the document ends inside an element".into(),
        ));
    }
    Ok(out)
}

fn write_piece(piece: &Piece, out: &mut String) {
    match piece {
        Piece::Start(_, tag) => out.push_str(tag),
        Piece::End(name) => {
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
        Piece::Text(text) => escape_text(text, out),
    }
}

/// Whether a held `cac:AdditionalDocumentReference` is the QR one: its
/// direct `cbc:ID` child says `QR`.
fn is_qr_reference(pieces: &[Piece]) -> bool {
    let mut depth = 0usize;
    let mut in_id = false;
    let mut id = String::new();
    for piece in pieces {
        match piece {
            Piece::Start(name, _) => {
                depth += 1;
                in_id = depth == 2 && name == "cbc:ID";
            }
            Piece::End(_) => {
                if in_id {
                    return id.trim() == "QR";
                }
                depth = depth.saturating_sub(1);
            }
            Piece::Text(text) if in_id => id.push_str(text),
            Piece::Text(_) => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zatca_xml_c14n_writes_the_canonical_form() {
        let xml = "<?xml version=\"1.0\"?>\r\n<a xmlns:z=\"u:z\" xmlns=\"u:d\"><b y=\"2\" x=\"1\"/><c>1 &lt; 2 &amp; 3 &gt; 0</c><d q=\"a&quot;b\"></d></a>\n";
        assert_eq!(
            canonicalize(xml, Removal::None).unwrap(),
            "<a xmlns=\"u:d\" xmlns:z=\"u:z\"><b x=\"1\" y=\"2\"></b><c>1 &lt; 2 &amp; 3 &gt; 0</c><d q=\"a&quot;b\"></d></a>"
        );
    }

    #[test]
    fn zatca_xml_c14n_removes_the_signature_parts_and_keeps_whitespace() {
        let xml = "<Invoice>\n    <ext:UBLExtensions><x/></ext:UBLExtensions>\n    <cbc:ID>1</cbc:ID>\n    <cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID></cac:AdditionalDocumentReference>\n    <cac:AdditionalDocumentReference>\n        <cbc:ID>QR</cbc:ID>\n    </cac:AdditionalDocumentReference>\n    <cac:Signature><cbc:ID>s</cbc:ID></cac:Signature>\n</Invoice>";
        assert_eq!(
            canonicalize(xml, Removal::InvoiceHash).unwrap(),
            "<Invoice>\n    \n    <cbc:ID>1</cbc:ID>\n    <cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID></cac:AdditionalDocumentReference>\n    \n    \n</Invoice>"
        );
    }

    #[test]
    fn zatca_xml_c14n_refuses_malformed_input() {
        assert!(canonicalize("<a><b></a>", Removal::None).is_err());
        assert!(canonicalize("<a>&nbsp;</a>", Removal::None).is_err());
        assert!(canonicalize("<a></a><b></b>", Removal::None).is_err());
    }
}
