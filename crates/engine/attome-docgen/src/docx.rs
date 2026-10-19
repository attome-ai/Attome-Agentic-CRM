//! K3-T2: DOCX output from the same template.
//!
//! A template renders to HTML (`crate::document_render`); for a `docx`
//! template that HTML becomes a Word document here instead of going to the
//! PDF sidecar. Pure Rust, no new dependency: the document is a ZIP of
//! WordprocessingML parts written with `flate2` (already in the build).
//!
//! What carries over: headings (`h1`–`h3` as Word's Heading 1–3, deeper
//! ones as Heading 3), paragraphs and line breaks, bold, italic and
//! underline, list items, and tables (one level; a table inside a table is
//! flattened into its cell). Paragraphs in Arabic (or any right-to-left
//! script) are marked right-to-left. Styling from the template's stylesheet,
//! images and page layout are PDF-only; a DOCX is for people who will edit
//! the document.

use std::io::Write;

/// The MIME type of a DOCX.
pub const DOCX_MIME: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

#[derive(Debug, Clone, PartialEq, Default)]
struct Run {
    text: String,
    bold: bool,
    italic: bool,
    underline: bool,
    line_break: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct Para {
    style: Option<&'static str>,
    runs: Vec<Run>,
}

#[derive(Debug, Clone, PartialEq)]
enum Block {
    Para(Para),
    /// Rows of cells of paragraphs.
    Table(Vec<Vec<Vec<Para>>>),
}

/// The open table being filled.
#[derive(Debug, Default)]
struct OpenTable {
    rows: Vec<Vec<Vec<Para>>>,
    in_cell: bool,
}

#[derive(Debug, Default)]
struct Builder {
    blocks: Vec<Block>,
    current: Para,
    table: Option<OpenTable>,
    bold: u32,
    italic: u32,
    underline: u32,
    skip: u32,
}

impl Builder {
    fn flush(&mut self) {
        let para = std::mem::take(&mut self.current);
        if para
            .runs
            .iter()
            .all(|r| r.text.trim().is_empty() && !r.line_break)
        {
            return;
        }
        match &mut self.table {
            Some(table) if table.in_cell => {
                if let Some(cell) = table.rows.last_mut().and_then(|r| r.last_mut()) {
                    cell.push(para);
                }
            }
            _ => self.blocks.push(Block::Para(para)),
        }
    }

    fn text(&mut self, raw: &str) {
        if self.skip > 0 {
            return;
        }
        let mut text = String::with_capacity(raw.len());
        let mut last_space = self
            .current
            .runs
            .last()
            .is_none_or(|r| r.line_break || r.text.ends_with(' '));
        for c in raw.chars() {
            if c.is_whitespace() {
                if !last_space {
                    text.push(' ');
                    last_space = true;
                }
            } else {
                text.push(c);
                last_space = false;
            }
        }
        if text.is_empty() {
            return;
        }
        self.current.runs.push(Run {
            text,
            bold: self.bold > 0,
            italic: self.italic > 0,
            underline: self.underline > 0,
            line_break: false,
        });
    }

    fn open(&mut self, name: &str) {
        match name {
            "style" | "script" | "head" | "title" => self.skip += 1,
            "b" | "strong" => self.bold += 1,
            "i" | "em" => self.italic += 1,
            "u" => self.underline += 1,
            "br" => self.current.runs.push(Run {
                line_break: true,
                ..Run::default()
            }),
            "p" | "div" | "section" | "article" | "blockquote" | "ul" | "ol" => self.flush(),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.flush();
                self.current.style = Some(match name {
                    "h1" => "Heading1",
                    "h2" => "Heading2",
                    _ => "Heading3",
                });
            }
            "li" => {
                self.flush();
                self.current.style = Some("ListParagraph");
                self.current.runs.push(Run {
                    text: "\u{2022} ".into(),
                    ..Run::default()
                });
            }
            "table" => {
                self.flush();
                if self.table.is_none() {
                    self.table = Some(OpenTable::default());
                }
            }
            "tr" => {
                self.flush();
                if let Some(table) = &mut self.table {
                    table.rows.push(Vec::new());
                    table.in_cell = false;
                }
            }
            "td" | "th" => {
                self.flush();
                if let Some(table) = &mut self.table {
                    if table.rows.is_empty() {
                        table.rows.push(Vec::new());
                    }
                    if let Some(row) = table.rows.last_mut() {
                        row.push(Vec::new());
                    }
                    table.in_cell = true;
                }
                if name == "th" {
                    self.bold += 1;
                }
            }
            _ => {}
        }
    }

    fn close(&mut self, name: &str) {
        match name {
            "style" | "script" | "head" | "title" => self.skip = self.skip.saturating_sub(1),
            "b" | "strong" => self.bold = self.bold.saturating_sub(1),
            "i" | "em" => self.italic = self.italic.saturating_sub(1),
            "u" => self.underline = self.underline.saturating_sub(1),
            "p" | "div" | "section" | "article" | "blockquote" | "li" | "ul" | "ol" | "h1"
            | "h2" | "h3" | "h4" | "h5" | "h6" => self.flush(),
            "td" | "th" => {
                self.flush();
                if let Some(table) = &mut self.table {
                    table.in_cell = false;
                }
                if name == "th" {
                    self.bold = self.bold.saturating_sub(1);
                }
            }
            "table" => {
                self.flush();
                if let Some(table) = self.table.take() {
                    let rows: Vec<Vec<Vec<Para>>> =
                        table.rows.into_iter().filter(|r| !r.is_empty()).collect();
                    if !rows.is_empty() {
                        self.blocks.push(Block::Table(rows));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Decodes the HTML entities a merged template produces. Pure.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = after;
            continue;
        };
        let entity = &after[..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The document's blocks from merged template HTML. Pure.
fn blocks_of(html: &str) -> Vec<Block> {
    let mut b = Builder::default();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        b.text(&decode_entities(&rest[..start]));
        let after = &rest[start + 1..];
        let Some(end) = after.find('>') else {
            rest = "";
            break;
        };
        let tag = after[..end].trim();
        rest = &after[end + 1..];
        if tag.starts_with('!') || tag.starts_with('?') {
            continue;
        }
        let (closing, body) = match tag.strip_prefix('/') {
            Some(body) => (true, body),
            None => (false, tag),
        };
        let name: String = body
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if closing {
            b.close(&name);
        } else {
            b.open(&name);
            if body.ends_with('/') && name != "br" {
                b.close(&name);
            }
        }
    }
    b.text(&decode_entities(rest));
    b.flush();
    if let Some(table) = b.table.take() {
        let rows: Vec<_> = table.rows.into_iter().filter(|r| !r.is_empty()).collect();
        if !rows.is_empty() {
            b.blocks.push(Block::Table(rows));
        }
    }
    b.blocks
}

fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn is_rtl(text: &str) -> bool {
    text.chars().any(|c| {
        matches!(c, '\u{0590}'..='\u{08FF}' | '\u{FB1D}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}')
    })
}

fn para_xml(para: &Para, out: &mut String) {
    let rtl = para.runs.iter().any(|r| is_rtl(&r.text));
    out.push_str("<w:p>");
    if para.style.is_some() || rtl {
        out.push_str("<w:pPr>");
        if let Some(style) = para.style {
            out.push_str("<w:pStyle w:val=\"");
            out.push_str(style);
            out.push_str("\"/>");
        }
        if rtl {
            out.push_str("<w:bidi/>");
        }
        out.push_str("</w:pPr>");
    }
    for run in &para.runs {
        out.push_str("<w:r>");
        let run_rtl = is_rtl(&run.text);
        if run.bold || run.italic || run.underline || run_rtl {
            out.push_str("<w:rPr>");
            if run.bold {
                out.push_str("<w:b/>");
            }
            if run.italic {
                out.push_str("<w:i/>");
            }
            if run.underline {
                out.push_str("<w:u w:val=\"single\"/>");
            }
            if run_rtl {
                out.push_str("<w:rtl/>");
            }
            out.push_str("</w:rPr>");
        }
        if run.line_break {
            out.push_str("<w:br/>");
        } else {
            out.push_str("<w:t xml:space=\"preserve\">");
            out.push_str(&escape_xml(&run.text));
            out.push_str("</w:t>");
        }
        out.push_str("</w:r>");
    }
    out.push_str("</w:p>");
}

/// `word/document.xml` for the blocks. Pure.
fn document_xml(blocks: &[Block]) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>",
    );
    for block in blocks {
        match block {
            Block::Para(para) => para_xml(para, &mut out),
            Block::Table(rows) => {
                out.push_str(
                    "<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/>\
                     <w:tblW w:w=\"0\" w:type=\"auto\"/></w:tblPr>",
                );
                for row in rows {
                    out.push_str("<w:tr>");
                    for cell in row {
                        out.push_str("<w:tc><w:tcPr><w:tcW w:w=\"0\" w:type=\"auto\"/></w:tcPr>");
                        if cell.is_empty() {
                            // A cell needs at least one paragraph.
                            out.push_str("<w:p/>");
                        }
                        for para in cell {
                            para_xml(para, &mut out);
                        }
                        out.push_str("</w:tc>");
                    }
                    out.push_str("</w:tr>");
                }
                out.push_str("</w:tbl>");
            }
        }
    }
    out.push_str("<w:sectPr/></w:body></w:document>");
    out
}

const CONTENT_TYPES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
<Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>\
<Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/>\
</Types>";

const ROOT_RELS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/>\
</Relationships>";

const DOCUMENT_RELS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>\
</Relationships>";

const STYLES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\"><w:name w:val=\"Normal\"/>\
<w:pPr><w:spacing w:after=\"120\"/></w:pPr><w:rPr><w:sz w:val=\"22\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading1\"><w:name w:val=\"heading 1\"/><w:basedOn w:val=\"Normal\"/>\
<w:pPr><w:keepNext/><w:spacing w:before=\"240\"/><w:outlineLvl w:val=\"0\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"32\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading2\"><w:name w:val=\"heading 2\"/><w:basedOn w:val=\"Normal\"/>\
<w:pPr><w:keepNext/><w:spacing w:before=\"200\"/><w:outlineLvl w:val=\"1\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"28\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading3\"><w:name w:val=\"heading 3\"/><w:basedOn w:val=\"Normal\"/>\
<w:pPr><w:keepNext/><w:spacing w:before=\"160\"/><w:outlineLvl w:val=\"2\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"24\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"ListParagraph\"><w:name w:val=\"List Paragraph\"/><w:basedOn w:val=\"Normal\"/>\
<w:pPr><w:ind w:left=\"360\"/></w:pPr></w:style>\
<w:style w:type=\"table\" w:styleId=\"TableGrid\"><w:name w:val=\"Table Grid\"/><w:tblPr><w:tblBorders>\
<w:top w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>\
<w:left w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>\
<w:bottom w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>\
<w:right w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>\
<w:insideH w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>\
<w:insideV w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>\
</w:tblBorders></w:tblPr></w:style>\
</w:styles>";

fn core_xml(title: &str) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:title>",
    );
    out.push_str(&escape_xml(title));
    out.push_str("</dc:title></cp:coreProperties>");
    out
}

/// A ZIP of `(name, bytes)` parts, each deflated. Pure.
fn zip(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    // 1980-01-01 00:00, the earliest DOS time: the parts carry no real time.
    const DOS_TIME: u16 = 0;
    const DOS_DATE: u16 = (1 << 5) | 1;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in parts {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        // Writing to a Vec cannot fail.
        let compressed = encoder
            .write_all(data)
            .and_then(|()| encoder.finish())
            .unwrap_or_default();
        let offset = u32::try_from(out.len()).unwrap_or(u32::MAX);
        let size = u32::try_from(compressed.len()).unwrap_or(u32::MAX);
        let raw = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        out.extend_from_slice(&8u16.to_le_bytes()); // deflate
        out.extend_from_slice(&DOS_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&raw.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&compressed);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&DOS_TIME.to_le_bytes());
        central.extend_from_slice(&DOS_DATE.to_le_bytes());
        central.extend_from_slice(&crc.sum().to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&raw.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_at = u32::try_from(out.len()).unwrap_or(u32::MAX);
    let central_len = u32::try_from(central.len()).unwrap_or(u32::MAX);
    let count = u16::try_from(parts.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_len.to_le_bytes());
    out.extend_from_slice(&central_at.to_le_bytes());
    out.extend_from_slice(&[0; 2]);
    out
}

/// A DOCX of the merged template HTML, titled `title`. Pure.
pub fn docx_from_html(html: &str, title: &str) -> Vec<u8> {
    let document = document_xml(&blocks_of(html));
    zip(&[
        ("[Content_Types].xml", CONTENT_TYPES.as_bytes().to_vec()),
        ("_rels/.rels", ROOT_RELS.as_bytes().to_vec()),
        (
            "word/_rels/document.xml.rels",
            DOCUMENT_RELS.as_bytes().to_vec(),
        ),
        ("word/document.xml", document.into_bytes()),
        ("word/styles.xml", STYLES.as_bytes().to_vec()),
        ("docProps/core.xml", core_xml(title).into_bytes()),
    ])
}

#[cfg(test)]
mod docx_output {
    use super::*;
    use attome_document::text_extract::{TextFormat, extract, zip_member};

    const OFFER: &str = "<html><head><style>p{color:red}</style></head><body>\
        <h1>Offer letter</h1><p>Dear <b>Sara</b> &amp; team,</p>\
        <ul><li>Start: 1 Nov</li></ul>\
        <table><tr><th>Item</th><th>Amount</th></tr><tr><td>Salary</td><td>12,000</td></tr></table>\
        <p dir=\"rtl\">مرحبا بكم</p></body></html>";

    #[test]
    fn docx_output_is_a_word_package_with_its_parts() {
        let docx = docx_from_html(OFFER, "Offer letter");
        for part in [
            "[Content_Types].xml",
            "_rels/.rels",
            "word/_rels/document.xml.rels",
            "word/document.xml",
            "word/styles.xml",
            "docProps/core.xml",
        ] {
            assert!(zip_member(&docx, part).is_some(), "{part}");
        }
        let core = String::from_utf8(zip_member(&docx, "docProps/core.xml").unwrap_or_default())
            .unwrap_or_default();
        assert!(core.contains("<dc:title>Offer letter</dc:title>"));
    }

    #[test]
    fn docx_output_keeps_the_text_in_order() {
        let docx = docx_from_html(OFFER, "Offer letter");
        let text = extract(TextFormat::Docx, &docx).unwrap_or_default();
        assert_eq!(
            text,
            "Offer letter\nDear Sara & team,\n\u{2022} Start: 1 Nov\nItem\nAmount\nSalary\n12,000\nمرحبا بكم",
            "{text}"
        );
        assert!(!text.contains("color:red"), "the stylesheet is not text");
    }

    #[test]
    fn docx_output_maps_headings_emphasis_tables_and_direction() {
        let xml = document_xml(&blocks_of(OFFER));
        assert!(xml.contains("<w:pStyle w:val=\"Heading1\"/>"));
        assert!(xml.contains("<w:b/>"));
        assert!(xml.contains("<w:tbl>"));
        assert_eq!(xml.matches("<w:tr>").count(), 2);
        assert!(xml.contains("<w:bidi/>"));
        assert!(xml.contains("&amp; team"));
    }

    #[test]
    fn docx_output_decodes_entities_and_collapses_space() {
        assert_eq!(
            decode_entities("a&lt;b&gt; &#1605; &#x41; &bogus; &"),
            "a<b> م A &bogus; &"
        );
        let blocks = blocks_of("<p>  one\n   two  </p><p></p>");
        assert_eq!(blocks.len(), 1);
        let Block::Para(para) = &blocks[0] else {
            panic!("a paragraph");
        };
        let text: String = para.runs.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(text.trim(), "one two");
    }
}
