//! P4-T1: a report run as a PowerPoint file (OOXML presentation), written
//! here with no dependency: a title slide, then the rows as a table, at most
//! [`ROWS_PER_SLIDE`] a slide, the header repeated on each. Text that holds
//! Arabic is laid out right to left. The formula guard applies to cells as it
//! does to CSV and XLSX (`crate::render::guard_formula`), since a table cell
//! pasted into a spreadsheet would run the same way.
//!
//! The package is a zip whose entries are stored (not compressed) — every
//! PowerPoint reader accepts that — built by [`ZipWriter`] with its own
//! CRC-32. A run over [`MAX_PPTX_ROWS`] rows is refused: a slide deck is a
//! summary, and XLSX carries the rest.

use attome_types::AppError;
use serde_json::Value;

/// Rows on one table slide.
pub const ROWS_PER_SLIDE: usize = 12;
/// The most rows a deck carries.
pub const MAX_PPTX_ROWS: usize = 600;
/// The most columns a table slide shows; the rest are left out of the deck.
pub const MAX_PPTX_COLUMNS: usize = 10;

/// Slide size: 16:9, in EMU.
const SLIDE_CX: i64 = 12_192_000;
const SLIDE_CY: i64 = 6_858_000;
const MARGIN: i64 = 457_200;
const ROW_HEIGHT: i64 = 370_840;

// ── CRC-32 and a stored zip ────────────────────────────────────────────────

/// The IEEE CRC-32 of `data` (the zip checksum). Pure.
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc = table[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// A zip archive of stored entries.
#[derive(Default)]
pub struct ZipWriter {
    out: Vec<u8>,
    central: Vec<u8>,
    entries: u16,
}

impl ZipWriter {
    /// Adds one file.
    pub fn add(&mut self, name: &str, data: &[u8]) -> Result<(), AppError> {
        let too_big = || AppError::internal("pptx part too large for a zip entry");
        let size = u32::try_from(data.len()).map_err(|_| too_big())?;
        let offset = u32::try_from(self.out.len()).map_err(|_| too_big())?;
        let name_len = u16::try_from(name.len()).map_err(|_| too_big())?;
        let crc = crc32(data);
        // Local file header: version 2.0, UTF-8 names (bit 11), stored.
        let mut local = Vec::with_capacity(30 + name.len());
        local.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0x0800u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // stored
        local.extend_from_slice(&0u16.to_le_bytes()); // time
        local.extend_from_slice(&0x0021u16.to_le_bytes()); // 1980-01-01
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&name_len.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(&local);
        self.out.extend_from_slice(data);
        // Central directory entry.
        self.central
            .extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        self.central.extend_from_slice(&20u16.to_le_bytes()); // made by
        self.central.extend_from_slice(&20u16.to_le_bytes()); // needed
        self.central.extend_from_slice(&0x0800u16.to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes());
        self.central.extend_from_slice(&0x0021u16.to_le_bytes());
        self.central.extend_from_slice(&crc.to_le_bytes());
        self.central.extend_from_slice(&size.to_le_bytes());
        self.central.extend_from_slice(&size.to_le_bytes());
        self.central.extend_from_slice(&name_len.to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes()); // extra
        self.central.extend_from_slice(&0u16.to_le_bytes()); // comment
        self.central.extend_from_slice(&0u16.to_le_bytes()); // disk
        self.central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        self.central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        self.central.extend_from_slice(&offset.to_le_bytes());
        self.central.extend_from_slice(name.as_bytes());
        self.entries = self.entries.checked_add(1).ok_or_else(too_big)?;
        Ok(())
    }

    /// The finished archive.
    pub fn finish(mut self) -> Result<Vec<u8>, AppError> {
        let too_big = || AppError::internal("pptx too large for a zip archive");
        let offset = u32::try_from(self.out.len()).map_err(|_| too_big())?;
        let size = u32::try_from(self.central.len()).map_err(|_| too_big())?;
        let central = std::mem::take(&mut self.central);
        self.out.extend_from_slice(&central);
        self.out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out.extend_from_slice(&self.entries.to_le_bytes());
        self.out.extend_from_slice(&self.entries.to_le_bytes());
        self.out.extend_from_slice(&size.to_le_bytes());
        self.out.extend_from_slice(&offset.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        Ok(self.out)
    }
}

// ── The presentation ───────────────────────────────────────────────────────

/// Text safe inside XML. Pure.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters other than tab and line breaks are not
            // allowed in XML 1.0.
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

/// Whether `text` holds Arabic letters. Pure.
pub fn has_arabic(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c as u32, 0x0600..=0x06FF | 0x0750..=0x077F | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF))
}

fn cell_text(value: &Value, guard: bool) -> String {
    let text = match value {
        Value::Null => String::new(),
        Value::String(s) if guard => crate::render::guard_formula(s).into_owned(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    };
    text.chars().take(500).collect()
}

/// One paragraph of text, right to left when it holds Arabic.
fn paragraph(text: &str, size: u32, bold: bool) -> String {
    let rtl = if has_arabic(text) {
        " rtl=\"1\" algn=\"r\""
    } else {
        ""
    };
    let b = if bold { " b=\"1\"" } else { "" };
    format!(
        "<a:p><a:pPr{rtl}/><a:r><a:rPr lang=\"{lang}\" sz=\"{size}\"{b} dirty=\"0\"/><a:t>{text}</a:t></a:r></a:p>",
        lang = if has_arabic(text) { "ar-SA" } else { "en-US" },
        text = xml_escape(text),
    )
}

fn text_box(id: u32, name: &str, y: i64, cy: i64, text: &str, size: u32) -> String {
    format!(
        "<p:sp><p:nvSpPr><p:cNvPr id=\"{id}\" name=\"{name}\"/><p:cNvSpPr txBox=\"1\"/><p:nvPr/></p:nvSpPr>\
         <p:spPr><a:xfrm><a:off x=\"{MARGIN}\" y=\"{y}\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm>\
         <a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr>\
         <p:txBody><a:bodyPr wrap=\"square\"/><a:lstStyle/>{p}</p:txBody></p:sp>",
        cx = SLIDE_CX - 2 * MARGIN,
        p = paragraph(text, size, true),
    )
}

fn slide_xml(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
         xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
         <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\
         <p:grpSpPr/>{body}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"
    )
}

fn table_xml(header: &[String], rows: &[&Value], guard: bool) -> String {
    let cols = header.len().max(1) as i64;
    let width = SLIDE_CX - 2 * MARGIN;
    let col_w = width / cols;
    let cell = |text: &str, bold: bool| {
        format!(
            "<a:tc><a:txBody><a:bodyPr/><a:lstStyle/>{}</a:txBody><a:tcPr/></a:tc>",
            paragraph(text, 1100, bold)
        )
    };
    let mut xml = String::new();
    xml.push_str("<a:tbl><a:tblPr firstRow=\"1\" bandRow=\"1\"/><a:tblGrid>");
    for _ in header {
        xml.push_str(&format!("<a:gridCol w=\"{col_w}\"/>"));
    }
    xml.push_str("</a:tblGrid>");
    xml.push_str(&format!("<a:tr h=\"{ROW_HEIGHT}\">"));
    for name in header {
        xml.push_str(&cell(name, true));
    }
    xml.push_str("</a:tr>");
    for row in rows {
        xml.push_str(&format!("<a:tr h=\"{ROW_HEIGHT}\">"));
        for name in header {
            xml.push_str(&cell(
                &cell_text(row.get(name).unwrap_or(&Value::Null), guard),
                false,
            ));
        }
        xml.push_str("</a:tr>");
    }
    xml.push_str("</a:tbl>");
    let cy = ROW_HEIGHT * (rows.len() as i64 + 1);
    format!(
        "<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id=\"3\" name=\"Table\"/><p:cNvGraphicFramePr>\
         <a:graphicFrameLocks noGrp=\"1\"/></p:cNvGraphicFramePr><p:nvPr/></p:nvGraphicFramePr>\
         <p:xfrm><a:off x=\"{MARGIN}\" y=\"1371600\"/><a:ext cx=\"{width}\" cy=\"{cy}\"/></p:xfrm>\
         <a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/table\">{xml}\
         </a:graphicData></a:graphic></p:graphicFrame>"
    )
}

const RELS_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/>\
</Relationships>";

const MASTER_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<p:sldMaster xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>\
<p:clrMap bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" accent3=\"accent3\" \
accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/>\
<p:sldLayoutIdLst><p:sldLayoutId id=\"2147483649\" r:id=\"rId1\"/></p:sldLayoutIdLst>\
</p:sldMaster>";

const MASTER_RELS_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/>\
<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme\" Target=\"../theme/theme1.xml\"/>\
</Relationships>";

const LAYOUT_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<p:sldLayout xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" type=\"blank\" preserve=\"1\">\
<p:cSld name=\"Blank\"><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>\
<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>";

const LAYOUT_RELS_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"../slideMasters/slideMaster1.xml\"/>\
</Relationships>";

const SLIDE_RELS_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/>\
</Relationships>";

const THEME_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<a:theme xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" name=\"Attome\"><a:themeElements>\
<a:clrScheme name=\"Attome\"><a:dk1><a:srgbClr val=\"1F2933\"/></a:dk1><a:lt1><a:srgbClr val=\"FFFFFF\"/></a:lt1>\
<a:dk2><a:srgbClr val=\"323F4B\"/></a:dk2><a:lt2><a:srgbClr val=\"F5F7FA\"/></a:lt2>\
<a:accent1><a:srgbClr val=\"0B6E4F\"/></a:accent1><a:accent2><a:srgbClr val=\"2D7FF9\"/></a:accent2>\
<a:accent3><a:srgbClr val=\"F7B32B\"/></a:accent3><a:accent4><a:srgbClr val=\"D64545\"/></a:accent4>\
<a:accent5><a:srgbClr val=\"7B61FF\"/></a:accent5><a:accent6><a:srgbClr val=\"3EBD93\"/></a:accent6>\
<a:hlink><a:srgbClr val=\"2D7FF9\"/></a:hlink><a:folHlink><a:srgbClr val=\"7B61FF\"/></a:folHlink></a:clrScheme>\
<a:fontScheme name=\"Attome\"><a:majorFont><a:latin typeface=\"Calibri\"/><a:ea typeface=\"\"/><a:cs typeface=\"Arial\"/></a:majorFont>\
<a:minorFont><a:latin typeface=\"Calibri\"/><a:ea typeface=\"\"/><a:cs typeface=\"Arial\"/></a:minorFont></a:fontScheme>\
<a:fmtScheme name=\"Attome\"><a:fillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>\
<a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:fillStyleLst>\
<a:lnStyleLst><a:ln w=\"6350\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln>\
<a:ln w=\"12700\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln>\
<a:ln w=\"19050\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln></a:lnStyleLst>\
<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle>\
<a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>\
<a:bgFillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>\
<a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>\
</a:themeElements></a:theme>";

/// The slides `rows` rows take: the title slide and the table slides. Pure.
pub fn slide_count(rows: usize) -> usize {
    1 + rows.div_ceil(ROWS_PER_SLIDE).max(1)
}

/// Renders a report run as a deck: `title`, `subtitle` (e.g. the run's time
/// and row count) and the rows. See the module doc.
pub fn render_pptx(
    title: &str,
    subtitle: &str,
    header: &[String],
    rows: &[Value],
    guard: bool,
) -> Result<Vec<u8>, AppError> {
    if rows.len() > MAX_PPTX_ROWS {
        return Err(AppError::Validation(format!(
            "a slide deck holds at most {MAX_PPTX_ROWS} rows; use xlsx for this report"
        )));
    }
    let header: Vec<String> = header.iter().take(MAX_PPTX_COLUMNS).cloned().collect();
    let count = slide_count(rows.len());
    let mut zip = ZipWriter::default();

    let mut types = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
         <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
         <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
         <Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/>\
         <Override PartName=\"/ppt/slideMasters/slideMaster1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml\"/>\
         <Override PartName=\"/ppt/slideLayouts/slideLayout1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml\"/>\
         <Override PartName=\"/ppt/theme/theme1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.theme+xml\"/>",
    );
    let mut presentation_rels = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"slideMasters/slideMaster1.xml\"/>",
    );
    let mut slide_ids = String::new();
    for n in 1..=count {
        types.push_str(&format!(
            "<Override PartName=\"/ppt/slides/slide{n}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>"
        ));
        presentation_rels.push_str(&format!(
            "<Relationship Id=\"rId{rid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" Target=\"slides/slide{n}.xml\"/>",
            rid = n + 1
        ));
        slide_ids.push_str(&format!(
            "<p:sldId id=\"{}\" r:id=\"rId{}\"/>",
            255 + n,
            n + 1
        ));
    }
    types.push_str("</Types>");
    presentation_rels.push_str(&format!(
        "<Relationship Id=\"rId{rid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme\" Target=\"theme/theme1.xml\"/></Relationships>",
        rid = count + 2
    ));
    let presentation = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <p:presentation xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
         xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
         <p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rId1\"/></p:sldMasterIdLst>\
         <p:sldIdLst>{slide_ids}</p:sldIdLst>\
         <p:sldSz cx=\"{SLIDE_CX}\" cy=\"{SLIDE_CY}\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/>\
         </p:presentation>"
    );

    zip.add("[Content_Types].xml", types.as_bytes())?;
    zip.add("_rels/.rels", RELS_XML.as_bytes())?;
    zip.add("ppt/presentation.xml", presentation.as_bytes())?;
    zip.add(
        "ppt/_rels/presentation.xml.rels",
        presentation_rels.as_bytes(),
    )?;
    zip.add("ppt/slideMasters/slideMaster1.xml", MASTER_XML.as_bytes())?;
    zip.add(
        "ppt/slideMasters/_rels/slideMaster1.xml.rels",
        MASTER_RELS_XML.as_bytes(),
    )?;
    zip.add("ppt/slideLayouts/slideLayout1.xml", LAYOUT_XML.as_bytes())?;
    zip.add(
        "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
        LAYOUT_RELS_XML.as_bytes(),
    )?;
    zip.add("ppt/theme/theme1.xml", THEME_XML.as_bytes())?;

    // The title slide.
    let title_slide = slide_xml(&format!(
        "{}{}",
        text_box(2, "Title", 2_286_000, 1_143_000, title, 4000),
        text_box(3, "Subtitle", 3_581_400, 685_800, subtitle, 2000),
    ));
    zip.add("ppt/slides/slide1.xml", title_slide.as_bytes())?;
    zip.add(
        "ppt/slides/_rels/slide1.xml.rels",
        SLIDE_RELS_XML.as_bytes(),
    )?;

    // The table slides; an empty run gets one table slide with the header.
    let all: Vec<&Value> = rows.iter().collect();
    let none: &[&Value] = &[];
    let chunks: Vec<&[&Value]> = if all.is_empty() {
        vec![none]
    } else {
        all.chunks(ROWS_PER_SLIDE).collect()
    };
    let pages = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let heading = if pages > 1 {
            format!("{title} ({}/{pages})", i + 1)
        } else {
            title.to_owned()
        };
        let body = format!(
            "{}{}",
            text_box(2, "Title", MARGIN, 685_800, &heading, 2400),
            table_xml(&header, chunk, guard),
        );
        let n = i + 2;
        zip.add(
            &format!("ppt/slides/slide{n}.xml"),
            slide_xml(&body).as_bytes(),
        )?;
        zip.add(
            &format!("ppt/slides/_rels/slide{n}.xml.rels"),
            SLIDE_RELS_XML.as_bytes(),
        )?;
    }
    zip.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names of a stored zip's entries, read back from its central
    /// directory.
    fn entry_names(zip: &[u8]) -> Vec<String> {
        let eocd = zip.len() - 22;
        assert_eq!(&zip[eocd..eocd + 4], &0x0605_4B50u32.to_le_bytes());
        let count = u16::from_le_bytes([zip[eocd + 10], zip[eocd + 11]]) as usize;
        let mut at = u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let mut names = Vec::new();
        for _ in 0..count {
            assert_eq!(&zip[at..at + 4], &0x0201_4B50u32.to_le_bytes());
            let len = u16::from_le_bytes([zip[at + 28], zip[at + 29]]) as usize;
            names.push(String::from_utf8(zip[at + 46..at + 46 + len].to_vec()).unwrap());
            at += 46 + len;
        }
        names
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_deck_has_a_title_slide_and_table_slides() {
        let header = vec!["name".to_owned(), "amount".to_owned()];
        let rows: Vec<Value> = (0..25)
            .map(|i| serde_json::json!({ "name": format!("عميل {i}"), "amount": i }))
            .collect();
        let bytes = render_pptx("Sales", "25 rows", &header, &rows, true).expect("rendered");
        assert_eq!(&bytes[..4], b"PK\x03\x04");
        let names = entry_names(&bytes);
        assert!(names.contains(&"[Content_Types].xml".to_owned()));
        assert!(names.contains(&"ppt/presentation.xml".to_owned()));
        // 25 rows at 12 a slide: three table slides after the title.
        assert_eq!(slide_count(25), 4);
        assert!(names.contains(&"ppt/slides/slide4.xml".to_owned()));
        assert!(!names.contains(&"ppt/slides/slide5.xml".to_owned()));
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("rtl=\"1\""), "Arabic cells run right to left");
        assert!(text.contains("Sales (3/3)"));
    }

    #[test]
    fn cells_are_escaped_and_guarded() {
        let header = vec!["note".to_owned()];
        let rows = vec![serde_json::json!({ "note": "=1+1 <b>&</b>" })];
        let bytes = render_pptx("T", "", &header, &rows, true).expect("rendered");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("&apos;=1+1 &lt;b&gt;&amp;&lt;/b&gt;"));
        let many: Vec<Value> = (0..=MAX_PPTX_ROWS)
            .map(|i| serde_json::json!({ "note": i }))
            .collect();
        assert!(render_pptx("T", "", &header, &many, true).is_err());
        assert_eq!(slide_count(0), 2, "an empty run still shows its header");
    }
}
