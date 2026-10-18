//! The little DER this crate needs: writing a certificate signing request
//! and reading the issuer, serial number and signature of a certificate.
//! Definite lengths only, as DER requires; nothing here parses anything but
//! certificates ZATCA issues and requests this crate writes.

/// Universal tags used here.
pub mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const IA5_STRING: u8 = 0x16;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
}

/// A DER element: tag, length, content.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of already-encoded elements.
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

/// A SET of already-encoded elements, sorted as DER requires.
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    tlv(tag::SET, &sorted.concat())
}

/// An OBJECT IDENTIFIER from its dotted form.
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| a.parse().unwrap_or_default())
        .collect();
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        push_base128(&mut body, arcs[0] * 40 + arcs[1]);
        for &arc in &arcs[2..] {
            push_base128(&mut body, arc);
        }
    }
    tlv(tag::OID, &body)
}

fn push_base128(out: &mut Vec<u8>, mut value: u64) {
    let mut groups = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        groups.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    groups.reverse();
    out.extend_from_slice(&groups);
}

/// The dotted form of an OID's content bytes.
pub fn oid_to_string(content: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value = 0u64;
    for &b in content {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// A UTF8String.
pub fn utf8(text: &str) -> Vec<u8> {
    tlv(tag::UTF8_STRING, text.as_bytes())
}

/// A PrintableString.
pub fn printable(text: &str) -> Vec<u8> {
    tlv(tag::PRINTABLE_STRING, text.as_bytes())
}

/// A small non-negative INTEGER.
pub fn integer(value: u8) -> Vec<u8> {
    tlv(tag::INTEGER, &[value])
}

/// A BIT STRING with no unused bits.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0u8];
    content.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &content)
}

/// A context-specific constructed element `[n]`.
pub fn context(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// One parsed element: its tag, its content and the whole encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Reads the element at the start of `input` and the rest after it.
pub fn read(input: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*input.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    let content = input.get(header..end)?;
    Some((
        Element {
            tag,
            content,
            raw: &input[..end],
        },
        &input[end..],
    ))
}

/// The elements inside a constructed element's content.
pub fn children(content: &[u8]) -> Option<Vec<Element<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (element, next) = read(rest)?;
        out.push(element);
        rest = next;
    }
    Some(out)
}

/// An unsigned big-endian integer in decimal.
pub fn big_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    if digits.is_empty() {
        return "0".into();
    }
    let mut out = Vec::new();
    while !digits.is_empty() {
        let mut remainder = 0u32;
        let mut next = Vec::with_capacity(digits.len());
        for &d in &digits {
            let acc = (remainder << 8) | u32::from(d);
            let q = acc / 10;
            remainder = acc % 10;
            if !(next.is_empty() && q == 0) {
                next.push(q as u8);
            }
        }
        out.push(b'0' + remainder as u8);
        digits = next;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zatca_api_der_round_trips_oids_lengths_and_integers() {
        let encoded = oid("1.3.6.1.4.1.311.20.2");
        let (element, rest) = read(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(oid_to_string(element.content), "1.3.6.1.4.1.311.20.2");
        let long = tlv(tag::OCTET_STRING, &[7u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(read(&long).unwrap().0.content.len(), 300);
        assert_eq!(big_decimal(&[0x01, 0x00]), "256");
        assert_eq!(big_decimal(&[0x00]), "0");
        assert_eq!(
            big_decimal(&[0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "313594649253062377473"
        );
    }
}
