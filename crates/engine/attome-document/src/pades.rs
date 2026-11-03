//! K4-T2: seal a finished PDF with a PAdES signature (pure Rust).
//!
//! [`seal`] appends an incremental update to the PDF, so the original bytes
//! stay a prefix of the sealed file and an earlier signature still covers its
//! revision. The update adds an invisible signature field on the first page
//! (listed in the catalog's `/AcroForm` with `/SigFlags 3`) whose value is a
//! `/Type /Sig` dictionary with `/SubFilter /ETSI.CAdES.detached`: a CMS
//! `SignedData` (RFC 5652) over the `/ByteRange`, which is the whole file
//! except the hex `/Contents` itself. The signed attributes are the three
//! PAdES baseline B-B asks for: content type, message digest and the ESS
//! signing-certificate-v2 (the certificate's SHA-256 with its issuer and
//! serial); the signing time is the dictionary's `/M`, not an attribute, as
//! PAdES requires. No timestamp (RFC 3161) is added: the step leaves it
//! optional and the deployment has no timestamp authority set.
//!
//! The key is the deployment's signing certificate ([`SealKey::from_pem`]):
//! an RSA key (PKCS #1 v1.5, SHA-256) or a P-256 key (ECDSA, SHA-256), in
//! PKCS #8 PEM (RSA also PKCS #1), with the certificate chain, signer first.
//! The key must belong to the first certificate.
//!
//! The reader resolves objects through the cross-reference data: classic
//! tables and cross-reference streams (Flate, PNG predictors), objects inside
//! object streams, `/Prev` and `/XRefStm` chains. The update is written in
//! the style of the last section (a table, or a stream). Encrypted PDFs are
//! refused. [`verify`] checks the last signature of a file the same way a
//! validator does: the byte range covers the whole file but the contents,
//! the digest matches, and the signature verifies under the certificate.

use std::collections::{HashMap, HashSet};
use std::io::Read;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair};
use sha2::{Digest, Sha256};

/// Why a PDF could not be sealed or verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Not a PDF this reader can follow (the reason says where it stopped).
    Unreadable(String),
    /// The PDF is encrypted; it is refused rather than sealed.
    Encrypted,
    /// The key or certificate is unusable.
    Key(String),
    /// No signature, or one that does not check.
    Invalid(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(why) => write!(f, "the PDF could not be read: {why}"),
            Self::Encrypted => f.write_str("the PDF is encrypted"),
            Self::Key(why) => write!(f, "the signing key is unusable: {why}"),
            Self::Invalid(why) => write!(f, "the signature does not check: {why}"),
        }
    }
}

impl std::error::Error for SealError {}

fn unreadable(why: impl Into<String>) -> SealError {
    SealError::Unreadable(why.into())
}

// ── The key ─────────────────────────────────────────────────────────────────

enum Signer {
    Rsa(RsaKeyPair),
    EcP256(EcdsaKeyPair),
}

/// The deployment's signing key with its certificate chain.
pub struct SealKey {
    signer: Signer,
    /// DER certificates, the signer's first.
    chain: Vec<Vec<u8>>,
    /// The signer certificate's subject common name.
    common_name: String,
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealKey")
            .field("common_name", &self.common_name)
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// The blocks of a PEM text with their labels, decoded.
fn pem_blocks(text: &str) -> Result<Vec<(String, Vec<u8>)>, SealError> {
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = Some(rest.trim_end_matches('-').to_owned());
            body.clear();
        } else if line.starts_with("-----END ") {
            let Some(l) = label.take() else {
                return Err(SealError::Key("a PEM END line without its BEGIN".into()));
            };
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .map_err(|_| SealError::Key(format!("the PEM block {l} is not base64")))?;
            out.push((l, der));
        } else if label.is_some() && !line.contains(':') {
            body.push_str(line);
        }
    }
    Ok(out)
}

impl SealKey {
    /// Reads the certificate chain (PEM, the signer's certificate first) and
    /// the private key (PEM). Refuses a key that is not the first
    /// certificate's.
    pub fn from_pem(certificates_pem: &str, key_pem: &str) -> Result<Self, SealError> {
        let chain: Vec<Vec<u8>> = pem_blocks(certificates_pem)?
            .into_iter()
            .filter(|(l, _)| l == "CERTIFICATE")
            .map(|(_, der)| der)
            .collect();
        let Some(first) = chain.first() else {
            return Err(SealError::Key("no certificate".into()));
        };
        let (_, cert) = x509_parser::parse_x509_certificate(first)
            .map_err(|_| SealError::Key("the certificate is not DER X.509".into()))?;
        let spki_key = cert.public_key().subject_public_key.data.to_vec();
        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("")
            .to_owned();
        let keys = pem_blocks(key_pem)?;
        let Some((label, der)) = keys.into_iter().find(|(l, _)| l.ends_with("PRIVATE KEY")) else {
            return Err(SealError::Key("no private key".into()));
        };
        let signer = match label.as_str() {
            "PRIVATE KEY" => match RsaKeyPair::from_pkcs8(&der) {
                Ok(k) => Signer::Rsa(k),
                Err(_) => EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &der,
                    &SystemRandom::new(),
                )
                .map(Signer::EcP256)
                .map_err(|_| {
                    SealError::Key("the key is neither RSA nor P-256 in PKCS #8".into())
                })?,
            },
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der)
                .map(Signer::Rsa)
                .map_err(|_| SealError::Key("the RSA key does not parse".into()))?,
            other => {
                return Err(SealError::Key(format!(
                    "a {other} is not supported; use PKCS #8 (BEGIN PRIVATE KEY)"
                )));
            }
        };
        let public = match &signer {
            Signer::Rsa(k) => k.public_key().as_ref().to_vec(),
            Signer::EcP256(k) => k.public_key().as_ref().to_vec(),
        };
        if public != spki_key {
            return Err(SealError::Key(
                "the private key does not belong to the first certificate".into(),
            ));
        }
        Ok(Self {
            signer,
            chain,
            common_name,
        })
    }

    /// The signer certificate's common name.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    fn signature_len(&self) -> usize {
        match &self.signer {
            Signer::Rsa(k) => k.public().modulus_len(),
            // DER ECDSA P-256 signatures are at most 72 bytes.
            Signer::EcP256(_) => 72,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SealError> {
        let rng = SystemRandom::new();
        match &self.signer {
            Signer::Rsa(k) => {
                let mut out = vec![0u8; k.public().modulus_len()];
                k.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut out)
                    .map_err(|_| SealError::Key("RSA signing failed".into()))?;
                Ok(out)
            }
            Signer::EcP256(k) => k
                .sign(&rng, message)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| SealError::Key("ECDSA signing failed".into())),
        }
    }

    fn signature_algorithm(&self) -> Vec<u8> {
        match &self.signer {
            Signer::Rsa(_) => der::seq(&[&der::oid(OID_RSA_ENCRYPTION), &der::null()]),
            Signer::EcP256(_) => der::seq(&[&der::oid(OID_ECDSA_SHA256)]),
        }
    }
}

// ── DER ─────────────────────────────────────────────────────────────────────

const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SIGNING_CERT_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

mod der {
    /// One element: its tag, its content and its whole encoding.
    pub type Element<'a> = (u8, &'a [u8], &'a [u8]);
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = content.len();
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let bytes: Vec<u8> = n
                .to_be_bytes()
                .iter()
                .copied()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(content);
        out
    }

    pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    /// A DER SET OF: its elements sorted by their encodings.
    pub fn set_of(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
        parts.sort();
        tlv(0x31, &parts.concat())
    }

    pub fn oid(content: &[u8]) -> Vec<u8> {
        tlv(0x06, content)
    }

    pub fn null() -> Vec<u8> {
        vec![0x05, 0x00]
    }

    pub fn int_small(v: u8) -> Vec<u8> {
        vec![0x02, 0x01, v]
    }

    pub fn octets(content: &[u8]) -> Vec<u8> {
        tlv(0x04, content)
    }

    /// One element and what follows it.
    pub fn read(input: &[u8]) -> Option<(Element<'_>, &[u8])> {
        let tag = *input.first()?;
        let first = *input.get(1)? as usize;
        let (len, header) = if first < 0x80 {
            (first, 2)
        } else {
            let k = first & 0x7F;
            if k == 0 || k > 4 {
                return None;
            }
            let mut n = 0usize;
            for i in 0..k {
                n = (n << 8) | *input.get(2 + i)? as usize;
            }
            (n, 2 + k)
        };
        let end = header.checked_add(len)?;
        if end > input.len() {
            return None;
        }
        Some(((tag, &input[header..end], &input[..end]), &input[end..]))
    }

    /// The elements inside a constructed value.
    pub fn children(mut content: &[u8]) -> Option<Vec<Element<'_>>> {
        let mut out = Vec::new();
        while !content.is_empty() {
            let (element, rest) = read(content)?;
            out.push(element);
            content = rest;
        }
        Some(out)
    }
}

/// The CMS `SignedData` (detached) over `digest`, the byte range's SHA-256.
fn signed_data(key: &SealKey, digest: &[u8]) -> Result<Vec<u8>, SealError> {
    signed_data_with(key, digest, |message| key.sign(message))
}

fn signed_data_with(
    key: &SealKey,
    digest: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, SealError>,
) -> Result<Vec<u8>, SealError> {
    let first = &key.chain[0];
    let (_, cert) = x509_parser::parse_x509_certificate(first)
        .map_err(|_| SealError::Key("the certificate is not DER X.509".into()))?;
    let issuer = cert.issuer().as_raw().to_vec();
    let serial = der::tlv(0x02, cert.tbs_certificate.raw_serial());
    let sha256 = der::seq(&[&der::oid(OID_SHA256)]);

    // ESS signing-certificate-v2: SEQ { SEQ OF ESSCertIDv2 }, the hash
    // algorithm left at its SHA-256 default.
    let issuer_serial = der::seq(&[&der::seq(&[&der::tlv(0xA4, &issuer)]), &serial]);
    let cert_id = der::seq(&[&der::octets(&Sha256::digest(first)), &issuer_serial]);
    let signing_cert = der::seq(&[&der::seq(&[&cert_id])]);

    let attributes = vec![
        der::seq(&[
            &der::oid(OID_CONTENT_TYPE),
            &der::set_of(vec![der::oid(OID_DATA)]),
        ]),
        der::seq(&[
            &der::oid(OID_MESSAGE_DIGEST),
            &der::set_of(vec![der::octets(digest)]),
        ]),
        der::seq(&[
            &der::oid(OID_SIGNING_CERT_V2),
            &der::set_of(vec![signing_cert]),
        ]),
    ];
    // Signed as a SET OF (tag 0x31), carried as [0] IMPLICIT.
    let signed_attrs = der::set_of(attributes);
    let signature = sign(&signed_attrs)?;
    let mut carried = signed_attrs.clone();
    carried[0] = 0xA0;

    let signer_info = der::seq(&[
        &der::int_small(1),
        &der::seq(&[&issuer, &serial]),
        &sha256,
        &carried,
        &key.signature_algorithm(),
        &der::octets(&signature),
    ]);
    let certificates = der::tlv(0xA0, &key.chain.concat());
    let content = der::seq(&[
        &der::int_small(1),
        &der::set_of(vec![sha256.clone()]),
        &der::seq(&[&der::oid(OID_DATA)]),
        &certificates,
        &der::set_of(vec![signer_info]),
    ]);
    Ok(der::seq(&[
        &der::oid(OID_SIGNED_DATA),
        &der::tlv(0xA0, &content),
    ]))
}

// ── PDF objects ─────────────────────────────────────────────────────────────

/// A PDF object. Names, strings and numbers keep their source text, so a
/// rewritten object says exactly what it said.
#[derive(Debug, Clone, PartialEq)]
enum Obj {
    Null,
    Bool(bool),
    /// A number's text.
    Num(Vec<u8>),
    /// A name without its slash, as written (escapes kept).
    Name(Vec<u8>),
    /// A literal or hex string with its delimiters.
    Str(Vec<u8>),
    Arr(Vec<Obj>),
    Dict(Vec<(Vec<u8>, Obj)>),
    Ref(u32, u16),
}

impl Obj {
    fn get(&self, key: &str) -> Option<&Obj> {
        match self {
            Obj::Dict(entries) => entries
                .iter()
                .find(|(k, _)| k.as_slice() == key.as_bytes())
                .map(|(_, v)| v),
            _ => None,
        }
    }

    fn set(&mut self, key: &str, value: Obj) {
        if let Obj::Dict(entries) = self {
            if let Some(slot) = entries
                .iter_mut()
                .find(|(k, _)| k.as_slice() == key.as_bytes())
            {
                slot.1 = value;
            } else {
                entries.push((key.as_bytes().to_vec(), value));
            }
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Obj::Num(t) => std::str::from_utf8(t).ok()?.parse().ok(),
            _ => None,
        }
    }

    fn is_name(&self, name: &str) -> bool {
        matches!(self, Obj::Name(n) if n.as_slice() == name.as_bytes())
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Obj::Null => out.extend_from_slice(b"null"),
            Obj::Bool(true) => out.extend_from_slice(b"true"),
            Obj::Bool(false) => out.extend_from_slice(b"false"),
            Obj::Num(t) | Obj::Str(t) => out.extend_from_slice(t),
            Obj::Name(n) => {
                out.push(b'/');
                out.extend_from_slice(n);
            }
            Obj::Arr(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b' ');
                    }
                    item.write(out);
                }
                out.push(b']');
            }
            Obj::Dict(entries) => {
                out.extend_from_slice(b"<<");
                for (k, v) in entries {
                    out.push(b'/');
                    out.extend_from_slice(k);
                    out.push(b' ');
                    v.write(out);
                }
                out.extend_from_slice(b">>");
            }
            Obj::Ref(n, g) => out.extend_from_slice(format!("{n} {g} R").as_bytes()),
        }
    }
}

fn num(v: i64) -> Obj {
    Obj::Num(v.to_string().into_bytes())
}

fn name(n: &str) -> Obj {
    Obj::Name(n.as_bytes().to_vec())
}

/// A text string: a literal when it is printable ASCII, otherwise UTF-16BE
/// with its byte-order mark, in hex.
fn text(s: &str) -> Obj {
    if s.bytes().all(|b| (0x20..0x7F).contains(&b)) {
        let mut t = vec![b'('];
        for b in s.bytes() {
            if matches!(b, b'(' | b')' | b'\\') {
                t.push(b'\\');
            }
            t.push(b);
        }
        t.push(b')');
        Obj::Str(t)
    } else {
        let mut t = b"<FEFF".to_vec();
        for unit in s.encode_utf16() {
            t.extend_from_slice(format!("{unit:04X}").as_bytes());
        }
        t.push(b'>');
        Obj::Str(t)
    }
}

fn is_white(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0C' | b'\0')
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// A reader over PDF syntax.
struct Lexer<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a [u8], pos: usize) -> Self {
        Self { s, pos }
    }

    fn skip_white(&mut self) {
        while self.pos < self.s.len() {
            let b = self.s[self.pos];
            if is_white(b) {
                self.pos += 1;
            } else if b == b'%' {
                while self.pos < self.s.len() && !matches!(self.s[self.pos], b'\r' | b'\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    /// A bare word (number, keyword) at the cursor, not consumed.
    fn peek_word(&mut self) -> &'a [u8] {
        self.skip_white();
        let start = self.pos;
        let mut end = start;
        while end < self.s.len() && !is_white(self.s[end]) && !is_delim(self.s[end]) {
            end += 1;
        }
        &self.s[start..end]
    }

    fn word(&mut self) -> &'a [u8] {
        let w = self.peek_word();
        self.pos += w.len();
        w
    }

    fn expect(&mut self, keyword: &[u8]) -> Result<(), SealError> {
        if self.word() == keyword {
            Ok(())
        } else {
            Err(unreadable(format!(
                "expected `{}` at byte {}",
                String::from_utf8_lossy(keyword),
                self.pos
            )))
        }
    }

    fn uint(&mut self) -> Option<u64> {
        std::str::from_utf8(self.word()).ok()?.parse().ok()
    }

    fn object(&mut self, depth: usize) -> Result<Obj, SealError> {
        if depth > 64 {
            return Err(unreadable("objects nested too deep"));
        }
        self.skip_white();
        let Some(&b) = self.s.get(self.pos) else {
            return Err(unreadable("unexpected end of file"));
        };
        match b {
            b'/' => {
                self.pos += 1;
                let start = self.pos;
                while self.pos < self.s.len()
                    && !is_white(self.s[self.pos])
                    && !is_delim(self.s[self.pos])
                {
                    self.pos += 1;
                }
                Ok(Obj::Name(self.s[start..self.pos].to_vec()))
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_white();
                    match self.s.get(self.pos) {
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Obj::Arr(items));
                        }
                        Some(_) => items.push(self.object(depth + 1)?),
                        None => return Err(unreadable("an array is not closed")),
                    }
                }
            }
            b'<' if self.s.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                let mut entries = Vec::new();
                loop {
                    self.skip_white();
                    match (self.s.get(self.pos), self.s.get(self.pos + 1)) {
                        (Some(b'>'), Some(b'>')) => {
                            self.pos += 2;
                            return Ok(Obj::Dict(entries));
                        }
                        (Some(b'/'), _) => {
                            let Obj::Name(k) = self.object(depth + 1)? else {
                                return Err(unreadable("a dictionary key"));
                            };
                            let v = self.object(depth + 1)?;
                            entries.push((k, v));
                        }
                        _ => {
                            return Err(unreadable(format!(
                                "a dictionary key at byte {}",
                                self.pos
                            )));
                        }
                    }
                }
            }
            b'<' => {
                let start = self.pos;
                while self.pos < self.s.len() && self.s[self.pos] != b'>' {
                    self.pos += 1;
                }
                self.pos += 1;
                if self.pos > self.s.len() {
                    return Err(unreadable("a hex string is not closed"));
                }
                Ok(Obj::Str(self.s[start..self.pos].to_vec()))
            }
            b'(' => {
                let start = self.pos;
                let mut level = 0usize;
                while self.pos < self.s.len() {
                    match self.s[self.pos] {
                        b'\\' => self.pos += 1,
                        b'(' => level += 1,
                        b')' => {
                            level -= 1;
                            if level == 0 {
                                self.pos += 1;
                                return Ok(Obj::Str(self.s[start..self.pos].to_vec()));
                            }
                        }
                        _ => {}
                    }
                    self.pos += 1;
                }
                Err(unreadable("a string is not closed"))
            }
            _ => {
                let w = self.word();
                match w {
                    b"null" => Ok(Obj::Null),
                    b"true" => Ok(Obj::Bool(true)),
                    b"false" => Ok(Obj::Bool(false)),
                    _ if !w.is_empty()
                        && w.iter()
                            .all(|c| c.is_ascii_digit() || matches!(*c, b'+' | b'-' | b'.')) =>
                    {
                        // `n g R`?
                        let save = self.pos;
                        if w.iter().all(u8::is_ascii_digit) {
                            let g = self.peek_word();
                            if !g.is_empty() && g.iter().all(u8::is_ascii_digit) {
                                self.pos += g.len();
                                if self.peek_word() == b"R" {
                                    self.word();
                                    let n = std::str::from_utf8(w)
                                        .ok()
                                        .and_then(|t| t.parse().ok())
                                        .ok_or_else(|| unreadable("an object number"))?;
                                    let g = std::str::from_utf8(g)
                                        .ok()
                                        .and_then(|t| t.parse().ok())
                                        .ok_or_else(|| unreadable("a generation number"))?;
                                    return Ok(Obj::Ref(n, g));
                                }
                            }
                        }
                        self.pos = save;
                        Ok(Obj::Num(w.to_vec()))
                    }
                    _ => Err(unreadable(format!(
                        "unexpected `{}` at byte {}",
                        String::from_utf8_lossy(w),
                        self.pos
                    ))),
                }
            }
        }
    }

    /// After a stream dictionary: the start of the stream's data.
    fn stream_start(&mut self) -> Result<usize, SealError> {
        self.expect(b"stream")?;
        if self.s.get(self.pos) == Some(&b'\r') {
            self.pos += 1;
        }
        if self.s.get(self.pos) == Some(&b'\n') {
            self.pos += 1;
        }
        Ok(self.pos)
    }
}

/// Where an object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loc {
    /// At a byte offset, with its generation.
    At(usize, u16),
    /// The `index`th object of object stream `stream`.
    InStream(u32, usize),
}

/// An object stream's decoded data and where each of its objects starts.
type ObjStm = (Vec<u8>, Vec<(u32, usize)>);

/// A PDF read through its cross-reference data.
struct Doc<'a> {
    s: &'a [u8],
    locs: HashMap<u32, Loc>,
    /// The last section's trailer (a stream's dictionary for a stream).
    trailer: Obj,
    /// Where the last cross-reference section starts.
    last_xref: usize,
    /// The last section is a cross-reference stream.
    stream_style: bool,
    objstm_cache: HashMap<u32, ObjStm>,
}

fn startxref(s: &[u8]) -> Result<usize, SealError> {
    let tail_from = s.len().saturating_sub(2048);
    let tail = &s[tail_from..];
    let at = tail
        .windows(9)
        .rposition(|w| w == b"startxref")
        .ok_or_else(|| unreadable("no startxref"))?;
    let mut lx = Lexer::new(s, tail_from + at + 9);
    lx.uint()
        .map(|v| v as usize)
        .ok_or_else(|| unreadable("startxref has no offset"))
}

fn inflate(data: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .take(256 * 1024 * 1024)
        .read_to_end(&mut out)
        .map_err(|_| unreadable("a Flate stream does not inflate"))?;
    Ok(out)
}

/// Undoes PNG row predictors (`/Predictor` 10 to 15).
fn unpredict(data: &[u8], columns: usize) -> Result<Vec<u8>, SealError> {
    let row = columns + 1;
    if columns == 0 || !data.len().is_multiple_of(row) {
        return Err(unreadable("predicted rows do not match /Columns"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() / row * columns);
    let mut prev = vec![0u8; columns];
    for chunk in data.chunks(row) {
        let kind = chunk[0];
        let mut cur = chunk[1..].to_vec();
        for i in 0..columns {
            let left = if i > 0 { cur[i - 1] } else { 0 };
            let up = prev[i];
            let up_left = if i > 0 { prev[i - 1] } else { 0 };
            let add = match kind {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((left as u16 + up as u16) / 2) as u8,
                4 => {
                    let p = left as i16 + up as i16 - up_left as i16;
                    let (pa, pb, pc) = (
                        (p - left as i16).abs(),
                        (p - up as i16).abs(),
                        (p - up_left as i16).abs(),
                    );
                    if pa <= pb && pa <= pc {
                        left
                    } else if pb <= pc {
                        up
                    } else {
                        up_left
                    }
                }
                _ => return Err(unreadable("an unknown PNG predictor")),
            };
            cur[i] = cur[i].wrapping_add(add);
        }
        out.extend_from_slice(&cur);
        prev = cur;
    }
    Ok(out)
}

impl<'a> Doc<'a> {
    fn open(s: &'a [u8]) -> Result<Self, SealError> {
        if !s.starts_with(b"%PDF-") {
            return Err(unreadable("no %PDF- header"));
        }
        let last_xref = startxref(s)?;
        let mut doc = Doc {
            s,
            locs: HashMap::new(),
            trailer: Obj::Null,
            last_xref,
            stream_style: false,
            objstm_cache: HashMap::new(),
        };
        let mut next = Some(last_xref);
        let mut seen = HashSet::new();
        let mut first = true;
        while let Some(at) = next {
            if !seen.insert(at) || seen.len() > 256 {
                return Err(unreadable("the cross-reference chain loops"));
            }
            let (trailer, is_stream) = doc.read_section(at)?;
            if first {
                doc.trailer = trailer.clone();
                doc.stream_style = is_stream;
                first = false;
            }
            if let Some(hybrid) = trailer.get("XRefStm").and_then(Obj::as_int)
                && seen.insert(hybrid as usize)
            {
                doc.read_section(hybrid as usize)?;
            }
            next = trailer
                .get("Prev")
                .and_then(Obj::as_int)
                .map(|v| v as usize);
        }
        if doc.trailer.get("Encrypt").is_some() {
            return Err(SealError::Encrypted);
        }
        Ok(doc)
    }

    fn note(&mut self, n: u32, loc: Option<Loc>) {
        // The latest section is read first, so the first entry seen wins; a
        // free entry still hides older ones.
        self.locs.entry(n).or_insert(loc.unwrap_or(Loc::At(0, 0)));
    }

    /// Reads one section; answers its trailer and whether it is a stream.
    fn read_section(&mut self, at: usize) -> Result<(Obj, bool), SealError> {
        let mut lx = Lexer::new(self.s, at);
        if lx.peek_word() == b"xref" {
            lx.word();
            loop {
                if lx.peek_word() == b"trailer" {
                    lx.word();
                    let trailer = lx.object(0)?;
                    return Ok((trailer, false));
                }
                let start = lx.uint().ok_or_else(|| unreadable("a subsection start"))?;
                let count = lx.uint().ok_or_else(|| unreadable("a subsection count"))?;
                for i in 0..count {
                    let offset = lx.uint().ok_or_else(|| unreadable("an xref offset"))?;
                    let generation = lx.uint().ok_or_else(|| unreadable("an xref generation"))?;
                    let kind = lx.word();
                    let n = (start + i) as u32;
                    match kind {
                        b"n" => self.note(n, Some(Loc::At(offset as usize, generation as u16))),
                        b"f" => self.note(n, None),
                        _ => return Err(unreadable("an xref entry type")),
                    }
                }
            }
        }
        // A cross-reference stream: `n g obj << … >> stream`.
        lx.uint()
            .ok_or_else(|| unreadable("no xref at startxref"))?;
        lx.uint()
            .ok_or_else(|| unreadable("no xref at startxref"))?;
        lx.expect(b"obj")?;
        let dict = lx.object(0)?;
        if !dict.get("Type").is_some_and(|t| t.is_name("XRef")) {
            return Err(unreadable("startxref does not point at a cross-reference"));
        }
        let start = lx.stream_start()?;
        let len = dict
            .get("Length")
            .and_then(Obj::as_int)
            .ok_or_else(|| unreadable("an xref stream without a direct /Length"))?
            as usize;
        let raw = self
            .s
            .get(start..start + len)
            .ok_or_else(|| unreadable("an xref stream runs past the file"))?;
        let data = self.decode(&dict, raw)?;
        let widths: Vec<usize> = match dict.get("W") {
            Some(Obj::Arr(w)) => w
                .iter()
                .map(|v| v.as_int().map(|i| i as usize))
                .collect::<Option<_>>()
                .ok_or_else(|| unreadable("/W"))?,
            _ => return Err(unreadable("an xref stream without /W")),
        };
        if widths.len() != 3 || widths.iter().any(|w| *w > 8) {
            return Err(unreadable("/W"));
        }
        let size = dict
            .get("Size")
            .and_then(Obj::as_int)
            .ok_or_else(|| unreadable("an xref stream without /Size"))?;
        let index: Vec<i64> = match dict.get("Index") {
            Some(Obj::Arr(v)) => v
                .iter()
                .map(Obj::as_int)
                .collect::<Option<_>>()
                .ok_or_else(|| unreadable("/Index"))?,
            _ => vec![0, size],
        };
        let entry = widths.iter().sum::<usize>();
        let field = |bytes: &[u8]| bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        let mut cursor = 0usize;
        for pair in index.chunks(2) {
            let [first, count] = pair else {
                return Err(unreadable("/Index"));
            };
            for i in 0..*count {
                let rec = data
                    .get(cursor..cursor + entry)
                    .ok_or_else(|| unreadable("an xref stream is short"))?;
                cursor += entry;
                let (a, rest) = rec.split_at(widths[0]);
                let (b, c) = rest.split_at(widths[1]);
                let kind = if widths[0] == 0 { 1 } else { field(a) };
                let n = (first + i) as u32;
                match kind {
                    0 => self.note(n, None),
                    1 => self.note(n, Some(Loc::At(field(b) as usize, field(c) as u16))),
                    2 => self.note(n, Some(Loc::InStream(field(b) as u32, field(c) as usize))),
                    _ => {}
                }
            }
        }
        Ok((dict, true))
    }

    /// A stream's data after its filters (Flate only, with PNG predictors).
    fn decode(&self, dict: &Obj, raw: &[u8]) -> Result<Vec<u8>, SealError> {
        let filters: Vec<&Obj> = match dict.get("Filter") {
            None => Vec::new(),
            Some(Obj::Arr(f)) => f.iter().collect(),
            Some(f) => vec![f],
        };
        let mut data = raw.to_vec();
        for f in &filters {
            if f.is_name("FlateDecode") {
                data = inflate(&data)?;
            } else {
                return Err(unreadable("a stream filter other than Flate"));
            }
        }
        let parms = match dict.get("DecodeParms") {
            Some(Obj::Arr(p)) => p.first().cloned(),
            Some(p) => Some(p.clone()),
            None => None,
        };
        if let Some(p) = parms {
            let predictor = p.get("Predictor").and_then(Obj::as_int).unwrap_or(1);
            if predictor >= 10 {
                let columns = p.get("Columns").and_then(Obj::as_int).unwrap_or(1) as usize;
                data = unpredict(&data, columns)?;
            } else if predictor != 1 {
                return Err(unreadable("a TIFF predictor"));
            }
        }
        Ok(data)
    }

    fn loc(&self, n: u32) -> Result<Loc, SealError> {
        match self.locs.get(&n) {
            Some(Loc::At(0, _)) | None => Err(unreadable(format!("object {n} is missing"))),
            Some(l) => Ok(*l),
        }
    }

    /// The generation an object is rewritten under.
    fn generation(&self, n: u32) -> u16 {
        match self.locs.get(&n) {
            Some(Loc::At(_, g)) => *g,
            _ => 0,
        }
    }

    fn get(&mut self, n: u32) -> Result<Obj, SealError> {
        match self.loc(n)? {
            Loc::At(offset, _) => {
                let mut lx = Lexer::new(self.s, offset);
                lx.uint().ok_or_else(|| unreadable(format!("object {n}")))?;
                lx.uint().ok_or_else(|| unreadable(format!("object {n}")))?;
                lx.expect(b"obj")?;
                lx.object(0)
            }
            Loc::InStream(stream, index) => {
                if !self.objstm_cache.contains_key(&stream) {
                    let loaded = self.load_objstm(stream)?;
                    self.objstm_cache.insert(stream, loaded);
                }
                let (data, offsets) = &self.objstm_cache[&stream];
                let (_, at) = offsets
                    .get(index)
                    .ok_or_else(|| unreadable(format!("object {n} in its stream")))?;
                Lexer::new(data, *at).object(0)
            }
        }
    }

    fn resolve(&mut self, o: &Obj) -> Result<Obj, SealError> {
        match o {
            Obj::Ref(n, _) => self.get(*n),
            other => Ok(other.clone()),
        }
    }

    fn load_objstm(&mut self, n: u32) -> Result<ObjStm, SealError> {
        let Loc::At(offset, _) = self.loc(n)? else {
            return Err(unreadable("an object stream inside an object stream"));
        };
        let mut lx = Lexer::new(self.s, offset);
        lx.uint();
        lx.uint();
        lx.expect(b"obj")?;
        let dict = lx.object(0)?;
        let start = lx.stream_start()?;
        let len = match dict.get("Length") {
            Some(Obj::Ref(r, _)) => {
                let r = *r;
                self.get(r)?.as_int()
            }
            Some(o) => o.as_int(),
            None => None,
        }
        .ok_or_else(|| unreadable("an object stream without /Length"))? as usize;
        let raw = self
            .s
            .get(start..start + len)
            .ok_or_else(|| unreadable("an object stream runs past the file"))?;
        let data = self.decode(&dict, raw)?;
        let count = dict.get("N").and_then(Obj::as_int).unwrap_or(0) as usize;
        let first = dict.get("First").and_then(Obj::as_int).unwrap_or(0) as usize;
        let mut header = Lexer::new(&data, 0);
        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            let num = header
                .uint()
                .ok_or_else(|| unreadable("an object stream header"))?;
            let off = header
                .uint()
                .ok_or_else(|| unreadable("an object stream header"))?;
            offsets.push((num as u32, first + off as usize));
        }
        Ok((data, offsets))
    }

    /// The first page: its object number and dictionary.
    fn first_page(&mut self, pages: &Obj) -> Result<(u32, Obj), SealError> {
        let mut node = pages.clone();
        for _ in 0..64 {
            let Obj::Ref(n, _) = node else {
                return Err(unreadable("a page tree node is not a reference"));
            };
            let dict = self.get(n)?;
            if dict.get("Type").is_some_and(|t| t.is_name("Page")) {
                return Ok((n, dict));
            }
            let kids = match dict.get("Kids") {
                Some(k) => self.resolve(&k.clone())?,
                None => return Err(unreadable("a page tree node without kids")),
            };
            let Obj::Arr(kids) = kids else {
                return Err(unreadable("/Kids is not an array"));
            };
            node = kids
                .first()
                .cloned()
                .ok_or_else(|| unreadable("a document without pages"))?;
        }
        Err(unreadable("the page tree is too deep"))
    }
}

// ── Sealing ─────────────────────────────────────────────────────────────────

/// What the seal says about itself.
#[derive(Debug, Clone)]
pub struct SealInfo<'a> {
    /// `/Reason`, e.g. "Signed by everyone".
    pub reason: &'a str,
    /// `/Location`, if any.
    pub location: Option<&'a str>,
    /// `/M`, the signing time.
    pub at: DateTime<Utc>,
}

/// The longest file sealed in memory.
pub const MAX_PDF_BYTES: usize = 64 * 1024 * 1024;

/// Seals `pdf`; see the module doc.
pub fn seal(pdf: &[u8], key: &SealKey, info: &SealInfo<'_>) -> Result<Vec<u8>, SealError> {
    if pdf.len() > MAX_PDF_BYTES {
        return Err(unreadable("the file is larger than 64 MB"));
    }
    let mut doc = Doc::open(pdf)?;
    let root_ref = match doc.trailer.get("Root") {
        Some(Obj::Ref(n, _)) => *n,
        _ => return Err(unreadable("the trailer names no catalog")),
    };
    let size = doc
        .trailer
        .get("Size")
        .and_then(Obj::as_int)
        .ok_or_else(|| unreadable("the trailer has no /Size"))? as u32;
    let mut catalog = doc.get(root_ref)?;
    let pages = catalog
        .get("Pages")
        .cloned()
        .ok_or_else(|| unreadable("the catalog has no /Pages"))?;
    let (page_ref, mut page) = doc.first_page(&pages)?;

    let field_n = size;
    let value_n = size + 1;
    let mut next_n = size + 2;
    // Objects this update writes, beside the two new ones.
    let mut rewritten: Vec<(u32, Obj)> = Vec::new();

    // The page's /Annots gains the field's widget.
    let widget = Obj::Ref(field_n, 0);
    match page.get("Annots").cloned() {
        Some(Obj::Ref(a, _)) => {
            let mut annots = doc.get(a)?;
            let Obj::Arr(items) = &mut annots else {
                return Err(unreadable("/Annots is not an array"));
            };
            items.push(widget.clone());
            rewritten.push((a, annots));
        }
        Some(Obj::Arr(mut items)) => {
            items.push(widget.clone());
            page.set("Annots", Obj::Arr(items));
            rewritten.push((page_ref, page.clone()));
        }
        _ => {
            page.set("Annots", Obj::Arr(vec![widget.clone()]));
            rewritten.push((page_ref, page.clone()));
        }
    }

    // The catalog's /AcroForm lists the field, with /SigFlags 3.
    let add_field = |doc: &mut Doc<'_>,
                     form: &mut Obj,
                     rewritten: &mut Vec<(u32, Obj)>|
     -> Result<(), SealError> {
        match form.get("Fields").cloned() {
            Some(Obj::Ref(f, _)) => {
                let mut fields = doc.get(f)?;
                let Obj::Arr(items) = &mut fields else {
                    return Err(unreadable("/Fields is not an array"));
                };
                items.push(Obj::Ref(field_n, 0));
                rewritten.push((f, fields));
            }
            Some(Obj::Arr(mut items)) => {
                items.push(Obj::Ref(field_n, 0));
                form.set("Fields", Obj::Arr(items));
            }
            _ => form.set("Fields", Obj::Arr(vec![Obj::Ref(field_n, 0)])),
        }
        form.set("SigFlags", num(3));
        Ok(())
    };
    match catalog.get("AcroForm").cloned() {
        Some(Obj::Ref(f, _)) => {
            let mut form = doc.get(f)?;
            add_field(&mut doc, &mut form, &mut rewritten)?;
            rewritten.push((f, form));
        }
        Some(mut form @ Obj::Dict(_)) => {
            add_field(&mut doc, &mut form, &mut rewritten)?;
            catalog.set("AcroForm", form);
            rewritten.push((root_ref, catalog.clone()));
        }
        _ => {
            let mut form = Obj::Dict(Vec::new());
            add_field(&mut doc, &mut form, &mut rewritten)?;
            catalog.set("AcroForm", form);
            rewritten.push((root_ref, catalog.clone()));
        }
    }
    // A page that is also the catalog's form holder cannot happen; but one
    // object rewritten twice keeps its last version.
    let mut dedup: Vec<(u32, Obj)> = Vec::new();
    for (n, o) in rewritten {
        dedup.retain(|(m, _)| *m != n);
        dedup.push((n, o));
    }

    let field = Obj::Dict(vec![
        (b"Type".to_vec(), name("Annot")),
        (b"Subtype".to_vec(), name("Widget")),
        (b"FT".to_vec(), name("Sig")),
        (b"T".to_vec(), text(&format!("AttomeSeal{field_n}"))),
        (b"V".to_vec(), Obj::Ref(value_n, 0)),
        // Print and locked.
        (b"F".to_vec(), num(132)),
        (
            b"Rect".to_vec(),
            Obj::Arr(vec![num(0), num(0), num(0), num(0)]),
        ),
        (b"P".to_vec(), Obj::Ref(page_ref, doc.generation(page_ref))),
    ]);

    // The contents' room: a CMS with a dummy signature of the longest size.
    let dummy_len =
        signed_data_with(key, &[0u8; 32], |_| Ok(vec![0xFF; key.signature_len()]))?.len();
    let room = dummy_len + 64;

    // The update, with placeholders for /ByteRange and /Contents.
    let mut out = pdf.to_vec();
    if !matches!(out.last(), Some(b'\n' | b'\r')) {
        out.push(b'\n');
    }
    let mut offsets: Vec<(u32, u16, usize)> = Vec::new();
    for (n, o) in &dedup {
        let g = doc.generation(*n);
        offsets.push((*n, g, out.len()));
        out.extend_from_slice(format!("{n} {g} obj\n").as_bytes());
        o.write(&mut out);
        out.extend_from_slice(b"\nendobj\n");
    }
    offsets.push((field_n, 0, out.len()));
    out.extend_from_slice(format!("{field_n} 0 obj\n").as_bytes());
    field.write(&mut out);
    out.extend_from_slice(b"\nendobj\n");

    offsets.push((value_n, 0, out.len()));
    out.extend_from_slice(format!("{value_n} 0 obj\n").as_bytes());
    let mut head = Obj::Dict(vec![
        (b"Type".to_vec(), name("Sig")),
        (b"Filter".to_vec(), name("Adobe.PPKLite")),
        (b"SubFilter".to_vec(), name("ETSI.CAdES.detached")),
        (
            b"M".to_vec(),
            text(&info.at.format("D:%Y%m%d%H%M%SZ").to_string()),
        ),
        (b"Name".to_vec(), text(key.common_name())),
        (b"Reason".to_vec(), text(info.reason)),
    ]);
    if let Some(l) = info.location {
        head.set("Location", text(l));
    }
    // Written by hand around the two placeholders: `<< … /ByteRange [ … ]
    // /Contents <…> >>`.
    let mut head_bytes = Vec::new();
    head.write(&mut head_bytes);
    head_bytes.truncate(head_bytes.len() - 2);
    out.extend_from_slice(&head_bytes);
    out.extend_from_slice(b"/ByteRange ");
    let range_at = out.len();
    const RANGE_ROOM: usize = 48;
    out.extend(std::iter::repeat_n(b' ', RANGE_ROOM));
    out.extend_from_slice(b"/Contents ");
    let contents_at = out.len();
    out.push(b'<');
    out.extend(std::iter::repeat_n(b'0', room * 2));
    out.push(b'>');
    let contents_end = out.len();
    out.extend_from_slice(b">>\nendobj\n");

    // The cross-reference section, in the last section's style.
    let mut trailer = vec![
        (b"Size".to_vec(), num(0)),
        (
            b"Root".to_vec(),
            Obj::Ref(root_ref, doc.generation(root_ref)),
        ),
        (b"Prev".to_vec(), num(doc.last_xref as i64)),
    ];
    for k in ["Info", "ID"] {
        if let Some(v) = doc.trailer.get(k) {
            trailer.push((k.as_bytes().to_vec(), v.clone()));
        }
    }
    let xref_at;
    if doc.stream_style {
        let xref_n = next_n;
        next_n += 1;
        xref_at = out.len();
        offsets.push((xref_n, 0, xref_at));
        offsets.sort_by_key(|(n, _, _)| *n);
        let mut data = Vec::new();
        let mut index = Vec::new();
        for (n, g, at) in &offsets {
            index.push(num(*n as i64));
            index.push(num(1));
            data.push(1u8);
            data.extend_from_slice(&(*at as u32).to_be_bytes());
            data.extend_from_slice(&g.to_be_bytes());
        }
        let mut dict = Obj::Dict(trailer);
        dict.set("Size", num(next_n.max(size) as i64));
        dict.set("Type", name("XRef"));
        dict.set("W", Obj::Arr(vec![num(1), num(4), num(2)]));
        dict.set("Index", Obj::Arr(index));
        dict.set("Length", num(data.len() as i64));
        out.extend_from_slice(format!("{xref_n} 0 obj\n").as_bytes());
        dict.write(&mut out);
        out.extend_from_slice(b"\nstream\n");
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\nendstream\nendobj\n");
    } else {
        xref_at = out.len();
        offsets.sort_by_key(|(n, _, _)| *n);
        out.extend_from_slice(b"xref\n");
        for (n, g, at) in &offsets {
            out.extend_from_slice(format!("{n} 1\n{at:010} {g:05} n\r\n").as_bytes());
        }
        let mut dict = Obj::Dict(trailer);
        dict.set("Size", num(next_n.max(size) as i64));
        out.extend_from_slice(b"trailer\n");
        dict.write(&mut out);
        out.push(b'\n');
    }
    if offsets.iter().any(|(_, _, at)| *at > u32::MAX as usize) {
        return Err(unreadable("the file is too large for this update"));
    }
    out.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());

    // Fill the byte range, digest it, sign, fill the contents.
    let total = out.len();
    let range = format!("[0 {contents_at} {contents_end} {}]", total - contents_end);
    if range.len() > RANGE_ROOM {
        return Err(unreadable("the byte range does not fit"));
    }
    out[range_at..range_at + range.len()].copy_from_slice(range.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&out[..contents_at]);
    hasher.update(&out[contents_end..]);
    let digest = hasher.finalize();
    let cms = signed_data(key, &digest)?;
    if cms.len() > room {
        return Err(SealError::Key(
            "the signature is larger than its room".into(),
        ));
    }
    let hexed = hex::encode_upper(&cms);
    out[contents_at + 1..contents_at + 1 + hexed.len()].copy_from_slice(hexed.as_bytes());
    Ok(out)
}

// ── Verifying ───────────────────────────────────────────────────────────────

/// What [`verify`] found in a file's last signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealReport {
    /// The signer certificate's subject common name.
    pub signer: String,
    /// `/SubFilter`.
    pub sub_filter: String,
    /// How many signature fields the file has.
    pub signatures: usize,
}

fn hex_contents(o: &Obj) -> Option<Vec<u8>> {
    let Obj::Str(raw) = o else { return None };
    let inner = raw.strip_prefix(b"<")?.strip_suffix(b">")?;
    let digits: Vec<u8> = inner.iter().copied().filter(|b| !is_white(*b)).collect();
    hex::decode(digits).ok()
}

/// Checks the file's last signature; see the module doc.
pub fn verify(pdf: &[u8]) -> Result<SealReport, SealError> {
    let invalid = |why: &str| SealError::Invalid(why.to_owned());
    let mut doc = Doc::open(pdf)?;
    let root = match doc.trailer.get("Root") {
        Some(Obj::Ref(n, _)) => *n,
        _ => return Err(unreadable("the trailer names no catalog")),
    };
    let catalog = doc.get(root)?;
    let form = match catalog.get("AcroForm") {
        Some(f) => doc.resolve(&f.clone())?,
        None => return Err(invalid("no form, so no signature")),
    };
    let fields = match form.get("Fields") {
        Some(f) => doc.resolve(&f.clone())?,
        None => return Err(invalid("no signature field")),
    };
    let Obj::Arr(fields) = fields else {
        return Err(invalid("/Fields is not an array"));
    };
    let mut values = Vec::new();
    for f in &fields {
        let field = doc.resolve(f)?;
        if field.get("FT").is_some_and(|t| t.is_name("Sig"))
            && let Some(v) = field.get("V")
        {
            values.push(doc.resolve(&v.clone())?);
        }
    }
    let signatures = values.len();
    // The last one is the one covering the most bytes.
    let mut best: Option<(i64, Obj)> = None;
    for v in values {
        let Some(Obj::Arr(r)) = v.get("ByteRange") else {
            continue;
        };
        let covered: i64 = r.iter().filter_map(Obj::as_int).skip(1).step_by(2).sum();
        if best.as_ref().is_none_or(|(c, _)| covered > *c) {
            best = Some((covered, v));
        }
    }
    let Some((_, sig)) = best else {
        return Err(invalid("no signature value"));
    };
    let range: Vec<usize> = match sig.get("ByteRange") {
        Some(Obj::Arr(r)) => r
            .iter()
            .map(|v| v.as_int().map(|i| i as usize))
            .collect::<Option<_>>()
            .ok_or_else(|| invalid("/ByteRange"))?,
        _ => return Err(invalid("/ByteRange")),
    };
    let [a0, a1, b0, b1] = range[..] else {
        return Err(invalid("/ByteRange has two parts"));
    };
    if a0 != 0 || b0 + b1 != pdf.len() || a1 >= b0 {
        return Err(invalid(
            "the byte range does not cover the whole file but the contents",
        ));
    }
    if pdf.get(a1) != Some(&b'<') || pdf.get(b0 - 1) != Some(&b'>') {
        return Err(invalid("the gap is not the contents string"));
    }
    let cms = sig
        .get("Contents")
        .and_then(hex_contents)
        .ok_or_else(|| invalid("/Contents"))?;
    let sub_filter = match sig.get("SubFilter") {
        Some(Obj::Name(n)) => String::from_utf8_lossy(n).into_owned(),
        _ => String::new(),
    };
    let mut hasher = Sha256::new();
    hasher.update(&pdf[..a1]);
    hasher.update(&pdf[b0..b0 + b1]);
    let digest = hasher.finalize();

    // ContentInfo → SignedData.
    let ((_, ci, _), _) = der::read(&cms).ok_or_else(|| invalid("the CMS"))?;
    let ci = der::children(ci).ok_or_else(|| invalid("the CMS"))?;
    let [(0x06, oid, _), (0xA0, explicit, _)] = ci[..] else {
        return Err(invalid("the CMS is not SignedData"));
    };
    if oid != OID_SIGNED_DATA {
        return Err(invalid("the CMS is not SignedData"));
    }
    let ((_, sd, _), _) = der::read(explicit).ok_or_else(|| invalid("SignedData"))?;
    let sd = der::children(sd).ok_or_else(|| invalid("SignedData"))?;
    let certs = sd
        .iter()
        .find(|(t, _, _)| *t == 0xA0)
        .ok_or_else(|| invalid("no certificates"))?;
    let first_cert = der::children(certs.1)
        .and_then(|c| c.first().map(|(_, _, whole)| *whole))
        .ok_or_else(|| invalid("no certificate"))?;
    let signer_infos = sd.last().ok_or_else(|| invalid("no signer"))?;
    let info = der::children(signer_infos.1)
        .and_then(|s| s.first().map(|(_, inner, _)| *inner))
        .ok_or_else(|| invalid("no signer"))?;
    let info = der::children(info).ok_or_else(|| invalid("SignerInfo"))?;
    let attrs = info
        .iter()
        .find(|(t, _, _)| *t == 0xA0)
        .ok_or_else(|| invalid("no signed attributes"))?;
    let signature = info
        .iter()
        .rev()
        .find(|(t, _, _)| *t == 0x04)
        .map(|(_, s, _)| *s)
        .ok_or_else(|| invalid("no signature"))?;
    let mut message_digest = None;
    let mut has_signing_cert = false;
    for (_, attr, _) in der::children(attrs.1).ok_or_else(|| invalid("attributes"))? {
        let parts = der::children(attr).ok_or_else(|| invalid("an attribute"))?;
        let [(0x06, oid, _), (0x31, values, _)] = parts[..] else {
            continue;
        };
        if oid == OID_MESSAGE_DIGEST {
            message_digest =
                der::children(values).and_then(|v| v.first().map(|(_, d, _)| d.to_vec()));
        } else if oid == OID_SIGNING_CERT_V2 {
            has_signing_cert = true;
        }
    }
    if message_digest.as_deref() != Some(digest.as_slice()) {
        return Err(invalid("the message digest does not match the file"));
    }
    if sub_filter == "ETSI.CAdES.detached" && !has_signing_cert {
        return Err(invalid("a CAdES signature without signing-certificate-v2"));
    }
    let mut signed = attrs.2.to_vec();
    signed[0] = 0x31;
    let (_, cert) =
        x509_parser::parse_x509_certificate(first_cert).map_err(|_| invalid("the certificate"))?;
    let spki = cert.public_key();
    let key = spki.subject_public_key.data.as_ref();
    let alg: &dyn signature::VerificationAlgorithm =
        match spki.algorithm.algorithm.to_id_string().as_str() {
            "1.2.840.113549.1.1.1" => &signature::RSA_PKCS1_2048_8192_SHA256,
            "1.2.840.10045.2.1" => &signature::ECDSA_P256_SHA256_ASN1,
            _ => return Err(invalid("a key type other than RSA or P-256")),
        };
    signature::UnparsedPublicKey::new(alg, key)
        .verify(&signed, signature)
        .map_err(|_| invalid("the signature does not verify under the certificate"))?;
    let signer = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_owned();
    Ok(SealReport {
        signer,
        sub_filter,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn put(out: &mut Vec<u8>, s: String) {
        out.extend_from_slice(s.as_bytes());
    }

    const RSA_CERT: &str = include_str!("../tests/fixtures/pades/rsa-cert.pem");
    const RSA_KEY: &str = include_str!("../tests/fixtures/pades/rsa-key.pem");
    const EC_CERT: &str = include_str!("../tests/fixtures/pades/ec-cert.pem");
    const EC_KEY: &str = include_str!("../tests/fixtures/pades/ec-key.pem");

    fn info() -> SealInfo<'static> {
        SealInfo {
            reason: "Signed by everyone",
            location: Some("Riyadh"),
            at: DateTime::parse_from_rfc3339("2026-11-03T10:00:00Z")
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }

    /// A one-page PDF with a classic cross-reference table.
    fn classic_pdf() -> Vec<u8> {
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << >> >>",
            "<< /Length 20 >>\nstream\nBT /F1 12 Tf (Hi) ET\nendstream",
        ];
        let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objects.iter().enumerate() {
            offsets.push(out.len());
            put(&mut out, format!("{} 0 obj\n{o}\nendobj\n", i + 1));
        }
        let xref = out.len();
        put(
            &mut out,
            format!("xref\n0 {}\n0000000000 65535 f\r\n", objects.len() + 1),
        );
        for at in offsets {
            put(&mut out, format!("{at:010} 00000 n\r\n"));
        }
        put(
            &mut out,
            format!(
                "trailer\n<< /Size {} /Root 1 0 R /ID [<AA> <AA>] >>\nstartxref\n{xref}\n%%EOF\n",
                objects.len() + 1
            ),
        );
        out
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).ok();
        e.finish().unwrap_or_default()
    }

    /// A PDF 1.5 file: the catalog and pages in a compressed object stream,
    /// a cross-reference stream with the PNG Up predictor.
    fn stream_pdf() -> Vec<u8> {
        let mut out = b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n".to_vec();
        // Objects 1 (catalog), 2 (pages), 3 (page) inside stream 5.
        let inner = [
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] >> >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << >> /Annots [] >>",
        ];
        let mut body = Vec::new();
        let mut header = String::new();
        for (i, o) in inner.iter().enumerate() {
            header.push_str(&format!("{} {} ", i + 1, body.len()));
            body.extend_from_slice(o.as_bytes());
            body.push(b' ');
        }
        let mut objstm = header.clone().into_bytes();
        let first = objstm.len();
        objstm.extend_from_slice(&body);
        let packed = deflate(&objstm);
        let content_at = out.len();
        put(
            &mut out,
            "4 0 obj\n<< /Length 20 >>\nstream\nBT /F1 12 Tf (Hi) ET\nendstream\nendobj\n"
                .to_owned(),
        );
        let objstm_at = out.len();
        put(
            &mut out,
            format!(
                "5 0 obj\n<< /Type /ObjStm /N 3 /First {first} /Filter /FlateDecode /Length {} >>\nstream\n",
                packed.len()
            ),
        );
        out.extend_from_slice(&packed);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        let xref_at = out.len();
        // Rows of W [1 4 2] for objects 0..=6, Up-predicted.
        let rows: Vec<[u8; 7]> = (0u32..7)
            .map(|n| {
                let (kind, b, c): (u8, u32, u16) = match n {
                    0 => (0, 0, 65535),
                    1..=3 => (2, 5, (n - 1) as u16),
                    4 => (1, content_at as u32, 0),
                    5 => (1, objstm_at as u32, 0),
                    _ => (1, xref_at as u32, 0),
                };
                let mut r = [0u8; 7];
                r[0] = kind;
                r[1..5].copy_from_slice(&b.to_be_bytes());
                r[5..7].copy_from_slice(&c.to_be_bytes());
                r
            })
            .collect();
        let mut predicted = Vec::new();
        let mut prev = [0u8; 7];
        for r in &rows {
            predicted.push(2u8);
            predicted.extend(r.iter().zip(prev.iter()).map(|(c, p)| c.wrapping_sub(*p)));
            prev = *r;
        }
        let packed = deflate(&predicted);
        put(
            &mut out,
            format!(
                "6 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode \
             /DecodeParms << /Predictor 12 /Columns 7 >> /Length {} >>\nstream\n",
                packed.len()
            ),
        );
        out.extend_from_slice(&packed);
        put(
            &mut out,
            format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n"),
        );
        out
    }

    /// With `ATTOME_PADES_OUT` set, keeps a sealed file there for an outside
    /// validator (pyHanko, a PDF reader).
    fn keep(name: &str, bytes: &[u8]) {
        if let Ok(dir) = std::env::var("ATTOME_PADES_OUT") {
            std::fs::write(std::path::Path::new(&dir).join(name), bytes).ok();
        }
    }

    fn rsa() -> SealKey {
        SealKey::from_pem(RSA_CERT, RSA_KEY).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn pades_seal_classic_rsa_verifies_and_keeps_the_original() {
        let pdf = classic_pdf();
        let sealed = seal(&pdf, &rsa(), &info()).unwrap_or_else(|e| panic!("{e}"));
        keep("classic-rsa.pdf", &sealed);
        assert!(
            sealed.starts_with(&pdf),
            "an incremental update keeps the original bytes"
        );
        let report = verify(&sealed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.signer, "Attome test seal RSA");
        assert_eq!(report.sub_filter, "ETSI.CAdES.detached");
        assert_eq!(report.signatures, 1);
        // The update reads back: the catalog has the form, the page the widget.
        let mut doc = Doc::open(&sealed).unwrap_or_else(|e| panic!("{e}"));
        let catalog = doc.get(1).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            catalog
                .get("AcroForm")
                .and_then(|f| f.get("SigFlags"))
                .is_some()
        );
        let page = doc.get(3).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(page.get("Annots"), Some(Obj::Arr(a)) if a.len() == 1));
    }

    #[test]
    fn pades_seal_object_streams_ecdsa_verifies() {
        let pdf = stream_pdf();
        let key = SealKey::from_pem(EC_CERT, EC_KEY).unwrap_or_else(|e| panic!("{e}"));
        let sealed = seal(&pdf, &key, &info()).unwrap_or_else(|e| panic!("{e}"));
        keep("streams-ec.pdf", &sealed);
        assert!(sealed.starts_with(&pdf));
        let report = verify(&sealed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.signer, "Attome test seal EC");
        // Written as a cross-reference stream, like the original.
        let tail = String::from_utf8_lossy(&sealed[pdf.len()..]).into_owned();
        assert!(tail.contains("/Type /XRef"), "{tail}");
    }

    #[test]
    fn pades_seal_detects_a_changed_byte() {
        let sealed = seal(&classic_pdf(), &rsa(), &info()).unwrap_or_else(|e| panic!("{e}"));
        let mut tampered = sealed.clone();
        let at = tampered
            .windows(2)
            .position(|w| w == b"Hi")
            .unwrap_or_else(|| panic!("no text"));
        tampered[at] = b'H' + 1;
        assert!(matches!(verify(&tampered), Err(SealError::Invalid(_))));
        // Bytes appended after the seal leave it outside the range.
        let mut appended = sealed;
        appended.extend_from_slice(b"% more\n");
        assert!(matches!(verify(&appended), Err(SealError::Invalid(_))));
    }

    #[test]
    fn pades_seal_twice_keeps_both_fields() {
        let once = seal(&classic_pdf(), &rsa(), &info()).unwrap_or_else(|e| panic!("{e}"));
        let key = SealKey::from_pem(EC_CERT, EC_KEY).unwrap_or_else(|e| panic!("{e}"));
        let twice = seal(&once, &key, &info()).unwrap_or_else(|e| panic!("{e}"));
        keep("twice.pdf", &twice);
        let report = verify(&twice).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.signatures, 2);
        assert_eq!(report.signer, "Attome test seal EC");
        // The first seal still checks over its own revision.
        assert!(verify(&once).is_ok());
    }

    #[test]
    fn pades_seal_refuses_a_mismatched_key_and_encrypted_files() {
        assert!(matches!(
            SealKey::from_pem(RSA_CERT, EC_KEY),
            Err(SealError::Key(_))
        ));
        let pdf = classic_pdf();
        let at = pdf
            .windows(6)
            .rposition(|w| w == b"/Root ")
            .unwrap_or_else(|| panic!("no root"));
        // The trailer follows the table, so startxref still points at it.
        let pdf = [&pdf[..at], b"/Encrypt 9 0 R ".as_slice(), &pdf[at..]].concat();
        assert_eq!(
            seal(&pdf, &rsa(), &info()).err(),
            Some(SealError::Encrypted)
        );
        assert!(matches!(
            seal(b"not a pdf", &rsa(), &info()),
            Err(SealError::Unreadable(_))
        ));
    }

    #[test]
    fn pades_seal_writes_arabic_text_as_utf16() {
        let t = text("موقّع");
        let Obj::Str(raw) = t else { panic!("a string") };
        assert!(raw.starts_with(b"<FEFF"));
        assert_eq!(text("a(b)"), Obj::Str(b"(a\\(b\\))".to_vec()));
    }
}
