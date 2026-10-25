//! Q9-T1: the offline country database for sign-in country rules.
//!
//! The file is in the MaxMind DB format (`.mmdb`), so GeoLite2-Country,
//! GeoIP2-Country, DB-IP's country lite file and IPinfo's free country file
//! all work. The operator points `auth.geoip_database` at it; boot reads it
//! once and a file that cannot be read or parsed stops boot. Replace the
//! file and restart to update it.
//!
//! The reader is small and in-crate rather than a new dependency: it walks
//! the search tree and decodes the one record an address lands on, taking
//! `country.iso_code` (or `registered_country.iso_code` when the record has
//! no `country`). Every offset is bounds-checked and decoding depth is
//! capped, so a corrupt file gives "unknown", never a panic.

use std::net::IpAddr;
use std::sync::OnceLock;

const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
const DATA_SEPARATOR: usize = 16;
const MAX_DEPTH: u8 = 16;

/// A parsed MaxMind DB file.
pub struct Mmdb {
    bytes: Vec<u8>,
    node_count: usize,
    record_size: usize,
    ip_version: u16,
    data_start: usize,
    /// The node IPv4 lookups start from in an IPv6 tree (after 96 zero bits).
    ipv4_start: usize,
}

impl std::fmt::Debug for Mmdb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mmdb")
            .field("node_count", &self.node_count)
            .field("record_size", &self.record_size)
            .field("ip_version", &self.ip_version)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Uint(u128),
    Map(Vec<(String, Value)>),
    /// A value of a type no lookup reads (numbers, booleans, arrays, bytes).
    Other,
}

impl Value {
    fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_uint(&self) -> Option<u128> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Decodes data-section values. `base` is where pointers count from.
struct Decoder<'a> {
    bytes: &'a [u8],
    base: usize,
}

impl Decoder<'_> {
    fn byte(&self, at: usize) -> Result<u8, String> {
        self.bytes
            .get(at)
            .copied()
            .ok_or_else(|| "truncated data".to_owned())
    }

    fn be(&self, at: usize, len: usize) -> Result<u128, String> {
        if len > 16 {
            return Err("number too wide".into());
        }
        let slice = self
            .bytes
            .get(at..at + len)
            .ok_or_else(|| "truncated number".to_owned())?;
        Ok(slice
            .iter()
            .fold(0u128, |acc, b| (acc << 8) | u128::from(*b)))
    }

    /// The value at `at` (absolute) and the offset just past it.
    fn decode(&self, at: usize, depth: u8) -> Result<(Value, usize), String> {
        if depth > MAX_DEPTH {
            return Err("data nested too deeply".into());
        }
        let ctrl = self.byte(at)?;
        let mut pos = at + 1;
        let mut kind = ctrl >> 5;
        if kind == 1 {
            // A pointer: follow it, then continue after the pointer itself.
            let ss = (ctrl >> 3) & 0x3;
            let vvv = usize::from(ctrl & 0x7);
            let (target, len) = match ss {
                0 => ((vvv << 8) | self.be(pos, 1)? as usize, 1),
                1 => (((vvv << 16) | self.be(pos, 2)? as usize) + 2048, 2),
                2 => (((vvv << 24) | self.be(pos, 3)? as usize) + 526_336, 3),
                _ => (self.be(pos, 4)? as usize, 4),
            };
            let target = self.base.checked_add(target).ok_or("pointer overflow")?;
            if self.byte(target)? >> 5 == 1 {
                return Err("pointer to a pointer".into());
            }
            let (value, _) = self.decode(target, depth + 1)?;
            return Ok((value, pos + len));
        }
        if kind == 0 {
            kind = 7 + self.byte(pos)?;
            pos += 1;
        }
        let mut size = usize::from(ctrl & 0x1f);
        match size {
            29 => {
                size = 29 + self.be(pos, 1)? as usize;
                pos += 1;
            }
            30 => {
                size = 285 + self.be(pos, 2)? as usize;
                pos += 2;
            }
            31 => {
                size = 65_821 + self.be(pos, 3)? as usize;
                pos += 3;
            }
            _ => {}
        }
        match kind {
            2 => {
                let raw = self
                    .bytes
                    .get(pos..pos + size)
                    .ok_or_else(|| "truncated string".to_owned())?;
                let s = std::str::from_utf8(raw).map_err(|_| "string is not UTF-8")?;
                Ok((Value::Str(s.to_owned()), pos + size))
            }
            3 => Ok((Value::Other, pos + 8)),
            4 | 8 => {
                self.bytes
                    .get(pos..pos + size)
                    .ok_or_else(|| "truncated value".to_owned())?;
                Ok((Value::Other, pos + size))
            }
            5 | 6 | 9 | 10 => Ok((Value::Uint(self.be(pos, size)?), pos + size)),
            7 => {
                let mut entries = Vec::with_capacity(size.min(64));
                for _ in 0..size {
                    let (key, next) = self.decode(pos, depth + 1)?;
                    let Value::Str(key) = key else {
                        return Err("map key is not a string".into());
                    };
                    let (value, next) = self.decode(next, depth + 1)?;
                    entries.push((key, value));
                    pos = next;
                }
                Ok((Value::Map(entries), pos))
            }
            11 => {
                for _ in 0..size {
                    pos = self.decode(pos, depth + 1)?.1;
                }
                Ok((Value::Other, pos))
            }
            14 => Ok((Value::Other, pos)),
            15 => Ok((Value::Other, pos + 4)),
            other => Err(format!("unsupported data type {other}")),
        }
    }
}

impl Mmdb {
    /// Parses a database held in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let marker = bytes
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .ok_or("no MaxMind DB metadata marker; is this an .mmdb file?")?;
        let meta_start = marker + METADATA_MARKER.len();
        let metadata = Decoder {
            bytes: &bytes,
            base: meta_start,
        }
        .decode(meta_start, 0)?
        .0;
        let field = |key: &str| {
            metadata
                .get(key)
                .and_then(Value::as_uint)
                .ok_or_else(|| format!("metadata has no {key}"))
        };
        let node_count =
            usize::try_from(field("node_count")?).map_err(|_| "node_count too large")?;
        let record_size = field("record_size")? as usize;
        let ip_version = field("ip_version")? as u16;
        if !matches!(record_size, 24 | 28 | 32) {
            return Err(format!("unsupported record size {record_size}"));
        }
        if !matches!(ip_version, 4 | 6) {
            return Err(format!("unsupported ip_version {ip_version}"));
        }
        let tree_size = node_count
            .checked_mul(record_size / 4)
            .ok_or("search tree too large")?;
        let data_start = tree_size + DATA_SEPARATOR;
        if data_start > marker {
            return Err("search tree runs past the data section".into());
        }
        let mut db = Self {
            bytes,
            node_count,
            record_size,
            ip_version,
            data_start,
            ipv4_start: 0,
        };
        if ip_version == 6 {
            let mut node = 0;
            for _ in 0..96 {
                if node >= node_count {
                    break;
                }
                node = db.record(node, 0)?;
            }
            db.ipv4_start = node;
        }
        Ok(db)
    }

    /// Reads and parses a database file.
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        Self::from_bytes(bytes)
    }

    /// Node `node`'s left (`bit` 0) or right (`bit` 1) record.
    fn record(&self, node: usize, bit: u8) -> Result<usize, String> {
        let width = self.record_size / 4;
        let at = node * width;
        let b = self
            .bytes
            .get(at..at + width)
            .ok_or_else(|| "search tree truncated".to_owned())?;
        let be = |s: &[u8]| s.iter().fold(0usize, |acc, x| (acc << 8) | usize::from(*x));
        Ok(match (self.record_size, bit) {
            (24, 0) => be(&b[0..3]),
            (24, _) => be(&b[3..6]),
            (28, 0) => (usize::from(b[3] & 0xF0) << 20) | be(&b[0..3]),
            (28, _) => (usize::from(b[3] & 0x0F) << 24) | be(&b[4..7]),
            (_, 0) => be(&b[0..4]),
            (_, _) => be(&b[4..8]),
        })
    }

    fn lookup(&self, ip: IpAddr) -> Result<Option<Value>, String> {
        let (bits, mut node): (Vec<u8>, usize) = match ip {
            IpAddr::V4(v4) => {
                let start = if self.ip_version == 6 {
                    self.ipv4_start
                } else {
                    0
                };
                (v4.octets().to_vec(), start)
            }
            IpAddr::V6(v6) => {
                if self.ip_version == 4 {
                    match v6.to_ipv4_mapped() {
                        Some(v4) => (v4.octets().to_vec(), 0),
                        None => return Ok(None),
                    }
                } else {
                    (v6.octets().to_vec(), 0)
                }
            }
        };
        for i in 0..bits.len() * 8 {
            if node >= self.node_count {
                break;
            }
            let bit = (bits[i / 8] >> (7 - (i % 8))) & 1;
            node = self.record(node, bit)?;
        }
        if node <= self.node_count {
            // `node_count` itself means "no data"; less means the address
            // ran out of bits inside the tree.
            return Ok(None);
        }
        let offset = node - self.node_count - DATA_SEPARATOR;
        let decoder = Decoder {
            bytes: &self.bytes,
            base: self.data_start,
        };
        Ok(Some(decoder.decode(self.data_start + offset, 0)?.0))
    }

    /// The ISO 3166 alpha-2 country of `ip`, upper case, or `None` when the
    /// database does not know it (or the record cannot be read).
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let record = match self.lookup(ip) {
            Ok(record) => record?,
            Err(error) => {
                tracing::warn!(%error, "geoip: a record could not be read");
                return None;
            }
        };
        ["country", "registered_country"].iter().find_map(|k| {
            record
                .get(k)?
                .get("iso_code")?
                .as_str()
                .map(str::to_ascii_uppercase)
        })
    }
}

static DATABASE: OnceLock<Mmdb> = OnceLock::new();

/// Loads `auth.geoip_database` for the process; called once at boot.
/// Returns the database's node count, for the boot log.
pub fn load_file(path: &std::path::Path) -> Result<usize, String> {
    let db = Mmdb::open(path)?;
    let nodes = db.node_count;
    if DATABASE.set(db).is_err() {
        return Err("the GeoIP database was already loaded".into());
    }
    Ok(nodes)
}

/// Whether a database was loaded.
pub fn is_loaded() -> bool {
    DATABASE.get().is_some()
}

/// The country of `ip` from the loaded database; `None` with no database.
pub fn country(ip: IpAddr) -> Option<String> {
    DATABASE.get()?.country(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny MaxMind DB writer: an IPv4 tree with 24-bit records.
    enum Child {
        Empty,
        Node(usize),
        Data(usize),
    }

    fn ctrl(kind: u8, size: usize, out: &mut Vec<u8>) {
        assert!(size < 29);
        if kind <= 7 {
            out.push((kind << 5) | size as u8);
        } else {
            out.push(size as u8);
            out.push(kind - 7);
        }
    }

    fn string(s: &str, out: &mut Vec<u8>) {
        ctrl(2, s.len(), out);
        out.extend_from_slice(s.as_bytes());
    }

    fn uint(kind: u8, n: u32, out: &mut Vec<u8>) {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        ctrl(kind, 4 - skip, out);
        out.extend_from_slice(&bytes[skip..]);
    }

    fn build(prefixes: &[(&str, u8, &str, &str)]) -> Vec<u8> {
        let mut nodes: Vec<[Child; 2]> = vec![[Child::Empty, Child::Empty]];
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for (net, len, key, code) in prefixes {
            offsets.push(data.len());
            // {key: {iso_code: code}}
            ctrl(7, 1, &mut data);
            string(key, &mut data);
            ctrl(7, 1, &mut data);
            string("iso_code", &mut data);
            string(code, &mut data);
            let ip: std::net::Ipv4Addr = net.parse().unwrap();
            let bits = u32::from(ip);
            let mut node = 0;
            for i in 0..*len {
                let bit = ((bits >> (31 - i)) & 1) as usize;
                if i + 1 == *len {
                    nodes[node][bit] = Child::Data(offsets.len() - 1);
                } else {
                    node = match nodes[node][bit] {
                        Child::Node(n) => n,
                        _ => {
                            nodes.push([Child::Empty, Child::Empty]);
                            let n = nodes.len() - 1;
                            nodes[node][bit] = Child::Node(n);
                            n
                        }
                    };
                }
            }
        }
        let count = nodes.len();
        let mut out = Vec::new();
        for pair in &nodes {
            for child in pair {
                let v = match child {
                    Child::Empty => count,
                    Child::Node(n) => *n,
                    Child::Data(i) => count + DATA_SEPARATOR + offsets[*i],
                };
                out.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0; DATA_SEPARATOR]);
        out.extend_from_slice(&data);
        out.extend_from_slice(METADATA_MARKER);
        ctrl(7, 3, &mut out);
        string("node_count", &mut out);
        uint(6, count as u32, &mut out);
        string("record_size", &mut out);
        uint(5, 24, &mut out);
        string("ip_version", &mut out);
        uint(5, 4, &mut out);
        out
    }

    fn sample() -> Mmdb {
        Mmdb::from_bytes(build(&[
            ("10.0.0.0", 8, "country", "sa"),
            ("192.0.2.0", 24, "country", "AE"),
            ("198.51.100.0", 24, "registered_country", "EG"),
        ]))
        .unwrap()
    }

    #[test]
    fn login_restrictions_geoip_finds_countries() {
        let db = sample();
        assert_eq!(
            db.country("10.20.30.40".parse().unwrap()).as_deref(),
            Some("SA")
        );
        assert_eq!(
            db.country("192.0.2.200".parse().unwrap()).as_deref(),
            Some("AE")
        );
        assert_eq!(
            db.country("198.51.100.1".parse().unwrap()).as_deref(),
            Some("EG")
        );
        assert_eq!(
            db.country("::ffff:10.0.0.1".parse().unwrap()).as_deref(),
            Some("SA")
        );
    }

    #[test]
    fn login_restrictions_geoip_unknown_addresses() {
        let db = sample();
        assert_eq!(db.country("11.0.0.1".parse().unwrap()), None);
        assert_eq!(db.country("192.0.3.1".parse().unwrap()), None);
        assert_eq!(db.country("2001:db8::1".parse().unwrap()), None);
    }

    #[test]
    fn login_restrictions_geoip_rejects_garbage() {
        assert!(Mmdb::from_bytes(b"not a database".to_vec()).is_err());
        let mut truncated = build(&[("10.0.0.0", 8, "country", "SA")]);
        truncated.drain(0..4);
        // A shifted tree either fails to parse or answers nothing; it never panics.
        if let Ok(db) = Mmdb::from_bytes(truncated) {
            let _ = db.country("10.0.0.1".parse().unwrap());
        }
    }

    #[test]
    fn login_restrictions_geoip_decodes_pointers_and_extended_types() {
        // A pointer (ss = 0) to offset 0, where a string sits.
        let mut bytes = Vec::new();
        string("SA", &mut bytes);
        let at = bytes.len();
        bytes.push(0b0010_0000);
        bytes.push(0);
        let d = Decoder {
            bytes: &bytes,
            base: 0,
        };
        let (value, next) = d.decode(at, 0).unwrap();
        assert_eq!(value, Value::Str("SA".into()));
        assert_eq!(next, at + 2);
        // An extended type (int32, one byte) is skipped whole.
        let bytes = [0x01, 0x01, 0xFF];
        let d = Decoder {
            bytes: &bytes,
            base: 0,
        };
        assert_eq!(d.decode(0, 0).unwrap(), (Value::Other, 3));
    }
}
