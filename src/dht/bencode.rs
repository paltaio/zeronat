//! Minimal bencode codec for the KRPC layer. Dicts use a `BTreeMap` so keys
//! encode in the lexicographic order bencode requires.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ben {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Ben>),
    Dict(BTreeMap<Vec<u8>, Ben>),
}

impl Ben {
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Ben::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn int(&self) -> Option<i64> {
        match self {
            Ben::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Look up a key in a dict value; `None` for non-dicts or missing keys.
    pub fn get(&self, key: &[u8]) -> Option<&Ben> {
        match self {
            Ben::Dict(d) => d.get(key),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Ben::Int(i) => {
                out.push(b'i');
                out.extend_from_slice(i.to_string().as_bytes());
                out.push(b'e');
            }
            Ben::Bytes(b) => encode_bytes(out, b),
            Ben::List(l) => {
                out.push(b'l');
                for e in l {
                    e.encode_into(out);
                }
                out.push(b'e');
            }
            Ben::Dict(d) => {
                out.push(b'd');
                for (k, v) in d {
                    encode_bytes(out, k);
                    v.encode_into(out);
                }
                out.push(b'e');
            }
        }
    }
}

fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(b);
}

/// Decode one value from the front of `buf`. Trailing bytes are tolerated, since
/// KRPC datagrams are self-delimiting and may be padded by some implementations.
pub fn decode(buf: &[u8]) -> Option<Ben> {
    parse(buf).map(|(v, _)| v)
}

fn parse(buf: &[u8]) -> Option<(Ben, &[u8])> {
    match buf.first()? {
        b'i' => {
            let end = buf.iter().position(|&c| c == b'e')?;
            let n: i64 = std::str::from_utf8(&buf[1..end]).ok()?.parse().ok()?;
            Some((Ben::Int(n), &buf[end + 1..]))
        }
        b'l' => {
            let mut rest = &buf[1..];
            let mut items = Vec::new();
            while *rest.first()? != b'e' {
                let (v, r) = parse(rest)?;
                items.push(v);
                rest = r;
            }
            Some((Ben::List(items), &rest[1..]))
        }
        b'd' => {
            let mut rest = &buf[1..];
            let mut map = BTreeMap::new();
            while *rest.first()? != b'e' {
                let (k, r) = parse_bytes(rest)?;
                let (v, r2) = parse(r)?;
                map.insert(k, v);
                rest = r2;
            }
            Some((Ben::Dict(map), &rest[1..]))
        }
        b'0'..=b'9' => {
            let (b, r) = parse_bytes(buf)?;
            Some((Ben::Bytes(b), r))
        }
        _ => None,
    }
}

fn parse_bytes(buf: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let colon = buf.iter().position(|&c| c == b':')?;
    let len: usize = std::str::from_utf8(&buf[..colon]).ok()?.parse().ok()?;
    let start = colon + 1;
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((buf[start..end].to_vec(), &buf[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut d = BTreeMap::new();
        d.insert(b"q".to_vec(), Ben::Bytes(b"get".to_vec()));
        d.insert(b"seq".to_vec(), Ben::Int(-7));
        d.insert(
            b"list".to_vec(),
            Ben::List(vec![Ben::Int(1), Ben::Bytes(b"x".to_vec())]),
        );
        let v = Ben::Dict(d);
        let enc = v.encode();
        assert_eq!(decode(&enc).unwrap(), v);
    }

    #[test]
    fn canonical_dict_key_order() {
        let mut d = BTreeMap::new();
        d.insert(b"b".to_vec(), Ben::Int(2));
        d.insert(b"a".to_vec(), Ben::Int(1));
        assert_eq!(Ben::Dict(d).encode(), b"d1:ai1e1:bi2ee");
    }

    #[test]
    fn known_values() {
        assert_eq!(Ben::Int(42).encode(), b"i42e");
        assert_eq!(Ben::Bytes(b"spam".to_vec()).encode(), b"4:spam");
        assert_eq!(decode(b"i0e").unwrap(), Ben::Int(0));
        assert_eq!(decode(b"5:hello").unwrap(), Ben::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(b"5:hi").is_none());
        assert!(decode(b"d1:a").is_none());
    }
}
