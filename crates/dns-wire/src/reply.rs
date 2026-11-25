use crate::{DecodeResult, Error, MAX_PACKET, RecordType, hostname};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn word(data: &[u8], at: usize) -> DecodeResult<u16> {
    data.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(Error("truncated DNS record"))
}

fn name(data: &[u8], at: &mut usize) -> DecodeResult<String> {
    let mut result = String::new();
    let mut pos = *at;
    let mut jumped = false;
    for _ in 0..128 {
        let len = *data.get(pos).ok_or(Error("truncated DNS label"))?;
        if len & 0xc0 == 0xc0 {
            let next = usize::from(word(data, pos)? & 0x3fff);
            if next >= pos {
                return Err(Error("forward DNS compression pointer"));
            }
            if !jumped {
                *at = pos + 2;
                jumped = true;
            }
            pos = next;
            continue;
        }
        pos += 1;
        if len == 0 {
            if !jumped {
                *at = pos;
            }
            return Ok(result);
        }
        if len > 63 {
            return Err(Error("invalid DNS label"));
        }
        let end = pos + usize::from(len);
        let label = data.get(pos..end).ok_or(Error("truncated DNS name"))?;
        if !label
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return Err(Error("invalid DNS name"));
        }
        if !result.is_empty() {
            result.push('.');
        }
        result.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
        if result.len() > 253 {
            return Err(Error("DNS name too long"));
        }
        pos = end;
    }
    Err(Error("too many DNS labels"))
}

/// Decode at most 16 addresses for the requested owner or its CNAME target.
/// The caller must authenticate the DNS transport when using an untrusted network.
pub fn answers(data: &[u8], asked: &str, kind: RecordType, id: u16) -> Result<Vec<IpAddr>, Error> {
    if data.len() > MAX_PACKET {
        return Err(Error("DNS reply exceeds 16 KiB"));
    }
    let asked = hostname(asked)?;

    let flags = word(data, 2)?;
    if word(data, 0)? != id
        || flags & 0xfa00 != 0x8000
        || word(data, 4)? != 1
        || !matches!(flags & 15, 0 | 3)
    {
        return Err(Error("invalid DNS response"));
    }
    let count = word(data, 6)?;
    if count > 256 {
        return Err(Error("too many DNS answers"));
    }
    let mut at = 12;
    let owner = name(data, &mut at)?;
    if !owner.eq_ignore_ascii_case(asked)
        || word(data, at)? != kind as u16
        || word(data, at + 2)? != 1
    {
        return Err(Error("mismatched DNS question"));
    }
    if flags & 15 == 3 {
        return Ok(Vec::new());
    }
    at += 4;
    let mut aliases = BTreeMap::new();
    let mut addresses = Vec::new();
    for _ in 0..count {
        let rr_name = name(data, &mut at)?;
        let typ = word(data, at)?;
        let class = word(data, at + 2)?;
        let size = usize::from(word(data, at + 8)?);
        at += 10;
        let rdata = data.get(at..at + size).ok_or(Error("truncated DNS data"))?;
        if class == 1 && typ == 5 {
            let mut end = at;
            let target = name(data, &mut end)?;
            if end != at + size || aliases.insert(rr_name, target).is_some() {
                return Err(Error("invalid CNAME record"));
            }
        } else if class == 1 && typ == kind as u16 {
            let ip = match kind {
                RecordType::A => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(rdata).map_err(|_| Error("invalid DNS address length"))?,
                )),
                RecordType::Aaaa => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(rdata).map_err(|_| Error("invalid DNS address length"))?,
                )),
            };
            addresses.push((rr_name, ip));
        }
        at += size;
    }
    let mut canonical = owner.as_str();
    for _ in 0..16 {
        match aliases.get(canonical) {
            Some(alias) => canonical = alias,
            None => {
                return Ok(addresses
                    .into_iter()
                    .filter_map(|(name, ip)| (name == canonical).then_some(ip))
                    .take(16)
                    .collect());
            }
        }
    }
    Err(Error("CNAME chain too long"))
}
