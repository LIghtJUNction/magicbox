//! Strict A/AAAA replies on a single authenticated DNS-over-TLS connection.
use crate::address::bad;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub fn query(name: &str, kind: u16, id: u16) -> Vec<u8> {
    let mut packet = vec![0; 12];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1; // recursive query
    packet[5] = 1;
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend(label.bytes());
    }
    packet.extend([0, 0, kind as u8, 0, 1]);
    packet
}

fn word(data: &[u8], at: usize) -> io::Result<u16> {
    data.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| bad("truncated DNS record"))
}

fn name(data: &[u8], at: &mut usize) -> io::Result<String> {
    let mut result = String::new();
    let mut pos = *at;
    let mut jumped = false;
    for _ in 0..128 {
        let len = *data.get(pos).ok_or_else(|| bad("truncated DNS label"))?;
        if len & 0xc0 == 0xc0 {
            let next = usize::from(word(data, pos)? & 0x3fff);
            if next >= pos {
                return Err(bad("forward DNS compression pointer"));
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
            return Err(bad("invalid DNS label"));
        }
        let end = pos + usize::from(len);
        let label = data
            .get(pos..end)
            .ok_or_else(|| bad("truncated DNS name"))?;
        if !label
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return Err(bad("invalid DNS name"));
        }
        if !result.is_empty() {
            result.push('.');
        }
        result.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
        if result.len() > 253 {
            return Err(bad("DNS name too long"));
        }
        pos = end;
    }
    Err(bad("too many DNS labels"))
}

pub fn answers(data: &[u8], asked: &str, kind: u16, id: u16) -> io::Result<Vec<IpAddr>> {
    let flags = word(data, 2)?;
    if word(data, 0)? != id
        || flags & 0xfa00 != 0x8000
        || word(data, 4)? != 1
        || !matches!(flags & 15, 0 | 3)
    {
        return Err(bad("invalid DNS response"));
    }
    let count = word(data, 6)?;
    if count > 256 {
        return Err(bad("too many DNS answers"));
    }
    let mut at = 12;
    let owner = name(data, &mut at)?;
    if owner != asked.trim_end_matches('.') || word(data, at)? != kind || word(data, at + 2)? != 1 {
        return Err(bad("mismatched DNS question"));
    }
    if flags & 15 == 3 {
        return Ok(Vec::new());
    }
    at += 4;
    let mut aliases = HashMap::new();
    let mut addresses = Vec::new();
    for _ in 0..count {
        let rr_name = name(data, &mut at)?;
        let typ = word(data, at)?;
        let class = word(data, at + 2)?;
        let size = usize::from(word(data, at + 8)?);
        at += 10;
        let rdata = data
            .get(at..at + size)
            .ok_or_else(|| bad("truncated DNS data"))?;
        if class == 1 && typ == 5 {
            let mut end = at;
            let target = name(data, &mut end)?;
            if end != at + size || aliases.insert(rr_name, target).is_some() {
                return Err(bad("invalid CNAME record"));
            }
        } else if class == 1 && typ == kind {
            let ip = match kind {
                1 => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(rdata).map_err(|_| bad("invalid DNS address length"))?,
                )),
                28 => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(rdata).map_err(|_| bad("invalid DNS address length"))?,
                )),
                _ => return Err(bad("invalid DNS query type")),
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
    Err(bad("CNAME chain too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply() -> Vec<u8> {
        let mut msg = query("a.test", 1, 42);
        msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        msg[7] = 1;
        msg
    }

    #[test]
    fn validates_transaction_and_ignores_unrelated_records() {
        let mut msg = reply();
        msg.extend([
            1, b'b', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1,
        ]);
        assert!(answers(&msg, "a.test", 1, 42).unwrap().is_empty());
        for (asked, kind, id) in [("a.test", 1, 43), ("b.test", 1, 42), ("a.test", 28, 42)] {
            assert!(answers(&msg, asked, kind, id).is_err());
        }
    }

    #[test]
    fn follows_compressed_cname_chain() {
        let mut msg = reply();
        msg[7] = 2;
        msg.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 4]);
        let alias = msg.len() as u8;
        msg.extend([1, b'b', 0xc0, 14]);
        msg.extend([0xc0, alias, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 1, 1, 1]);
        assert_eq!(
            answers(&msg, "a.test", 1, 42).unwrap(),
            [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
        );
    }

    #[test]
    fn rejects_truncation_compression_cycles_and_bogus_lengths() {
        let base = reply();
        for suffix in [
            vec![0xc0, base.len() as u8],
            vec![64],
            vec![0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 255],
            vec![0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1],
        ] {
            let mut msg = base.clone();
            msg.extend(suffix);
            assert!(answers(&msg, "a.test", 1, 42).is_err());
        }
        let mut truncated = base;
        truncated[2] |= 2;
        assert!(answers(&truncated, "a.test", 1, 42).is_err());
    }
}
