use crate::address::bad;
use std::io::{self, BufRead, BufReader, Read};

pub const LIMIT: usize = 2 << 20;

fn line(r: &mut impl BufRead, cap: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    r.take(cap as u64 + 1).read_until(b'\n', &mut bytes)?;
    if bytes.len() > cap || !bytes.ends_with(b"\r\n") {
        return Err(bad("invalid HTTP chunk framing"));
    }
    bytes.truncate(bytes.len() - 2);
    Ok(bytes)
}

fn append(r: &mut impl Read, out: &mut Vec<u8>, len: usize) -> io::Result<()> {
    let end = out
        .len()
        .checked_add(len)
        .filter(|n| *n <= LIMIT)
        .ok_or_else(|| bad("feed exceeds 2 MiB"))?;
    let start = out.len();
    out.resize(end, 0);
    r.read_exact(&mut out[start..])
}

pub fn read(r: impl Read, length: Option<usize>, chunked: bool) -> io::Result<Vec<u8>> {
    let mut input = BufReader::new(r);
    let mut out = Vec::new();
    if chunked {
        let mut overhead = 0;
        loop {
            let size = line(&mut input, 1024)?;
            overhead += size.len() + 4;
            if overhead > 65536 {
                return Err(bad("excessive chunk framing"));
            }
            let size = size.split(|&b| b == b';').next().unwrap_or_default();
            if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
                return Err(bad("invalid chunk size"));
            }
            let size = usize::from_str_radix(
                std::str::from_utf8(size).map_err(|_| bad("invalid chunk size"))?,
                16,
            )
            .map_err(|_| bad("invalid chunk size"))?;
            if size == 0 {
                let mut total = 0;
                loop {
                    let v = line(&mut input, 1024)?;
                    if v.is_empty() {
                        break;
                    }
                    total += v.len() + 2;
                    if total > 8192 {
                        return Err(bad("excessive trailers"));
                    }
                }
                break;
            }
            append(&mut input, &mut out, size)?;
            if !line(&mut input, 2)?.is_empty() {
                return Err(bad("invalid chunk ending"));
            }
        }
    } else if let Some(len) = length {
        append(&mut input, &mut out, len)?;
    } else {
        input.take((LIMIT + 1) as u64).read_to_end(&mut out)?;
        if out.len() > LIMIT {
            return Err(bad("feed exceeds 2 MiB"));
        }
    }
    if out.is_empty() {
        return Err(bad("empty feed"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_bounds_and_content_length() {
        assert_eq!(
            read(&b"3\r\nabc\r\n0\r\n\r\n"[..], None, true).unwrap(),
            b"abc"
        );
        for bytes in [
            &b"ffffff\r\n"[..],
            b"3\r\nab",
            b"3\r\nabcxx",
            b"xyz\r\n",
            b"0\r\n",
        ] {
            assert!(read(bytes, None, true).is_err());
        }
        assert!(read(&b"a"[..], Some(2), false).is_err());
        assert!(read(&b""[..], Some(LIMIT + 1), false).is_err());
    }
}
