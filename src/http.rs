use crate::{
    address::{Target, bad},
    config::Upstream,
};
use std::io::{self, Read, Write};

const HEADER_LIMIT: usize = 8192;

pub(crate) fn head(w: &mut impl Read, prefix: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = prefix.to_vec();
    let mut start = 0;
    let mut buf = [0; 1024];
    loop {
        if let Some(index) = data[start..].windows(4).position(|b| b == b"\r\n\r\n") {
            let tail = data.split_off(start + index + 4);
            return Ok((data, tail));
        }
        let size = (HEADER_LIMIT - data.len()).min(buf.len());
        if size == 0 {
            return Err(bad("HTTP headers exceed 8 KiB"));
        }
        start = data.len().saturating_sub(3);
        let n = w.read(&mut buf[..size])?;
        if n == 0 {
            return Err(bad("incomplete HTTP headers"));
        }
        data.extend_from_slice(&buf[..n]);
    }
}

pub(crate) fn reply(w: &mut impl Write, code: u16) -> io::Result<()> {
    let data = match code {
        200 => "HTTP/1.1 200 Connection Established\r\n\r\n",
        407 => {
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"magicbox\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        403 => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        502 => "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        _ => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    };
    w.write_all(data.as_bytes())
}

pub(crate) struct Request {
    pub target: Target,
    pub tail: Vec<u8>,
    pub authorization: Option<String>,
}

pub(crate) fn accept(w: &mut impl Read, prefix: &[u8]) -> io::Result<Request> {
    let (raw, tail) = head(w, prefix)?;
    let text = std::str::from_utf8(&raw).map_err(|_| bad("invalid HTTP request encoding"))?;
    let mut lines = text.split("\r\n");
    let mut fields = lines.next().unwrap_or_default().split(' ');
    let method = fields.next().unwrap_or_default();
    let authority = fields.next().ok_or_else(|| bad("missing HTTP authority"))?;
    let version = fields.next().unwrap_or_default();
    if method != "CONNECT" || !matches!(version, "HTTP/1.0" | "HTTP/1.1") || fields.next().is_some()
    {
        return Err(bad("invalid CONNECT request"));
    }
    let target = Target::parse_authority(authority)?;
    let mut has_host = false;
    let mut authorization = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad("invalid HTTP field"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err(bad("invalid HTTP header bytes"));
        }
        if name.eq_ignore_ascii_case("proxy-authorization")
            && authorization.replace(value.trim().to_owned()).is_some()
        {
            return Err(bad("duplicate Proxy-Authorization"));
        }
        if name.eq_ignore_ascii_case("host") {
            if has_host || !value.trim().eq_ignore_ascii_case(authority) {
                return Err(bad("invalid Host field"));
            }
            has_host = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(bad("unexpected CONNECT body"));
        }
    }
    if version == "HTTP/1.1" && !has_host {
        return Err(bad("missing Host header"));
    }
    Ok(Request {
        target,
        tail,
        authorization,
    })
}

pub(crate) fn connect(
    w: &mut (impl Read + Write),
    upstream: &Upstream,
    target: &Target,
) -> io::Result<Vec<u8>> {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((user, password)) = &upstream.auth {
        let mut pair = user.clone();
        pair.push(b':');
        pair.extend(password);
        let mut out = vec![0; pair.len().div_ceil(3) * 4];
        let size = z64::encode(&pair, &mut out, z64::Mode::Standard)
            .map_err(|_| bad("base64 output size"))?;
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(std::str::from_utf8(&out[..size]).map_err(|_| bad("base64 output"))?);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    w.write_all(req.as_bytes())?;
    let (data, tail) = head(w, &[])?;
    let line = data.split(|&v| v == b'\r').next().unwrap_or_default();
    let mut parts = line.split(|&v| v == b' ');
    if !matches!(parts.next(), Some(b"HTTP/1.0" | b"HTTP/1.1"))
        || !parts
            .next()
            .is_some_and(|s| s.len() == 3 && s[0] == b'2' && s[1..].iter().all(u8::is_ascii_digit))
    {
        return Err(bad("upstream refused CONNECT"));
    }
    Ok(tail)
}
