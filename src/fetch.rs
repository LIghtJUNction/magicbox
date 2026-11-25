mod body;
mod url;

use crate::{address::bad, egress, handshake::Wire, policy::Rules, resolver::Resolver};
use rustls::{ClientConfig, ClientConnection};
use std::{
    env,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;

enum Response {
    Feed(Vec<u8>),
    Redirect(String),
}

fn fetch(
    url: &Url,
    agent: &str,
    resolver: &Resolver,
    roots: Arc<ClientConfig>,
    rules: &Rules,
    deadline: Instant,
) -> io::Result<Response> {
    let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let mut socket = egress::open(&url.target, local, rules, resolver, deadline)?;
    let mut wire = Wire {
        stream: &mut socket,
        deadline,
    };
    let mut session = ClientConnection::new(roots, url.identity()?).map_err(io::Error::other)?;
    let mut secure = rustls::Stream::new(&mut session, &mut wire);
    write!(
        secure,
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {agent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path, url.authority
    )?;
    secure.flush()?;
    let (headers, tail) = crate::http::head(&mut secure, &[])?;
    let mut lines = std::str::from_utf8(&headers)
        .map_err(|_| bad("invalid HTTP headers"))?
        .split("\r\n");
    let mut status = lines.next().unwrap_or_default().split(' ');
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(bad("invalid feed HTTP response"));
    }
    let status = status.next().unwrap_or_default();
    let mut location = None;
    let mut length = None;
    let mut chunked = false;
    for line in lines.take_while(|s| !s.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad("invalid feed HTTP header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err(bad("invalid HTTP field"));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("location") && location.replace(value.to_owned()).is_some() {
            return Err(bad("ambiguous feed redirect"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
                return Err(bad("invalid content length"));
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| bad("invalid content length"))?,
            );
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(bad("unsupported transfer encoding"));
            }
            chunked = true;
        }
        if status == "200"
            && name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(bad("unsupported content encoding"));
        }
    }
    if chunked && length.is_some() {
        return Err(bad("ambiguous feed framing"));
    }
    match status {
        "200" => Ok(Response::Feed(body::read(
            tail.as_slice().chain(secure),
            length,
            chunked,
        )?)),
        "301" | "302" | "303" | "307" | "308" => Ok(Response::Redirect(
            location.ok_or_else(|| bad("missing redirect location"))?,
        )),
        _ => Err(bad("subscription endpoint returned a non-success status")),
    }
}

pub fn cli(argument: &str) -> Result<(), String> {
    let mut raw = String::new();
    let raw = if argument == "-" {
        io::stdin()
            .take(8194)
            .read_to_string(&mut raw)
            .map_err(|_| "cannot read feed URL")?;
        if raw.len() > 8193 {
            return Err("feed URL too long".into());
        }
        raw.strip_suffix('\n').unwrap_or(&raw)
    } else {
        argument
    };
    let mut url = Url::parse(raw).map_err(|e| e.to_string())?;
    let origin = url.authority.clone();
    let default_agent = concat!("magicbox/", env!("CARGO_PKG_VERSION"));
    let agent = env::var("MAGICBOX_USER_AGENT").unwrap_or_else(|_| default_agent.into());
    if agent.is_empty()
        || agent.len() > 255
        || !agent.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return Err("invalid subscription user agent".into());
    }
    let resolver = Resolver::new(
        &env::var("MAGICBOX_RESOLVER").unwrap_or_else(|_| crate::resolver::DEFAULT.into()),
    )?;
    let roots = crate::tls::trust()?;
    let rules = Rules::from_env().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(20);
    for redirect in 0..=3 {
        let ua = if url.authority == origin {
            agent.as_str()
        } else {
            default_agent
        };
        match fetch(&url, ua, &resolver, roots.clone(), &rules, deadline)
            .map_err(|_| "HTTPS feed request failed")?
        {
            Response::Feed(bytes) => {
                return io::stdout()
                    .lock()
                    .write_all(&bytes)
                    .map_err(|e| e.to_string());
            }
            Response::Redirect(loc) if redirect < 3 => {
                url = url.redirect(&loc).map_err(|e| e.to_string())?
            }
            Response::Redirect(_) => return Err("too many feed redirects".into()),
        }
    }
    Err("invalid redirect state".into())
}
