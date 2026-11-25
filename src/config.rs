pub(crate) mod ss_uri;

use std::{
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
};

pub(crate) enum Protocol {
    Socks5,
    Http,
    Https,
    Shadowsocks,
}

pub(crate) struct Upstream {
    pub scheme: Protocol,
    pub addr: SocketAddr,
    pub server_name: Option<String>,
    pub auth: Option<(Vec<u8>, Vec<u8>)>,
}

impl Upstream {
    pub fn parse(uri: &str) -> Result<Self, &'static str> {
        let (scheme, authority) = uri.split_once("://").ok_or("invalid upstream URL")?;
        let scheme = match scheme {
            "ss" => return ss_uri::parse(authority),
            "socks5" => Protocol::Socks5,
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            _ => return Err("upstream scheme must be socks5, http, https or ss"),
        };
        if matches!(scheme, Protocol::Https) && !cfg!(unix) {
            return Err("HTTPS upstreams require a Unix target");
        }
        let (authority, server_name) = match authority.split_once('?') {
            None => (authority, None),
            Some((authority, query)) if matches!(scheme, Protocol::Https) => {
                let value = query
                    .strip_prefix("server_name=")
                    .ok_or("invalid HTTPS query")?;
                let name = rustls::pki_types::DnsName::try_from(value)
                    .map_err(|_| "invalid TLS server name")?;
                (authority, Some(name.as_ref().to_ascii_lowercase()))
            }
            Some(_) => return Err("query is only supported for HTTPS"),
        };
        let (address, auth) = match authority.rsplit_once('@') {
            None => (authority, None),
            Some((info, address)) => {
                let (user, pass) = info
                    .split_once(':')
                    .ok_or("expected upstream user and password")?;
                let pair = (decode_field(user)?, decode_field(pass)?);
                if matches!(scheme, Protocol::Http | Protocol::Https) && pair.0.contains(&b':') {
                    return Err("HTTP Basic username contains a colon");
                }
                (address, Some(pair))
            }
        };
        let addr = parse_address(address)?;
        Ok(Self {
            scheme,
            addr,
            auth,
            server_name,
        })
    }
}

fn parse_address(address: &str) -> Result<SocketAddr, &'static str> {
    let addr: SocketAddr = address
        .parse()
        .map_err(|_| "upstream requires a numeric IP and port")?;
    let ip = addr.ip().to_canonical();
    if addr.port() == 0
        || ip.is_multicast()
        || ip.is_unspecified()
        || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
    {
        return Err("invalid upstream endpoint");
    }
    Ok(addr)
}

fn decode_field(value: &str) -> Result<Vec<u8>, &'static str> {
    decode_bounded(value, 255)
}

fn decode_bounded(value: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::new();
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        let byte = match byte {
            b'%' => {
                let mut hex = || {
                    bytes
                        .next()
                        .and_then(|v| (v as char).to_digit(16))
                        .ok_or("invalid percent escape")
                };
                (hex()? * 16 + hex()?) as u8
            }
            b if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:".contains(&b) => b,
            _ => return Err("invalid upstream credentials"),
        };
        if byte.is_ascii_control() {
            return Err("control byte in credentials");
        }
        result.push(byte);
        if result.len() > limit {
            return Err("upstream credential length exceeded");
        }
    }
    if result.is_empty() {
        return Err("upstream credentials must be nonempty");
    }
    Ok(result)
}

pub(crate) struct Config {
    pub listen: SocketAddr,
    pub upstream: Option<Upstream>,
    pub tls: Option<std::sync::Arc<rustls::ClientConfig>>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let mut raw = String::new();
        File::open(path)
            .and_then(|f| f.take(65_537).read_to_string(&mut raw))
            .map_err(|e| format!("read config: {e}"))?;
        if raw.len() > 65_536 {
            return Err("config exceeds 64 KiB".into());
        }
        let mut table = raw.parse::<toml::Table>().map_err(|_| "invalid TOML")?;
        let mut field = |name: &str| {
            table
                .remove(name)
                .map(|v| match v {
                    toml::Value::String(s) => Ok(s),
                    _ => Err(format!("{name} must be a string")),
                })
                .transpose()
        };
        let listen: SocketAddr = field("listen")?
            .as_deref()
            .unwrap_or("127.0.0.1:1080")
            .parse()
            .map_err(|_| "listen requires a loopback IP and port")?;
        if !listen.ip().to_canonical().is_loopback() {
            return Err("listen must use a loopback address".into());
        }
        let upstream = field("upstream")?
            .as_deref()
            .map(Upstream::parse)
            .transpose()?;
        if !table.is_empty() {
            return Err("unknown TOML key".into());
        }
        let tls = match &upstream {
            Some(u) if matches!(u.scheme, Protocol::Https) => Some(crate::tls::trust()?),
            _ => None,
        };
        let config = Self {
            listen,
            upstream,
            tls,
        };
        config.check_listener(listen)?;
        Ok(config)
    }

    pub fn check_listener(&self, addr: SocketAddr) -> Result<(), &'static str> {
        if self
            .upstream
            .as_ref()
            .is_some_and(|u| same_endpoint(u.addr, addr))
        {
            return Err("upstream points to the listener");
        }
        Ok(())
    }
}

pub fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}
