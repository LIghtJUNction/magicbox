use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
};

pub(crate) enum Host {
    Ip(IpAddr),
    Name(String),
}

pub(crate) struct Target {
    pub host: Host,
    pub port: u16,
}

pub fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Target {
    pub fn parse_authority(raw: &str) -> io::Result<Self> {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return Self::new(Host::Ip(addr.ip()), addr.port());
        }
        let (host, port) = raw.rsplit_once(':').ok_or_else(|| bad("missing port"))?;
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("invalid port"));
        }
        let port = port.parse().map_err(|_| bad("invalid port"))?;
        Self::new(Self::parse_name(host.as_bytes())?, port)
    }

    pub fn parse_name(bytes: &[u8]) -> io::Result<Host> {
        let name = std::str::from_utf8(bytes).map_err(|_| bad("invalid domain"))?;
        let bare = name.strip_suffix('.').unwrap_or(name);
        if let Ok(ip) = bare.parse() {
            return Ok(Host::Ip(ip));
        }
        if bare.len() > 253
            || bare.split('.').any(|s| {
                s.is_empty()
                    || s.len() > 63
                    || s.starts_with('-')
                    || s.ends_with('-')
                    || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(bad("invalid DNS name"));
        }
        // Reject ambiguous non-canonical numeric hosts accepted by legacy IP parsers.
        if bare.split('.').all(|s| {
            s.bytes().all(|c| c.is_ascii_digit())
                || s.strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_hexdigit()))
        }) {
            return Err(bad("ambiguous numeric address"));
        }
        Ok(Host::Name(name.to_ascii_lowercase()))
    }

    pub fn new(host: Host, port: u16) -> io::Result<Self> {
        if port == 0 {
            return Err(bad("port zero"));
        }
        Ok(Self { host, port })
    }

    pub fn permitted(
        &self,
        listener: SocketAddr,
        upstream: SocketAddr,
        rules: &crate::policy::Rules,
    ) -> bool {
        match &self.host {
            Host::Name(name) => !rules.blocks(name.trim_end_matches('.')),
            Host::Ip(ip) => {
                let ip = ip.to_canonical();
                let endpoint = SocketAddr::new(ip, self.port);
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast() || v4.is_link_local())
                    && !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
                    && !crate::config::same_endpoint(endpoint, listener)
                    && !crate::config::same_endpoint(endpoint, upstream)
            }
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(ip) => write!(f, "{}", SocketAddr::new(*ip, self.port)),
            Host::Name(name) => write!(f, "{name}:{}", self.port),
        }
    }
}
