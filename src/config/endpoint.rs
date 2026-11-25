use crate::{
    address::{Host, Target},
    policy::Rules,
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

pub(crate) enum Endpoint {
    Ip(SocketAddr),
    Name(String, u16),
}

impl Endpoint {
    pub fn from_host(host: &str, port: u16) -> Result<Self, &'static str> {
        if port == 0 {
            return Err("invalid upstream port");
        }
        match Target::parse_name(host.as_bytes()).map_err(|_| "invalid upstream hostname")? {
            Host::Ip(ip) => Self::numeric(SocketAddr::new(ip, port)),
            Host::Name(name) => {
                let name = name.trim_end_matches('.');
                if !name.contains('.')
                    || Rules::default().blocks(name)
                    || ["arpa", "onion", "internal", "lan", "corp", "ts.net"]
                        .iter()
                        .any(|s| {
                            name == *s || name.strip_suffix(s).is_some_and(|p| p.ends_with('.'))
                        })
                {
                    return Err("private upstream names require an explicit IP");
                }
                Ok(Self::Name(name.to_owned(), port))
            }
        }
    }

    fn numeric(addr: SocketAddr) -> Result<Self, &'static str> {
        let ip = addr.ip().to_canonical();
        if addr.port() == 0
            || ip.is_multicast()
            || ip.is_unspecified()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
        {
            return Err("invalid upstream endpoint");
        }
        Ok(Self::Ip(addr))
    }
}

impl FromStr for Endpoint {
    type Err = &'static str;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return Self::numeric(addr);
        }
        let (host, port) = raw.rsplit_once(':').ok_or("missing upstream port")?;
        if host.contains(':') || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid upstream authority");
        }
        Self::from_host(host, port.parse().map_err(|_| "invalid upstream port")?)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => addr.fmt(f),
            Self::Name(name, port) => write!(f, "{name}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_and_numeric_authorities_are_canonical_and_unambiguous() {
        for (raw, canonical) in [
            ("PrOxY.ExAmPlE.:443", "proxy.example:443"),
            ("[2001:db8::1]:98", "[2001:db8::1]:98"),
        ] {
            assert_eq!(raw.parse::<Endpoint>().unwrap().to_string(), canonical);
        }
        for address in [
            "single:443",
            "127.1:9",
            "0x7f000001:9",
            "::1:92",
            "thing.arpa:443",
            "node.home.arpa:90",
            "abc.localhost:53",
            "x.onion:90",
            "node..example:1",
            "example.org:0",
            "example.org:+9",
        ] {
            assert!(address.parse::<Endpoint>().is_err(), "{address}");
        }
    }
}
