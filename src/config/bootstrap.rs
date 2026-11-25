//! Import and configuration validation never dial. At activation a single
//! authenticated DNS transaction pins the usable peers for this process.
use super::{Endpoint, NodeSpec, Protocol, Upstream, same_endpoint};
use crate::{
    address::{Host, Target},
    egress,
    policy::Rules,
    resolver::Resolver,
};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Peers {
    name: Option<String>,
    other: Vec<SocketAddr>,
}

impl NodeSpec {
    pub fn activate(self) -> Result<Upstream, String> {
        let mut peers = Peers::default();
        let mut tls_name = self.server_name;
        let addr = match self.addr {
            Endpoint::Ip(addr) => addr,
            Endpoint::Name(name, port) => {
                let resolver = Resolver::from_env()?;
                let deadline = Instant::now() + Duration::from_secs(5);
                let ips = resolver
                    .resolve(&name, deadline)
                    .map_err(|_| "encrypted upstream DNS failed")?;
                let mut addrs = Vec::new();
                for ip in ips {
                    let ip = ip.to_canonical();
                    let addr = SocketAddr::new(ip, port);
                    if egress::public(ip)
                        && !addrs.contains(&addr)
                        && matches!(egress::local_interface(ip), Ok(false))
                    {
                        addrs.push(addr);
                    }
                }
                let mut addrs = addrs.into_iter();
                let first = addrs.next().ok_or("no eligible public upstream address")?;
                if matches!(self.scheme, Protocol::Https) && tls_name.is_none() {
                    tls_name = Some(name.clone());
                }
                peers = Peers {
                    name: Some(name),
                    other: addrs.collect(),
                };
                first
            }
        };
        Ok(Upstream {
            scheme: self.scheme,
            addr,
            peers,
            auth: self.auth,
            server_name: tls_name,
        })
    }
}

impl Upstream {
    pub fn connect(&self, deadline: Instant) -> io::Result<TcpStream> {
        let mut error = io::ErrorKind::NotFound.into();
        let mut peers = std::iter::once(&self.addr)
            .chain(&self.peers.other)
            .peekable();
        while let Some(addr) = peers.next() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(io::ErrorKind::TimedOut)?;
            let timeout = if peers.peek().is_some() {
                remaining.min(Duration::from_secs(1))
            } else {
                remaining
            };
            match TcpStream::connect_timeout(addr, timeout) {
                Ok(socket) => return Ok(socket),
                Err(e) => error = e,
            }
        }
        Err(error)
    }

    pub fn permits(&self, target: &Target, listener: SocketAddr, rules: &Rules) -> bool {
        if target.port == self.addr.port() {
            match &target.host {
                Host::Name(name)
                    if self.peers.name.as_deref() == Some(name.trim_end_matches('.')) =>
                {
                    return false;
                }
                Host::Ip(ip)
                    if self
                        .peers
                        .other
                        .iter()
                        .any(|a| same_endpoint(*a, SocketAddr::new(*ip, target.port))) =>
                {
                    return false;
                }
                _ => {}
            }
        }
        target.permitted(listener, self.addr, rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn tries_the_next_pinned_address_after_a_connection_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        // Linux refuses immediately on 127.0.0.2; the other peer accepts.
        let active = listener.local_addr().unwrap();
        let first = SocketAddr::new("127.0.0.2".parse().unwrap(), active.port());
        let upstream = Upstream {
            scheme: Protocol::Http,
            addr: first,
            auth: None,
            server_name: None,
            peers: Peers {
                name: Some("proxy.example".into()),
                other: vec![active],
            },
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        let stream = upstream.connect(deadline).unwrap();
        assert_eq!(stream.peer_addr().unwrap(), active);
        assert!(Instant::now() < deadline);
    }
}
