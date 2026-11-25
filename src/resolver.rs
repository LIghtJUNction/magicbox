use crate::{
    address::bad,
    config::{Endpoint, NodeSpec},
    handshake::Wire,
};
use magicbox_dns_wire::{self as dns_wire, RecordType};
use rustls::{ClientConfig, ClientConnection, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Instant,
};

pub const DEFAULT: &str = "tls://1.1.1.1:853?server_name=cloudflare-dns.com";

pub struct Resolver {
    address: SocketAddr,
    name: ServerName<'static>,
    trust: Arc<ClientConfig>,
}

impl Resolver {
    pub fn from_env() -> Result<Self, String> {
        Self::new(&std::env::var("MAGICBOX_RESOLVER").unwrap_or_else(|_| DEFAULT.into()))
    }

    pub fn new(uri: &str) -> Result<Self, String> {
        let value = uri
            .strip_prefix("tls://")
            .ok_or("resolver must use tls://")?;
        let peer = NodeSpec::parse(&format!("https://{value}"))?;
        if peer.auth.is_some() {
            return Err("DNS resolver cannot contain credentials".into());
        }
        let Endpoint::Ip(address) = peer.addr else {
            return Err("resolver requires a numeric IP and port".into());
        };
        let name = match peer.server_name {
            Some(s) => ServerName::try_from(s).map_err(|_| "invalid resolver identity")?,
            None => ServerName::IpAddress(address.ip().into()),
        };
        let mut trust = crate::tls::trust()?;
        Arc::make_mut(&mut trust).alpn_protocols = vec![b"dot".to_vec()];
        Ok(Self {
            address,
            name,
            trust,
        })
    }

    pub fn resolve(&self, host: &str, deadline: Instant) -> io::Result<Vec<IpAddr>> {
        let ttl = deadline
            .checked_duration_since(Instant::now())
            .ok_or(io::ErrorKind::TimedOut)?;
        let mut socket = TcpStream::connect_timeout(&self.address, ttl)?;
        let mut wire = Wire {
            stream: &mut socket,
            deadline,
        };
        let mut session = ClientConnection::new(self.trust.clone(), self.name.clone())
            .map_err(io::Error::other)?;
        let mut secure = rustls::Stream::new(&mut session, &mut wire);
        static NEXT: AtomicU16 = AtomicU16::new(1);
        let a = NEXT.fetch_add(2, Ordering::Relaxed);
        let pending = [(a, RecordType::A), (a.wrapping_add(1), RecordType::Aaaa)];
        let mut flight = Vec::new();
        for (id, kind) in pending {
            let q = dns_wire::query(host, kind, id).map_err(io::Error::other)?;
            flight.extend_from_slice(&(q.len() as u16).to_be_bytes());
            flight.extend(q);
        }
        secure.write_all(&flight)?;
        secure.flush()?;
        let mut results = [None, None];
        for _ in 0..pending.len() {
            let mut length = [0u8; 2];
            secure.read_exact(&mut length)?;
            let size = usize::from(u16::from_be_bytes(length));
            if !(12..=dns_wire::MAX_PACKET).contains(&size) {
                return Err(bad("invalid DNS frame size"));
            }
            let mut data = vec![0; size];
            secure.read_exact(&mut data)?;
            let id = u16::from_be_bytes([data[0], data[1]]);
            let index = pending
                .iter()
                .position(|p| p.0 == id)
                .ok_or_else(|| bad("unexpected DNS reply"))?;
            if results[index].is_some() {
                return Err(bad("duplicate DNS reply"));
            }
            results[index] = Some(
                dns_wire::answers(&data, host, pending[index].1, id)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }
        let [v4, v6] = results.map(|set| set.unwrap_or_default());
        let count = v4.len().max(v6.len());
        let mut ordered = Vec::with_capacity(v4.len() + v6.len());
        for i in 0..count {
            ordered.extend(v4.get(i));
            ordered.extend(v6.get(i));
        }
        Ok(ordered)
    }
}
