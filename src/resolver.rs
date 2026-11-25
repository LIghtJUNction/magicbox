use crate::{address::bad, config::Upstream, dns_wire, handshake::Wire};
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
    pub fn new(uri: &str) -> Result<Self, String> {
        let value = uri
            .strip_prefix("tls://")
            .ok_or("resolver must use tls://")?;
        let peer = Upstream::parse(&format!("https://{value}"))?;
        if peer.auth.is_some() {
            return Err("DNS resolver cannot contain credentials".into());
        }
        let name = match peer.server_name {
            Some(s) => ServerName::try_from(s).map_err(|_| "invalid resolver identity")?,
            None => ServerName::IpAddress(peer.addr.ip().into()),
        };
        let mut trust = crate::tls::trust()?;
        Arc::make_mut(&mut trust).alpn_protocols = vec![b"dot".to_vec()];
        Ok(Self {
            address: peer.addr,
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
        let mut result = Vec::new();
        static NEXT: AtomicU16 = AtomicU16::new(1);
        for kind in [1, 28] {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let q = dns_wire::query(host, kind, id);
            secure.write_all(&(q.len() as u16).to_be_bytes())?;
            secure.write_all(&q)?;
            secure.flush()?;
            let mut length = [0u8; 2];
            secure.read_exact(&mut length)?;
            let size = usize::from(u16::from_be_bytes(length));
            if !(12..=16_384).contains(&size) {
                return Err(bad("invalid DNS frame size"));
            }
            let mut data = vec![0; size];
            secure.read_exact(&mut data)?;
            result.extend(dns_wire::answers(&data, host, kind, id)?);
        }
        Ok(result)
    }
}
