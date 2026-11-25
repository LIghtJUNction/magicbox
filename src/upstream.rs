use crate::{
    address::{Target, bad},
    config::{Protocol, Upstream},
    handshake::Wire,
};
use std::{
    io::{self, Write},
    net::TcpStream,
    sync::Arc,
    time::Instant,
};

pub(crate) struct Remote {
    socket: TcpStream,
    transport: Transport,
}
enum Transport {
    Plain,
    Tls(Box<rustls::ClientConnection>),
    Shadowsocks(Box<crate::shadowsocks::Session>),
}

impl Remote {
    pub fn relay(mut self, client: TcpStream, early: &[u8], deadline: Instant) -> io::Result<()> {
        let mut wire = Wire {
            stream: &mut self.socket,
            deadline,
        };
        if let Transport::Shadowsocks(session) = self.transport {
            return session.relay(client, self.socket, early);
        }
        if let Transport::Tls(mut session) = self.transport {
            let mut stream = rustls::Stream::new(session.as_mut(), &mut wire);
            stream.write_all(early)?;
            stream.flush()?;
            return crate::tls_relay::run(
                client,
                self.socket,
                Box::new(rustls::Connection::Client(*session)),
            );
        }
        wire.write_all(early)?;
        crate::relay::run(client, self.socket)
    }
}

pub(crate) fn open(
    upstream: &Upstream,
    target: &Target,
    deadline: Instant,
    trust: Option<&Arc<rustls::ClientConfig>>,
) -> io::Result<(Remote, Vec<u8>)> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "handshake deadline"))?;
    let mut socket = TcpStream::connect_timeout(&upstream.addr, timeout)?;
    socket.set_nodelay(true)?;
    let mut wire = Wire {
        stream: &mut socket,
        deadline,
    };
    let (transport, tail) = match upstream.scheme {
        Protocol::Socks5 => {
            crate::socks::connect(&mut wire, upstream, target)?;
            (Transport::Plain, Vec::new())
        }
        Protocol::Http => (
            Transport::Plain,
            crate::http::connect(&mut wire, upstream, target)?,
        ),
        Protocol::Shadowsocks => (
            Transport::Shadowsocks(Box::new(crate::shadowsocks::open(
                &mut wire, upstream, target,
            )?)),
            Vec::new(),
        ),
        Protocol::Https => {
            let (session, tail) = crate::tls::open(
                &mut socket,
                target,
                upstream,
                Arc::clone(trust.ok_or_else(|| bad("missing trust store"))?),
                deadline,
            )?;
            (Transport::Tls(session), tail)
        }
    };
    Ok((Remote { socket, transport }, tail))
}
