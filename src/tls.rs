use crate::{
    address::{Target, bad},
    config::Upstream,
    handshake::Wire,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use std::{
    fs::File,
    io::{self, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Instant,
};

pub fn trust() -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = std::env::var_os("MAGICBOX_CA_BUNDLE") {
        let mut data = Vec::new();
        const LIMIT: usize = 1024 * 1024;
        File::open(path)
            .and_then(|f| f.take((LIMIT + 1) as u64).read_to_end(&mut data))
            .map_err(|_| "cannot read extra CA bundle")?;
        if data.len() > LIMIT {
            return Err("extra CA bundle exceeds 1 MiB".into());
        }
        let mut count = 0;
        for certificate in CertificateDer::pem_slice_iter(&data) {
            roots
                .add(certificate.map_err(|_| "invalid PEM certificate")?)
                .map_err(|_| "invalid trust anchor")?;
            count += 1;
        }
        if count == 0 {
            return Err("extra CA bundle is empty".into());
        }
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub fn open(
    socket: &mut TcpStream,
    target: &Target,
    upstream: &Upstream,
    trust: Arc<ClientConfig>,
    deadline: Instant,
) -> io::Result<(Box<ClientConnection>, Vec<u8>)> {
    let name = match &upstream.server_name {
        Some(name) => {
            ServerName::try_from(name.clone()).map_err(|_| bad("invalid TLS server name"))?
        }
        None => ServerName::IpAddress(upstream.addr.ip().into()),
    };
    let mut session =
        ClientConnection::new(trust, name).map_err(|_| bad("invalid TLS configuration"))?;
    session.set_buffer_limit(Some(32768));
    let mut wire = Wire {
        stream: socket,
        deadline,
    };
    while session.is_handshaking() {
        session.complete_io(&mut wire)?;
    }
    let mut tunnel = rustls::Stream::new(&mut session, &mut wire);
    let tail = crate::http::connect(&mut tunnel, upstream, target)?;
    tunnel.flush()?;
    Ok((Box::new(session), tail))
}
