//! The public-facing endpoint only accepts authenticated CONNECT over TLS.
use crate::{egress, handshake::Wire, http, policy::Rules, resolver::Resolver};
use rustls::{
    ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

pub struct Gateway {
    listen: SocketAddr,
    identity: Arc<ServerConfig>,
    credential: Vec<u8>,
    resolver: Resolver,
    rules: Rules,
}

fn read(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take((limit + 1) as u64).read_to_end(&mut bytes))
        .map_err(|e| format!("cannot read required server file: {e}"))?;
    if bytes.len() > limit {
        return Err("server file exceeds size limit".into());
    }
    Ok(bytes)
}

fn identity(cert: &str, key: &str) -> Result<Arc<ServerConfig>, String> {
    let certs = CertificateDer::pem_slice_iter(&read(cert, 1 << 20)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid certificate chain PEM")?;
    let key = PrivateKeyDer::from_pem_slice(&read(key, 1 << 16)?)
        .map_err(|_| "invalid private key PEM")?;
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "invalid TLS identity")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

fn credential(path: &str) -> Result<Vec<u8>, String> {
    let input = read(path, 1024)?;
    let value = input.strip_suffix(b"\n").unwrap_or(&input);
    let value = value.strip_suffix(b"\r").unwrap_or(value);
    let Some(index) = value.iter().position(|&v| v == b':') else {
        return Err("expected username:password in credential file".into());
    };
    if index == 0
        || index > 255
        || !(16..=255).contains(&(value.len() - index - 1))
        || value.iter().any(|b| b.is_ascii_control())
    {
        return Err(
            "server credentials require a nonempty username and 16–255 byte password".into(),
        );
    }
    let mut out = vec![0; value.len().div_ceil(3) * 4];
    z64::encode(value, &mut out, z64::Mode::Standard).map_err(|_| "invalid credential encoding")?;
    Ok(out)
}

impl Gateway {
    pub fn load(path: &str) -> Result<Self, String> {
        if !cfg!(unix) {
            return Err("TLS server requires a Unix target".into());
        }
        let raw = read(path, 65536)?;
        let mut t = std::str::from_utf8(&raw)
            .ok()
            .and_then(|s| s.parse::<toml::Table>().ok())
            .ok_or("invalid server TOML")?;
        let mut field = |key: &str| {
            t.remove(key)
                .map(|v| match v {
                    toml::Value::String(s) => Ok(s),
                    _ => Err(format!("{key} must be a string")),
                })
                .transpose()
        };
        let listen = field("listen")?
            .unwrap_or_else(|| "127.0.0.1:8443".into())
            .parse()
            .map_err(|_| "invalid server listen endpoint")?;
        let cert = field("certificate")?.ok_or("missing certificate path")?;
        let key = field("private_key")?.ok_or("missing private_key path")?;
        let secret = field("credential_file")?.ok_or("missing credential_file path")?;
        let dns = field("resolver")?.unwrap_or_else(|| crate::resolver::DEFAULT.into());
        if !t.is_empty() {
            return Err("unknown server TOML key".into());
        }
        Ok(Self {
            listen,
            identity: identity(&cert, &key)?,
            credential: credential(&secret)?,
            resolver: Resolver::new(&dns)?,
            rules: Rules::from_env().map_err(|e| e.to_string())?,
        })
    }

    pub fn serve(self) -> io::Result<()> {
        let listener = TcpListener::bind(self.listen)?;
        crate::slots::accept(listener, move |client| self.session(client))
    }

    fn authorized(&self, value: Option<&str>) -> bool {
        let Some((scheme, data)) = value.and_then(|v| v.split_once(' ')) else {
            return false;
        };
        scheme.eq_ignore_ascii_case("basic") && bool::from(self.credential.ct_eq(data.as_bytes()))
    }

    fn session(&self, mut socket: TcpStream) -> io::Result<()> {
        let local = socket.local_addr()?;
        socket.set_nodelay(true)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut tls =
            ServerConnection::new(Arc::clone(&self.identity)).map_err(io::Error::other)?;
        tls.set_buffer_limit(Some(32768));
        let mut wire = Wire {
            stream: &mut socket,
            deadline,
        };
        while tls.is_handshaking() {
            tls.complete_io(&mut wire)?;
        }
        let mut stream = rustls::Stream::new(&mut tls, &mut wire);
        let request = match http::accept(&mut stream, &[]) {
            Ok(r) => r,
            Err(_) => return http::reply(&mut stream, 400),
        };
        if !self.authorized(request.authorization.as_deref()) {
            return http::reply(&mut stream, 407);
        }
        let mut destination = match egress::open(
            &request.target,
            local,
            &self.rules,
            &self.resolver,
            deadline,
        ) {
            Ok(s) => s,
            Err(e) => {
                return http::reply(
                    &mut stream,
                    if e.kind() == io::ErrorKind::PermissionDenied {
                        403
                    } else {
                        502
                    },
                );
            }
        };
        destination.set_nodelay(true)?;
        http::reply(&mut stream, 200)?;
        stream.flush()?;
        Wire {
            stream: &mut destination,
            deadline,
        }
        .write_all(&request.tail)?;
        crate::tls_relay::run(
            destination,
            socket,
            Box::new(rustls::Connection::Server(tls)),
        )
    }
}
