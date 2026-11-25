use crate::{
    address::{Host, Target},
    policy::Rules,
    resolver::Resolver,
};
use std::{
    io,
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

pub(crate) fn public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(
                (a, b, c),
                (0 | 10 | 127, _, _)
                    | (169, 254, _)
                    | (192, 168, _)
                    | (192, 0, 0 | 2)
                    | (192, 88, 99)
                    | (198, 18 | 19, _)
                    | (198, 51, 100)
                    | (203, 0, 113)
            ) && !(a == 100 && (64..=127).contains(&b))
                && !(a == 172 && (16..=31).contains(&b))
                && a < 224
        }
        IpAddr::V6(ip) => {
            let [hi, next, ..] = ip.segments();
            hi & 0xe000 == 0x2000
                && !(hi == 0x2001 && (next < 0x0200 || next == 0x0db8))
                && hi != 0x2002
                && !(hi == 0x3fff && next < 0x1000)
        }
    }
}

pub(crate) fn local_interface(ip: IpAddr) -> io::Result<bool> {
    // A connected UDP descriptor asks the kernel which source address it would
    // select. No bytes are sent. Reject services on this host's own public IPs.
    let probe = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    probe.connect(SocketAddr::new(ip, 9))?;
    Ok(probe.local_addr()?.ip().to_canonical() == ip.to_canonical())
}

pub fn open(
    target: &Target,
    local: SocketAddr,
    rules: &Rules,
    resolver: &Resolver,
    deadline: Instant,
) -> io::Result<TcpStream> {
    let denied = || io::Error::new(io::ErrorKind::PermissionDenied, "protected destination");
    let candidates = match &target.host {
        Host::Ip(ip) => vec![*ip],
        Host::Name(name) => {
            if rules.blocks(name) {
                return Err(denied());
            }
            resolver.resolve(name, deadline)?
        }
    };
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address available");
    for ip in candidates {
        let ip = ip.to_canonical();
        if !public(ip) || ip == local.ip().to_canonical() {
            last = denied();
            continue;
        }
        match local_interface(ip) {
            Ok(true) => {
                last = denied();
                continue;
            }
            Err(e) => {
                last = e;
                continue;
            }
            Ok(false) => {}
        }
        let limit = deadline
            .checked_duration_since(Instant::now())
            .ok_or(io::ErrorKind::TimedOut)?
            .min(Duration::from_secs(2));
        match TcpStream::connect_timeout(&SocketAddr::new(ip, target.port), limit) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_egress_only() {
        for s in [
            "127.0.0.1",
            "::ffff:127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "192.0.2.9",
            "0.0.0.0",
            "fc00::1",
            "fe80::1",
            "::1",
            "64:ff9b::ffff:7f00:1",
            "2002:7f00::",
            "2001:db8::1",
        ] {
            assert!(!public(s.parse().unwrap()), "{s}");
        }
        for s in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public(s.parse().unwrap()), "{s}");
        }
    }
}
