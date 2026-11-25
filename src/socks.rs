use crate::{
    address::{Host, Target, bad},
    config::Upstream,
    handshake::Wire,
};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub(crate) fn reply(w: &mut Wire<'_>, code: u8) -> io::Result<()> {
    w.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

pub(crate) fn read_host(w: &mut Wire<'_>, kind: u8) -> io::Result<Host> {
    match kind {
        1 => Ok(Host::Ip(Ipv4Addr::from(w.bytes::<4>()?).into())),
        4 => Ok(Host::Ip(Ipv6Addr::from(w.bytes::<16>()?).into())),
        3 => {
            let len = w.bytes::<1>()?[0] as usize;
            let mut name = [0; 255];
            w.read_exact(&mut name[..len])?;
            Target::parse_name(&name[..len])
        }
        _ => Err(bad("unknown address type")),
    }
}

pub(crate) enum Request {
    Connect(Target),
    Associate(SocketAddr),
}

pub(crate) fn accept(w: &mut Wire<'_>, allow_udp: bool) -> io::Result<Request> {
    let count = w.bytes::<1>()?[0] as usize;
    let mut methods = [0; 255];
    w.read_exact(&mut methods[..count])?;
    if !methods[..count].contains(&0) {
        w.write_all(&[5, 255])?;
        return Err(bad("unsupported SOCKS authentication method"));
    }
    w.write_all(&[5, 0])?;
    let [version, cmd, rsv, kind] = w.bytes()?;
    if version != 5 || rsv != 0 {
        reply(w, 1)?;
        return Err(bad("invalid SOCKS request"));
    }
    if cmd != 1 && !(cmd == 3 && allow_udp) {
        reply(w, 7)?;
        return Err(bad("command unavailable for this upstream"));
    }
    let host = read_host(w, kind).inspect_err(|_| {
        let _ = reply(w, 8);
    })?;
    let port = u16::from_be_bytes(w.bytes()?);
    if cmd == 3 {
        return match host {
            Host::Ip(ip) => Ok(Request::Associate(SocketAddr::new(ip, port))),
            Host::Name(_) => {
                reply(w, 8)?;
                Err(bad("UDP client address must be numeric"))
            }
        };
    }
    Target::new(host, port)
        .map(Request::Connect)
        .inspect_err(|_| {
            let _ = reply(w, 1);
        })
}

pub(crate) fn authenticate(w: &mut Wire<'_>, upstream: &Upstream) -> io::Result<()> {
    let method = if upstream.auth.is_some() { 2 } else { 0 };
    w.write_all(&[5, 1, method])?;
    if w.bytes::<2>()? != [5, method] {
        return Err(bad("upstream authentication negotiation failed"));
    }
    if let Some((user, pass)) = &upstream.auth {
        let mut auth = Vec::with_capacity(user.len() + pass.len() + 3);
        auth.extend([1, user.len() as u8]);
        auth.extend(user);
        auth.push(pass.len() as u8);
        auth.extend(pass);
        w.write_all(&auth)?;
        if w.bytes::<2>()? != [1, 0] {
            return Err(bad("upstream rejected credentials"));
        }
    }
    Ok(())
}

pub(crate) fn socket_address(address: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match address.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend(ip.octets());
        }
    }
    out.extend(address.port().to_be_bytes());
    out
}

pub(crate) fn append_target(request: &mut Vec<u8>, target: &Target) {
    match &target.host {
        Host::Name(name) => {
            request.extend([3, name.len() as u8]);
            request.extend(name.as_bytes());
        }
        Host::Ip(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend(ip.octets());
        }
    }
    request.extend(target.port.to_be_bytes());
}

pub(crate) fn connect(w: &mut Wire<'_>, upstream: &Upstream, target: &Target) -> io::Result<()> {
    authenticate(w, upstream)?;
    let mut request = vec![5, 1, 0];
    append_target(&mut request, target);
    w.write_all(&request)?;
    let [version, result, rsv, kind] = w.bytes()?;
    if [version, result, rsv] != [5, 0, 0] {
        return Err(bad("upstream refused CONNECT"));
    }
    // BND.ADDR is informational; discard the wire field without interpreting its name.
    let len = match kind {
        1 => 4,
        4 => 16,
        3 => usize::from(w.bytes::<1>()?[0]),
        _ => return Err(bad("invalid upstream bound address")),
    };
    let mut discard = [0; 257];
    w.read_exact(&mut discard[..len + 2])
}
