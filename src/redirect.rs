//! Only a netfilter-translated TCP socket supplies the tunnel destination.
//! The payload is opaque. The peer cannot select a destination in-band.
use crate::{
    address::{Host, Target, bad},
    config::{Config, same_endpoint},
    handshake::Wire,
    policy::Rules,
    upstream,
};
use std::{
    io::{self, Write},
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

fn dual_listener(port: u16) -> io::Result<TcpListener> {
    // SAFETY: the returned descriptor is transferred to OwnedFd exactly once.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let v6only: libc::c_int = 0;
    let reuse: libc::c_int = 1;
    for (level, option, value) in [
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &v6only),
        (libc::SOL_SOCKET, libc::SO_REUSEADDR, &reuse),
    ] {
        // SAFETY: the integer lives for the duration of setsockopt.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                option,
                (value as *const libc::c_int).cast(),
                mem::size_of_val(value) as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: sockaddr_in6 has an all-zero valid representation.
    let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as _;
    addr.sin6_port = port.to_be();
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            mem::size_of_val(&addr) as _,
        )
    } != 0
        || unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd.into())
}

fn original(socket: &TcpStream, ipv4: bool) -> io::Result<SocketAddr> {
    // Linux UAPI SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST both have number 80.
    const ORIGINAL: libc::c_int = 80;
    // SAFETY: storage is writable, aligned and sized for either result. Check
    // the returned family and size before accessing the typed socket address.
    let mut out: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut size = mem::size_of_val(&out) as libc::socklen_t;
    let level = if ipv4 {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    };
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            ORIGINAL,
            (&raw mut out).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    match out.ss_family as libc::c_int {
        libc::AF_INET if size as usize >= mem::size_of::<libc::sockaddr_in>() => {
            let v = unsafe { &*(&raw const out).cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::new(
                Ipv4Addr::from(v.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(v.sin_port),
            ))
        }
        libc::AF_INET6 if size as usize >= mem::size_of::<libc::sockaddr_in6>() => {
            let v = unsafe { &*(&raw const out).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::new(
                Ipv6Addr::from(v.sin6_addr.s6_addr).into(),
                u16::from_be(v.sin6_port),
            ))
        }
        _ => Err(bad("no original TCP endpoint")),
    }
}

pub fn run(config: Config, rules: Rules, port: u16) -> io::Result<()> {
    let peer = config
        .upstream
        .ok_or_else(|| bad("redirect requires a configured upstream"))?;
    if port == 0
        || port == config.listen.port()
        || (port == peer.addr.port() && peer.addr.ip().to_canonical().is_loopback())
    {
        return Err(bad("redirect requires its own nonzero TCP port"));
    }
    crate::slots::accept(dual_listener(port)?, move |mut client| {
        let local = client.local_addr()?;
        let original = original(&client, local.ip().to_canonical().is_ipv4())?;
        let destination = Target::new(Host::Ip(original.ip().to_canonical()), original.port())?;
        if same_endpoint(original, local)
            || original.port() == 53
            || !crate::egress::public(original.ip())
            || !destination.permitted(config.listen, peer.addr, &rules)
        {
            return Err(bad("expected an eligible redirected public TCP connection"));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let (remote, welcome) = upstream::open(&peer, &destination, deadline, config.tls.as_ref())?;
        client.set_nodelay(true)?;
        Wire {
            stream: &mut client,
            deadline,
        }
        .write_all(&welcome)?;
        remote.relay(client, &[], deadline)
    })
}
