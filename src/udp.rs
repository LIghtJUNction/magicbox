//! RFC 1928 UDP ASSOCIATE. The two TCP sessions own the UDP relay's lifetime.
use crate::{
    address::{Host, Target, bad},
    config::Upstream,
    handshake::Wire,
    policy::Rules,
    socks,
};
use std::{
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

fn target(packet: &[u8]) -> Option<Target> {
    if packet.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (host, end) = match *packet.get(3)? {
        1 => (
            Host::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(4..8)?).ok()?).into()),
            8,
        ),
        4 => (
            Host::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(4..20)?).ok()?).into()),
            20,
        ),
        3 => {
            let end = 5 + usize::from(*packet.get(4)?);
            (Target::parse_name(packet.get(5..end)?).ok()?, end)
        }
        _ => return None,
    };
    Target::new(
        host,
        u16::from_be_bytes(packet.get(end..end + 2)?.try_into().ok()?),
    )
    .ok()
}

fn upstream_relay(
    control: &mut Wire<'_>,
    upstream: &Upstream,
    addr: SocketAddr,
    peer: SocketAddr,
) -> io::Result<SocketAddr> {
    socks::authenticate(control, upstream)?;
    let mut request = vec![5, 3, 0];
    request.extend(socks::socket_address(addr));
    control.write_all(&request)?;
    let [version, code, reserved, kind] = control.bytes()?;
    if [version, code, reserved] != [5, 0, 0] {
        return Err(bad("upstream rejected UDP ASSOCIATE"));
    }
    let Host::Ip(ip) = socks::read_host(control, kind)? else {
        return Err(bad("numeric UDP relay required"));
    };
    let port = u16::from_be_bytes(control.bytes()?);
    // A wildcard denotes the peer on the authenticated TCP control channel.
    // A different relay host requires an explicit trust policy.
    if port == 0 || (!ip.is_unspecified() && ip.to_canonical() != peer.ip().to_canonical()) {
        return Err(bad("unexpected UDP relay endpoint"));
    }
    Ok(SocketAddr::new(peer.ip(), port))
}

pub(crate) fn associate(
    mut inbound: Wire<'_>,
    source: SocketAddr,
    upstream: &Upstream,
    listener: SocketAddr,
    rules: &Rules,
) -> io::Result<()> {
    let peer = inbound.stream.peer_addr()?.ip();
    if !source.ip().is_unspecified() && source.ip().to_canonical() != peer.to_canonical() {
        return socks::reply(&mut inbound, 2);
    }
    let local = UdpSocket::bind(SocketAddr::new(listener.ip(), 0))?;
    let mut control = match upstream.connect(inbound.deadline) {
        Ok(s) => s,
        Err(_) => return socks::reply(&mut inbound, 1),
    };
    // Bind on the same local interface the kernel chose for the upstream TCP connection.
    let remote = UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0))?;
    let control_peer = control.peer_addr()?;
    let mut wire = Wire {
        stream: &mut control,
        deadline: inbound.deadline,
    };
    let relay = match upstream_relay(
        &mut wire,
        upstream,
        SocketAddr::new(
            if control_peer.is_ipv4() {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        ),
        control_peer,
    ) {
        Ok(addr) => addr,
        Err(_) => return socks::reply(&mut inbound, 1),
    };
    remote.connect(relay)?;
    let mut response = vec![5, 0, 0];
    response.extend(socks::socket_address(local.local_addr()?));
    inbound.write_all(&response)?;
    let mut fds = [
        inbound.stream.as_raw_fd(),
        control.as_raw_fd(),
        local.as_raw_fd(),
        remote.as_raw_fd(),
    ]
    .map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    let mut client = (source.port() != 0).then(|| SocketAddr::new(peer, source.port()));
    let idle = Duration::from_secs(120);
    let mut active = Instant::now();
    let mut buf = vec![0; 65535];
    loop {
        let Some(left) = idle.checked_sub(active.elapsed()) else {
            return Ok(());
        };
        // poll only borrows the live file descriptors for the duration of this call.
        let count = unsafe { libc::poll(fds.as_mut_ptr(), 4, left.as_millis() as i32) };
        if count < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if count == 0 || fds[0].revents != 0 || fds[1].revents != 0 {
            return Ok(());
        }
        if fds[2..]
            .iter()
            .any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            return Err(bad("UDP relay socket closed"));
        }
        if fds[2].revents & libc::POLLIN != 0 {
            let (len, from) = local.recv_from(&mut buf)?;
            if from.ip() == peer
                && client.is_none_or(|p| p == from)
                && target(&buf[..len]).is_some_and(|t| upstream.permits(&t, listener, rules))
            {
                remote.send(&buf[..len])?;
                client = Some(from);
                active = Instant::now();
            }
        }
        if fds[3].revents & libc::POLLIN != 0 {
            let len = remote.recv(&mut buf)?;
            if let Some(to) = client
                && target(&buf[..len]).is_some()
            {
                local.send_to(&buf[..len], to)?;
                active = Instant::now();
            }
        }
    }
}
