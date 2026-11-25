//! Move application bytes independently of TLS record readiness. The Rustls
//! writer has a bounded queue; new uploads wait until pending records flush.
use rustls::Connection;
use std::{io, net::TcpStream};

#[cfg(unix)]
pub fn run(
    mut client: TcpStream,
    mut remote: TcpStream,
    mut tls: Box<Connection>,
) -> io::Result<()> {
    use std::{
        io::{Read, Write},
        net::Shutdown,
        os::fd::AsRawFd,
    };
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;
    let mut download = [0; 16384];
    let mut upload = [0; 16384];
    let mut outgoing = 0..0;
    let mut incoming = 0..0;
    let mut client_eof = false;
    let mut tls_eof = false;
    loop {
        if !outgoing.is_empty() && !tls.wants_write() {
            let n = tls.writer().write(&upload[outgoing.clone()])?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            outgoing.start += n;
        }
        if incoming.is_empty() && !tls_eof {
            match tls.reader().read(&mut download) {
                Ok(0) => {
                    tls_eof = true;
                    client.shutdown(Shutdown::Write)?;
                }
                Ok(n) => incoming = 0..n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if client_eof && tls_eof && !tls.wants_write() {
            return Ok(());
        }
        let pollfd = |s: &TcpStream, rd: bool, wr: bool| {
            let events = (if rd { libc::POLLIN } else { 0 }) | (if wr { libc::POLLOUT } else { 0 });
            libc::pollfd {
                fd: if events == 0 { -1 } else { s.as_raw_fd() },
                events,
                revents: 0,
            }
        };
        let mut fds = [
            pollfd(
                &client,
                !client_eof && outgoing.is_empty() && !tls.wants_write(),
                !incoming.is_empty(),
            ),
            pollfd(
                &remote,
                !tls_eof && incoming.is_empty() && tls.wants_read(),
                tls.wants_write(),
            ),
        ];
        // SAFETY: both polled socket owners remain alive, and fds has length two.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 300_000) };
        if n == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let ready = |i: usize, event| {
            fds[i].events & event != 0
                && fds[i].revents & (event | libc::POLLHUP | libc::POLLERR) != 0
        };
        let pending = |e: &io::Error| {
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            )
        };
        if ready(0, libc::POLLIN) {
            match client.read(&mut upload) {
                Ok(0) => {
                    client_eof = true;
                    tls.send_close_notify();
                }
                Ok(n) => outgoing = 0..n,
                Err(e) if pending(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if ready(0, libc::POLLOUT) {
            match client.write(&download[incoming.clone()]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => incoming.start += n,
                Err(e) if pending(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if ready(1, libc::POLLIN) {
            match tls.read_tls(&mut remote) {
                Ok(_) => {
                    tls.process_new_packets().map_err(io::Error::other)?;
                }
                Err(e) if pending(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if ready(1, libc::POLLOUT) {
            match tls.write_tls(&mut remote) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(e) if pending(&e) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(not(unix))]
pub fn run(_: TcpStream, _: TcpStream, _: Box<Connection>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTPS tunnels require a Unix target",
    ))
}
