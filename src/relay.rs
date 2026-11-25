use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
};

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::fd::AsRawFd;

    #[derive(Default)]
    struct Direction {
        data: Box<Buffer>,
        start: usize,
        end: usize,
        eof: bool,
    }

    struct Buffer([u8; 32768]);

    impl Default for Buffer {
        fn default() -> Self {
            Self([0; 32768])
        }
    }

    impl Direction {
        fn readable(&self) -> bool {
            !self.eof && self.start == self.end
        }
        fn writable(&self) -> bool {
            self.start < self.end
        }

        fn read(&mut self, mut source: &TcpStream, destination: &TcpStream) -> io::Result<()> {
            match source.read(&mut self.data.0) {
                Ok(0) => {
                    self.eof = true;
                    destination.shutdown(Shutdown::Write)?;
                }
                Ok(len) => {
                    self.start = 0;
                    self.end = len;
                    // Most destinations accept immediately. Poll for writability
                    // only when this attempt actually encounters backpressure.
                    self.write(destination)?;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
            Ok(())
        }

        fn write(&mut self, mut destination: &TcpStream) -> io::Result<()> {
            match destination.write(&self.data.0[self.start..self.end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(len) => self.start += len,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
            Ok(())
        }
    }

    fn interests(socket: &TcpStream, outgoing: &Direction, incoming: &Direction) -> libc::pollfd {
        let mut events = 0;
        if outgoing.readable() {
            events |= libc::POLLIN;
        }
        if incoming.writable() {
            events |= libc::POLLOUT;
        }
        libc::pollfd {
            fd: if events == 0 { -1 } else { socket.as_raw_fd() },
            events,
            revents: 0,
        }
    }

    pub(super) fn run(client: TcpStream, remote: TcpStream) -> io::Result<()> {
        client.set_nonblocking(true)?;
        remote.set_nonblocking(true)?;
        let mut forward = Direction::default();
        let mut reverse = Direction::default();
        while !(forward.eof && reverse.eof) {
            let mut fds = [
                interests(&client, &forward, &reverse),
                interests(&remote, &reverse, &forward),
            ];
            // SAFETY: fds holds two writable pollfd values; both socket owners outlive poll.
            let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, 300_000) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let ready = |i: usize, event| {
                fds[i].events & event != 0
                    && fds[i].revents & (event | libc::POLLHUP | libc::POLLERR) != 0
            };
            if ready(0, libc::POLLIN) {
                forward.read(&client, &remote)?;
            }
            if ready(1, libc::POLLOUT) {
                forward.write(&remote)?;
            }
            if ready(1, libc::POLLIN) {
                reverse.read(&remote, &client)?;
            }
            if ready(0, libc::POLLOUT) {
                reverse.write(&client)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn run(client: TcpStream, remote: TcpStream) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix::run(client, remote)
    }
    #[cfg(not(unix))]
    {
        let idle = Some(std::time::Duration::from_secs(300));
        for socket in [&client, &remote] {
            socket.set_read_timeout(idle)?;
            socket.set_write_timeout(idle)?;
        }
        fn copy(mut src: &TcpStream, mut dst: &TcpStream) -> io::Result<()> {
            let result = io::copy(&mut src, &mut dst);
            let _ = dst.shutdown(if result.is_ok() {
                Shutdown::Write
            } else {
                Shutdown::Both
            });
            result.map(|_| ())
        }
        std::thread::scope(|scope| {
            let forward = scope.spawn(|| copy(&client, &remote));
            let reverse = copy(&remote, &client);
            forward
                .join()
                .map_err(|_| io::Error::other("relay thread failed"))??;
            reverse
        })
    }
}
