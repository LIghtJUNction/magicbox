//! Classic AEAD Shadowsocks client over TCP (SIP004 and SIP007).
mod record;

use crate::{
    address::{Target, bad},
    config::Upstream,
};
use record::{Cipher, Master};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::Mutex,
    thread,
    time::Duration,
};

pub(crate) fn supported(name: &[u8]) -> bool {
    record::algorithm(name).is_some()
}

// Bounded process-local replay window. The current connection's outbound
// salt is always checked separately, even after eviction from this window.
static SALTS: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());
fn remember(salt: [u8; 32]) -> io::Result<()> {
    let mut recent = SALTS
        .lock()
        .map_err(|_| io::Error::other("salt cache unavailable"))?;
    if recent.contains(&salt) {
        return Err(bad("duplicate Shadowsocks salt"));
    }
    if recent.len() == 2048 {
        recent.pop_front();
    }
    recent.push_back(salt);
    Ok(())
}

pub(crate) struct Session {
    master: Master,
    salt: [u8; 32],
    tx: Cipher,
}
pub(crate) fn open(wire: &mut impl Write, up: &Upstream, target: &Target) -> io::Result<Session> {
    let (method, pass) = up
        .auth
        .as_ref()
        .ok_or_else(|| bad("missing Shadowsocks credentials"))?;
    let master = Master::new(method, pass)?;
    let mut salt = [0; 32];
    SystemRandom::new()
        .fill(&mut salt[..master.salt_len()])
        .map_err(|_| io::Error::other("system randomness unavailable"))?;
    remember(salt)?;
    let mut tx = master.session(&salt[..master.salt_len()])?;
    let mut destination = vec![0; record::HEADER];
    crate::socks::append_target(&mut destination, target);
    let size = destination.len() - record::HEADER;
    destination.resize(destination.len() + 16, 0);
    let mut preface = salt[..master.salt_len()].to_vec();
    tx.write(&mut preface, &mut destination, size)?;
    wire.write_all(&preface)?;
    Ok(Session { master, salt, tx })
}

fn download(
    mut remote: &TcpStream,
    mut client: &TcpStream,
    master: Master,
    own_salt: [u8; 32],
) -> io::Result<()> {
    let mut salt = [0; 32];
    remote.read_exact(&mut salt[..master.salt_len()])?;
    if salt == own_salt {
        return Err(bad("reflected Shadowsocks salt"));
    }
    let mut rx = master.session(&salt[..master.salt_len()])?;
    let mut payload = vec![0; record::MAX + 16];
    let mut first = true;
    while let Some(len) = rx.read(&mut remote, &mut payload)? {
        if first {
            remember(salt)?;
            first = false;
        }
        client.write_all(&payload[..len])?;
    }
    if first {
        return Err(bad("missing authenticated Shadowsocks response"));
    }
    Ok(())
}

fn upload(
    mut client: &TcpStream,
    mut remote: &TcpStream,
    mut tx: Cipher,
    early: &[u8],
) -> io::Result<()> {
    let mut frame = vec![0; record::CAPACITY];
    for chunk in early.chunks(record::MAX) {
        frame[record::HEADER..record::HEADER + chunk.len()].copy_from_slice(chunk);
        tx.write(&mut remote, &mut frame, chunk.len())?;
    }
    loop {
        let count = client.read(&mut frame[record::HEADER..record::HEADER + record::MAX])?;
        if count == 0 {
            return Ok(());
        }
        tx.write(&mut remote, &mut frame, count)?;
    }
}

impl Session {
    pub fn relay(self, client: TcpStream, remote: TcpStream, early: &[u8]) -> io::Result<()> {
        let timeout = Some(Duration::from_secs(300));
        for socket in [&client, &remote] {
            socket.set_read_timeout(timeout)?;
            socket.set_write_timeout(timeout)?;
        }
        let finish = |result: io::Result<()>, destination: &TcpStream| {
            if result.is_ok() {
                let _ = destination.shutdown(Shutdown::Write);
            } else {
                let _ = client.shutdown(Shutdown::Both);
                let _ = remote.shutdown(Shutdown::Both);
            }
            result
        };
        thread::scope(|scope| {
            let forward = thread::Builder::new()
                .name("ss-upload".into())
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    finish(upload(&client, &remote, self.tx, early), &remote)
                })?;
            let reverse = finish(download(&remote, &client, self.master, self.salt), &client);
            forward
                .join()
                .map_err(|_| io::Error::other("Shadowsocks upload thread failed"))??;
            reverse
        })
    }
}
