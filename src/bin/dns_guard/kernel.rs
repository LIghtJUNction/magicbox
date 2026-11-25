//! Linux UAPI, linux/bpf.h. Zero-filled command attributes preserve the
//! kernel's forward/backward compatibility contract for appended fields.
use super::filter;
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

struct Attr([u8; 80]);

impl Attr {
    fn new() -> Self {
        Self([0; 80])
    }
    fn word(&mut self, at: usize, n: u32) {
        self.0[at..at + 4].copy_from_slice(&n.to_ne_bytes());
    }
    fn pointer<T>(&mut self, at: usize, ptr: *const T) {
        self.0[at..at + 8].copy_from_slice(&(ptr as usize as u64).to_ne_bytes());
    }
    fn call(&self, cmd: libc::c_uint) -> io::Result<libc::c_long> {
        // SAFETY: the buffer is initialized, spans its declared length, and
        // each pointer field remains valid for the synchronous syscall.
        let result = unsafe { libc::syscall(libc::SYS_bpf, cmd, self.0.as_ptr(), self.0.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
    fn fd(&self, cmd: libc::c_uint) -> io::Result<OwnedFd> {
        let fd = self.call(cmd)?;
        // SAFETY: MAP_CREATE, PROG_LOAD and LINK_CREATE return fresh owned fds.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

fn map() -> io::Result<OwnedFd> {
    let mut a = Attr::new();
    a.word(0, 2); // BPF_MAP_TYPE_ARRAY
    a.word(4, 4); // key_size
    a.word(8, 4); // value_size
    a.word(12, 1); // max_entries
    a.fd(0)
}

fn load(hook: u32, map: &OwnedFd) -> io::Result<OwnedFd> {
    let code = filter::program(map.as_raw_fd());
    let mut a = Attr::new();
    a.word(0, 18); // BPF_PROG_TYPE_CGROUP_SOCK_ADDR
    a.word(4, code.len() as u32);
    a.pointer(8, code.as_ptr());
    a.pointer(16, c"GPL".as_ptr());
    a.word(68, hook);
    match a.fd(5) {
        // BPF_PROG_LOAD
        Ok(fd) => Ok(fd),
        Err(first) => {
            let mut log = [0_u8; 8192];
            a.word(24, 1);
            a.word(28, log.len() as u32);
            a.pointer(32, log.as_mut_ptr());
            match a.fd(5) {
                Ok(fd) => Ok(fd),
                Err(_) => {
                    let count = log.iter().position(|&b| b == 0).unwrap_or(log.len());
                    if count == 0 {
                        return Err(first);
                    }
                    Err(io::Error::other(format!(
                        "{first}: {}",
                        String::from_utf8_lossy(&log[..count]).trim()
                    )))
                }
            }
        }
    }
}

pub fn attach(group: File) -> io::Result<Vec<OwnedFd>> {
    let enabled = map().map_err(|e| io::Error::other(format!("create BPF activation map: {e}")))?;
    let mut links = Vec::new();
    // INET4_CONNECT, INET6_CONNECT, UDP4_SENDMSG, UDP6_SENDMSG. All links
    // permit traffic until the one shared flag is committed. Errors drop
    // every acquired fd without modifying any other attached programs.
    for hook in [10, 11, 14, 15] {
        let prog = load(hook, &enabled)
            .map_err(|e| io::Error::other(format!("load cgroup hook {hook}: {e}")))?;
        let mut a = Attr::new();
        a.word(0, prog.as_raw_fd() as u32);
        a.word(4, group.as_raw_fd() as u32);
        a.word(8, hook);
        links.push(
            a.fd(28)
                .map_err(|e| io::Error::other(format!("link cgroup hook {hook}: {e}")))?,
        );
    }
    let key = 0_u32;
    let value = 1_u32;
    let mut a = Attr::new();
    a.word(0, enabled.as_raw_fd() as u32);
    a.pointer(8, &key);
    a.pointer(16, &value);
    a.call(2)?; // BPF_MAP_UPDATE_ELEM
    Ok(links)
}
