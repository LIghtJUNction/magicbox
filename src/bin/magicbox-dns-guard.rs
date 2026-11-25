//! A foreground, scoped cgroup-v2 DNS guard. The kernel releases every link
//! when the process exits. The runtime never changes a task's cgroup itself.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "dns_guard/filter.rs"]
mod filter;
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "dns_guard/group.rs"]
mod group;
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "dns_guard/kernel.rs"]
mod kernel;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn run() -> std::io::Result<()> {
    use std::{
        io::{Error, Write},
        path::Path,
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [command, path] = args.as_slice() else {
        return Err(Error::other(
            "usage: magicbox-dns-guard attach /absolute/dedicated/empty/cgroup",
        ));
    };
    if command != "attach" {
        return Err(Error::other("expected attach"));
    }
    let group = group::open_empty(Path::new(path))?;
    let _links = kernel::attach(group)?;
    println!("ready");
    std::io::stdout().flush()?;
    loop {
        // No pins, daemon threads or signal handlers. SIGTERM/SIGKILL both
        // close the link fds and leave other programs attached to this cgroup.
        std::thread::park();
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn run() -> std::io::Result<()> {
    Err(std::io::Error::other("cgroup v2 requires Linux or Android"))
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("magicbox-dns-guard: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
