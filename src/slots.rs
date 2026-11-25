use std::{
    io,
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn accept(
    listener: TcpListener,
    serve: impl Fn(TcpStream) -> io::Result<()> + Send + Sync + 'static,
) -> io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    let operation = Arc::new(serve);
    eprintln!("ready {}", listener.local_addr()?);
    for incoming in listener.incoming() {
        let client = match incoming {
            Ok(s) => s,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        if active.load(Ordering::Relaxed) >= 128 {
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let slot = Slot(Arc::clone(&active));
        let serve = Arc::clone(&operation);
        let _ = thread::Builder::new()
            .name("tunnel".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let _slot = slot;
                let _ = serve(client);
            });
    }
    Ok(())
}
