use crate::{address::bad, config::Config, handshake::Wire, http, policy::Rules, socks, upstream};
use std::{
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    time::{Duration, Instant},
};

struct State {
    config: Config,
    listener: SocketAddr,
    rules: Rules,
}

pub(crate) fn run(config: Config, rules: Rules) -> io::Result<()> {
    let listener = TcpListener::bind(config.listen)?;
    let addr = listener.local_addr()?;
    config.check_listener(addr).map_err(bad)?;
    let state = State {
        config,
        listener: addr,
        rules,
    };
    crate::slots::accept(listener, move |client| session(client, &state))
}

fn session(mut client: TcpStream, state: &State) -> io::Result<()> {
    client.set_nodelay(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut inbound = Wire {
        stream: &mut client,
        deadline,
    };
    let [first] = inbound.bytes()?;
    let is_socks = first == 5;
    let (target, early) = if is_socks {
        let upstream = state.config.upstream.as_ref();
        let allow_udp = cfg!(unix)
            && upstream.is_some_and(|up| matches!(up.scheme, crate::config::Protocol::Socks5));
        match socks::accept(&mut inbound, allow_udp)? {
            socks::Request::Connect(target) => (target, Vec::new()),
            socks::Request::Associate(source) => {
                #[cfg(unix)]
                return crate::udp::associate(
                    inbound,
                    source,
                    upstream.unwrap(),
                    state.listener,
                    &state.rules,
                );
                #[cfg(not(unix))]
                {
                    let _ = source;
                    return socks::reply(&mut inbound, 7);
                }
            }
        }
    } else {
        let request = http::accept(&mut inbound, &[first]).inspect_err(|_| {
            let _ = http::reply(&mut inbound, 400);
        })?;
        (request.target, request.tail)
    };
    let reply = |w: &mut Wire<'_>, socks_code, http_code| {
        if is_socks {
            socks::reply(w, socks_code)
        } else {
            http::reply(w, http_code)
        }
    };
    let Some(upstream) = &state.config.upstream else {
        return reply(&mut inbound, 2, 403);
    };
    if !upstream.permits(&target, state.listener, &state.rules) {
        return reply(&mut inbound, 2, 403);
    }
    let (remote, welcome) =
        match upstream::open(upstream, &target, deadline, state.config.tls.as_ref()) {
            Ok(pair) => pair,
            Err(_) => return reply(&mut inbound, 1, 502),
        };
    reply(&mut inbound, 0, 200)?;
    inbound.write_all(&welcome)?;
    remote.relay(client, &early, deadline)
}
