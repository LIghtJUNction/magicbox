mod address;
mod config;
mod dns_wire;
mod egress;
mod fetch;
mod gateway;
mod handshake;
mod http;
mod inputs;
mod policy;
mod relay;
mod resolver;
mod server;
mod shadowsocks;
mod slots;
mod socks;
mod tls;
mod tls_relay;
#[cfg(unix)]
mod udp;
mod upstream;

use std::process::ExitCode;

fn execute() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "--version" => {
            println!("magicbox {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [command, path] if command == "check" || command == "run" => {
            let rules = policy::Rules::from_env().map_err(|e| e.to_string())?;
            if command == "check" {
                config::Config::read(path)?;
                println!("valid");
                return Ok(());
            }
            server::run(config::Config::load(path)?, rules).map_err(|e| e.to_string())
        }
        [command, path] if command == "serve" || command == "check-server" => {
            let gateway = gateway::Gateway::load(path)?;
            if command == "check-server" { println!("valid"); return Ok(()); }
            gateway.serve().map_err(|e| e.to_string())
        }
        [command, url] if command == "fetch" => fetch::cli(url),
        [command, rest @ ..] if command == "import" => inputs::cli(rest),
        _ => Err("usage: magicbox check FILE | run FILE | serve FILE | check-server FILE | fetch URL|- | import FILE|- | --version".into()),
    }
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("magicbox: {e}");
            ExitCode::FAILURE
        }
    }
}
