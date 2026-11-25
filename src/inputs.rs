//! Import subscription data without performing network I/O or executing feed content.
mod label;
mod structured;
mod yaml;

use crate::config::{NodeSpec, Protocol};
use std::{
    fmt::Write as _,
    fs::File,
    io::{self, Read},
};

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

struct Node {
    kind: &'static str,
    label: String,
    uri: Result<String, &'static str>,
}

impl Node {
    fn unsupported(kind: &'static str, label: String) -> Self {
        Self {
            kind,
            label,
            uri: Err("this node type or transport is not implemented"),
        }
    }

    fn from_uri(uri: &str) -> Result<Self, &'static str> {
        let (scheme, location) = uri
            .split_once("://")
            .ok_or("expected a proxy URI on each line")?;
        if scheme.is_empty()
            || scheme.len() > 32
            || !scheme
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"+.-".contains(&c))
        {
            return Err("invalid URI scheme");
        }
        let scheme = scheme.to_ascii_lowercase();
        let kind = protocol(&scheme);
        let (rest, fragment) = location
            .split_once('#')
            .map_or((location, None), |(rest, tag)| (rest, Some(tag)));
        if kind == "shadowsocks" {
            let parsed = crate::config::ss_uri::parse(rest);
            let label = match (
                fragment.and_then(label::decode),
                parsed.as_ref().ok().and_then(|n| n.auth.as_ref()),
            ) {
                (Some(name), Some((_, pass))) => label::safe(&name, std::str::from_utf8(pass).ok()),
                _ => String::new(),
            };
            return Ok(Self {
                kind,
                uri: parsed.map(canonical_uri),
                label,
            });
        }
        let label = if matches!(kind, "shadowsocksr" | "vmess" | "other") {
            String::new()
        } else {
            label::fragment(fragment, rest)
        };
        let uri = match kind {
            "socks5" | "http" | "https" => {
                NodeSpec::parse(&format!("{kind}://{rest}")).map(canonical_uri)
            }
            _ => return Ok(Self::unsupported(kind, label)),
        };
        Ok(Self { kind, uri, label })
    }
}

fn protocol(name: &str) -> &'static str {
    match name {
        "socks5" | "socks5h" => "socks5",
        "http" => "http",
        "https" => "https",
        "ss" | "shadowsocks" => "shadowsocks",
        "ssr" => "shadowsocksr",
        "vmess" => "vmess",
        "vless" => "vless",
        "trojan" => "trojan",
        "wireguard" | "wg" => "wireguard",
        "hysteria" => "hysteria",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        _ => "other",
    }
}

fn escape(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            escaped.push(b as char);
        } else {
            write!(escaped, "%{b:02X}").expect("writing to String");
        }
    }
    escaped
}

fn canonical_uri(endpoint: NodeSpec) -> String {
    let scheme = match endpoint.scheme {
        Protocol::Socks5 => "socks5",
        Protocol::Http => "http",
        Protocol::Https => "https",
        Protocol::Shadowsocks => {
            let (method, password) = endpoint.auth.expect("validated Shadowsocks endpoint");
            return crate::config::ss_uri::format(endpoint.addr, &method, &password);
        }
    };
    let auth = endpoint
        .auth
        .map(|(u, p)| format!("{}:{}@", escape(&u), escape(&p)))
        .unwrap_or_default();
    let query = endpoint
        .server_name
        .map(|name| format!("?server_name={name}"))
        .unwrap_or_default();
    format!("{scheme}://{auth}{}{query}", endpoint.addr)
}

fn uri_list(text: &str) -> Result<Vec<Node>, &'static str> {
    let mut entries = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
    {
        if entries.len() == MAX_ENTRIES {
            return Err("subscription has too many nodes");
        }
        entries.push(Node::from_uri(line)?);
    }
    if entries.is_empty() {
        return Err("subscription has no nodes");
    }
    Ok(entries)
}

fn parse(raw: &[u8], decode: bool) -> Result<Vec<Node>, &'static str> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| "subscription must be UTF-8")?
        .trim()
        .trim_start_matches('\u{feff}')
        .trim_start();
    if text.starts_with('{') || text.starts_with('[') {
        return structured::nodes(text);
    }
    let first = text
        .lines()
        .map(str::trim)
        .find(|s| !s.is_empty() && !s.starts_with('#'))
        .unwrap_or("");
    if first.split_once("://").is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    }) {
        return uri_list(text);
    }
    if first.contains(':') || first.starts_with("---") || first.starts_with("%YAML") {
        return structured::nodes(text);
    }
    if !decode {
        return Err("unrecognized subscription format");
    }
    let input: Vec<_> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let url = input.iter().any(|b| matches!(b, b'-' | b'_'));
    let mode = match (url, input.ends_with(b"=")) {
        (false, true) => z64::Mode::Standard,
        (false, false) => z64::Mode::StandardNoPad,
        (true, true) => z64::Mode::UrlSafe,
        (true, false) => z64::Mode::UrlSafeNoPad,
    };
    let mut output = vec![0; z64::decoded_capacity(input.len()).ok_or("subscription too large")?];
    let n =
        z64::decode(&input, &mut output, mode).map_err(|_| "unrecognized subscription format")?;
    parse(&output[..n], false)
}

pub fn cli(args: &[String]) -> Result<(), String> {
    let usage = "usage: magicbox import [--list | --select INDEX] FILE|-";
    let (list, choice, path) = match args {
        [path] => (false, None, path),
        [flag, path] if flag == "--list" => (true, None, path),
        [flag, index, path] if flag == "--select" => (
            false,
            Some(index.parse::<usize>().map_err(|_| usage)?),
            path,
        ),
        _ => return Err(usage.to_owned()),
    };
    let input: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path).map_err(|_| "cannot open subscription")?)
    };
    let mut data = Vec::new();
    input
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read subscription")?;
    if data.len() > MAX_BYTES {
        return Err("subscription exceeds 2 MiB".into());
    }
    let nodes = parse(&data, true)?;
    if list {
        for (index, node) in nodes.iter().enumerate() {
            let status = if node.uri.is_ok() {
                "ready"
            } else {
                "unavailable"
            };
            println!("{}\t{}\t{}\t{}", index + 1, node.kind, status, node.label);
        }
        return Ok(());
    }
    let index = match choice {
        None if nodes.len() == 1 => 0,
        None => return Err("multiple nodes; run import --list, then --select INDEX".into()),
        Some(index) => index.checked_sub(1).ok_or("node indexes start at 1")?,
    };
    let node = nodes.get(index).ok_or("node index out of range")?;
    let uri = node.uri.as_ref().map_err(|reason| (*reason).to_owned())?;
    println!("upstream = \"{uri}\"");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_feeds_never_downgrade_or_leak_secrets_in_listing() {
        let nodes = parse(
            b"# export\nhttps://secret@x.y\nsocks5h://u:p%23@127.0.0.1:1080#name\n",
            true,
        )
        .unwrap();
        assert!(
            Node::from_uri("ss://YWVzOnByaXZhdGU@192.0.2.1:80#private")
                .unwrap()
                .label
                .is_empty()
        );
        assert_eq!(nodes[0].kind, "https");
        assert!(nodes[0].uri.is_err());
        assert_eq!(
            nodes[1].uri.as_ref().unwrap(),
            "socks5://u:p%23@127.0.0.1:1080"
        );
        assert!(
            Node::from_uri("http://secret:x@dns.local:80")
                .unwrap()
                .uri
                .is_err()
        );
        assert!(
            Node::from_uri("http://127.0.0.1:80?tls=true")
                .unwrap()
                .uri
                .is_err()
        );
    }

    #[test]
    fn z64_and_urlsafe_accept_wrapping_and_reject_noncanonical_or_nested_feed() {
        for mode in [z64::Mode::Standard, z64::Mode::UrlSafeNoPad] {
            let raw = b"http://[::1]:1080#~?~";
            let mut encoded = vec![0; z64::encoded_len(raw.len(), mode).unwrap()];
            z64::encode(raw, &mut encoded, mode).unwrap();
            encoded.insert(3, b'\n');
            assert_eq!(
                parse(&encoded, true).unwrap()[0].uri.as_ref().unwrap(),
                "http://[::1]:1080"
            );
        }
        for bad in [b"abcd===".as_slice(), b"YQ%3D%3D", b"YVE9PQ=="] {
            assert!(parse(bad, true).is_err());
        }
    }
}
