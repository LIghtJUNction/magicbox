//! A structured node can acquire transport/security semantics from optional
//! keys. Import only nodes whose options are understood by this runtime.
use super::{MAX_ENTRIES, Node, escape, protocol};
use crate::config::Endpoint;
use toml::{Table, Value};

enum Shape {
    Clash,
    Sing,
    Sip008,
}

pub(super) fn nodes(raw: &str) -> Result<Vec<Node>, &'static str> {
    structured(&super::yaml::document(raw)?)
}

fn structured(value: &Value) -> Result<Vec<Node>, &'static str> {
    let (shape, items) = match (
        value.get("proxies"),
        value.get("outbounds"),
        value.get("servers"),
    ) {
        (Some(items), None, None) => (Shape::Clash, items),
        (None, Some(items), None) => (Shape::Sing, items),
        (None, None, Some(items))
            if value.get("version").and_then(Value::as_integer) == Some(1) =>
        {
            (Shape::Sip008, items)
        }
        (None, None, None) if value.is_array() => (Shape::Sip008, value),
        _ => return Err("unrecognized or ambiguous subscription document"),
    };
    let items = items.as_array().ok_or("expected an array of nodes")?;
    if items.is_empty() || items.len() > MAX_ENTRIES {
        return Err("invalid number of subscription nodes");
    }
    items
        .iter()
        .map(|item| {
            let node = item.as_table().ok_or("node must be an object")?;
            let display_key = match shape {
                Shape::Clash => "name",
                Shape::Sing => "tag",
                Shape::Sip008 => "remarks",
            };
            let label = super::label::safe(
                node.get(display_key).and_then(Value::as_str).unwrap_or(""),
                [
                    "username",
                    "password",
                    "uuid",
                    "server",
                    "token",
                    "private-key",
                    "pre-shared-key",
                ]
                .iter()
                .filter_map(|k| node.get(*k).and_then(Value::as_str)),
            );
            let kind = if matches!(shape, Shape::Sip008) {
                if !["server", "method", "password"]
                    .iter()
                    .all(|k| node.get(*k).is_some_and(Value::is_str))
                {
                    return Err("invalid SIP008 node");
                }
                "shadowsocks"
            } else {
                let typ = node
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or("missing node type")?;
                if matches!(shape, Shape::Sing) && typ == "socks" {
                    "socks5"
                } else {
                    protocol(typ)
                }
            };
            if kind == "shadowsocks" {
                return Ok(Node {
                    kind,
                    label,
                    uri: shadowsocks(node, &shape),
                });
            }
            if !matches!(kind, "socks5" | "http") {
                return Ok(Node::unsupported(kind, label));
            }
            let uri = convert(node, &shape, kind);
            let kind = if uri.as_ref().is_ok_and(|u| u.starts_with("https://")) {
                "https"
            } else {
                kind
            };
            Ok(Node { kind, uri, label })
        })
        .collect()
}

fn shadowsocks(node: &Table, shape: &Shape) -> Result<String, &'static str> {
    let (label, method, port) = match shape {
        Shape::Clash => ("name", "cipher", "port"),
        Shape::Sing => ("tag", "method", "server_port"),
        Shape::Sip008 => ("remarks", "method", "server_port"),
    };
    for (key, value) in node {
        if [label, method, port, "server", "password"].contains(&key.as_str()) {
            continue;
        }
        let allowed = match (shape, key.as_str()) {
            (Shape::Clash | Shape::Sing, "type") => true,
            (Shape::Sip008, "id") => value.is_str(),
            (Shape::Clash, "udp") => value.as_bool() == Some(false),
            (Shape::Sing, "network") => value.as_str() == Some("tcp"),
            (_, "plugin" | "plugin_opts" | "plugin-opts") => value.as_str() == Some(""),
            _ => false,
        };
        if !allowed {
            return Err("Shadowsocks node requires unsupported options");
        }
    }
    let method = node
        .get(method)
        .and_then(Value::as_str)
        .ok_or("missing Shadowsocks method")?;
    let password = node
        .get("password")
        .and_then(Value::as_str)
        .ok_or("missing Shadowsocks password")?;
    if !crate::shadowsocks::supported(method.as_bytes()) || password.len() > 4096 {
        return Err("unsupported Shadowsocks method or password length");
    }
    let addr = address(node, port)?;
    let uri = crate::config::ss_uri::format(addr, method.as_bytes(), password.as_bytes());
    Node::from_uri(&uri)?.uri
}

fn address(node: &Table, port_key: &str) -> Result<Endpoint, &'static str> {
    let host = node
        .get("server")
        .and_then(Value::as_str)
        .ok_or("missing server")?;
    let port = node
        .get(port_key)
        .and_then(Value::as_integer)
        .and_then(|p| u16::try_from(p).ok())
        .ok_or("invalid server port")?;
    Endpoint::from_host(host, port)
}

fn convert(node: &Table, shape: &Shape, kind: &str) -> Result<String, &'static str> {
    let (label, port) = if matches!(shape, Shape::Clash) {
        ("name", "port")
    } else {
        ("tag", "server_port")
    };
    let mut tls = false;
    let mut server_name = None;
    for (key, val) in node {
        if [label, port, "type", "server", "username", "password"].contains(&key.as_str()) {
            continue;
        }
        match (shape, key.as_str()) {
            (Shape::Clash, "tls") if kind == "http" => {
                tls = val.as_bool().ok_or("invalid TLS setting")?
            }
            (Shape::Clash, "sni") if kind == "http" => {
                server_name = Some(val.as_str().ok_or("invalid TLS name")?)
            }
            (Shape::Clash, "skip-cert-verify" | "udp" | "tls") if val.as_bool() == Some(false) => {}
            (Shape::Sing, "version")
                if kind == "socks5"
                    && (val.as_str() == Some("5") || val.as_integer() == Some(5)) => {}
            (Shape::Sing, "network") if val.as_str() == Some("tcp") => {}
            (Shape::Sing, "tls") if kind == "http" => {
                let opts = val.as_table().ok_or("invalid TLS setting")?;
                tls = opts
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or("invalid TLS setting")?;
                for (option, setting) in opts {
                    match option.as_str() {
                        "enabled" => {}
                        "server_name" => {
                            server_name = Some(setting.as_str().ok_or("invalid TLS name")?)
                        }
                        "insecure" if setting.as_bool() == Some(false) => {}
                        _ => return Err("node requires unsupported TLS options"),
                    }
                }
            }
            _ => return Err("node requires unsupported options"),
        }
    }
    let query = match server_name {
        Some(name)
            if tls
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)) =>
        {
            format!("?server_name={name}")
        }
        Some(_) => return Err("invalid TLS name"),
        None => String::new(),
    };
    let scheme = if tls { "https" } else { kind };
    let socket = address(node, port)?;
    let creds = match (node.get("username"), node.get("password")) {
        (None, None) => String::new(),
        (Some(Value::String(u)), Some(Value::String(p))) => {
            format!("{}:{}@", escape(u.as_bytes()), escape(p.as_bytes()))
        }
        _ => return Err("invalid credentials"),
    };
    Node::from_uri(&format!("{scheme}://{creds}{}{query}", socket))?.uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_nodes_round_trip_across_subscription_dialects() {
        let fixtures = [
            (
                r#"{"proxies":[{"type":"http","server":"HK.Example.","port":443,"tls":true}]}"#,
                "https://hk.example:443",
            ),
            (
                r#"{"outbounds":[{"type":"socks","server":"hk.example","server_port":1080}]}"#,
                "socks5://hk.example:1080",
            ),
            (
                r#"{"version":1,"servers":[{"method":"aes-128-gcm","password":"x","server":"hk.example","server_port":8388}]}"#,
                "ss://YWVzLTEyOC1nY206eA@hk.example:8388",
            ),
        ];
        for (feed, expected) in fixtures {
            assert_eq!(nodes(feed).unwrap().remove(0).uri.unwrap(), expected);
            assert_eq!(Node::from_uri(expected).unwrap().uri.unwrap(), expected);
        }
    }

    #[test]
    fn sip008_clash_and_sing_select_the_same_classic_tcp_node() {
        let inputs = [
            r#"{"version":1,"servers":[{"id":"test","remarks":"HK 01","server":"192.0.2.8","server_port":9000,"method":"chacha20-ietf-poly1305","password":"pass","plugin":"","plugin_opts":""}]}"#,
            r#"{"proxies":[{"type":"ss","name":"HK 01","server":"192.0.2.8","port":9000,"cipher":"chacha20-ietf-poly1305","password":"pass","udp":false}]}"#,
            r#"{"outbounds":[{"type":"shadowsocks","tag":"HK 01","server":"192.0.2.8","server_port":9000,"method":"chacha20-ietf-poly1305","password":"pass","network":"tcp"}]}"#,
        ];
        let expected = crate::config::ss_uri::format(
            "192.0.2.8:9000".parse().unwrap(),
            b"chacha20-ietf-poly1305",
            b"pass",
        );
        for input in inputs {
            let n = nodes(input).unwrap().remove(0);
            assert_eq!(n.label, "HK 01");
            assert_eq!(n.uri.unwrap(), expected);
        }
        for suffix in [
            r#","plugin":"obfs-local""#,
            r#","udp":true"#,
            r#","dialer-proxy":"relay""#,
        ] {
            let s = format!(
                r#"{{"proxies":[{{"type":"ss","server":"192.0.2.8","port":9000,"cipher":"aes-256-gcm","password":"x"{suffix}}}]}}"#
            );
            assert!(nodes(&s).unwrap()[0].uri.is_err());
        }
    }

    #[test]
    fn display_uses_only_explicit_non_sensitive_fields() {
        let nodes = nodes(r#"{"proxies":[{"type":"http","name":"Tokyo 02","server":"192.0.2.3","port":80},{"type":"http","name":"token hunter2","server":"192.0.2.4","port":80,"username":"u","password":"hunter2"},{"type":"vless","name":"https://private","server":"10.0.0.1"}]}"#).unwrap();
        assert_eq!(nodes[0].label, "Tokyo 02");
        assert!(nodes[1].label.is_empty());
        assert!(nodes[2].label.is_empty());
    }

    #[test]
    fn verified_tls_identity_round_trips_and_insecure_tls_is_refused() {
        let parsed = nodes(r#"{"outbounds":[{"type":"http","server":"192.0.2.6","server_port":443,"tls":{"enabled":true,"server_name":"proxy.example"}},{"type":"http","server":"192.0.2.6","server_port":443,"tls":{"enabled":true,"insecure":true}}]}"#).unwrap();
        assert_eq!(
            parsed[0].uri.as_ref().unwrap(),
            "https://192.0.2.6:443?server_name=proxy.example"
        );
        assert!(parsed[1].uri.is_err());
    }

    #[test]
    fn transport_and_authentication_semantics_are_preserved() {
        let parsed = nodes(r#"{"proxies":[{"name":"lab","type":"http","server":"::1","port":1080,"username":"a","password":"?!&"},{"type":"http","server":"::1","port":1080,"tls":true}]}"#).unwrap();
        assert_eq!(
            parsed[0].uri.as_ref().unwrap(),
            "http://a:%3F%21%26@[::1]:1080"
        );
        assert_eq!(parsed[1].uri.as_ref().unwrap(), "https://[::1]:1080");
        let parsed = nodes(r#"{"outbounds":[{"type":"socks","server":"127.0.0.1","server_port":1080,"version":"4"},{"type":"http","server":"127.0.0.1","server_port":1080,"detour":"chain"}]}"#).unwrap();
        assert!(parsed.iter().all(|n| n.uri.is_err()));
    }
}
