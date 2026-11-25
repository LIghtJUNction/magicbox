//! SIP002 plus legacy Base64(method:password@address). Named servers are resolved only on activation; plugins are outside the transport contract.
use super::{Endpoint, NodeSpec, Protocol, decode_bounded};

fn base64(raw: &str) -> Result<Vec<u8>, &'static str> {
    if raw.len() > 8192 {
        return Err("Shadowsocks credentials too long");
    }
    let url = raw.bytes().any(|b| b == b'-' || b == b'_');
    let mode = match (url, raw.ends_with('=')) {
        (true, true) => z64::Mode::UrlSafe,
        (true, false) => z64::Mode::UrlSafeNoPad,
        (false, true) => z64::Mode::Standard,
        (false, false) => z64::Mode::StandardNoPad,
    };
    let mut out = vec![0; z64::decoded_capacity(raw.len()).ok_or("invalid credential length")?];
    let n =
        z64::decode(raw.as_bytes(), &mut out, mode).map_err(|_| "invalid Shadowsocks Base64")?;
    out.truncate(n);
    Ok(out)
}

fn pair(raw: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    let index = raw
        .iter()
        .position(|&b| b == b':')
        .ok_or("missing Shadowsocks credentials")?;
    Ok((&raw[..index], &raw[index + 1..]))
}

pub fn parse(authority: &str) -> Result<NodeSpec, &'static str> {
    if authority.contains(['?', '#']) || authority.len() > 8192 {
        return Err("unsupported Shadowsocks URI options or length");
    }
    let (addr, method, password) = match authority.rsplit_once('@') {
        Some((info, addr)) => {
            let addr = addr.strip_suffix('/').unwrap_or(addr).parse()?;
            let (method, password) = match info.split_once(':') {
                Some((m, p)) => (decode_bounded(m, 64)?, decode_bounded(p, 4096)?),
                None => {
                    let decoded = base64(info)?;
                    let (m, p) = pair(&decoded)?;
                    (m.to_vec(), p.to_vec())
                }
            };
            (addr, method, password)
        }
        None => {
            let decoded = base64(authority)?;
            let index = decoded
                .iter()
                .rposition(|&b| b == b'@')
                .ok_or("missing Shadowsocks address")?;
            let addr = std::str::from_utf8(&decoded[index + 1..])
                .map_err(|_| "invalid Shadowsocks address")?;
            let (method, password) = pair(&decoded[..index])?;
            (addr.parse()?, method.to_vec(), password.to_vec())
        }
    };
    if !crate::shadowsocks::supported(&method) {
        return Err("unsupported Shadowsocks method");
    }
    if password.is_empty() || password.len() > 4096 || password.iter().any(u8::is_ascii_control) {
        return Err("invalid Shadowsocks password");
    }
    Ok(NodeSpec {
        scheme: Protocol::Shadowsocks,
        addr,
        auth: Some((method, password)),
        server_name: None,
    })
}

pub fn format(addr: Endpoint, method: &[u8], password: &[u8]) -> String {
    let mut secret = Vec::with_capacity(method.len() + 1 + password.len());
    secret.extend_from_slice(method);
    secret.push(b':');
    secret.extend_from_slice(password);
    let mode = z64::Mode::UrlSafeNoPad;
    let mut encoded = vec![0; z64::encoded_len(secret.len(), mode).expect("bounded credentials")];
    z64::encode(&secret, &mut encoded, mode).expect("exact buffer");
    format!(
        "ss://{}@{}",
        std::str::from_utf8(&encoded).expect("Base64 ASCII"),
        addr
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(raw: &[u8]) -> String {
        let mode = z64::Mode::Standard;
        let mut text = vec![0; z64::encoded_len(raw.len(), mode).unwrap()];
        z64::encode(raw, &mut text, mode).unwrap();
        String::from_utf8(text).unwrap()
    }
    #[test]
    fn classic_uri_variants_preserve_colons_at_sign_and_utf8() {
        let pass = "p@ss:密";
        let canonical = format(
            "127.0.0.1:1080".parse().unwrap(),
            b"aes-128-gcm",
            pass.as_bytes(),
        );
        let legacy = encode(format!("aes-128-gcm:{pass}@127.0.0.1:1080").as_bytes());
        for link in [
            canonical.strip_prefix("ss://").unwrap(),
            &legacy,
            "aes-128-gcm:p%40ss%3A%E5%AF%86@127.0.0.1:1080/",
        ] {
            let node = parse(link).unwrap();
            let pair = node.auth.unwrap();
            assert_eq!(pair.0, b"aes-128-gcm");
            assert_eq!(pair.1, pass.as_bytes());
        }
    }
    #[test]
    fn plugin_stream_cipher_local_hostname_and_control_refused() {
        for link in [
            "aes-128-gcm:test@127.0.0.1:80/?plugin=x",
            "rc4-md5:test@127.0.0.1:80",
            "aes-128-gcm:test@proxy.local:443",
            "aes-128-gcm:%0d%0a@127.0.0.1:80",
            "2022-blake3-aes-128-gcm:test@127.0.0.1:80",
            "aes-128-gcm:@127.0.0.1:1080",
            "YWJj=",
        ] {
            assert!(parse(link).is_err(), "{link}");
        }
    }
}
