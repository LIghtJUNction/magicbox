use crate::address::{Host, Target, bad};
use rustls::pki_types::ServerName;
use std::io;

pub struct Url {
    pub authority: String,
    pub path: String,
    pub target: Target,
}

impl Url {
    pub fn parse(raw: &str) -> io::Result<Self> {
        if raw.len() > 8192 || !raw.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
            return Err(bad("invalid feed URL"));
        }
        let rest = raw
            .strip_prefix("https://")
            .ok_or_else(|| bad("feed must use HTTPS"))?;
        let rest = rest.split('#').next().unwrap_or_default();
        let at = rest.find(['/', '?']).unwrap_or(rest.len());
        let host = &rest[..at];
        if host.contains('@') || host.is_empty() {
            return Err(bad("invalid feed authority"));
        }
        let with_port = if host.starts_with('[') {
            host.contains("]:")
        } else {
            host.contains(':')
        };
        let target = Target::parse_authority(&if with_port {
            host.to_owned()
        } else {
            format!("{host}:443")
        })?;
        let path = match &rest[at..] {
            "" => "/".into(),
            query if query.starts_with('?') => format!("/{query}"),
            other => other.into(),
        };
        Ok(Self {
            authority: target.to_string(),
            target,
            path,
        })
    }

    pub fn identity(&self) -> io::Result<ServerName<'static>> {
        match &self.target.host {
            Host::Ip(ip) => Ok(ServerName::IpAddress((*ip).into())),
            Host::Name(name) => ServerName::try_from(name.trim_end_matches('.').to_owned())
                .map_err(|_| bad("invalid feed TLS identity")),
        }
    }

    pub fn redirect(&self, loc: &str) -> io::Result<Self> {
        if loc.contains("://") {
            return Self::parse(loc);
        }
        if loc.starts_with("//") {
            return Self::parse(&format!("https:{loc}"));
        }
        let path = match loc.chars().next() {
            Some('/') => loc.to_owned(),
            Some('?') => format!("{}{loc}", self.path.split('?').next().unwrap_or("/")),
            Some('#') | None => return Err(bad("empty feed redirect")),
            Some(_) => {
                let (dir, _) = self
                    .path
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .rsplit_once('/')
                    .unwrap_or(("", ""));
                format!("{dir}/{loc}")
            }
        };
        Self::parse(&format!("https://{}{path}", self.authority))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_query_and_refuses_authority_confusion() {
        let link = Url::parse("https://ExAmple.com?x=1#local").unwrap();
        assert_eq!(link.authority, "example.com:443");
        assert_eq!(link.path, "/?x=1");
        assert_eq!(
            link.redirect("//other.net/sub").unwrap().authority,
            "other.net:443"
        );
        assert_eq!(link.redirect("?rev=2").unwrap().path, "/?rev=2");
        for raw in [
            "http://example.com",
            "https://user:password@example.com",
            "https://127.1/",
            "https://example.com/hello\r\nX: 1",
            "https://good.com\\@bad.com",
            "https:///",
        ] {
            assert!(Url::parse(raw).is_err());
        }
        assert!(link.redirect("http://example.com/feed").is_err());
    }
}
