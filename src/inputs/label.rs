//! A feed's optional human-readable name is the only display field. URI
//! authorities, authentication and TLS names are never used as fallback text.
pub(super) fn decode(value: &str) -> Option<String> {
    if value.len() > 1024 {
        return None;
    }
    let mut bytes = value.bytes();
    let mut result = Vec::with_capacity(value.len());
    while let Some(mut byte) = bytes.next() {
        if byte == b'%' {
            let mut hex = || (bytes.next()? as char).to_digit(16).map(|v| v as u8);
            byte = (hex()? << 4) | hex()?;
        }
        result.push(byte);
    }
    String::from_utf8(result).ok()
}

pub fn safe<'a>(raw: &str, private: impl IntoIterator<Item = &'a str>) -> String {
    let name = raw.trim_matches(' ');
    if name.is_empty()
        || name.len() > 128
        || name.chars().count() > 48
        || !name.chars().all(|c| {
            c.is_alphanumeric() || " -_()·".contains(c) || ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
        })
        || name
            .split_whitespace()
            .any(|word| word.is_ascii() && word.len() >= 24)
        || name.bytes().all(|b| b.is_ascii_digit())
    {
        return String::new();
    }
    let lower = name.to_lowercase();
    if private
        .into_iter()
        .any(|s| !s.is_empty() && lower.contains(&s.to_lowercase()))
    {
        return String::new();
    }
    name.to_owned()
}

pub fn fragment(raw: Option<&str>, location: &str) -> String {
    let Some(display) = raw.and_then(decode) else {
        return String::new();
    };
    let (authority, query) = location.split_once('?').unwrap_or((location, ""));
    let (auth, server) = authority.rsplit_once('@').unwrap_or(("", authority));
    let mut private: Vec<_> = auth
        .split(':')
        .chain(
            query
                .split('&')
                .filter_map(|v| v.split_once('=').map(|kv| kv.1)),
        )
        .filter(|v| !v.is_empty())
        .filter_map(decode)
        .collect();
    if let Some((host, _)) = server.rsplit_once(':') {
        private.push(host.trim_matches(['[', ']']).to_owned());
    }
    safe(&display, private.iter().map(String::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn human_labels_keep_utf8_and_never_emit_authority_or_parser_delimiters() {
        assert_eq!(
            fragment(Some("%E9%A6%99%E6%B8%AF%20A"), "10.0.0.1:80"),
            "香港 A"
        );
        for dangerous in [
            "http%3A%2F%2Fx",
            "192.0.2.1",
            "user%40foo",
            "%09a",
            "%0Atag",
            "%E2%80%AEtag",
            "%xy",
            "abcXYZabcXYZabcXYZabcXYZ",
            "proxy hunter2",
        ] {
            assert!(
                fragment(Some(dangerous), "user:hunter2@192.0.2.1:80").is_empty(),
                "{dangerous}"
            );
        }
        assert!(fragment(Some("tok abc"), "opaque%20tok:abc@127.0.0.1:80").is_empty());
    }
}
