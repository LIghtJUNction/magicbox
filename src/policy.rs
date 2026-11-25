//! Immutable exact-name blocklist. Loading one backing string and a table of
//! offsets avoids allocating a String per DNS name.
use std::{
    env,
    fs::File,
    io::{self, Read},
};

const MAX_BYTES: usize = 12 * 1024 * 1024;
const MAX_NAMES: usize = 350_000;
const HEADER: &str = "magicbox-exact-v1";

#[derive(Default)]
pub struct Rules {
    text: String,
    offsets: Vec<u32>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unsorted MagicBox blocklist",
    )
}

impl Rules {
    pub fn from_env() -> io::Result<Self> {
        match env::var_os("MAGICBOX_BLOCKLIST") {
            None => Ok(Self::default()),
            Some(path) => Self::read(File::open(path)?),
        }
    }

    fn read(input: impl Read) -> io::Result<Self> {
        let mut text = String::new();
        input
            .take((MAX_BYTES + 1) as u64)
            .read_to_string(&mut text)?;
        if text.len() > MAX_BYTES || !text.ends_with('\n') {
            return Err(invalid());
        }
        let mut lines = text.split_terminator('\n');
        if lines.next() != Some(HEADER) {
            return Err(invalid());
        }
        let mut previous = "";
        let mut offset = HEADER.len() + 1;
        let mut offsets = Vec::new();
        for line in lines {
            if line <= previous || !valid_name(line) || offsets.len() == MAX_NAMES {
                return Err(invalid());
            }
            offsets.push(offset as u32);
            offset += line.len() + 1;
            previous = line;
        }
        if offsets.is_empty() {
            return Err(invalid());
        }
        Ok(Self { text, offsets })
    }

    pub fn blocks(&self, name: &str) -> bool {
        let name = name.strip_suffix('.').unwrap_or(name);
        let lower;
        let name = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = name.to_ascii_lowercase();
            lower.as_str()
        } else {
            name
        };
        if ["localhost", "local", "home.arpa"].iter().any(|suffix| {
            name == *suffix
                || name
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        }) {
            return true;
        }
        self.offsets
            .binary_search_by(|&offset| {
                let rest = &self.text[offset as usize..];
                let end = rest.find('\n').expect("line endings validated at load");
                rest[..end].cmp(name)
            })
            .is_ok()
    }
}

fn valid_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_names_and_label_boundaries() {
        let rules = Rules::read("magicbox-exact-v1\na.example\nz.example\n".as_bytes()).unwrap();
        for yes in [
            "LOCALHOST.",
            "x.local",
            "branch.Home.Arpa",
            "A.example.",
            "z.example",
        ] {
            assert!(rules.blocks(yes), "{yes}");
        }
        for no in [
            "notlocalhost",
            "home.arpa.test",
            "child.a.example",
            "example",
            "w.example",
        ] {
            assert!(!rules.blocks(no), "{no}");
        }
    }

    #[test]
    fn malformed_pack_rejected_atomically() {
        for bad in [
            "",
            "some.domain\n",
            "magicbox-exact-v1\n",
            "magicbox-exact-v1\nfoo\nfoo\n",
            "magicbox-exact-v1\na\nZ\n",
            "magicbox-exact-v1\na..test\n",
            "magicbox-exact-v1\nz\na\n",
            "magicbox-exact-v1\na.test",
        ] {
            assert!(Rules::read(bad.as_bytes()).is_err());
        }
    }
}
