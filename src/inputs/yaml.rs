//! Load a single small YAML document. Aliases and custom tags are rejected,
//! so expansion cannot allocate memory beyond the input/event bounds.
use saphyr_parser::{Event, Parser, ScalarStyle, StrInput};
use toml::{Table, Value};

type Error = &'static str;
struct Reader<'a> {
    parser: Parser<'a, StrInput<'a>>,
    events: usize,
}

impl<'a> Reader<'a> {
    fn next(&mut self) -> Result<Event<'a>, Error> {
        self.events += 1;
        if self.events > 100_000 {
            return Err("too many YAML events");
        }
        let (event, _) = self
            .parser
            .next_event()
            .ok_or("incomplete YAML")?
            .map_err(|_| "invalid YAML")?;
        Ok(event)
    }

    fn value(&mut self, event: Event<'a>, depth: u8) -> Result<Value, Error> {
        if depth > 32 {
            return Err("YAML nesting exceeds 32");
        }
        match event {
            Event::Scalar(value, style, 0, None) => {
                if style == ScalarStyle::Plain {
                    match value.as_ref() {
                        "true" => return Ok(Value::Boolean(true)),
                        "false" => return Ok(Value::Boolean(false)),
                        _ => {}
                    }
                    if let Ok(number) = value.parse::<i64>() {
                        return Ok(Value::Integer(number));
                    }
                }
                Ok(Value::String(value.into_owned()))
            }
            Event::MappingStart(0, None) => {
                let mut map = Table::new();
                loop {
                    match self.next()? {
                        Event::MappingEnd => return Ok(Value::Table(map)),
                        Event::Scalar(key, _, 0, None) if key != "<<" => {
                            if map.contains_key(key.as_ref()) {
                                return Err("duplicate YAML key");
                            }
                            let event = self.next()?;
                            map.insert(key.into_owned(), self.value(event, depth + 1)?);
                        }
                        _ => return Err("unsupported YAML key, alias or tag"),
                    }
                }
            }
            Event::SequenceStart(0, None) => {
                let mut items = Vec::new();
                loop {
                    let child = self.next()?;
                    if child == Event::SequenceEnd {
                        return Ok(Value::Array(items));
                    }
                    items.push(self.value(child, depth + 1)?);
                }
            }
            _ => Err("unsupported YAML alias, anchor or tag"),
        }
    }
}

pub(super) fn document(text: &str) -> Result<Value, Error> {
    let mut reader = Reader {
        parser: Parser::new_from_str(text),
        events: 0,
    };
    if reader.next()? != Event::StreamStart || !matches!(reader.next()?, Event::DocumentStart(_)) {
        return Err("expected a YAML document");
    }
    let root = reader.next()?;
    let result = reader.value(root, 0)?;
    if reader.next()? != Event::DocumentEnd || reader.next()? != Event::StreamEnd {
        return Err("subscription requires exactly one YAML document");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    #[test]
    fn clash_block_and_flow_styles() {
        let data = b"# provider\n---\nproxies:\n  - {name: one, type: http, server: 127.0.0.1, port: 8123}\n  - name: two\n    type: socks5\n    server: '::1'\n    port: 19080\n    username: a\n    password: '12345'\n";
        let nodes = parse(data, true).unwrap();
        assert_eq!(nodes[0].uri.as_ref().unwrap(), "http://127.0.0.1:8123");
        assert_eq!(
            nodes[1].uri.as_ref().unwrap(),
            "socks5://a:12345@[::1]:19080"
        );
    }
    #[test]
    fn fail_on_alias_multi_doc_and_ambiguous_mapping() {
        for bad in [
            "proxies: &a []\nbookmark: *a\n",
            "proxies: []\n---\nproxies: []",
            "proxies: [{type: http, type: socks5, server: '::1', port: 80}]",
        ] {
            assert!(parse(bad.as_bytes(), true).is_err());
        }
    }
}
