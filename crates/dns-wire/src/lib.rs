#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::fmt;

mod reply;
pub use reply::answers;

/// Maximum accepted DNS payload, excluding the two-byte TCP frame length.
pub const MAX_PACKET: usize = 16 * 1024;

/// Address resource record type of an Internet-class question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    Aaaa = 28,
}

/// An invalid DNS name, packet, or response to the requested question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl core::error::Error for Error {}

type DecodeResult<T> = Result<T, Error>;

fn hostname(input: &str) -> DecodeResult<&str> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.len() > 253
        || name.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(Error("invalid DNS query name"));
    }
    Ok(name)
}

/// Encode a recursive IN query for an ASCII hostname and caller-selected ID.
pub fn query(name: &str, kind: RecordType, id: u16) -> Result<Vec<u8>, Error> {
    let name = hostname(name)?;
    let mut packet = vec![0; 12];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1; // recursive query
    packet[5] = 1;
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend(label.bytes());
    }
    packet.extend([0, 0, kind as u8, 0, 1]);
    Ok(packet)
}

#[cfg(test)]
mod tests;
