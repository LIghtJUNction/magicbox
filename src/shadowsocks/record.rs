//! SIP004 record protection. Length and payload are separately authenticated.
use crate::address::bad;
use md5::{Digest, Md5};
use ring::{aead, hkdf};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub(super) const MAX: usize = 0x3fff;
pub(super) const HEADER: usize = 2 + 16;
pub(super) const CAPACITY: usize = HEADER + MAX + 16;

pub(super) fn algorithm(name: &[u8]) -> Option<&'static aead::Algorithm> {
    match name {
        b"aes-128-gcm" => Some(&aead::AES_128_GCM),
        b"aes-256-gcm" => Some(&aead::AES_256_GCM),
        b"chacha20-ietf-poly1305" => Some(&aead::CHACHA20_POLY1305),
        _ => None,
    }
}

pub(super) struct Master {
    algorithm: &'static aead::Algorithm,
    bytes: Zeroizing<[u8; 32]>,
}

impl Master {
    pub fn new(method: &[u8], password: &[u8]) -> io::Result<Self> {
        let algorithm = algorithm(method).ok_or_else(|| bad("unsupported Shadowsocks cipher"))?;
        // SIP004 inherits the unsalted, single-round EVP_BytesToKey from the original protocol.
        let mut bytes = Zeroizing::new([0; 32]);
        bytes[..16].copy_from_slice(&Md5::digest(password));
        if algorithm.key_len() == 32 {
            let second = Md5::new()
                .chain_update(&bytes[..16])
                .chain_update(password)
                .finalize();
            bytes[16..].copy_from_slice(&second);
        }
        Ok(Self { algorithm, bytes })
    }
    pub fn salt_len(&self) -> usize {
        self.algorithm.key_len()
    }
    pub fn session(&self, salt: &[u8]) -> io::Result<Cipher> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
            .extract(&self.bytes[..self.salt_len()]);
        let key = prk
            .expand(&[b"ss-subkey"], self.algorithm)
            .map_err(|_| bad("invalid subkey"))?;
        Ok(Cipher {
            key: aead::LessSafeKey::new(key.into()),
            counter: 0,
        })
    }
}

pub(super) struct Cipher {
    key: aead::LessSafeKey,
    counter: u64,
}

impl Cipher {
    fn nonce(&mut self) -> io::Result<aead::Nonce> {
        let mut nonce = [0; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| bad("record limit reached"))?;
        Ok(aead::Nonce::assume_unique_for_key(nonce))
    }
    fn seal(&mut self, bytes: &mut [u8]) -> io::Result<aead::Tag> {
        let nonce = self.nonce()?;
        self.key
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), bytes)
            .map_err(|_| bad("failed to seal Shadowsocks record"))
    }
    fn open(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let nonce = self.nonce()?;
        self.key
            .open_in_place(nonce, aead::Aad::empty(), bytes)
            .map(|_| ())
            .map_err(|_| bad("invalid Shadowsocks authentication tag"))
    }

    /// The caller placed len plaintext bytes immediately after HEADER.
    pub fn write(&mut self, to: &mut impl Write, frame: &mut [u8], len: usize) -> io::Result<()> {
        debug_assert!(len <= MAX && frame.len() >= HEADER + len + 16);
        frame[..2].copy_from_slice(&(len as u16).to_be_bytes());
        let header_tag = self.seal(&mut frame[..2])?;
        frame[2..HEADER].copy_from_slice(header_tag.as_ref());
        let end = HEADER + len;
        let tag = self.seal(&mut frame[HEADER..end])?;
        frame[end..end + 16].copy_from_slice(tag.as_ref());
        to.write_all(&frame[..end + 16])
    }
    pub fn read(&mut self, from: &mut impl Read, payload: &mut [u8]) -> io::Result<Option<usize>> {
        let mut header = [0; HEADER];
        // EOF is valid only between records, never inside a length, tag or payload.
        loop {
            match from.read(&mut header[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        from.read_exact(&mut header[1..])?;
        self.open(&mut header)?;
        let len = u16::from_be_bytes([header[0], header[1]]) as usize;
        if len > MAX {
            return Err(bad("invalid Shadowsocks record length"));
        }
        from.read_exact(&mut payload[..len + 16])?;
        self.open(&mut payload[..len + 16])?;
        Ok(Some(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_frames_reject_corruption_and_truncation() {
        let master = Master::new(b"aes-256-gcm", b"test-password").unwrap();
        let salt = [7; 32];
        let mut sealed = Vec::new();
        let mut frame = [0; HEADER + 3 + 16];
        frame[HEADER..HEADER + 3].copy_from_slice(b"abc");
        master
            .session(&salt)
            .unwrap()
            .write(&mut sealed, &mut frame, 3)
            .unwrap();
        let mut buf = [0; MAX + 16];
        for pos in [0, 2, HEADER, sealed.len() - 1] {
            let mut corrupt = sealed.clone();
            corrupt[pos] ^= 1;
            assert!(
                master
                    .session(&salt)
                    .unwrap()
                    .read(&mut &corrupt[..], &mut buf)
                    .is_err()
            );
        }
        for end in [1, HEADER - 1, HEADER, sealed.len() - 1] {
            assert!(
                master
                    .session(&salt)
                    .unwrap()
                    .read(&mut &sealed[..end], &mut buf)
                    .is_err()
            );
        }
        assert_eq!(
            master
                .session(&salt)
                .unwrap()
                .read(&mut &sealed[..], &mut buf)
                .unwrap(),
            Some(3)
        );
        assert_eq!(&buf[..3], b"abc");
    }
}
