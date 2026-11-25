use super::*;
use core::net::{IpAddr, Ipv4Addr};

fn reply() -> Vec<u8> {
    let mut msg = query("a.test", RecordType::A, 42).unwrap();
    msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    msg[7] = 1;
    msg
}

#[test]
fn validates_transaction_and_ignores_unrelated_records() {
    let mut msg = reply();
    msg.extend([
        1, b'b', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1,
    ]);
    assert!(
        answers(&msg, "a.test", RecordType::A, 42)
            .unwrap()
            .is_empty()
    );
    for (asked, kind, id) in [
        ("a.test", RecordType::A, 43),
        ("b.test", RecordType::A, 42),
        ("a.test", RecordType::Aaaa, 42),
    ] {
        assert!(answers(&msg, asked, kind, id).is_err());
    }
}

#[test]
fn follows_compressed_cname_chain() {
    let mut msg = reply();
    msg[7] = 2;
    msg.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 4]);
    let alias = msg.len() as u8;
    msg.extend([1, b'b', 0xc0, 14]);
    msg.extend([0xc0, alias, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 1, 1, 1]);
    assert_eq!(
        answers(&msg, "a.test", RecordType::A, 42).unwrap(),
        [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
    );
}

#[test]
fn rejects_truncation_compression_cycles_and_bogus_lengths() {
    let base = reply();
    for suffix in [
        vec![0xc0, base.len() as u8],
        vec![64],
        vec![0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 255],
        vec![0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1],
    ] {
        let mut msg = base.clone();
        msg.extend(suffix);
        assert!(answers(&msg, "a.test", RecordType::A, 42).is_err());
    }
    let mut truncated = base;
    truncated[2] |= 2;
    assert!(answers(&truncated, "a.test", RecordType::A, 42).is_err());
}
#[test]
fn public_api_bounds_and_case() {
    for invalid in ["", ".", "a..", "a..b", "bad label", "bäd"] {
        assert!(query(invalid, RecordType::A, 1).is_err());
    }
    assert!(query(&"a".repeat(64), RecordType::A, 9).is_err());
    assert!(query(&"x".repeat(63), RecordType::A, 9).is_ok());
    let mut packet = query("Node.Test.", RecordType::Aaaa, 9).unwrap();
    packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    assert!(
        answers(&packet, "nODE.test", RecordType::Aaaa, 9)
            .unwrap()
            .is_empty()
    );
    assert!(answers(&vec![0; MAX_PACKET + 1], "n.test", RecordType::A, 0).is_err());
}
