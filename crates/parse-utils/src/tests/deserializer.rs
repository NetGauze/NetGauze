use crate::reader::SliceReader;
use crate::traits::ParseFrom;
use crate::writer::WriteTo;
use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[test]
fn test_ipv4() {
    let good_ipv4_wire = [0x04, 0xc0, 0xa8, 0x38, 0x00];
    let good_ipv6_wire = [
        0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    let ipv4 = IpAddr::V4(Ipv4Addr::from_str("192.168.56.0").unwrap());
    let ipv6 = IpAddr::V6(Ipv6Addr::from_str("2001:db8:2::").unwrap());

    let mut ipv4_reader = SliceReader::new(&good_ipv4_wire[..]);
    let mut ipv6_reader = SliceReader::new(&good_ipv6_wire[..]);

    assert_eq!(IpAddr::parse(&mut ipv4_reader), Ok(ipv4));
    assert!(ipv4_reader.is_empty());

    assert_eq!(IpAddr::parse(&mut ipv6_reader), Ok(ipv6));
    assert!(ipv6_reader.is_empty());

    let mut ipv4_buf = BytesMut::new();
    ipv4.write_to(&mut ipv4_buf)
        .expect("Failed to write IPv4 address");
    assert_eq!(&ipv4_buf, &good_ipv4_wire[..]);

    let mut ipv6_buf = BytesMut::new();
    ipv6.write_to(&mut ipv6_buf)
        .expect("Failed to write IPv6 address");
    assert_eq!(&ipv6_buf, &good_ipv6_wire[..]);
}
