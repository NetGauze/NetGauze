// Copyright (C) 2026-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::ParseError;
use crate::reader::SliceReader;
use crate::traits::{ParseFrom, ParseFromWithTwoInputs};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const IPV4_LEN: u8 = 4;
pub(crate) const IPV6_LEN: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4PrefixParsingError {
    #[error("failed to parse IPv4 prefix: {0}")]
    Parse(#[from] ParseError),

    #[error("invalid prefix length {prefix_len} at byte offset {offset} (must be 0–32)")]
    InvalidIpv4PrefixLen { offset: usize, prefix_len: u8 },
}

impl<'a> ParseFromWithTwoInputs<'a, u8, usize> for Ipv4Net {
    type Error = Ipv4PrefixParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        prefix_len: u8,
        prefix_offset: usize,
    ) -> Result<Self, Self::Error> {
        // The prefix value must fall into the octet boundary, even if the prefix_len
        // doesn't. For example,
        // prefix_len=24 => prefix_size=24 while prefix_len=19 => prefix_size=24
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        let prefix = cur.read_bytes(prefix_size.min(4) as usize)?;
        // Fill the rest of bits with zeros if
        let mut network = [0; 4];
        prefix.iter().enumerate().for_each(|(i, v)| network[i] = *v);
        let addr = Ipv4Addr::from(network);
        match Ipv4Net::new(addr, prefix_len) {
            Ok(net) => Ok(net),
            Err(_) => Err(Ipv4PrefixParsingError::InvalidIpv4PrefixLen {
                offset: prefix_offset,
                prefix_len,
            }),
        }
    }
}

impl<'a> ParseFrom<'a> for Ipv4Net {
    type Error = Ipv4PrefixParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        ParseFromWithTwoInputs::parse(cur, prefix_len, offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6PrefixParsingError {
    #[error("failed to parse IPv6 prefix: {0}")]
    Parse(#[from] ParseError),

    #[error("invalid prefix length {prefix_len} at byte offset {offset} (must be 0–128)")]
    InvalidIpv6PrefixLen { offset: usize, prefix_len: u8 },
}

impl<'a> ParseFromWithTwoInputs<'a, u8, usize> for Ipv6Net {
    type Error = Ipv6PrefixParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        prefix_len: u8,
        prefix_offset: usize,
    ) -> Result<Self, Self::Error> {
        // The prefix value must fall into the octet boundary, even if the prefix_len
        // doesn't. For example,
        // prefix_len=24 => prefix_size=24 while prefix_len=19 => prefix_size=24
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        let prefix = cur.read_bytes(prefix_size.min(16) as usize)?;
        // Fill the rest of bits with zeros if
        let mut network = [0; 16];
        prefix.iter().enumerate().for_each(|(i, v)| network[i] = *v);
        let addr = Ipv6Addr::from(network);

        match Ipv6Net::new(addr, prefix_len) {
            Ok(net) => Ok(net),
            Err(_) => Err(Ipv6PrefixParsingError::InvalidIpv6PrefixLen {
                offset: prefix_offset,
                prefix_len,
            }),
        }
    }
}

impl<'a> ParseFrom<'a> for Ipv6Net {
    type Error = Ipv6PrefixParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        ParseFromWithTwoInputs::parse(cur, prefix_len, offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum IpAddrParsingError {
    #[error("IP address parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid IP address length `{length}` at offset {offset}")]
    InvalidIpAddressLength { offset: usize, length: u8 },
}

impl<'a> ParseFrom<'a> for IpAddr {
    type Error = IpAddrParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let ip_len = cur.read_u8()?;
        match ip_len {
            IPV4_LEN => {
                let addr = cur.read_u32_be()?;
                Ok(IpAddr::V4(Ipv4Addr::from(addr)))
            }
            IPV6_LEN => {
                let addr = cur.read_u128_be()?;
                Ok(IpAddr::V6(Ipv6Addr::from(addr)))
            }
            _ => Err(IpAddrParsingError::InvalidIpAddressLength {
                offset,
                length: ip_len,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_slash24_octet_aligned() {
        let data = [192, 168, 1];
        let expected = Ok(Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 1, 0), 24));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 24, 0);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv4_slash0_reads_no_bytes() {
        let data: [u8; 0] = [];
        let expected = Ok(Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 0));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 0, 0);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv4_slash32_full_address() {
        let data = [10, 20, 30, 40];
        let expected = Ok(Ipv4Net::new_assert(Ipv4Addr::new(10, 20, 30, 40), 32));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 32, 0);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv4_non_octet_boundary_slash19_consumes_three_bytes() {
        // /19 => 19.div_ceil(8) = 3 bytes; the 4th byte must stay unread.
        let data = [10, 0, 32, 0xFF];
        let expected = Ok(Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 32, 0), 19));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 19, 0);

        assert_eq!(parsed, expected);
        assert_eq!(r.as_slice(), &[0xFF]);
    }

    #[test]
    fn ipv4_prefix_len_out_of_range() {
        // Needs >= 4 bytes so the read succeeds and Ipv4Net::new is what rejects.
        let data = [1, 2, 3, 4, 5];
        let expected = Err(Ipv4PrefixParsingError::InvalidIpv4PrefixLen {
            offset: 7,
            prefix_len: 33,
        });

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 33, 7);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv4_truncated_body() {
        let data = [192, 168]; // /24 needs 3 bytes, only 2 present
        let expected = Err(Ipv4PrefixParsingError::Parse(ParseError::eof(0, 3, 2)));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 24, 0);

        eprintln!("E: {}", expected.clone().unwrap_err());
        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv4_parsefrom_reads_len_then_body() {
        let data = [24, 192, 168, 1];
        let expected = Ok(Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 1, 0), 24));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
        assert_eq!(r.offset(), 4); // 1 length byte + 3 body bytes
    }

    #[test]
    fn ipv4_parsefrom_consumes_only_its_own_entry() {
        // NLRI-loop semantics: the next entry stays intact for the caller.
        let data = [16, 10, 1, /* next entry: */ 8, 172];
        let expected = Ok(Ipv4Net::new_assert(Ipv4Addr::new(10, 1, 0, 0), 16));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv4Net as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
        assert_eq!(r.as_slice(), &[8, 172]);
    }

    #[test]
    fn ipv6_slash64_consumes_eight_bytes() {
        let data = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0xFF];
        let expected = Ok(Ipv6Net::new_assert(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            64,
        ));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv6Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 64, 0);

        assert_eq!(parsed, expected);
        assert_eq!(r.as_slice(), &[0xFF]);
    }

    #[test]
    fn ipv6_slash128_full_address() {
        let data = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let expected = Ok(Ipv6Net::new_assert(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            128,
        ));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv6Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 128, 0);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv6_slash0_reads_no_bytes() {
        let data: [u8; 0] = [];
        let expected = Ok(Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 0));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv6Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 0, 0);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv6_prefix_len_out_of_range() {
        let data = [0u8; 16];
        let expected = Err(Ipv6PrefixParsingError::InvalidIpv6PrefixLen {
            offset: 3,
            prefix_len: 129,
        });

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv6Net as ParseFromWithTwoInputs<'_, u8, usize>>::parse(&mut r, 129, 3);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipv6_parsefrom_reads_len_then_body() {
        let data = [64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0];
        let expected = Ok(Ipv6Net::new_assert(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            64,
        ));

        let mut r = SliceReader::new(&data);
        let parsed = <Ipv6Net as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
        assert_eq!(r.offset(), 9); // 1 + 8
    }

    #[test]
    fn ipaddr_v4() {
        let data = [4, 10, 0, 0, 1];
        let expected = Ok(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut r = SliceReader::new(&data);
        let parsed = <IpAddr as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
        assert_eq!(r.offset(), 5);
    }

    #[test]
    fn ipaddr_v6() {
        let data = [
            16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let expected = Ok(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));

        let mut r = SliceReader::new(&data);
        let parsed = <IpAddr as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
        assert_eq!(r.offset(), 17);
    }

    #[test]
    fn ipaddr_invalid_length_tag() {
        let data = [5, 1, 2, 3, 4, 5]; // 5 is neither 4 nor 16
        let expected = Err(IpAddrParsingError::InvalidIpAddressLength {
            offset: 0,
            length: 5,
        });

        let mut r = SliceReader::new(&data);
        let parsed = <IpAddr as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ipaddr_v4_truncated_body() {
        let data = [4, 10, 0]; // claims v4 but only 2 address bytes follow
        let expected = Err(IpAddrParsingError::Parse(ParseError::eof(1, 4, 2)));

        let mut r = SliceReader::new(&data);
        let parsed = <IpAddr as ParseFrom<'_>>::parse(&mut r);

        assert_eq!(parsed, expected);
    }
}
