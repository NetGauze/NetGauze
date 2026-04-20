use crate::WritablePdu;
use crate::error::ParseError;
use crate::reader::BytesReader;
use crate::traits::{ParseFrom, ParseFromWithTwoInputs};
use crate::writer::WriteTo;
use bytes::BufMut;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const IPV4_LEN: u8 = 4;
pub(crate) const IPV6_LEN: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4PrefixParsingError {
    #[error("IPv4 parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Invalid prefix length `{prefix_len}` for IPv4 prefix, must be in the range [0, 32]")]
    InvalidIpv4PrefixLen { offset: usize, prefix_len: u8 },
}

impl<'a> ParseFromWithTwoInputs<'a, u8, usize> for Ipv4Net {
    type Error = Ipv4PrefixParsingError;

    fn parse(
        cur: &mut BytesReader,
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

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        ParseFromWithTwoInputs::parse(cur, prefix_len, offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6PrefixParsingError {
    #[error("IPv6 parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error(
        "Invalid IPv6 prefix length `{prefix_len}` for IPv6 prefix, must be in the range [0, 128]"
    )]
    InvalidIpv6PrefixLen { offset: usize, prefix_len: u8 },
}

impl<'a> ParseFromWithTwoInputs<'a, u8, usize> for Ipv6Net {
    type Error = Ipv6PrefixParsingError;

    fn parse(
        cur: &mut BytesReader,
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

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        ParseFromWithTwoInputs::parse(cur, prefix_len, offset)
    }
}

// #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize,
// Deserialize)] pub enum Ipv6NetWritingError {
//     #[error("std::io::Error: {0}")]
//     StdIOError(String),
// }
//
// impl From<std::io::Error> for Ipv6NetWritingError {
//     fn from(err: std::io::Error) -> Self {
//         Self::StdIOError(err.to_string())
//     }
// }
//
// impl WriteTo for IpAddr {
//     type Error = IpAddrWritingError;
//
//     fn wire_len(&self) -> Ipv6Net {
//         let len = match self {
//             IpAddr::V4(_) => IPV4_LEN,
//             IpAddr::V6(_) => IPV6_LEN,
//         };
//         len as usize
//     }
//
//     fn write_to<W: BufMut>(&self, buf: &mut W) -> Result<(), Self::Error> {
//         match self {
//             IpAddr::V4(value) => {
//                 buf.writer().write_all(&[IPV4_LEN])?;
//                 buf.writer().write_all(&value.octets())?;
//             }
//             IpAddr::V6(value) => {
//                 buf.writer().write_all(&[IPV6_LEN])?;
//                 buf.writer().write_all(&value.octets())?;
//             }
//         }
//         Ok(())
//     }
// }

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum IpAddrParsingError {
    #[error("IP address parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Invalid IP address type `{addr_type}` at offset {offset}")]
    InvalidIpAddressType { offset: usize, addr_type: u8 },
    #[error("Invalid IP address length `{length}` at offset {offset}")]
    InvalidIpAddressLength { offset: usize, length: u8 },
}

impl<'a> ParseFrom<'a> for IpAddr {
    type Error = IpAddrParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum IpAddrWritingError {
    #[error("std::io::Error: {0}")]
    StdIOError(String),
}

impl From<std::io::Error> for IpAddrWritingError {
    fn from(err: std::io::Error) -> Self {
        IpAddrWritingError::StdIOError(err.to_string())
    }
}

impl WriteTo for IpAddr {
    type Error = IpAddrWritingError;

    fn wire_len(&self) -> usize {
        let len = match self {
            IpAddr::V4(_) => IPV4_LEN,
            IpAddr::V6(_) => IPV6_LEN,
        };
        len as usize
    }

    fn write_to<W: BufMut>(&self, buf: &mut W) -> Result<(), Self::Error> {
        match self {
            IpAddr::V4(value) => {
                buf.writer().write_all(&[IPV4_LEN])?;
                buf.writer().write_all(&value.octets())?;
            }
            IpAddr::V6(value) => {
                buf.writer().write_all(&[IPV6_LEN])?;
                buf.writer().write_all(&value.octets())?;
            }
        }
        Ok(())
    }
}

impl WritablePdu<IpAddrWritingError> for IpAddr {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        self.wire_len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), IpAddrWritingError> {
        match self {
            Self::V4(value) => {
                writer.write_all(&[IPV4_LEN])?;
                writer.write_all(&value.octets())?;
            }
            Self::V6(value) => {
                writer.write_all(&[IPV6_LEN])?;
                writer.write_all(&value.octets())?;
            }
        }
        Ok(())
    }
}
