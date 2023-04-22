# NetGauze BGP Pkt

BGP-4 Protocol representation and wire format serialization/deserialization (serde)

## Overview

NetGauze BGP Pkt is library to represent BGP-4 Packets. It aims to achieve 4 goals

1. Extensive support for the various BGP related RFCs.
   See [Supported BGP-4 Protocol features](#Supported-BGP-Protocol-features).
2. Rust native representation of BGP protocol that makes it hard to construct an incorrect BGP packet. We achieve that
   by heavily relying on the rich type system provided by Rust.
3. Native BGP wire-protocol Serializing/deserialization (serde) is optional. In addition to support the
   well-known [serde](https://crates.io/crates/serde) library This to make this library useful for building wider range
   of applications.
4. Extensive testing. This includes testing using unit tests extracted from real packets traces and fuzzing.

## Example

To run example: `cargo run --example bgp`

```rust
use std::io::Cursor;
use std::net::Ipv4Addr;

use netgauze_bgp_pkt::capabilities::*;
use netgauze_bgp_pkt::open::*;
use netgauze_bgp_pkt::*;
use netgauze_iana::address_family::*;
use netgauze_parse_utils::{ReadablePDUWithOneInput, Span, WritablePDU};

pub fn main() {
    // Construct a new BGP message
    let msg = BgpMessage::Open(BgpOpenMessage::new(
        100,
        180,
        Ipv4Addr::new(5, 5, 5, 5),
        vec![
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4MplsLabeledVpn),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::RouteRefresh]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                FourOctetAsCapability::new(100),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::ExtendedNextHopEncoding(
                ExtendedNextHopEncodingCapability::new(vec![
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Multicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(
                        AddressType::Ipv4MplsLabeledVpn,
                        AddressFamily::IPv6,
                    ),
                ]),
            )]),
        ],
    ));

    println!("JSON representation of BGP packet: {}", serde_json::to_string(&msg).unwrap());

    // Serialize the message into it's BGP binary format
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    msg.write(&mut cursor).unwrap();
    assert_eq!(
        buf,
        vec![
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 83,
            1, 4, 0, 100, 0, 180, 5, 5, 5, 5, 54, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 128,
            2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 0, 100, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0,
            1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2
        ]
    );

    // Deserialize the message from binary format
    let (_, msg_back) = BgpMessage::from_wire(Span::new(&buf), true).unwrap();
    assert_eq!(msg, msg_back);
}
```

## Supported BGP Protocol features

### Supported message types

| Message Type | RFCs                                                                                                                    | notes                                         |
|--------------|-------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| Open         | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | See below for the supported capabilities      |
| Update       | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | See below for the supported path attributes   |
| Notification | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | See below for the supported notif sub-codes   |
| KeepAlive    | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               |                                               |
| RouteRefresh | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) and [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313) | See below for the supported Route refresh ops |

### Supported Capabilities In BGP Open message

| Capability                       | RFCs                                                      | Notes                                                                                       |
|----------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------|
| MultiProtocolExtensions (MP-BGP) | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) | See MP-BGP supported address families below                                                 |
| RouteRefresh                     | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) |                                                                                             |
| EnhancedRouteRefresh             | [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313) |                                                                                             |
| Add Path                         | [RFC 7911](https://datatracker.ietf.org/doc/html/RFC7911) |                                                                                             |
| Extended Message                 | [RFC 8654](https://datatracker.ietf.org/doc/html/RFC8654) |                                                                                             |
| Four Octet AS Number             | [RFC 6793](https://datatracker.ietf.org/doc/html/RFC6793) |                                                                                             |
| Extended Next Hop Encoding       | [RFC 8950](https://datatracker.ietf.org/doc/html/rfc8950) |                                                                                             |
| Multiple Labels                  | [RFC 8277](https://datatracker.ietf.org/doc/html/rfc8277) |                                                                                             |
| Experimental                     | [RFC 8810](https://datatracker.ietf.org/doc/html/RFC8810) | Capabilities with codes 239-254 are marked as experimental, we read their values as Vec<u8> |
| Unrecognized                     | [RFC 5492](https://datatracker.ietf.org/doc/html/rfc5492) | We carry the capability code and the `u8` vector for it's value                             |

### Supported Path Attributes In BGP Update message

| Path Attribute               | RFCs                                                                                                                    | Well-known | Optional | transitive | Notes                                                              |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------|------------|----------|------------|--------------------------------------------------------------------|
| Origin                       | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | Yes        | No       | Yes        |                                                                    |
| AS_PATH                      | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) and [RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793) | Yes        | No       | Yes        |                                                                    |
| NEXT_HOP                     | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | Yes        | No       | Yes        |                                                                    |
| MultiExitDiscriminator (MED) | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | Yes        | Yes      | No         |                                                                    |
| Local Preference (LocalPref) | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | Yes        |          | Yes        |                                                                    |
| Atomic Aggregate             | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | Yes        | Yes      | Yes        |                                                                    |
| Aggregator                   | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | Yes        | Yes      | Yes        |                                                                    |
| Communities                  | [RFC 1997](https://datatracker.ietf.org/doc/html/rfc1997)                                                               | No         | Yes      | Yes        |                                                                    |
| Extended Communities         | [RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360)                                                               | No         | Yes      | Yes        |                                                                    |
| Extended Communities IPv6    | [RFC 5701](https://datatracker.ietf.org/doc/html/rfc5701)                                                               | No         | Yes      | Yes        |                                                                    |
| Large Communities            | [RFC 8092](https://datatracker.ietf.org/doc/html/rfc8092)                                                               | No         | Yes      | Yes        |                                                                    |
| Route Reflection             | [RFC 4456](https://datatracker.ietf.org/doc/html/rfc4456)                                                               | No         | Yes      | No         |                                                                    |
| Four Octet AS_PATH           | [RFC 6793](https://datatracker.ietf.org/doc/html/RFC6793)                                                               | No         | Yes      | Yes        |                                                                    |
| MP_REACH_NLRI                | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760)                                                               | No         | Yes      | No         |                                                                    |
| MP_UNREACH_NLRI              | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760)                                                               | No         | Yes      | No         |                                                                    |
| UnknownAttribute             |                                                                                                                         | N/A        | N/A      | N/A        | Catch all attribute that will read and keep the value as a Vec<u8> |

### MP-BGP supported address families

| RFC                                                                                                                    | Address Family (AFI) | Subsequence Address Family (SAFI) | Notes                                   |
|------------------------------------------------------------------------------------------------------------------------|----------------------|-----------------------------------|-----------------------------------------|
|                                                                                                                        | 1 = IPv4             | 1 = Unicast                       |                                         |
|                                                                                                                        | 1 = IPv4             | 2 = Multicast                     |                                         |
| [RFC 8277](https://datatracker.ietf.org/doc/html/RFC8277)                                                              | 1 = IPv4             | 4 = MPLS Labeled Unicast          | NLRI with MPLS Labels                   |
| [RFC 4364](https://datatracker.ietf.org/doc/html/RFC4364)                                                              | 1 = IPv4             | 128 = MPLS Labeled Unicast        |                                         |
| [RFC 4684](https://datatracker.ietf.org/doc/html/RFC4684)                                                              | 1 = IPv4             | 132 = Route Target constrains     |                                         |
|                                                                                                                        | 2 = IPv6             | 1 = Unicast                       |                                         |
|                                                                                                                        | 2 = IPv6             | 2 = Multicast                     |                                         |
| [RFC 8277](https://datatracker.ietf.org/doc/html/RFC8277)                                                              | 2 = IPv6             | 4 = MPLS Labeled Unicast          | NLRI with MPLS Labels                   |
| [RFC 4659](https://datatracker.ietf.org/doc/html/RFC4659)                                                              | 2 = IPv4             | 128 = MPLS Labeled Unicast        |                                         |
| [RFC 7432](https://datatracker.ietf.org/doc/html/RFC7432) and [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136) | 25 = L2 VPN          | 70 = BGP EVPNs                    | Route types from 1 till 5 are supported |

# Development documentation

*Running Packet Serde benchmarks*
```cargo bench --features bench```
