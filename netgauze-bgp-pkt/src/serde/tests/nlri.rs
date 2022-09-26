// Copyright (C) 2022-present The NetGauze Authors.
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

use crate::{
    nlri::{
        InvalidIpv4MulticastNetwork, InvalidIpv4UnicastNetwork, InvalidIpv6MulticastNetwork,
        InvalidIpv6UnicastNetwork, Ipv4Multicast, Ipv4Unicast, Ipv6Multicast, Ipv6Unicast,
    },
    serde::{
        deserializer::nlri::{
            Ipv4MulticastParsingError, Ipv4UnicastParsingError, Ipv6MulticastParsingError,
            Ipv6UnicastParsingError, LocatedIpv4MulticastParsingError,
            LocatedIpv4UnicastParsingError, LocatedIpv6MulticastParsingError,
            LocatedIpv6UnicastParsingError,
        },
        serializer::nlri::{
            Ipv4MulticastWritingError, Ipv4UnicastWritingError, Ipv6MulticastWritingError,
            Ipv6UnicastWritingError,
        },
    },
};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_parse_utils::{
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
    Span,
};
use std::str::FromStr;

#[test]
fn test_ipv6_unicast() -> Result<(), Ipv6UnicastWritingError> {
    let good_wire = [0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];
    let bad_multicast_wire = [0x40, 0xff, 0x00, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];

    let unicast_net = Ipv6Net::from_str("2001:db8:2::/64").unwrap();
    let multicast_net = Ipv6Net::from_str("ff00:db8:2::/64").unwrap();
    let good = Ipv6Unicast::from_net(unicast_net).unwrap();
    let bad_multicast = LocatedIpv6UnicastParsingError::new(
        Span::new(&bad_multicast_wire),
        Ipv6UnicastParsingError::InvalidUnicastNetwork(InvalidIpv6UnicastNetwork(multicast_net)),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv6Unicast, LocatedIpv6UnicastParsingError<'_>>(
        &bad_multicast_wire,
        &bad_multicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv6_multicast() -> Result<(), Ipv6MulticastWritingError> {
    let good_wire = [0x40, 0xff, 0x00, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];
    let bad_unicast_wire = [0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];

    let unicast_net = Ipv6Net::from_str("2001:db8:2::/64").unwrap();
    let multicast_net = Ipv6Net::from_str("ff00:db8:2::/64").unwrap();
    let good = Ipv6Multicast::from_net(multicast_net).unwrap();
    let bad_unicast = LocatedIpv6MulticastParsingError::new(
        Span::new(&bad_unicast_wire),
        Ipv6MulticastParsingError::InvalidMulticastNetwork(InvalidIpv6MulticastNetwork(
            unicast_net,
        )),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv6Multicast, LocatedIpv6MulticastParsingError<'_>>(
        &bad_unicast_wire,
        &bad_unicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_unicast() -> Result<(), Ipv4UnicastWritingError> {
    let good_wire = [24, 192, 168, 56];
    let bad_multicast_wire = [24, 224, 0, 0];

    let unicast_net = Ipv4Net::from_str("192.168.56.0/24").unwrap();
    let multi_net = Ipv4Net::from_str("224.0.0.0/24").unwrap();
    let good = Ipv4Unicast::from_net(unicast_net).unwrap();
    let bad_multicast = LocatedIpv4UnicastParsingError::new(
        Span::new(&bad_multicast_wire),
        Ipv4UnicastParsingError::InvalidUnicastNetwork(InvalidIpv4UnicastNetwork(multi_net)),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv4Unicast, LocatedIpv4UnicastParsingError<'_>>(
        &bad_multicast_wire,
        &bad_multicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_multicast() -> Result<(), Ipv4MulticastWritingError> {
    let good_wire = [24, 224, 0, 0];
    let bad_unicast_wire = [24, 192, 168, 56];

    let unicast_net = Ipv4Net::from_str("192.168.56.0/24").unwrap();
    let multicast_net = Ipv4Net::from_str("224.0.0.0/24").unwrap();
    let good = Ipv4Multicast::from_net(multicast_net).unwrap();
    let bad_unicast = LocatedIpv4MulticastParsingError::new(
        Span::new(&bad_unicast_wire),
        Ipv4MulticastParsingError::InvalidMulticastNetwork(InvalidIpv4MulticastNetwork(
            unicast_net,
        )),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv4Multicast, LocatedIpv4MulticastParsingError<'_>>(
        &bad_unicast_wire,
        &bad_unicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}
