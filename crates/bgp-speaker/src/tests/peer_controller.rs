// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::events::BgpEvent;
use crate::fsm::FsmState;
use crate::peer::*;
use crate::peer_controller::PeerController;
use crate::tests::{
    BgpIoMockBuilder, HOLD_TIME, MY_AS, MY_BGP_ID, MockActiveConnect, PEER_ADDR, PEER_AS,
    PEER_BGP_ID, PEER_KEY, POLICY, PROPERTIES,
};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::capabilities::{
    BgpCapability, FourOctetAsCapability, MultiProtocolExtensionsCapability,
};
use netgauze_bgp_pkt::iana::AS_TRANS;
use netgauze_bgp_pkt::notification::{BgpNotificationMessage, CeaseError};
use netgauze_bgp_pkt::open::{BgpOpenMessage, BgpOpenMessageParameter};
use netgauze_iana::address_family::AddressType;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
#[tracing_test::traced_test]
#[allow(clippy::result_large_err)]
async fn test_start_stop()
-> Result<(), mpsc::error::SendError<PeerEvent<SocketAddr, tokio_test::io::Mock>>> {
    let config = PeerConfigBuilder::default().build();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .wait(Duration::from_millis(100))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown {
                value: vec![],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let controller = PeerController::new(PEER_KEY, PROPERTIES, config, tx, POLICY, active_connect);
    let handle = controller.get_new_handle();

    handle.start()?;
    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Connect, BgpEvent::ManualStart)))
    );
    assert_eq!(
        rx.recv().await,
        Some(Ok((
            FsmState::OpenSent,
            BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)
        )))
    );

    handle.shutdown()?;
    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Idle, BgpEvent::ManualStop)))
    );
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
#[allow(clippy::result_large_err)]
async fn test_start_stop_with_passive_tcp()
-> Result<(), mpsc::error::SendError<PeerEvent<SocketAddr, tokio_test::io::Mock>>> {
    let config = PeerConfigBuilder::default()
        .passive_tcp_establishment(true)
        .build();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.wait(Duration::from_secs(1));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let controller = PeerController::new(PEER_KEY, PROPERTIES, config, tx, POLICY, active_connect);
    let handle = controller.get_new_handle();
    handle.start()?;
    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Active, BgpEvent::ManualStartWithPassiveTcp)))
    );

    handle.shutdown()?;
    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Idle, BgpEvent::ManualStop)))
    );
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
#[allow(clippy::result_large_err)]
async fn test_get_exchanged_capabilities()
-> Result<(), mpsc::error::SendError<PeerEvent<SocketAddr, tokio_test::io::Mock>>> {
    let my_asn = 66_000;
    let extended_msg_cap = BgpCapability::ExtendedMessage;
    let route_refresh_cap = BgpCapability::RouteRefresh;
    let enhanced_route_refresh_cap = BgpCapability::EnhancedRouteRefresh;
    let ipv4_unicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
    );
    let ipv4_multicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv4Multicast),
    );
    let ipv6_unicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv6Unicast),
    );
    let ipv6_multicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv6Multicast),
    );

    let pushed_caps = vec![
        route_refresh_cap.clone(),
        extended_msg_cap.clone(),
        ipv6_unicast_cap.clone(),
    ];
    let rejected_caps = vec![
        enhanced_route_refresh_cap.clone(),
        ipv6_multicast_cap.clone(),
    ];
    let policy = EchoCapabilitiesPolicy::new(
        my_asn,
        false,
        MY_BGP_ID,
        HOLD_TIME,
        pushed_caps.clone(),
        rejected_caps.clone(),
    );

    let my_caps = vec![
        BgpCapability::FourOctetAs(FourOctetAsCapability::new(my_asn)),
        route_refresh_cap.clone(),
        extended_msg_cap,
        ipv6_unicast_cap,
    ];

    let peer_caps = vec![
        BgpCapability::FourOctetAs(FourOctetAsCapability::new(PEER_AS)),
        route_refresh_cap.clone(),
        enhanced_route_refresh_cap,
        ipv4_unicast_cap,
        ipv4_multicast_cap,
    ];
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![BgpOpenMessageParameter::Capabilities(peer_caps.clone())],
    );
    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            AS_TRANS,
            HOLD_TIME,
            MY_BGP_ID,
            vec![BgpOpenMessageParameter::Capabilities(my_caps.clone())],
        )))
        .wait(Duration::from_millis(10))
        .read(BgpMessage::Open(peer_open.clone()))
        .wait(Duration::from_secs(1))
        .write(BgpMessage::KeepAlive)
        .wait(Duration::from_millis(100))
        .write(BgpMessage::KeepAlive);
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let config = PeerConfigBuilder::new().build();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let peer_controller =
        PeerController::new(PEER_KEY, PROPERTIES, config, tx, policy, active_connect);

    let mut handle = peer_controller.get_new_handle();

    let sent_caps = handle.connection_sent_capabilities().await.unwrap();
    let recv_caps = handle.connection_received_capabilities().await.unwrap();
    assert_eq!(sent_caps, None);
    assert_eq!(recv_caps, None);

    handle.start()?;

    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Connect, BgpEvent::ManualStart)))
    );

    assert_eq!(
        rx.recv().await,
        Some(Ok((
            FsmState::OpenSent,
            BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)
        )))
    );

    let sent_caps = handle.connection_sent_capabilities().await.unwrap();
    let recv_caps = handle.connection_received_capabilities().await.unwrap();
    assert_eq!(sent_caps, Some(my_caps.clone()));
    assert_eq!(recv_caps, None);

    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::OpenConfirm, BgpEvent::BGPOpen(peer_open))))
    );

    let sent_caps = handle.connection_sent_capabilities().await.unwrap();
    let recv_caps = handle.connection_received_capabilities().await.unwrap();
    assert_eq!(sent_caps, Some(my_caps));
    assert_eq!(recv_caps, Some(peer_caps));

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
#[allow(clippy::result_large_err)]
async fn test_get_exchanged_capabilities_tracked_connection()
-> Result<(), mpsc::error::SendError<PeerEvent<SocketAddr, tokio_test::io::Mock>>> {
    let my_asn = 66_000;
    let extended_msg_cap = BgpCapability::ExtendedMessage;
    let route_refresh_cap = BgpCapability::RouteRefresh;
    let enhanced_route_refresh_cap = BgpCapability::EnhancedRouteRefresh;
    let ipv4_unicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
    );
    let ipv4_multicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv4Multicast),
    );
    let ipv6_unicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv6Unicast),
    );
    let ipv6_multicast_cap = BgpCapability::MultiProtocolExtensions(
        MultiProtocolExtensionsCapability::new(AddressType::Ipv6Multicast),
    );

    let pushed_caps = vec![
        route_refresh_cap.clone(),
        extended_msg_cap.clone(),
        ipv6_unicast_cap.clone(),
    ];
    let rejected_caps = vec![
        enhanced_route_refresh_cap.clone(),
        ipv6_multicast_cap.clone(),
    ];
    let my_caps = vec![
        BgpCapability::FourOctetAs(FourOctetAsCapability::new(my_asn)),
        route_refresh_cap.clone(),
        extended_msg_cap,
        ipv6_unicast_cap,
    ];

    let peer_caps = vec![
        BgpCapability::FourOctetAs(FourOctetAsCapability::new(PEER_AS)),
        route_refresh_cap.clone(),
        enhanced_route_refresh_cap,
        ipv4_unicast_cap,
        ipv4_multicast_cap,
    ];
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![BgpOpenMessageParameter::Capabilities(peer_caps.clone())],
    );

    let policy = EchoCapabilitiesPolicy::new(
        my_asn,
        false,
        MY_BGP_ID,
        HOLD_TIME,
        pushed_caps.clone(),
        rejected_caps.clone(),
    );
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            AS_TRANS,
            HOLD_TIME,
            MY_BGP_ID,
            vec![BgpOpenMessageParameter::Capabilities(my_caps.clone())],
        )))
        .wait(Duration::from_millis(100))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            AS_TRANS,
            HOLD_TIME,
            MY_BGP_ID,
            vec![BgpOpenMessageParameter::Capabilities(my_caps.clone())],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .wait(Duration::from_millis(100))
        .read(BgpMessage::KeepAlive);
    let config = PeerConfigBuilder::new().build();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let peer_controller =
        PeerController::new(PEER_KEY, PROPERTIES, config, tx, policy, active_connect);

    let mut handle = peer_controller.get_new_handle();
    handle.start()?;

    let sent_caps = handle.tracked_connection_sent_capabilities().await.unwrap();
    let recv_caps = handle
        .tracked_connection_received_capabilities()
        .await
        .unwrap();
    assert_eq!(sent_caps, None);
    assert_eq!(recv_caps, None);

    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Connect, BgpEvent::ManualStart)))
    );
    assert_eq!(
        rx.recv().await,
        Some(Ok((
            FsmState::OpenSent,
            BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)
        )))
    );

    let sent_caps = handle.tracked_connection_sent_capabilities().await.unwrap();
    let recv_caps = handle
        .tracked_connection_received_capabilities()
        .await
        .unwrap();
    assert_eq!(sent_caps, None);
    assert_eq!(recv_caps, None);

    handle.accept_connection(passive_addr, passive_io_builder.build())?;
    assert_eq!(
        rx.recv().await,
        Some(Ok((
            FsmState::OpenSent,
            BgpEvent::TcpConnectionConfirmed(passive_addr)
        )))
    );

    let sent_caps = handle.tracked_connection_sent_capabilities().await.unwrap();
    let recv_caps = handle
        .tracked_connection_received_capabilities()
        .await
        .unwrap();
    assert_eq!(sent_caps, Some(my_caps.clone()));
    assert_eq!(recv_caps, Some(peer_caps.clone()));

    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::OpenConfirm, BgpEvent::OpenCollisionDump)))
    );

    assert_eq!(
        rx.recv().await,
        Some(Ok((FsmState::Established, BgpEvent::KeepAliveMsg)))
    );
    Ok(())
}
