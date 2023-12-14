use std::{
    collections::HashMap,
    io,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use netgauze_bgp_pkt::{
    iana::RouteRefreshSubcode,
    notification::{
        HoldTimerExpiredError, MessageHeaderError, OpenMessageError, UpdateMessageError,
    },
    BgpMessage,
};

use netgauze_bgp_pkt::{
    notification::{FiniteStateMachineError, *},
    open::{BgpOpenMessage, BgpOpenMessageParameter::Capabilities},
    route_refresh::BgpRouteRefreshMessage,
    update::BgpUpdateMessage,
};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::WritablePdu;

use crate::{events::*, fsm::*, peer::*, test::*};

const MY_AS: u32 = 100;
const PEER_AS: u32 = 200;
const HOLD_TIME: u16 = 180;
const MY_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

const PEER_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);
const PEER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)), 179);

const PROPERTIES: PeerProperties<SocketAddr> = PeerProperties::new(
    MY_AS,
    PEER_AS,
    MY_BGP_ID,
    PEER_BGP_ID,
    PEER_ADDR,
    false,
    false,
);

#[test_log::test(tokio::test)]
async fn test_idle_manual_start() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new().build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();

    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_idle_manual_start_with_passive_tcp() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();

    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_idle_automatic_start() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new().build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = peer.run().await.unwrap();

    assert_eq!(event, BgpEvent::AutomaticStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_idle_automatic_start_with_passive() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);

    assert_eq!(peer.fsm_state(), FsmState::Idle);
    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::AutomaticStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_connect_manual_start() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    // Start should be ignored
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Connect);
}

#[test_log::test(tokio::test)]
async fn test_connect_automatic_start() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::AutomaticStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    // Start should be ignored
    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = peer.run().await.unwrap();
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Connect);
}

#[test_log::test(tokio::test)]
async fn test_connect_manual_stop() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Notification(
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] }),
    ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();

    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    // Check start is correct
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    // Check active connection is established
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    // Check ManualStop
    peer.add_admin_event(PeerAdminEvents::ManualStop);
    let event = peer.run().await.unwrap();
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(event, BgpEvent::ManualStop);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_connect_retry_timer_expires() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Notification(
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] }),
    ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(10),
    };
    let config = PeerConfigBuilder::new()
        .connect_retry_duration(1)
        .open_delay_timer_duration(3)
        .build();

    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    // Check start is correct
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ConnectRetryTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_connect_delay_open_timer_expires() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .wait(Duration::from_secs(1))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = tokio::time::timeout(
        Duration::from_secs(delay_open_duration as u64 + 1),
        peer.run(),
    )
    .await;
    assert_eq!(event, Ok(Ok(BgpEvent::DelayOpenTimerExpires)));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);

    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_none());
    assert!(conn.hold_timer().is_some());
    assert_eq!(
        conn.hold_timer_duration().as_secs(),
        peer.config().hold_timer_duration_large_value as u64
    );
}

#[test_log::test(tokio::test)]
async fn test_connect_tcp_connection_confirmed() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(10),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(0)
        .build();

    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    // Check start is correct
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));

    // Check active connection is established
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_none());
    assert!(conn.hold_timer().is_some());
    assert_eq!(
        conn.hold_timer_duration(),
        peer.config().hold_timer_duration_large_value()
    );
}

#[test_log::test(tokio::test)]
async fn test_connect_tcp_connection_confirmed_with_open_delay() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(10),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();

    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    // Check start is correct
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));

    // Check active connection is established
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_some())
}

#[test_log::test(tokio::test)]
async fn test_connect_tcp_connection_fails() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_connect = MockFailedActiveConnect {
        peer_addr: PEER_ADDR,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(0)
        .build();

    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    // Check start is correct
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionFails);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_connect_tcp_connection_fails_with_open_delay_timer() {
    // TODO
}

#[test_log::test(tokio::test)]
async fn test_connect_bgp_open_with_delay() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );

    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .wait(Duration::from_millis(10))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .write(BgpMessage::KeepAlive);
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = tokio::time::timeout(
        Duration::from_secs(delay_open_duration as u64 + 1),
        peer.run(),
    )
    .await;
    assert_eq!(
        event,
        Ok(Ok(BgpEvent::BGPOpenWithDelayOpenTimer(peer_open)))
    );
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_none());
    assert_eq!(conn.hold_timer_duration().as_secs(), HOLD_TIME as u64);
    assert!(conn.hold_timer().is_some())
}

#[test_log::test(tokio::test)]
async fn test_connect_tcp_cr_acked() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_bgp_header_err() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    let bad_header = [0xee; 16];
    io_builder
        .read_u8(&bad_header) // Malformed header
        .read_u8(&[0x00, 0x13, 0x04]) // Keep alive message body
        .write(BgpMessage::Notification(
            BgpNotificationMessage::MessageHeaderError(
                MessageHeaderError::ConnectionNotSynchronized {
                    value: Vec::from(&bad_header),
                },
            ),
        ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::BGPHeaderErr(
            MessageHeaderError::ConnectionNotSynchronized {
                value: Vec::from(&bad_header)
            }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_bgp_open_err() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    let bgp_version = 0x03;
    io_builder
        .read_u8(&[0xff; 16]) // BGP Standard header
        .read_u8(&[0x00, 0x14]) // Length
        .read_u8(&[0x01]) // Message type = open
        .read_u8(&[bgp_version])
        .write(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version],
            }),
        ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::BGPOpenMsgErr(
            OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version]
            }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[ignore]
#[test_log::test(tokio::test)]
async fn test_connect_notif_version_err() {
    // TODO: hard to do since without open delay peer will immediately send
    // a BGP Open and transition to OpenSent state
}

#[test_log::test(tokio::test)]
async fn test_connect_notif_version_err_with_open_delay() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.read(BgpMessage::Notification(
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![3],
        }),
    ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsgVerErr));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_automatic_stop() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Notification(
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] }),
    ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    peer.add_admin_event(PeerAdminEvents::AutomaticStop);
    let event = peer.run().await;

    assert_eq!(event, Ok(BgpEvent::AutomaticStop));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[ignore]
#[test_log::test(tokio::test)]
async fn test_connect_hold_timer_expires() {
    // TODO: this sound like impossible to test since a BGP message is sent
    // and state is transitioned to OpenSent
}

#[test_log::test(tokio::test)]
async fn test_connect_notif_msg() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    io_builder.read(BgpMessage::Notification(notif.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsg(notif)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_keepalive_msg() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.read(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::KeepAliveMsg));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_update_msg() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    io_builder.read(BgpMessage::Update(update.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::UpdateMsg(update)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_update_err_msg() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    let update = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x19, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    io_builder.read_u8(&update);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::UpdateMsgErr(
            UpdateMessageError::InvalidNetworkField { value: vec![] }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_route_refresh_msg() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    let route_refresh = BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::BeginningOfRouteRefresh,
    );
    io_builder.read(BgpMessage::RouteRefresh(route_refresh.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .send_notif_without_open(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::RouteRefresh(route_refresh)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_manual_start() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);
    // // Start should be ignored
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = tokio::time::timeout(Duration::from_millis(1), peer.run()).await;
    // since manual start is ignored, and no connection is added, no more new events
    // should be returned by run
    assert!(event.is_err());
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connect_retry_timer().is_some());
}

#[test_log::test(tokio::test)]
async fn test_active_automatic_start() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);
    // // Start should be ignored
    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = tokio::time::timeout(Duration::from_millis(1), peer.run()).await;
    // since start is ignored, and no connection is added, no more new events should
    // be returned by run
    assert!(event.is_err());
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connect_retry_timer().is_some());
}

#[test_log::test(tokio::test)]
async fn test_active_connect_retry_timer_expires() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let io_builder = BgpIoMockBuilder::new();

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ConnectRetryTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Connect);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_some());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
}

#[test_log::test(tokio::test)]
async fn test_active_delay_open_timer_expires() {
    let open_delay = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(open_delay)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_some());

    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::DelayOpenTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connect_retry_timer().is_none());
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_none());
    assert!(conn.hold_timer().is_some());
    assert_eq!(
        conn.hold_timer_duration().as_secs(),
        peer.config().hold_timer_duration_large_value as u64
    );
}

#[test_log::test(tokio::test)]
async fn test_active_tcp_connection_confirmed() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(0)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.hold_timer().is_some());
    assert_eq!(
        conn.hold_timer_duration().as_secs(),
        peer.config().hold_timer_duration_large_value as u64
    );
}

#[test_log::test(tokio::test)]
async fn test_active_tcp_connection_confirmed_with_open_delay() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_some());
}

#[test_log::test(tokio::test)]
async fn test_active_tcp_connection_fails() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let passive_io = tokio_test::io::Builder::new()
        .read_error(io::Error::from(io::ErrorKind::ConnectionAborted))
        .build();

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR, passive_io,
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_some());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionFails);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_active_bgp_open_with_open_delay() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .wait(Duration::from_millis(10))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .write(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_some());

    let event = tokio::time::timeout(
        Duration::from_secs(delay_open_duration as u64 + 1),
        peer.run(),
    )
    .await;
    assert_eq!(
        event,
        Ok(Ok(BgpEvent::BGPOpenWithDelayOpenTimer(peer_open)))
    );
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    let conn = peer.connection().unwrap();
    assert!(conn.open_delay_timer().is_none());
    assert_eq!(conn.hold_timer_duration().as_secs(), 0);
    assert!(conn.hold_timer().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_bgp_header_err() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    let bad_header = [0xee; 16];
    passive_io_builder
        .read_u8(&bad_header) // Malformed header
        .read_u8(&[0x00, 0x13, 0x04]) // Keep alive message body
        .write(BgpMessage::Notification(
            BgpNotificationMessage::MessageHeaderError(
                MessageHeaderError::ConnectionNotSynchronized {
                    value: Vec::from(&bad_header),
                },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::BGPHeaderErr(
            MessageHeaderError::ConnectionNotSynchronized {
                value: Vec::from(&bad_header)
            }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_bgp_open_err() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    let bgp_version = 0x03;
    passive_io_builder
        .read_u8(&[0xff; 16]) // BGP Standard header
        .read_u8(&[0x00, 0x14]) // Length
        .read_u8(&[0x01]) // Message type = open
        .read_u8(&[bgp_version])
        .write(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::BGPOpenMsgErr(
            OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version]
            }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[ignore]
#[test_log::test(tokio::test)]
async fn test_active_notif_version_err() {
    // TODO: hard to do since without open delay peer will immediately send
    // a BGP Open and transition to OpenSent state
}

#[test_log::test(tokio::test)]
async fn test_active_notif_version_err_with_open_delay() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    let bgp_version = 0x03;
    passive_io_builder.read(BgpMessage::Notification(
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![bgp_version],
        }),
    ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsgVerErr));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_automatic_stop() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Notification(
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] }),
    ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::AutomaticStop);
    let event = peer.run().await;

    assert_eq!(event, Ok(BgpEvent::AutomaticStop));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_notif_msg() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.read(BgpMessage::Notification(notif.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;

    assert_eq!(event, Ok(BgpEvent::NotifMsg(notif)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_keepalive_msg() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.read(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;

    assert_eq!(event, Ok(BgpEvent::KeepAliveMsg));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_update_msg() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.read(BgpMessage::Update(update.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::UpdateMsg(update)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_update_err_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let update = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x19, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.read_u8(&update);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await?;

    assert_eq!(
        event,
        BgpEvent::UpdateMsgErr(UpdateMessageError::InvalidNetworkField { value: vec![] })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_active_route_refresh_msg() {
    let delay_open_duration = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());

    let active_io_builder = BgpIoMockBuilder::new();
    let route_refresh = BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::BeginningOfRouteRefresh,
    );
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.read(BgpMessage::RouteRefresh(route_refresh.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .connect_retry_duration(1)
        .passive_tcp_establishment(true)
        .hold_timer_duration(0)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    assert_eq!(peer.fsm_state(), FsmState::Idle);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStartWithPassiveTcp);
    assert_eq!(peer.fsm_state(), FsmState::Active);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR,
        passive_io_builder.build(),
    )));
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Active);

    let event = peer.run().await;

    assert_eq!(event, Ok(BgpEvent::RouteRefresh(route_refresh)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_open_sent_manual_stop() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
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
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    peer.add_admin_event(PeerAdminEvents::ManualStop);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStop));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connect_retry_timer().is_none());
}

#[test_log::test(tokio::test)]
async fn test_open_sent_automatic_stop() {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
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
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    peer.add_admin_event(PeerAdminEvents::AutomaticStop);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::AutomaticStop));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
}

#[test_log::test(tokio::test)]
async fn test_open_sent_hold_timer_expires() {
    let hold_time = 1;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::HoldTimerExpiredError(HoldTimerExpiredError::Unspecific {
                sub_code: 0,
                value: vec![],
            }),
        ));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(0)
        .send_notif_without_open(false)
        .hold_timer_duration(hold_time)
        .hold_timer_duration_large_value(hold_time)
        .build();
    let mut peer = Peer::new(PROPERTIES.clone(), config, policy, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::HoldTimerExpires));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_open_sent_tcp_connection_confirmed() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(1),
    };
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    )));

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());
    Ok(())
}

#[ignore]
#[test_log::test(tokio::test)]
async fn test_open_sent_tcp_cr_acked() {
    // TODO: this implementation doesn't initiate connections in OpenSent
    // state, hence TCP CR acked is impossible
}

#[test_log::test(tokio::test)]
async fn test_open_sent_tcp_connections_fails() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let active_io_builder = BgpIoMockBuilder::new();

    let msg = BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    ));
    let buf = vec![];
    let mut cursor = Cursor::new(buf);
    msg.write(&mut cursor).unwrap();

    let passive_io = tokio_test::io::Builder::new()
        .write(&cursor.into_inner())
        .read_error(io::Error::from(io::ErrorKind::ConnectionAborted))
        .build();

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(1),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR, passive_io,
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));

    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionFails);
    assert_eq!(peer.fsm_state(), FsmState::Active);
    assert!(peer.connect_retry_timer().is_some());
    assert!(peer.connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_bgp_open() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_some());
    let conn = peer.connection().unwrap();
    assert!(conn.keepalive_timer().is_some());
    assert!(conn.hold_timer().is_some());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_bgp_header_err() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let bad_header = [0xee; 16];
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read_u8(&bad_header) // Malformed header
        .read_u8(&[0x00, 0x13, 0x04]) // Keep alive message body
        .write(BgpMessage::Notification(
            BgpNotificationMessage::MessageHeaderError(
                MessageHeaderError::ConnectionNotSynchronized {
                    value: Vec::from(&bad_header),
                },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(
        event,
        BgpEvent::BGPHeaderErr(MessageHeaderError::ConnectionNotSynchronized {
            value: Vec::from(&bad_header)
        })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_bgp_open_err() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let bgp_version = 0x03;
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read_u8(&[0xff; 16]) // BGP Standard header
        .read_u8(&[0x00, 0x14]) // Length
        .read_u8(&[0x01]) // Message type = open
        .read_u8(&[bgp_version])
        .write(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(
        event,
        BgpEvent::BGPOpenMsgErr(OpenMessageError::UnsupportedVersionNumber {
            value: vec![bgp_version]
        })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_collision_dump_main_connection() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) + 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive);

    let mut peer = Peer::new(properties, PeerConfig::default(), policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::OpenCollisionDump)));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert_eq!(
        *peer.connection().as_ref().unwrap().peer_addr(),
        passive_addr
    );

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::KeepAliveMsg)));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_collision_dump_tracked_connection() -> Result<(), FsmStateError<SocketAddr>>
{
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .wait(Duration::from_millis(10))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));

    let mut peer = Peer::new(properties, PeerConfig::default(), policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::OpenCollisionDump)));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert_eq!(*peer.connection().as_ref().unwrap().peer_addr(), PEER_ADDR);

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::BGPOpen(peer_open.clone()))));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_notif_version_err() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let bgp_version = 0x03;
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsgVerErr));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_notif_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Notification(notif.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { value: vec![] },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsg(notif)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_keep_alive_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { value: vec![] },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::KeepAliveMsg));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_update_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Update(update.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { value: vec![] },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::UpdateMsg(update));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_update_err() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let update = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x19, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read_u8(&update)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { value: vec![] },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(
        event,
        BgpEvent::UpdateMsgErr(UpdateMessageError::InvalidNetworkField { value: vec![] })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_route_refresh_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let route_refresh = BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::BeginningOfRouteRefresh,
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::RouteRefresh(route_refresh.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { value: vec![] },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::RouteRefresh(route_refresh));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_starts() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .wait(Duration::from_secs(1));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = tokio::time::timeout(Duration::from_millis(1), peer.run()).await;
    // event should ignored
    assert!(event.is_err());
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = tokio::time::timeout(Duration::from_millis(1), peer.run()).await;
    // event should ignored
    assert!(event.is_err());
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_manual_stop() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
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
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    peer.add_admin_event(PeerAdminEvents::ManualStop);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStop);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_automatic_stop() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
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
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    peer.add_admin_event(PeerAdminEvents::AutomaticStop);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::AutomaticStop);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.peer_stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_hold_timer_expires() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::HoldTimerExpiredError(HoldTimerExpiredError::Unspecific {
                sub_code: 0,
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(hold_time as u64 + 1));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::HoldTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.peer_stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_keep_alive_timer_expires() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .wait(Duration::from_secs(hold_time as u64 + 1));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_notif_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::Notification(notif.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsg(notif)));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_notif_version_err() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let bgp_version = 0x03;
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![bgp_version],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::NotifMsgVerErr));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_collision_dump_main_connection() -> Result<(), FsmStateError<SocketAddr>>
{
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) + 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive);

    let mut peer = Peer::new(properties, PeerConfig::default(), policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::OpenCollisionDump)));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert_eq!(
        *peer.connection().as_ref().unwrap().peer_addr(),
        passive_addr
    );

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::KeepAliveMsg)));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_collision_dump_tracked_connection(
) -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .wait(Duration::from_millis(10))
        .read(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));

    let mut peer = Peer::new(properties, PeerConfig::default(), policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::OpenCollisionDump)));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert_eq!(*peer.connection().as_ref().unwrap().peer_addr(), PEER_ADDR);

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::KeepAliveMsg)));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_open_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let notif = BgpNotificationMessage::FiniteStateMachineError(
        FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState { value: vec![] },
    );
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Notification(notif));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open.clone()));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open.clone()));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_bgp_open_err() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let bgp_version = 0x03;
    let notif =
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![bgp_version],
        });
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read_u8(&[0xff; 16]) // BGP Standard header
        .read_u8(&[0x00, 0x14]) // Length
        .read_u8(&[0x01]) // Message type = open
        .read_u8(&[bgp_version])
        .write(BgpMessage::Notification(notif));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open.clone()));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(
        event,
        BgpEvent::BGPOpenMsgErr(OpenMessageError::UnsupportedVersionNumber {
            value: vec![bgp_version]
        })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_bgp_header_err() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let bad_header = [0xee; 16];
    let notif =
        BgpNotificationMessage::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized {
            value: Vec::from(&bad_header),
        });
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read_u8(&bad_header) // Malformed header
        .read_u8(&[0x00, 0x13, 0x04]) // Keep alive message body
        .write(BgpMessage::Notification(notif));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open.clone()));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(
        event,
        BgpEvent::BGPHeaderErr(MessageHeaderError::ConnectionNotSynchronized {
            value: Vec::from(&bad_header)
        })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_keep_alive_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .wait(Duration::from_secs(1));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_update_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::Update(update.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                    value: vec![],
                },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::UpdateMsg(update));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_update_err() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let update = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x19, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read_u8(&update)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                    value: vec![],
                },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(
        event,
        BgpEvent::UpdateMsgErr(UpdateMessageError::InvalidNetworkField { value: vec![] })
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_route_refresh_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let route_refresh = BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::BeginningOfRouteRefresh,
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::RouteRefresh(route_refresh.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::FiniteStateMachineError(
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                    value: vec![],
                },
            ),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::RouteRefresh(route_refresh));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_starts() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .wait(Duration::from_secs(1));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = tokio::time::timeout(Duration::from_millis(1), peer.run()).await;
    // event should ignored
    assert!(event.is_err());
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::AutomaticStart);
    let event = tokio::time::timeout(Duration::from_millis(1), peer.run()).await;
    // event should ignored
    assert!(event.is_err());
    assert!(peer.waiting_admin_events().is_empty());
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_manual_stop() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
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
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::ManualStop);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStop);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_automatic_stop() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
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
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::AutomaticStop);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::AutomaticStop);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.peer_stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_hold_timer_expires() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::HoldTimerExpiredError(HoldTimerExpiredError::Unspecific {
                sub_code: 0,
                value: vec![],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::HoldTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.peer_stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    assert!(peer.connect_retry_timer().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_keep_alive_timer_expires() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::KeepAlive)
        .wait(Duration::from_secs(3));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveTimerExpires);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_collision_dump_main_connection() -> Result<(), FsmStateError<SocketAddr>>
{
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) + 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive);

    let config = PeerConfigBuilder::new()
        .collision_detect_established_state(true)
        .build();

    let mut peer = Peer::new(properties, config, policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::OpenCollisionDump)));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert_eq!(
        *peer.connection().as_ref().unwrap().peer_addr(),
        passive_addr
    );
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 1);

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::KeepAliveMsg)));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_collision_dump_tracked_connection(
) -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .wait(Duration::from_millis(10))
        .read(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));

    let config = PeerConfigBuilder::new()
        .collision_detect_established_state(true)
        .build();

    let mut peer = Peer::new(properties, config, policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(passive_addr));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_some());

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::OpenCollisionDump)));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    assert_eq!(*peer.connection().as_ref().unwrap().peer_addr(), PEER_ADDR);
    assert!(peer.connect_retry_timer().is_none());
    assert_eq!(peer.peer_stats().connect_retry_counter(), 0);

    let event = tokio::time::timeout(Duration::from_secs(3), peer.run()).await;
    assert_eq!(event, Ok(Ok(BgpEvent::KeepAliveMsg)));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_reject_connection_tracking_disabled(
) -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(
        MY_AS,
        PEER_AS,
        MY_BGP_ID,
        peer_bgp_id,
        PEER_ADDR,
        false,
        false,
    );
    let mut passive_addr = PEER_ADDR.clone();
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        peer_bgp_id,
        vec![Capabilities(vec![])],
    );

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .wait(Duration::from_millis(10))
        .read(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Notification(
        BgpNotificationMessage::CeaseError(CeaseError::ConnectionRejected { value: vec![] }),
    ));

    let config = PeerConfigBuilder::new()
        .collision_detect_established_state(false)
        .build();

    let mut peer = Peer::new(properties, config, policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        passive_addr,
        passive_io_builder.build(),
    )));

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_notif_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .read(BgpMessage::Notification(notif.clone()))
        .wait(Duration::from_secs(3));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::NotifMsg(notif));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_notif_version_error() -> Result<(), FsmStateError<SocketAddr>> {
    let hold_time = 3;
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, hold_time, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let bgp_version = 0x03;
    let notif =
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![bgp_version],
        });
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .read(BgpMessage::Notification(notif.clone()))
        .wait(Duration::from_secs(3));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::NotifMsgVerErr);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_tcp_connection_fails() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let my_open = BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![])],
    ));
    let buf = vec![];
    let mut cursor = Cursor::new(buf);
    my_open.write(&mut cursor).unwrap();
    let my_open_buf = cursor.into_inner();

    let peer_open = BgpMessage::Open(BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    ));
    let buf = vec![];
    let mut cursor = Cursor::new(buf);
    peer_open.write(&mut cursor).unwrap();
    let peer_open_buf = cursor.into_inner();

    let buf = vec![];
    let mut cursor = Cursor::new(buf);
    BgpMessage::KeepAlive.write(&mut cursor).unwrap();
    let keepalive_buf = cursor.into_inner();

    let passive_io = tokio_test::io::Builder::new()
        .write(&my_open_buf)
        .read(&peer_open_buf)
        .write(&keepalive_buf)
        .read(&keepalive_buf)
        .read_error(io::Error::from(io::ErrorKind::ConnectionAborted))
        .build();

    let active_connect = MockFailedActiveConnect {
        peer_addr: PEER_ADDR,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    peer.add_admin_event(PeerAdminEvents::TcpConnectionConfirmed((
        PEER_ADDR, passive_io,
    )));
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionConfirmed(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let _event = peer.run().await?;
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionFails);
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_keep_alive_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_established_update_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let policy = EchoCapabilitiesPolicy::new(MY_AS, MY_BGP_ID, HOLD_TIME, HashMap::new());
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![])],
    );
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![Capabilities(vec![])],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive)
        .read(BgpMessage::Update(update.clone()));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PROPERTIES.clone(),
        PeerConfig::default(),
        policy,
        active_connect,
    );
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::OpenSent);
    assert_eq!(peer.stats().connect_retry_counter(), 0);
    assert!(peer.connection().is_some());
    assert!(peer.tracked_connection().is_none());

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpen(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::KeepAliveMsg);
    assert_eq!(peer.fsm_state(), FsmState::Established);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::UpdateMsg(update));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}
