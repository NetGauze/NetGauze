use netgauze_bgp_pkt::iana::RouteRefreshSubcode;

use netgauze_bgp_pkt::{
    capabilities::{BgpCapability, FourOctetAsCapability, MultiProtocolExtensionsCapability},
    iana::AS_TRANS,
    notification::*,
    open::{BgpOpenMessage, BgpOpenMessageParameter::Capabilities},
    route_refresh::BgpRouteRefreshMessage,
    update::BgpUpdateMessage,
};
use netgauze_iana::address_family::AddressType;

use crate::{events::*, fsm::*, peer::*, tests::*};

#[test_log::test(tokio::test)]
async fn test_idle_manual_start() {
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new().build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new().build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .passive_tcp_establishment(true)
        .build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);

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
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let io_builder = BgpIoMockBuilder::new();
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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

    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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

    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .wait(Duration::from_secs(1))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(delay_open_duration)
        .build();
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder: active_io_builder,
        connect_delay: Duration::from_secs(10),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(0)
        .build();

    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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

    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let active_connect = MockFailedActiveConnect {
        peer_addr: PEER_ADDR,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(0)
        .build();

    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);

    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .wait(Duration::from_millis(10))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
    )));
    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
async fn test_connect_bgp_open_err_unsupported_version() {
    let mut io_builder = BgpIoMockBuilder::new();
    let bgp_version = 0x03;
    io_builder
        .read_u8(&[0xff; 16]) // BGP Standard header
        .read_u8(&[0x00, 0x14]) // Length
        .read_u8(&[0x01]) // Message type = open
        .read_u8(&[bgp_version])
        .write(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![0x00, 0x04],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
                value: vec![0x00, 0x04]
            }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_bgp_open_err_unacceptable_hold_time() {
    let mut io_builder = BgpIoMockBuilder::new();
    let hold_time = 1;
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);

    io_builder
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnacceptableHoldTime {
                value: hold_time.to_be_bytes().to_vec(),
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await.unwrap();
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::BGPOpenMsgErr(
            OpenMessageError::UnacceptableHoldTime {
                value: hold_time.to_be_bytes().to_vec(),
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::ManualStart));

    let event = peer.run().await;
    assert_eq!(event, Ok(BgpEvent::TcpConnectionRequestAcked(PEER_ADDR)));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await;
    assert_eq!(
        event,
        Ok(BgpEvent::UpdateMsg(update, UpdateTreatment::Normal,))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_update_err_msg() {
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
            UpdateMessageError::MalformedAttributeList { value: vec![] }
        ))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_connect_route_refresh_msg() {
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder
        .wait(Duration::from_millis(10))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
                value: vec![0x00, 0x04],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
                value: vec![0x00, 0x04]
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

    let active_io_builder = BgpIoMockBuilder::new();
    let mut passive_io_builder = BgpIoMockBuilder::new();
    passive_io_builder.read(BgpMessage::Notification(
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![0x00, 0x04],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
        Ok(BgpEvent::UpdateMsg(update, UpdateTreatment::Normal))
    );
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
}

#[test_log::test(tokio::test)]
async fn test_active_update_err_msg() -> Result<(), FsmStateError<SocketAddr>> {
    let delay_open_duration = 1;
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
        BgpEvent::UpdateMsgErr(UpdateMessageError::MalformedAttributeList { value: vec![] })
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, POLICY, active_connect);
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, policy, active_connect);
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
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder.write(BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
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
        vec![],
    )));

    let mut peer = Peer::new(
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let active_io_builder = BgpIoMockBuilder::new();

    let msg = BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let bad_header = [0xee; 16];
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let bgp_version = 0x03;
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .read_u8(&[0xff; 16]) // BGP Standard header
        .read_u8(&[0x00, 0x14]) // Length
        .read_u8(&[0x01]) // Message type = open
        .read_u8(&[bgp_version])
        .write(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![0x00, 0x04],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
            value: vec![0x00, 0x04]
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
async fn test_open_sent_notif_version_err() -> Result<(), FsmStateError<SocketAddr>> {
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .read(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![0x00, 0x04],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let mut peer = Peer::new(
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    assert_eq!(event, BgpEvent::UpdateMsg(update, UpdateTreatment::Normal));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_update_err() -> Result<(), FsmStateError<SocketAddr>> {
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
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
        BgpEvent::UpdateMsgErr(UpdateMessageError::MalformedAttributeList { value: vec![] })
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
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::Notification(
            BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
                value: vec![0x00, 0x04],
            }),
        ));

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };

    let mut peer = Peer::new(
        PEER_KEY,
        PROPERTIES,
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
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) + 1);
    let properties = PeerProperties::new(MY_AS, PEER_AS, MY_BGP_ID, PEER_ADDR, false);
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, peer_bgp_id, vec![]);

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
            vec![],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive);

    let mut peer = Peer::new(
        PEER_KEY,
        properties,
        PeerConfig::default(),
        POLICY,
        active_connect,
    );

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
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(MY_AS, PEER_AS, MY_BGP_ID, PEER_ADDR, false);
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, peer_bgp_id, vec![]);

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
            vec![],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .write(BgpMessage::Notification(
            BgpNotificationMessage::CeaseError(CeaseError::ConnectionCollisionResolution {
                value: vec![],
            }),
        ))
        .wait(Duration::from_secs(1));

    let mut peer = Peer::new(
        PEER_KEY,
        properties,
        PeerConfig::default(),
        POLICY,
        active_connect,
    );

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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let notif = BgpNotificationMessage::FiniteStateMachineError(
        FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState { value: vec![] },
    );
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let bgp_version = 0x03;
    let notif =
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![0x00, 0x04],
        });
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
            value: vec![0x00, 0x04]
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let bad_header = [0xee; 16];
    let notif =
        BgpNotificationMessage::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized {
            value: Vec::from(&bad_header),
        });
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    assert_eq!(event, BgpEvent::UpdateMsg(update, UpdateTreatment::Normal,));
    assert_eq!(peer.fsm_state(), FsmState::Idle);
    assert_eq!(peer.stats().connect_retry_counter(), 1);
    assert!(peer.connect_retry_timer().is_none());
    assert!(peer.connection().is_none());
    assert!(peer.tracked_connection().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_update_err() -> Result<(), FsmStateError<SocketAddr>> {
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
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
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
        BgpEvent::UpdateMsgErr(UpdateMessageError::MalformedAttributeList { value: vec![] })
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
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
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) + 1);
    let properties = PeerProperties::new(MY_AS, PEER_AS, MY_BGP_ID, PEER_ADDR, false);
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, peer_bgp_id, vec![]);

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
            vec![],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .read(BgpMessage::KeepAlive);

    let config = PeerConfigBuilder::new()
        .collision_detect_established_state(true)
        .build();

    let mut peer = Peer::new(PEER_KEY, properties, config, POLICY, active_connect);

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
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(MY_AS, PEER_AS, MY_BGP_ID, PEER_ADDR, false);
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, peer_bgp_id, vec![]);

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
            vec![],
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

    let mut peer = Peer::new(PEER_KEY, properties, config, POLICY, active_connect);

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
    let peer_bgp_id = Ipv4Addr::from(u32::from(MY_BGP_ID) - 1);
    let properties = PeerProperties::new(MY_AS, PEER_AS, MY_BGP_ID, PEER_ADDR, false);
    let mut passive_addr = PEER_ADDR;
    passive_addr.set_port(5000);
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, peer_bgp_id, vec![]);

    let mut active_io_builder = BgpIoMockBuilder::new();
    active_io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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

    let mut peer = Peer::new(PEER_KEY, properties, config, POLICY, active_connect);

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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let notif =
        BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown { value: vec![] });
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, hold_time, Vec::new(), Vec::new());
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, hold_time, PEER_BGP_ID, vec![]);
    let notif =
        BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: vec![0x00, 0x04],
        });
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
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
    let my_open = BgpMessage::Open(BgpOpenMessage::new(
        MY_AS as u16,
        HOLD_TIME,
        MY_BGP_ID,
        vec![],
    ));
    let buf = vec![];
    let mut cursor = Cursor::new(buf);
    my_open.write(&mut cursor).unwrap();
    let my_open_buf = cursor.into_inner();

    let peer_open = BgpMessage::Open(BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, HOLD_TIME, PEER_BGP_ID, vec![]);
    let update = BgpUpdateMessage::new(vec![], vec![], vec![]);
    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
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
        PEER_KEY,
        PROPERTIES,
        PeerConfig::default(),
        POLICY,
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
    assert_eq!(event, BgpEvent::UpdateMsg(update, UpdateTreatment::Normal));
    assert_eq!(peer.fsm_state(), FsmState::Established);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_connect_echo_policy() -> Result<(), FsmStateError<SocketAddr>> {
    let my_asn = 66_000; // must be encoded as ASN4
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

    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        HOLD_TIME,
        PEER_BGP_ID,
        vec![Capabilities(vec![
            route_refresh_cap.clone(),
            enhanced_route_refresh_cap.clone(),
            ipv4_unicast_cap.clone(),
            ipv4_multicast_cap.clone(),
            ipv6_multicast_cap.clone(),
        ])],
    );

    let my_open = BgpOpenMessage::new(
        AS_TRANS,
        HOLD_TIME,
        MY_BGP_ID,
        vec![Capabilities(vec![
            // ASN 4 should be added automatically since my_asn > u16::MAX
            BgpCapability::FourOctetAs(FourOctetAsCapability::new(my_asn)),
            // in pushed_caps and learned from peer
            route_refresh_cap.clone(),
            // Should be added since it's in pushed_caps
            extended_msg_cap.clone(),
            // In pushed_caps
            ipv6_unicast_cap.clone(),
            // Learned from peer
            ipv4_unicast_cap.clone(),
            // Learned from peer
            ipv4_multicast_cap.clone(),
        ])],
    );

    let mut io_builder = BgpIoMockBuilder::new();
    io_builder
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::Open(my_open))
        .write(BgpMessage::KeepAlive);

    let active_connect = MockActiveConnect {
        peer_addr: PEER_ADDR,
        io_builder,
        connect_delay: Duration::from_secs(0),
    };
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();

    let mut peer = Peer::new(PEER_KEY, PROPERTIES, config, policy, active_connect);

    peer.add_admin_event(PeerAdminEvents::ManualStart);
    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::ManualStart);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::TcpConnectionRequestAcked(PEER_ADDR));
    assert_eq!(peer.fsm_state(), FsmState::Connect);

    let event = peer.run().await?;
    assert_eq!(event, BgpEvent::BGPOpenWithDelayOpenTimer(peer_open));
    assert_eq!(peer.fsm_state(), FsmState::OpenConfirm);

    Ok(())
}
