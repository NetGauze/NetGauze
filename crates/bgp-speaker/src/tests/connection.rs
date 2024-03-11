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

use crate::connection::{Connection, ConnectionConfigBuilder, ConnectionState, ConnectionType};
use futures::StreamExt;
use netgauze_bgp_pkt::notification::{
    BgpNotificationMessage, HoldTimerExpiredError, MessageHeaderError,
};
use tokio_test::io::Mock;
use tokio_util::codec::Framed;

use crate::{connection::ConnectionConfig, events::ConnectionEvent, fsm::FsmStateError, tests::*};
use netgauze_bgp_pkt::open::BgpOpenMessage;

async fn get_connection(
    io: Mock,
    policy: &mut EchoCapabilitiesPolicy<SocketAddr, Mock, BgpCodec>,
    config: ConnectionConfig,
) -> Result<Connection<SocketAddr, Mock, BgpCodec>, FsmStateError<SocketAddr>> {
    let framed = Framed::new(io, BgpCodec::new(true));
    let mut connection = Connection::new(
        &PROPERTIES,
        PEER_ADDR,
        ConnectionType::Active,
        config,
        framed,
    );
    connection
        .handle_event(
            policy,
            ConnectionEvent::TcpConnectionRequestAcked(PEER_ADDR),
        )
        .await?;
    Ok(connection)
}

#[test_log::test(tokio::test)]
async fn test_connected_delay_open_timer_expires() -> io::Result<()> {
    let mut policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());
    let open_delay_duration = Duration::from_secs(1);
    let io = BgpIoMockBuilder::new()
        .wait(open_delay_duration)
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .build();
    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(open_delay_duration.as_secs() as u16)
        .build();
    let mut connection = get_connection(io, &mut policy, config).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::Connected);
    let event = tokio::time::timeout(open_delay_duration, connection.next()).await?;
    assert_eq!(event, Some(ConnectionEvent::DelayOpenTimerExpires));
    let event = event.unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert!(matches!(event, Ok(ConnectionEvent::DelayOpenTimerExpires)));
    assert_eq!(connection.state(), ConnectionState::OpenSent);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_connected_open_with_delay_open_timer() -> io::Result<()> {
    let mut policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());
    let open_delay_duration = Duration::from_secs(1);
    let io = BgpIoMockBuilder::new()
        .read(BgpMessage::Open(BgpOpenMessage::new(
            PEER_AS as u16,
            HOLD_TIME,
            PEER_BGP_ID,
            vec![],
        )))
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .write(BgpMessage::KeepAlive)
        .build();

    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(open_delay_duration.as_secs() as u16)
        .build();
    let mut connection = get_connection(io, &mut policy, config).await.unwrap();

    assert_eq!(connection.state(), ConnectionState::Connected);
    assert_eq!(connection.stats().open_sent(), 0);
    assert_eq!(connection.stats().open_received(), 0);
    assert!(connection.stats().last_sent().is_none());
    assert!(connection.stats().last_received().is_none());

    let event = connection.next().await.unwrap();
    assert!(matches!(
        event,
        ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
    ));
    assert_eq!(connection.stats().open_received(), 1);
    assert_eq!(connection.stats().open_sent(), 0);
    assert!(connection.stats().last_received().is_some());
    assert!(connection.stats().last_sent().is_none());

    let handle_event = connection.handle_event(&mut policy, event).await.unwrap();
    assert!(matches!(
        handle_event,
        ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
    ));
    assert_eq!(connection.state(), ConnectionState::OpenConfirm);
    assert_eq!(connection.stats().open_received(), 1);
    assert_eq!(connection.stats().open_sent(), 1);
    assert_eq!(connection.stats().keepalive_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_some());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_connected_bgp_header_err() -> io::Result<()> {
    let mut policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());
    let open_delay_duration = Duration::from_secs(1);
    let io = BgpIoMockBuilder::new()
        .read_u8(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x13, 0xff,
        ])
        .write(BgpMessage::Notification(
            BgpNotificationMessage::MessageHeaderError(MessageHeaderError::BadMessageType {
                value: vec![0xff],
            }),
        ))
        .build();
    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(open_delay_duration.as_secs() as u16)
        .build();

    let mut connection = get_connection(io, &mut policy, config).await.unwrap();

    let event = connection.next().await.expect("Expected an event");
    assert!(matches!(event, ConnectionEvent::BGPHeaderErr(_)));
    connection.handle_event(&mut policy, event).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::Terminate);
    assert_eq!(connection.stats().open_received(), 0);
    assert_eq!(connection.stats().notification_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_connected_open_sent() -> io::Result<()> {
    let mut policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());
    let io = BgpIoMockBuilder::new()
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .build();

    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(0)
        .build();
    let connection = get_connection(io, &mut policy, config).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::OpenSent);
    assert_eq!(connection.stats().open_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_hold_timer_expires() -> io::Result<()> {
    let mut policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());
    let hold_time_seconds = 1;
    let io = BgpIoMockBuilder::new()
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .wait(Duration::from_secs(hold_time_seconds * 2))
        .write(BgpMessage::Notification(
            BgpNotificationMessage::HoldTimerExpiredError(HoldTimerExpiredError::Unspecific {
                sub_code: 0,
                value: vec![],
            }),
        ))
        .build();

    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(0)
        .hold_timer_duration(hold_time_seconds as u16)
        .hold_timer_duration_large_value(hold_time_seconds as u16)
        .build();
    let mut connection = get_connection(io, &mut policy, config).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::OpenSent);
    let event =
        tokio::time::timeout(Duration::from_secs(hold_time_seconds), connection.next()).await;
    assert_eq!(event, Ok(Some(ConnectionEvent::HoldTimerExpires)));
    let event = event.unwrap().unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::HoldTimerExpires));
    assert_eq!(connection.state(), ConnectionState::Terminate);
    assert_eq!(connection.stats().open_sent(), 1);
    assert_eq!(connection.stats().notification_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_bgp_open() -> io::Result<()> {
    let peer_hold_time = 120;
    let our_hold_time = 240;
    let mut policy = EchoCapabilitiesPolicy::new(
        MY_AS,
        false,
        MY_BGP_ID,
        our_hold_time,
        Vec::new(),
        Vec::new(),
    );
    let peer_open = BgpOpenMessage::new(PEER_AS as u16, peer_hold_time, PEER_BGP_ID, vec![]);
    let io = BgpIoMockBuilder::new()
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            our_hold_time,
            MY_BGP_ID,
            vec![],
        )))
        .read(BgpMessage::Open(peer_open.clone()))
        .write(BgpMessage::KeepAlive)
        .build();

    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(0)
        .hold_timer_duration(our_hold_time)
        .build();
    let mut connection = get_connection(io, &mut policy, config).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::OpenSent);
    let event = connection.next().await;
    assert_eq!(event, Some(ConnectionEvent::BGPOpen(peer_open.clone())));
    let event = event.unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::BGPOpen(peer_open.clone())));
    assert_eq!(connection.state(), ConnectionState::OpenConfirm);
    assert_eq!(
        connection.hold_timer_duration(),
        Duration::from_secs(peer_hold_time as u64)
    );
    assert_eq!(
        connection.keepalive_timer_duration(),
        Duration::from_secs((peer_hold_time / 3) as u64)
    );
    assert!(connection.keepalive_timer().is_some());
    assert_eq!(connection.stats().open_sent(), 1);
    assert_eq!(connection.stats().open_received(), 1);
    assert_eq!(connection.stats().keepalive_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_some());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_sent_tcp_connection_fails() -> io::Result<()> {
    let mut policy =
        EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());
    let hold_time_seconds = 1;
    let io = BgpIoMockBuilder::new()
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            HOLD_TIME,
            MY_BGP_ID,
            vec![],
        )))
        .build();

    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(0)
        .hold_timer_duration(hold_time_seconds as u16)
        .hold_timer_duration_large_value(hold_time_seconds as u16)
        .build();
    let mut connection = get_connection(io, &mut policy, config).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::OpenSent);
    let event =
        tokio::time::timeout(Duration::from_secs(hold_time_seconds), connection.next()).await;
    assert_eq!(event, Ok(Some(ConnectionEvent::TcpConnectionFails)));
    let event = event.unwrap().unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::TcpConnectionFails));
    assert_eq!(connection.state(), ConnectionState::Terminate);
    assert_eq!(connection.stats().open_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_open_confirm_hold_timer_expires() -> io::Result<()> {
    let hold_time_seconds = 3;
    let mut policy = EchoCapabilitiesPolicy::new(
        MY_AS,
        false,
        MY_BGP_ID,
        hold_time_seconds as u16,
        Vec::new(),
        Vec::new(),
    );
    let peer_open = BgpOpenMessage::new(
        PEER_AS as u16,
        hold_time_seconds as u16,
        PEER_BGP_ID,
        vec![],
    );
    let io = BgpIoMockBuilder::new()
        .write(BgpMessage::Open(BgpOpenMessage::new(
            MY_AS as u16,
            hold_time_seconds as u16,
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
        .wait(Duration::from_secs(hold_time_seconds))
        .build();

    let config = ConnectionConfigBuilder::new()
        .open_delay_timer_duration(0)
        .hold_timer_duration(hold_time_seconds as u16)
        .hold_timer_duration_large_value(hold_time_seconds as u16)
        .build();
    let mut connection = get_connection(io, &mut policy, config).await.unwrap();
    assert_eq!(connection.state(), ConnectionState::OpenSent);

    // Receive and handle open message
    let event =
        tokio::time::timeout(Duration::from_secs(hold_time_seconds), connection.next()).await;
    assert_eq!(event, Ok(Some(ConnectionEvent::BGPOpen(peer_open.clone()))));
    let event = event.unwrap().unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::BGPOpen(peer_open.clone())));
    assert_eq!(connection.state(), ConnectionState::OpenConfirm);

    // Receive and handle first KeepAliveTimerExpires
    let event =
        tokio::time::timeout(Duration::from_secs(hold_time_seconds), connection.next()).await;
    assert_eq!(event, Ok(Some(ConnectionEvent::KeepAliveTimerExpires)));
    let event = event.unwrap().unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::KeepAliveTimerExpires));

    // Receive and handle Second KeepAliveTimerExpires
    let event =
        tokio::time::timeout(Duration::from_secs(hold_time_seconds), connection.next()).await;
    assert_eq!(event, Ok(Some(ConnectionEvent::KeepAliveTimerExpires)));
    let event = event.unwrap().unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::KeepAliveTimerExpires));

    // Receive and handle third KeepAliveTimerExpires
    let event =
        tokio::time::timeout(Duration::from_secs(hold_time_seconds), connection.next()).await;
    assert_eq!(event, Ok(Some(ConnectionEvent::HoldTimerExpires)));
    let event = event.unwrap().unwrap();
    let event = connection.handle_event(&mut policy, event).await;
    assert_eq!(event, Ok(ConnectionEvent::HoldTimerExpires));

    assert_eq!(connection.state(), ConnectionState::Terminate);
    assert_eq!(connection.stats().open_sent(), 1);
    assert_eq!(connection.stats().keepalive_sent(), 3);
    assert_eq!(connection.stats().keepalive_received(), 0);
    assert_eq!(connection.stats().notification_sent(), 1);
    assert!(connection.stats().last_sent().is_some());
    assert!(connection.stats().last_received().is_some());
    Ok(())
}
