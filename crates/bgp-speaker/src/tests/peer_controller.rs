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

use crate::{
    events::BgpEvent,
    fsm::FsmState,
    peer::*,
    peer_controller::PeerController,
    tests::{
        BgpIoMockBuilder, MockActiveConnect, HOLD_TIME, MY_AS, MY_BGP_ID, PEER_ADDR, PEER_KEY,
        POLICY, PROPERTIES,
    },
};
use netgauze_bgp_pkt::{
    notification::{BgpNotificationMessage, CeaseError},
    open::BgpOpenMessage,
    BgpMessage,
};
use std::{net::SocketAddr, time::Duration};
use tokio::sync::mpsc;

#[test_log::test(tokio::test)]
async fn test_start_stop(
) -> Result<(), mpsc::error::SendError<PeerEvent<SocketAddr, tokio_test::io::Mock>>> {
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

#[test_log::test(tokio::test)]
async fn test_start_stop_with_passive_tcp(
) -> Result<(), mpsc::error::SendError<PeerEvent<SocketAddr, tokio_test::io::Mock>>> {
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
