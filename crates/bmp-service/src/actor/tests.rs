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

use super::*;
use futures_util::SinkExt;
use netgauze_bmp_pkt::v3::{InitiationInformation, InitiationMessage};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::FramedWrite;

/// Helper to create a valid BMP Initiation Message for testing
fn create_test_message() -> BmpMessage {
    BmpMessage::V3(netgauze_bmp_pkt::v3::BmpMessageValue::Initiation(
        InitiationMessage::new(vec![InitiationInformation::SystemDescription(
            "NetGauze Test Actor".to_string(),
        )]),
    ))
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_actor_lifecycle() {
    let meter = opentelemetry::global::meter("test_lifecycle");
    // Bind to port 0 to let OS select an available port
    let addr: SocketAddr = "127.0.0.1:17990".parse().unwrap();

    let (join_handle, handle) = BmpActorHandle::new(
        1,
        addr,
        None,
        100,
        Duration::from_millis(500),
        either::Either::Left(meter),
    )
    .expect("failed to create actor");

    // Verify basic properties
    assert_eq!(handle.actor_id(), 1);
    let local_addr = handle.local_addr();
    assert_eq!(local_addr.ip(), addr.ip());
    assert_eq!(local_addr.port(), 17990);

    // Verify commands work (get peers on empty actor)
    let (actor_id, peers) = handle
        .get_connected_peers()
        .await
        .expect("failed to get peers");
    assert_eq!(actor_id, 1);
    assert!(peers.is_empty());

    // Graceful shutdown
    let stopped_ids = handle.shutdown().await.expect("failed to shutdown");
    assert_eq!(stopped_ids, vec![1]);

    // Ensure the actor task completes successfully
    let result = join_handle.await.expect("actor task panicked");
    assert!(result.is_ok());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_bmp_message_reception() {
    let meter = opentelemetry::global::meter("test_message");
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (_join_handle, handle) = BmpActorHandle::new(
        2,
        addr,
        None,
        100,
        Duration::from_millis(500),
        either::Either::Left(meter),
    )
    .expect("failed to create actor");

    // 1. Subscribe to messages
    let (rx, _sub) = handle.subscribe(10).await.expect("failed to subscribe");

    // 2. Connect as a BMP client (router)
    let server_addr = handle.local_addr();
    let stream = TcpStream::connect(server_addr)
        .await
        .expect("failed to connect to actor");

    // 3. Send a valid BMP message
    let mut framed = FramedWrite::new(stream, BmpCodec::default());
    let msg = create_test_message();

    framed
        .send(msg.clone())
        .await
        .expect("failed to send message");

    // 4. Verify message is received by subscriber
    let packet = timeout(Duration::from_millis(1000), rx.recv())
        .await
        .expect("timed out waiting for message")
        .expect("channel closed");
    let (addr_info, received_msg) = &*packet;

    assert_eq!(received_msg, &msg);
    assert_eq!(addr_info.local_socket(), server_addr);

    handle.shutdown().await.expect("failed to shutdown actor");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_peer_management_disconnect() {
    let meter = opentelemetry::global::meter("test_disconnect");
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (_join_handle, handle) = BmpActorHandle::new(
        3,
        addr,
        None,
        100,
        Duration::from_millis(500),
        either::Either::Left(meter),
    )
    .expect("failed to create actor");

    // Connect a client
    let stream = TcpStream::connect(handle.local_addr())
        .await
        .expect("failed to create TCP connection to actor");
    let peer_addr = stream
        .local_addr()
        .expect("failed to get actor's socket local address");

    // Allow async accept to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify peer is listed
    let (actor_id, peers) = handle
        .get_connected_peers()
        .await
        .expect("failed to get connected peers list");
    assert!(
        peers.contains(&peer_addr),
        "Peer should be in connected list"
    );
    assert_eq!(actor_id, 3);

    // Disconnect peer
    let disconnected = handle
        .disconnect_peer(peer_addr)
        .await
        .expect("failed to disconnect peer");
    assert!(disconnected, "Should return true for disconnected peer");

    // Verify peer is gone from list
    let (_, peers) = handle
        .get_connected_peers()
        .await
        .expect("failed to get connected peers list");
    assert!(
        !peers.contains(&peer_addr),
        "Peer should be removed from list"
    );

    // Try disconnecting again (should fail)
    let disconnected_again = handle
        .disconnect_peer(peer_addr)
        .await
        .expect("failed to disconnect peer");
    assert!(
        !disconnected_again,
        "Should return false for already disconnected peer"
    );

    handle.shutdown().await.expect("failed to shutdown actor");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_sharded_subscription() {
    let meter = opentelemetry::global::meter("test_sharding");
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (_join_handle, handle) = BmpActorHandle::new(
        4,
        addr,
        None,
        100,
        Duration::from_millis(500),
        either::Either::Left(meter),
    )
    .expect("failed to create actor");

    // Subscribe with 2 shards
    let (receivers, _) = handle
        .subscribe_shards(2, 10)
        .await
        .expect("failed to subscribe with shards");
    assert_eq!(receivers.len(), 2);

    // Connect and send
    let stream = TcpStream::connect(handle.local_addr())
        .await
        .expect("failed to create TCP connection to actor");
    let mut framed = FramedWrite::new(stream, BmpCodec::default());
    framed
        .send(create_test_message())
        .await
        .expect("failed to send test BMP message");

    let recv_result = timeout(Duration::from_millis(1000), async {
        tokio::select! {
            msg = receivers[0].recv() => msg,
            msg = receivers[1].recv() => msg,
        }
    })
    .await
    .expect("Timed out waiting for message on shards");

    let packet = recv_result.expect("Channel closed unexpectedly or receive failed");
    let (_, msg) = &*packet;

    assert_eq!(msg, &create_test_message());

    handle.shutdown().await.expect("failed to shutdown actor");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_subscription_unsubscribe() {
    let meter = opentelemetry::global::meter("test_subs");
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (_join_handle, handle) = BmpActorHandle::new(
        5,
        addr,
        None,
        100,
        Duration::from_millis(500),
        either::Either::Left(meter),
    )
    .expect("failed to create actor");

    // Subscribe
    let (rx, sub) = handle.subscribe(10).await.expect("failed to subscribe");

    // Connect and send
    let stream = TcpStream::connect(handle.local_addr())
        .await
        .expect("failed to create TCP connection to actor");
    let mut framed = FramedWrite::new(stream, BmpCodec::default());
    framed
        .send(create_test_message())
        .await
        .expect("failed to send test BMP message");

    // Ensure we get the message
    assert!(timeout(Duration::from_millis(500), rx.recv()).await.is_ok());

    // Unsubscribe
    let result = handle
        .unsubscribe(sub.id)
        .await
        .expect("failed to unsubscribe");
    assert!(result.is_some());
    assert_eq!(result.unwrap().id, sub.id);

    // Send another message
    framed
        .send(create_test_message())
        .await
        .expect("failed to send test BMP message");

    // The receiving channel should now be closed by the sender (actor dropped tx)
    timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("Timed out waiting for channel closure")
        .expect_err("Channel should be closed");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_subscription_updates_existing_connection() {
    // This test ensures that an existing connection picks up new subscriptions via
    // the broadcast channel
    let meter = opentelemetry::global::meter("test_subs_update");
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (_join_handle, handle) = BmpActorHandle::new(
        6,
        addr,
        None,
        100,
        Duration::from_millis(500),
        either::Either::Left(meter),
    )
    .expect("failed to create actor");

    // 1. Establish connection FIRST (before any subscription)
    let stream = TcpStream::connect(handle.local_addr())
        .await
        .expect("failed to create TCP connection to actor");
    let mut framed = FramedWrite::new(stream, BmpCodec::default());

    // Allow time for connection handling to stabilize
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Subscribe AFTER connection is established
    let (rx, _sub) = handle.subscribe(10).await.expect("failed to subscribe");

    // Allow time for the broadcast message to propagate to the connection task
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Send message
    framed
        .send(create_test_message())
        .await
        .expect("failed to send test BMP message");

    // 4. Verify the "late" subscriber receives the message
    let packet = timeout(Duration::from_millis(1000), rx.recv())
        .await
        .expect("timed out waiting for message")
        .expect("channel closed");

    let (_, msg) = &*packet;
    assert_eq!(msg, &create_test_message());

    handle.shutdown().await.expect("failed to shutdown actor");
}
