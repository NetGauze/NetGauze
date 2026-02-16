use super::*;
use futures_util::SinkExt;
use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmp_pkt::codec::BmpCodec;
use netgauze_bmp_pkt::v3::{InitiationInformation, InitiationMessage};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tokio_util::codec::FramedWrite;

/// Helper to create a valid BMP Initiation Message for testing
fn create_test_message() -> BmpMessage {
    BmpMessage::V3(netgauze_bmp_pkt::v3::BmpMessageValue::Initiation(
        InitiationMessage::new(vec![InitiationInformation::SystemDescription(
            "NetGauze Test Actor".to_string(),
        )]),
    ))
}

// Helper function to create a test configuration
fn create_test_config() -> SupervisorConfig {
    SupervisorConfig {
        binding_addresses: vec![
            // Two workers on one port
            BindingAddress {
                socket_addr: "127.0.0.1:0".parse().unwrap(),
                num_workers: 2,
                interface: None,
            },
            // One worker on another port
            BindingAddress {
                socket_addr: "127.0.0.1:0".parse().unwrap(),
                num_workers: 1,
                interface: None,
            },
        ],
        cmd_buffer_size: 10,
        subscriber_timeout: Duration::from_secs(1),
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_supervisor_lifecycle() {
    let config = create_test_config();
    let meter = opentelemetry::global::meter("test-lifecycle");
    let (join_handle, handle) =
        BmpSupervisorHandle::new(config, meter).expect("failed to create supervisor");

    assert!(!join_handle.is_finished());

    // Verify we have 3 actors (2 + 1)
    let addresses = handle
        .local_addresses()
        .await
        .expect("failed to get addresses");
    assert_eq!(addresses.len(), 3);

    // Shutdown the supervisor
    handle
        .shutdown()
        .await
        .expect("failed to shutdown supervisor");

    // Wait for the join handle to complete
    timeout(Duration::from_secs(5), join_handle)
        .await
        .expect("supervisor didn't shut down in time")
        .expect("supervisor panicked");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_supervisor_subscribe_unsubscribe() {
    let config = create_test_config();
    let meter = opentelemetry::global::meter("test-subs");
    let (_join_handle, handle) =
        BmpSupervisorHandle::new(config, meter).expect("failed to create supervisor");

    // Subscribe
    let (pkt_rx, subscriptions) = handle.subscribe(10).await.expect("failed to subscribe");
    assert_eq!(subscriptions.len(), 3); // 2 + 1 workers from our config

    // Unsubscribe
    let unsubscribe_results = handle
        .unsubscribe(subscriptions)
        .await
        .expect("failed to unsubscribe");

    assert_eq!(unsubscribe_results.len(), 3);
    assert!(unsubscribe_results.iter().all(|r| r.is_some()));

    // Validate channel closure
    // The channel should be closed because all producers (actors) dropped their
    // senders
    timeout(Duration::from_millis(500), pkt_rx.recv())
        .await
        .expect("Timed out waiting for channel closure")
        .expect_err("Channel should be closed");

    handle
        .shutdown()
        .await
        .expect("failed to shutdown supervisor");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_supervisor_peer_management() {
    let config = create_test_config();
    let meter = opentelemetry::global::meter("test-peers");
    let (_join_handle, handle) =
        BmpSupervisorHandle::new(config, meter).expect("failed to create supervisor");

    let local_addrs = handle
        .local_addresses()
        .await
        .expect("failed to get local addresses");

    // Connect to the FIRST actor specifically
    let (target_actor_id, target_addr) = local_addrs[0];
    let stream = TcpStream::connect(target_addr).await.unwrap();
    let client_addr = stream.local_addr().unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Verify specific actor has the peer
    let peers_list = handle.get_connected_peers().await.unwrap();

    // Find the peers for our specific target actor
    let (_, active_peers) = peers_list
        .iter()
        .find(|(id, _)| *id == target_actor_id)
        .expect("Actor should exist in peers list");

    assert!(
        active_peers.contains(&client_addr),
        "Target actor should have the peer"
    );
    // 2. Disconnect
    let results = handle.disconnect_peer(client_addr).await.unwrap();

    // Verify only the target actor returned 'true'
    let (_disconnected_actor, was_disconnected) = results
        .iter()
        .find(|(id, _)| *id == target_actor_id)
        .unwrap();
    assert!(was_disconnected);
    assert!(
        results
            .iter()
            .filter(|(id, _)| *id != target_actor_id)
            .all(|(_, disc)| !disc)
    );

    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_supervisor_sharded_subscription() {
    let config = create_test_config();
    let meter = opentelemetry::global::meter("test-sup-shards");
    let (_join_handle, handle) =
        BmpSupervisorHandle::new(config, meter).expect("failed to create supervisor");

    // Subscribe with 2 shards. The supervisor distributes the senders for these
    // shards to all managed actors.
    let (receivers, _) = handle
        .subscribe_shards(2, 10)
        .await
        .expect("failed to subscribe");

    assert_eq!(receivers.len(), 2);

    // Connect to the first available actor
    let target_addr = handle.local_addresses().await.unwrap()[0].1;
    let stream = TcpStream::connect(target_addr).await.unwrap();
    let mut framed = FramedWrite::new(stream, BmpCodec::default());

    // Send a test message
    let test_msg = create_test_message();
    framed.send(test_msg.clone()).await.unwrap();

    // Wait for the message on either of the two shards
    // recv() returns Result<Arc<(AddrInfo, BmpMessage)>, RecvError>
    let recv_result = timeout(Duration::from_millis(1000), async {
        tokio::select! {
             msg = receivers[0].recv() => msg,
             msg = receivers[1].recv() => msg,
        }
    })
    .await
    .expect("Timed out waiting for message");

    let packet = recv_result.expect("Channel closed unexpectedly");
    let (_, received_msg) = &*packet;

    assert_eq!(received_msg, &test_msg);

    handle.shutdown().await.unwrap();
}
