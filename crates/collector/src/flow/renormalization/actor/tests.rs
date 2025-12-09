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
use chrono::Utc;
use netgauze_flow_pkt::ipfix::IpfixPacket;
use std::time::Duration;
use tracing_test::traced_test;

fn create_stats() -> RenormalizationStats {
    let meter = opentelemetry::global::meter("test");
    RenormalizationStats::new(meter)
}

#[tokio::test]
#[traced_test]
async fn test_shutdown_command() {
    let (cmd_tx, cmd_rx) = mpsc::channel(1);
    let (_flow_tx, flow_rx) = async_channel::unbounded();
    let (next_tx, _next_rx) = async_channel::unbounded();

    let actor = RenormalizationActor::new(cmd_rx, flow_rx, next_tx, create_stats(), 0);

    let handle = tokio::spawn(async move { actor.run().await });

    cmd_tx.send(RenormalizationCommand::Shutdown).await.unwrap();

    let result = handle.await.unwrap();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Renormalization shutdown successfully");

    assert!(logs_contain("Shutting down flow renormalization actor"));
}

#[tokio::test]
#[traced_test]
async fn test_cmd_channel_closed() {
    let (cmd_tx, cmd_rx) = mpsc::channel(1);
    let (_flow_tx, flow_rx) = async_channel::unbounded();
    let (next_tx, _next_rx) = async_channel::unbounded();

    let actor = RenormalizationActor::new(cmd_rx, flow_rx, next_tx, create_stats(), 0);

    let handle = tokio::spawn(async move { actor.run().await });

    // Drop sender to close channel
    drop(cmd_tx);

    let result = handle.await.unwrap();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Renormalization shutdown successfully");

    assert!(logs_contain(
        "Flow renormalization actor terminated due to command channel closing"
    ));
}

#[tokio::test]
#[traced_test]
async fn test_flow_processing() {
    let (cmd_tx, cmd_rx) = mpsc::channel(1);
    let (flow_tx, flow_rx) = async_channel::unbounded();
    let (next_tx, next_rx) = async_channel::unbounded();

    let actor = RenormalizationActor::new(cmd_rx, flow_rx, next_tx, create_stats(), 0);

    let handle = tokio::spawn(async move { actor.run().await });

    let pkt = IpfixPacket::new(Utc::now(), 0, 0, vec![].into_boxed_slice());
    let flow_info = FlowInfo::IPFIX(pkt);
    let peer = "127.0.0.1:1234".parse().unwrap();

    flow_tx.send((peer, flow_info.clone())).await.unwrap();

    let (processed_peer, processed_flow) = next_rx.recv().await.unwrap();
    assert_eq!(processed_peer, peer);
    assert_eq!(processed_flow, flow_info);

    // Shutdown cleanly
    drop(cmd_tx);
    let result = handle.await.unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
#[traced_test]
async fn test_flow_send_error() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let (flow_tx, flow_rx) = async_channel::unbounded();
    let (next_tx, next_rx) = async_channel::unbounded();

    let actor = RenormalizationActor::new(cmd_rx, flow_rx, next_tx, create_stats(), 0);

    let handle = tokio::spawn(async move { actor.run().await });

    // Drop receiver to cause send error in actor
    drop(next_rx);

    let pkt = IpfixPacket::new(Utc::now(), 0, 0, vec![].into_boxed_slice());
    flow_tx
        .send(("127.0.0.1:1234".parse().unwrap(), FlowInfo::IPFIX(pkt)))
        .await
        .unwrap();

    // Give some time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(logs_contain("Flow renormalization send error"));

    // Cleanup
    handle.abort();
}

#[tokio::test]
#[traced_test]
async fn test_flow_recv_error() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let (flow_tx, flow_rx) = async_channel::unbounded();
    let (next_tx, _next_rx) = async_channel::unbounded();

    let actor = RenormalizationActor::new(cmd_rx, flow_rx, next_tx, create_stats(), 0);

    // Drop sender
    drop(flow_tx);

    let result = actor.run().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string()
            .contains("error in renormalization receive channel")
    );

    assert!(logs_contain(
        "Shutting down due to Renormalization recv error"
    ));
}

#[tokio::test]
#[traced_test]
async fn test_actor_handle() {
    let meter = opentelemetry::global::meter("test");
    let (flow_tx, flow_rx) = async_channel::bounded(100);
    let (join_handle, handle) =
        RenormalizationActorHandle::new(100, flow_rx, Either::Left(meter), 0);

    let pkt = IpfixPacket::new(Utc::now(), 0, 0, vec![].into_boxed_slice());
    let flow_info = FlowInfo::IPFIX(pkt);
    let peer = "127.0.0.1:1234".parse().unwrap();

    flow_tx.send((peer, flow_info.clone())).await.unwrap();

    let sub = handle.subscribe();
    let (processed_peer, processed_flow) = sub.recv().await.unwrap();

    assert_eq!(processed_peer, peer);
    assert_eq!(processed_flow, flow_info);

    handle.shutdown().await.unwrap();
    let result = join_handle.await.unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
#[traced_test]
async fn test_actor_handle_shutdown_error() {
    let meter = opentelemetry::global::meter("test");
    let (_flow_tx, flow_rx) = async_channel::bounded(100);
    let (join_handle, handle) =
        RenormalizationActorHandle::new(100, flow_rx, Either::Left(meter), 0);

    // First shutdown should succeed
    handle.shutdown().await.unwrap();

    // Wait for actor to finish
    let result = join_handle.await.unwrap();
    assert!(result.is_ok());

    // Second shutdown should fail because actor is gone
    let err = handle.shutdown().await.unwrap_err();
    assert!(matches!(err, RenormalizationActorHandleError::SendError));
    assert_eq!(
        err.to_string(),
        "Failed to send command to renormalization actor"
    );
}
