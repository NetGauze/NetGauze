// Copyright (C) 2025-present The NetGauze Authors.
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

pub mod actor;
pub mod fetcher;
pub mod storage;

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use anyhow::anyhow;
//     use std::str::FromStr;
//     use std::time::Duration;
//
//     #[tokio::test]
//     #[tracing_test::traced_test]
//     async fn test_get_schema() {
//         let key_string =
// std::fs::read_to_string("/Users/taaahel1/.ssh/daisy_ssh_key_id_rsa")
//             .expect("failed to read private key");
//         let private_key = russh::keys::decode_secret_key(key_string.as_str(),
// None)             .expect("failed to decode private key");
//
//         let (j, handle) = CacheActorHandle::new(
//             100,
//             either::Right(PathBuf::from("/tmp/cache")),
//             NetconfYangLibraryFetcher {
//                 user: "daisy1".to_string(),
//                 private_key: Arc::new(private_key),
//                 client_config: Arc::new(russh::client::Config::default()),
//                 default_port: 830,
//             },
//         )
//         .unwrap();
//
//         tokio::time::sleep(Duration::from_millis(100)).await;
//         let request = handle.request_tx();
//         let (one_tx, one_rx) = oneshot::channel();
//         let subscription_info = SubscriptionInfo::new(
//             SocketAddr::from_str("10.215.132.91:8301").unwrap(),
//             "".into(),
//             "".into(),
//             vec!["ietf-interfaces".into()],
//         );
//         tokio::time::sleep(Duration::from_millis(100)).await;
//         request
//             .send(CacheLookupCommand::LookupBySubscriptionInfoOneShot(
//                 subscription_info,
//                 one_tx,
//             ))
//             .await
//             .unwrap();
//         tokio::time::sleep(Duration::from_millis(100)).await;
//         let x = one_rx.await.expect("Failed to receive response");
//         eprintln!("GOT: {x:?}");
//     }
// }
