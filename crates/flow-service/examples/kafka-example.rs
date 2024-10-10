// use netgauze_flow_pkt::{ipfix, FlowInfo};
// use netgauze_flow_service::flow_supervisor::{
//     FlowCollectorsSupervisorActorHandle, SupervisorConfig,
// };
// use rdkafka::{
//     producer::{FutureProducer, FutureRecord},
//     ClientConfig,
// };
// use serde::Serialize;
// use std::time::Duration;
// use tokio::{sync::mpsc, task::JoinHandle};
//
// use netgauze_flow_pkt::ie::HasIE;
//
// fn init_tracing() {
//     // Very simple setup at the moment to validate the instrumentation in the
// code     // is working in the future that should be configured automatically
// based on     // configuration options
//     let subscriber = tracing_subscriber::FmtSubscriber::builder()
//         .with_max_level(tracing::Level::DEBUG)
//         .finish();
//     tracing::subscriber::set_global_default(subscriber).expect("setting
// default subscriber failed"); }
//
// #[derive(Debug, Serialize)]
// struct KafkaFlowMessage {
//     peer: String,
//     flow_info: FlowInfo,
// }
//
// pub struct KafkaPublisherActor {
//     supervisor_handle: FlowCollectorsSupervisorActorHandle,
//     producer: FutureProducer,
//     kafka_topic: String,
// }
//
// impl KafkaPublisherActor {
//     pub async fn new(
//         supervisor_handle: FlowCollectorsSupervisorActorHandle,
//         kafka_brokers: Vec<String>,
//         kafka_topic: String,
//     ) -> Result<(JoinHandle<()>, mpsc::Sender<KafkaPublisherCommand>),
// Box<dyn std::error::Error>>     {
//         let producer: FutureProducer = ClientConfig::new()
//             .set("bootstrap.servers", &kafka_brokers.join(","))
//             .set("message.timeout.ms", "5000")
//             .create()?;
//
//         let actor = Self {
//             supervisor_handle,
//             producer,
//             kafka_topic,
//         };
//
//         let (tx, rx) = mpsc::channel(100);
//         let join_handle = tokio::spawn(actor.run(rx));
//
//         Ok((join_handle, tx))
//     }
//
//     async fn run(self, mut cmd_rx: mpsc::Receiver<KafkaPublisherCommand>) {
//         let (flow_rx, subscriptions) = self
//             .supervisor_handle
//             .subscribe(10000)
//             .await
//             .expect("Failed to subscribe to supervisor");
//
//         tokio::pin!(flow_rx);
//
//         loop {
//             tokio::select! {
//                 Some(cmd) = cmd_rx.recv() => {
//                     match cmd {
//                         KafkaPublisherCommand::Shutdown => {
//                             println!("Shutting down KafkaPublisherActor");
//                             break;
//                         }
//                     }
//                 }
//                 Some(flow_result) = flow_rx.recv() => {
//                     let (peer, flow_info) = flow_result.as_ref();
//                     let c = flow_info.clone();
//                     match c {
//
//                         FlowInfo::NetFlowV9(_) => {}
//                         FlowInfo::IPFIX(pkt) => {
//                             for s in pkt.sets() {
//                                 match s {
//                                 ipfix::Set::Template(_) => {}
//                                     ipfix::Set::OptionsTemplate(_) => {}
//                                     ipfix::Set::Data{ id, records } => {
//                                         for record in records {
//                                             for field in record.fields() {
//                                                 field.ie();
//                                             }
//                                         }
//                                     }
//                                 }
//                             }
//                         }
//                     }
//                     let message = KafkaFlowMessage {
//                         peer: peer.to_string(),
//                         flow_info: flow_info.clone(),
//                     };
//
//                     let key = peer.to_string();
//                     let payload = serde_json::to_string(&message).unwrap();
//
//                     let record = FutureRecord::to(&self.kafka_topic)
//                         .payload(&payload)
//                         .key(&key);
//
//                     if let Err(e) = self.producer.send(record,
// Duration::from_secs(0)).await {                         eprintln!("Failed to
// send message to Kafka: {:?}", e);                     }
//                 }
//                 else => break,
//             }
//         }
//
//         // Unsubscribe and shutdown
//         let _ = self.supervisor_handle.unsubscribe(subscriptions).await;
//         let _ = self.supervisor_handle.shutdown().await;
//     }
// }
//
// pub enum KafkaPublisherCommand {
//     Shutdown,
// }
//
// fn a() {
//     use apache_avro::{types::Record, Schema, Writer};
//
//     let raw_schema = r#"
//     {
//         "type": "record",
//         "name": "test",
//         "fields": [
//             {"name": "a", "type": "long", "default": 42},
//             {"name": "b", "type": "string"}
//         ]
//     }
//     "#;
//
//     // if the schema is not valid, this function will return an error
//     let schema = Schema::parse_str(raw_schema).unwrap();
//
//     // a writer needs a schema and something to write to
//     let mut writer = Writer::new(&schema, Vec::new());
//
//     // the Record type models our Record schema
//     let mut record = Record::new(writer.schema()).unwrap();
//     record.put("a", 27i64);
//     record.put("b", "foo");
//
//     // schema validation happens here
//     writer.append(record).unwrap();
//
//     // this is how to get back the resulting avro bytecode
//     // this performs a flush operation to make sure data has been written, so
// it can     // fail you can also call `writer.flush()` yourself without
// consuming the     // writer
//     let encoded = writer.into_inner().unwrap();
// }
// // Usage example
// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     init_tracing();
//     let supervisor_config = SupervisorConfig::default();
//     let kafka_brokers = vec!["localhost:19092".to_string()];
//     let kafka_topic = "flow_data".to_string();
//
//     let (supervisor_join_handle, supervisor_handle) =
//         FlowCollectorsSupervisorActorHandle::new(supervisor_config).await;
//
//     let (join_handle, cmd_tx) =
//         KafkaPublisherActor::new(supervisor_handle.clone(), kafka_brokers,
// kafka_topic).await?;
//
//     // Run for a while...
//     tokio::time::sleep(Duration::from_secs(600)).await;
//
//     supervisor_join_handle.await?;
//     // Shutdown kafka producer
//     let _ = cmd_tx.send(KafkaPublisherCommand::Shutdown).await;
//     join_handle.await?;
//
//     Ok(())
// }

fn main() {}
