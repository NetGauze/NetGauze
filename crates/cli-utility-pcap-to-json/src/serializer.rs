use crate::PcapData;
use netgauze_flow_pkt::FlowInfo;
use serde::Serialize;
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf};
use netgauze_udp_notif_pkt::MediaType;
use serde_json::Value;
use tokio::{fs::File as AsyncFile, io::AsyncWriteExt, io::BufWriter};

#[derive(Debug, Serialize)]
struct SerializableFlowInfo {
    info: FlowInfo,
    source_address: SocketAddr,
}

pub async fn serialize_data_to_jsonl(
    rx: async_channel::Receiver<Arc<PcapData>>,
    output_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let output_file = AsyncFile::create(output_path.as_path()).await?;
    let mut writer = BufWriter::new(output_file);

    while let Ok(pcap_data_arc) = rx.recv().await {
        match pcap_data_arc.as_ref() {
            PcapData::Flow(flow_request) => {
                let (source_address, flow_info) = flow_request;
                let serializable_flow = SerializableFlowInfo {
                    info: flow_info.clone(),
                    source_address: *source_address,
                };
                let json_string = serde_json::to_string(&serializable_flow)?;
                writer.write_all(json_string.as_bytes()).await?;
                writer.write_all(b"\n").await?; // Add a newline to separate JSON objects
            }
            PcapData::Bmp(bmp_message) => {
                let json_string = serde_json::to_string(&bmp_message)?;
                writer.write_all(json_string.as_bytes()).await?;
                writer.write_all(b"\n").await?; // Add a newline to separate JSON objects
            }
            PcapData::UDPNotif(udp_notif_packet) => {
                let mut value = serde_json::to_value(&udp_notif_packet)
                    .expect("Couldn't serialize UDP-Notif message to json");
                // Convert when possible inner payload into human-readable format
                match udp_notif_packet.media_type() {
                    MediaType::YangDataJson => {
                        let payload = serde_json::from_slice(udp_notif_packet.payload())
                            .expect("Couldn't deserialize JSON payload into a JSON object");
                        if let Value::Object(val) = &mut value {
                            val.insert("payload".to_string(), payload);
                        }
                    }
                    MediaType::YangDataXml => {
                        let payload = std::str::from_utf8(udp_notif_packet.payload())
                            .expect("Couldn't deserialize XML payload into an UTF-8 string");
                        if let Value::Object(val) = &mut value {
                            val.insert(
                                "payload".to_string(),
                                Value::String(payload.to_string()),
                            );
                        }
                    }
                    MediaType::YangDataCbor => {
                        let payload: Value =
                            ciborium::de::from_reader(std::io::Cursor::new(udp_notif_packet.payload()))
                                .expect("Couldn't deserialize CBOR payload into a CBOR object");
                        if let Value::Object(val) = &mut value {
                            val.insert("payload".to_string(), payload);
                        }
                    }
                    _ => {}
                }
                let json_string = serde_json::to_string(&value).unwrap();
                writer.write_all(json_string.as_bytes()).await?;
                writer.write_all(b"\n").await?; // Add a newline to separate JSON objects
            }
        }
    }

    writer.flush().await?;
    println!("Successfully wrote flows to {:?}", output_path);
    Ok(())
}
