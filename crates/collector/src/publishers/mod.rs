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

use netgauze_rdkafka::{
    message::DeliveryResult,
    producer::{NoCustomPartitioner, ProducerContext},
    ClientContext,
};
use tracing::{trace, warn};

pub mod http;
pub mod kafka_avro;
pub mod kafka_json;

/// Producer context with tracing logs enabled
#[derive(Clone)]
pub struct LoggingProducerContext {
    pub telemetry_attributes: Box<[opentelemetry::KeyValue]>,
    pub delivered_messages: opentelemetry::metrics::Counter<u64>,
    pub failed_delivery_messages: opentelemetry::metrics::Counter<u64>,
}

impl ClientContext for LoggingProducerContext {}

impl ProducerContext<NoCustomPartitioner> for LoggingProducerContext {
    type DeliveryOpaque = ();

    fn delivery(&self, delivery_result: &DeliveryResult<'_>, _: Self::DeliveryOpaque) {
        match delivery_result {
            Ok(_) => {
                trace!("Message delivered successfully to kafka");
                self.delivered_messages.add(1, &self.telemetry_attributes);
            }
            Err((err, _)) => {
                warn!("Failed to deliver message to kafka: {err}");
                self.failed_delivery_messages
                    .add(1, &self.telemetry_attributes)
            }
        }
    }
}
