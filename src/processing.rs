use crate::{
    dns::{DnsAnswer, DnsBody, DnsQuery},
    metrics::Metrics,
    packet::Packet,
    tracking::RequestTracker,
};
use log::{debug, warn};
use pcap_async::Packet as RawPacket;
use smol::prelude::*;
use std::time::SystemTime;

pub struct PacketProcessor<T>
where
    T: Stream<Item = RawPacket>,
{
    raw_packet_stream: T,
    tracker: RequestTracker,
    metrics: Metrics,
}

impl<T> PacketProcessor<T>
where
    T: Stream<Item = RawPacket> + Unpin,
{
    pub fn new(raw_packet_stream: T, tracker: RequestTracker, metrics: Metrics) -> Self {
        Self {
            raw_packet_stream,
            tracker,
            metrics,
        }
    }

    pub async fn run(mut self) -> Result<(), ()> {
        while let Some(raw_packet) = self.raw_packet_stream.next().await {
            let timestamp = *raw_packet.timestamp();
            let data = raw_packet.into_data();
            let packet = match Packet::new(&data, timestamp) {
                Ok(packet) => packet,
                Err(e) => {
                    debug!("Invalid packet found: {:?}", e);
                    continue;
                }
            };
            self.process_packet(packet);
        }
        warn!("Stopping packet processor run loop");
        Ok(())
    }

    fn process_packet(&mut self, packet: Packet) {
        let id = packet.id();
        let body = packet.body();
        match body {
            DnsBody::Query(query) => {
                self.emit_query_metrics(&query);
                self.tracker.add_query(id, query);
            }
            DnsBody::Answer(answer) => {
                let original_query = self.tracker.match_answer(&id);
                if let Some(query) = original_query {
                    self.emit_answer_metrics(&query.timestamp, answer);
                }
            }
        }
    }

    fn emit_query_metrics(&mut self, query: &DnsQuery) {
        self.metrics.record_query();
        for question in &query.questions {
            self.metrics
                .record_question(&question.query_type, &question.query_class);
        }
    }

    fn emit_answer_metrics(&mut self, query_timestamp: &SystemTime, answer: DnsAnswer) {
        match answer.timestamp.duration_since(*query_timestamp) {
            Ok(elapsed) => self.metrics.observe_query_latency(&elapsed),
            Err(_) => warn!("Answer came before request (clock drift?)"),
        };
    }
}
