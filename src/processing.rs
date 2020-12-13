use std::time::SystemTime;
use log::{
    debug,
    warn,
};
use smol::prelude::*;
use pcap_async::Packet as RawPacket;
use crate::{
    dns::{
        DnsAnswer,
        DnsBody,
    },
    packet::Packet,
};
use crate::tracking::RequestTracker;

pub struct PacketProcessor<T>
where
    T: Stream<Item = RawPacket>
{
    raw_packet_stream: T,
    tracker: RequestTracker,
}

impl<T> PacketProcessor<T>
where
    T: Stream<Item = RawPacket> + Unpin
{
    pub fn new(raw_packet_stream: T, tracker: RequestTracker) -> Self {
        Self {
            raw_packet_stream,
            tracker,
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
                },
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
            DnsBody::Query(query) => self.tracker.add_query(id, query),
            DnsBody::Answer(answer) => {
                let original_query = self.tracker.match_answer(&id);
                match original_query {
                    Some(query) => self.emit_answer_metrics(&query.timestamp, answer),
                    None => (),
                }
            }
        }
    }

    fn emit_answer_metrics(&mut self, query_timestamp: &SystemTime, answer: DnsAnswer) {
        match answer.timestamp.duration_since(*query_timestamp) {
            Ok(elapsed) => println!("Query latency {:?}", elapsed),
            Err(_) => warn!("Answer came before request (clock drift?)"),
        };
    }
}