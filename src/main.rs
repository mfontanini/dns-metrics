use log::{
    warn,
    LevelFilter,
};
use simple_logger::SimpleLogger;
use smol::prelude::*;
use smol::channel;
use std::sync::Arc;
use pcap_async::{Config, Handle, PacketStream};
use dns_metrics::{
    processing::PacketProcessor,
    tracking::RequestTracker,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    SimpleLogger::new()
        .with_level(LevelFilter::Off)
        .with_module_level("dns_metrics", LevelFilter::Debug)
        .init()
        .unwrap();
    let handle = Handle::lookup().expect("No handle created");
    let mut config = Config::default();
    config.with_bpf("udp port 53".into());
    let (sender, receiver) = channel::bounded(5000);
    let processor = PacketProcessor::new(receiver, RequestTracker::default());
    smol::spawn(async move {
        processor.run().await
    }).detach();

    smol::block_on(async move {
        let mut provider = PacketStream::new(config, Arc::clone(&handle))
            .expect("Could not create provider")
            .boxed();
        while let Some(packets) = provider.next().await {
            for packet in packets? {
                if let Err(_) = sender.try_send(packet) {
                    warn!("Buffer is full, dropping packet");
                };
            }
        }
        handle.interrupt();
        Ok(())
    })
}
