use log::{
    warn,
    LevelFilter,
};
use simple_logger::SimpleLogger;
use smol::prelude::*;
use smol::channel;
use std::sync::Arc;
use pcap_async::{Config, Handle, PacketStream};
use prometheus::{
    Encoder,
    Registry,
    TextEncoder,
};
use dns_metrics::{
    processing::PacketProcessor,
    tracking::RequestTracker,
    metrics::Metrics,
};

async fn collect_metrics(request: tide::Request<Registry>) -> tide::Result<String> {
    let registry = request.state();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_familys = registry.gather();
    for mf in metric_familys {
        if let Err(e) = encoder.encode(&[mf], &mut buffer) {
            warn!("Ignoring prometheus encoding error: {:?}", e);
        }
    }
    Ok(String::from_utf8(buffer.clone()).unwrap())
}

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
    let mut registry = Registry::default();
    let metrics = Metrics::new(&mut registry);
    let processor = PacketProcessor::new(receiver, RequestTracker::default(), metrics);
    smol::spawn(async move {
        processor.run().await
    }).detach();

    let mut app = tide::with_state(registry);
    app.at("/metrics").get(collect_metrics);
    smol::spawn(async move {
        app.listen("127.0.0.1:8080").await
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
