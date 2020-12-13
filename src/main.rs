use std::process::exit;
use async_std;
use futures::try_join;
use log::{
    error,
    warn,
    LevelFilter,
};
use simple_logger::SimpleLogger;
use smol::prelude::*;
use smol::{
    channel::{
        self,
        Sender,
    },
};
use std::sync::Arc;
use pcap_async::{
    Config,
    Handle,
    Packet,
    PacketStream,
};
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

async fn packet_loop(
    mut packet_stream: PacketStream,
    sender: Sender<Packet>
) -> Result<(), Box<dyn std::error::Error>>
{
    while let Some(packets) = packet_stream.next().await {
        for packet in packets? {
            if let Err(_) = sender.try_send(packet) {
                warn!("Buffer is full, dropping packet");
            };
        }
    }
    Ok(())
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    SimpleLogger::new()
        .with_level(LevelFilter::Off)
        .with_module_level("dns_metrics", LevelFilter::Info)
        .init()
        .unwrap();
    let handle = Handle::lookup().expect("No handle created");
    let mut config = Config::default();
    config.with_bpf("udp port 53".into());
    let packet_stream = match PacketStream::new(config, Arc::clone(&handle)) {
        Ok(packet_stream) => packet_stream,
        Err(error) => {
            error!("Could not start packet capture: {}", error);
            exit(1);
        },
    };

    let mut registry = Registry::default();
    let metrics = Metrics::new(&mut registry);
    let (sender, receiver) = channel::bounded(5000);
    let processor = PacketProcessor::new(receiver, RequestTracker::default(), metrics);
    let mut app = tide::with_state(registry);
    app.at("/metrics").get(collect_metrics);

    let processor_task = smol::spawn(async move {
        processor.run().await
    });
    let exposer_task = smol::spawn(async move {
        match app.listen("127.0.0.1:8080").await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Error starting HTTP server: {}", e);
                Err(())
            }
        }
    });
    let packet_sniffer_task = smol::spawn(async move {
        let result = packet_loop(packet_stream, sender).await;
        handle.interrupt();
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                error!("Error while capturing packets: {:?}", error);
                Err(())
            }
        }
    });
    if let Err(_) = try_join!(processor_task, exposer_task, packet_sniffer_task) {
        error!("Error encountered, shutting down");
    }
    Ok(())
}
