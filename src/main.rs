use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use async_std;
use async_std::task::sleep;
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
use structopt::StructOpt;
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

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct Options {
    #[structopt(short, long, default_value = "0.0.0.0")]
    address: String,

    #[structopt(short, long, default_value = "8080")]
    port: u16,

    #[structopt(short, long, default_value = "5000")]
    buffer_size: u16,

    /// The number of seconds to wait until a non answered DNS query is considered to be timed out
    #[structopt(short, long, default_value = "10")]
    timeout: u16,

    #[structopt(name = "interface")]
    interface: String,
}

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

fn construct_packet_handle(interface: &String) -> (Arc<Handle>, PacketStream) {
    let handle = match Handle::live_capture(interface) {
        Ok(handle) => handle,
        Err(error) => {
            error!("Failed to create capture handle: {}", error);
            exit(1);
        }
    };
    let mut config = Config::default();
    config.with_bpf("udp port 53".into());
    let packet_stream = match PacketStream::new(config, Arc::clone(&handle)) {
        Ok(packet_stream) => packet_stream,
        Err(error) => {
            error!("Could not start packet capture: {}", error);
            exit(1);
        },
    };
    (handle, packet_stream)
}

async fn entry_expiration_loop(request_tracker: RequestTracker, metrics: Metrics) {
    loop {
        sleep(Duration::from_secs(10)).await;
        let timed_out_requests = request_tracker.expire_requests();
        metrics.record_query_timeouts(timed_out_requests as u64);
    }
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    SimpleLogger::new()
        .with_level(LevelFilter::Off)
        .with_module_level("dns_metrics", LevelFilter::Info)
        .init()
        .unwrap();

    let options = Options::from_args();
    let metrics_endpoint = format!("{}:{}", options.address, options.port);
    let (handle, packet_stream) = construct_packet_handle(&options.interface);

    let mut registry = Registry::default();
    let metrics = Metrics::new(&mut registry);
    let (sender, receiver) = channel::bounded(options.buffer_size as usize);
    let request_tracker = RequestTracker::with_expiration(Duration::from_secs(options.timeout as u64));
    let processor = PacketProcessor::new(receiver, request_tracker.clone(), metrics.clone());
    let mut web_app = tide::with_state(registry);
    web_app.at("/metrics").get(collect_metrics);

    let processor_task = smol::spawn(async move {
        processor.run().await
    });
    let exposer_task = smol::spawn(async move {
        match web_app.listen(metrics_endpoint).await {
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
    let expire_requests_task = smol::spawn(async move {
        entry_expiration_loop(request_tracker, metrics).await;
        Ok(())
    });
    if let Err(_) = try_join!(processor_task, exposer_task, packet_sniffer_task, expire_requests_task) {
        error!("Error encountered, shutting down");
    }
    Ok(())
}
