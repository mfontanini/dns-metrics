use std::time::Duration;
use dns_parser::{
    QueryClass,
    QueryType,
};
use prometheus::{
    Histogram,
    HistogramOpts,
    IntCounter,
    IntCounterVec,
    Registry,
    Opts,
};

pub struct Metrics {
    queries_counter: IntCounter,
    questions_counter: IntCounterVec,
    query_latencies: Histogram,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let queries_counter = IntCounter::new("queries_total", "Number of queries made",).unwrap();
        let questions_counter = IntCounterVec::new(
            Opts::new("questions_total", "Number of questions per type/class"),
            &["type", "class"],
        ).unwrap();
        let query_latencies_opts = HistogramOpts::new("query_latency_seconds", "DNS query latency in seconds")
            .buckets(vec![0.001, 0.003, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]);
        let query_latencies = Histogram::with_opts(query_latencies_opts).unwrap();
        let output = Self {
            queries_counter,
            questions_counter,
            query_latencies,
        };
        output.register(registry);
        output
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(Box::new(self.queries_counter.clone())).unwrap();
        registry.register(Box::new(self.questions_counter.clone())).unwrap();
        registry.register(Box::new(self.query_latencies.clone())).unwrap();
    }

    pub fn record_query(&self) {
        self.queries_counter.inc();
    }

    pub fn record_question(&self, query_type: &QueryType, query_class: &QueryClass) {
        let query_type = format!("{:?}", query_type);
        let query_class = format!("{:?}", query_class);
        self.questions_counter.with_label_values(&[&query_type, &query_class]).inc();
    }

    pub fn observe_query_latency(&self, latency: &Duration) {
        self.query_latencies.observe(latency.as_millis() as f64 / 1000.0);
    }
}
