# dns metrics

A [Rust](https://www.rust-lang.org/) toy project to capture DNS packets and emit various metrics based on them:

* Number of queries
* Number of records queried by record type and class
* Query latency

The collected metrics are exposed via an HTTP endpoint using [prometheus](https://prometheus.io/) format.

## Running

This application requires either **root permissions** or the right capabilities to run.

There's only a handful of parameters you can provide. The only required one is the interface to capture on:

```bash
./target/release/dns-metrics eth0
```

This will start capturing DNS packets and exposing prometheus metrics in an endpoint reachable at http://0.0.0.0:8080/metrics.

The following option parameters can also be specified:

* `-a, --address <address>` (default: 0.0.0.0): the address to bind the HTTP server on.
* `-b, --buffer-size <buffer-size>` (default: 5000): the buffer size to use internally. If the consumption of this buffer
is not fast enough, packets will be dropped.
* `-p, --port <port>` (default: 8080): the port to bind the HTTP server on.


## Metrics

The exposed metrics are the following ones:

* `queries_total`: A counter that is increased for every query captured.
* `query_latency_seconds`: A histogram that contains the latency between a query and the associated response are captured.
The timestamp of the captured packets is used to determine the latency.
* `questions_total`: The total number of queried records per class and type.

As an example, this is what the HTTP endpoint exposes:

```
# HELP queries_total Number of queries made
# TYPE queries_total counter
queries_total 219
# HELP query_latency_seconds DNS query latency in seconds
# TYPE query_latency_seconds histogram
query_latency_seconds_bucket{le="0.001"} 0
query_latency_seconds_bucket{le="0.003"} 0
query_latency_seconds_bucket{le="0.005"} 0
query_latency_seconds_bucket{le="0.01"} 0
query_latency_seconds_bucket{le="0.025"} 111
query_latency_seconds_bucket{le="0.05"} 138
query_latency_seconds_bucket{le="0.075"} 155
query_latency_seconds_bucket{le="0.1"} 180
query_latency_seconds_bucket{le="0.25"} 219
query_latency_seconds_bucket{le="0.5"} 219
query_latency_seconds_bucket{le="1"} 219
query_latency_seconds_bucket{le="2.5"} 219
query_latency_seconds_bucket{le="5"} 219
query_latency_seconds_bucket{le="10"} 219
query_latency_seconds_bucket{le="+Inf"} 219
query_latency_seconds_sum 11.573999999999995
query_latency_seconds_count 219
# HELP questions_total Number of questions per type/class
# TYPE questions_total counter
questions_total{class="IN",type="A"} 200
questions_total{class="IN",type="AAAA"} 18
questions_total{class="IN",type="MX"} 1

```

## Caveat

This is using a `HashMap` to keep DNS queries made and nothing is cleaning up timed out requests from it. As a side
effect, this will eventually blow up in any environment given DNS query timeouts are bound to happen everywhere.
This would also blow up a lot faster if someone was purposely sending DNS queries which would never be answered
