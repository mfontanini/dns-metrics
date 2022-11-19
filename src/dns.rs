use dns_parser::{Class, QueryClass, QueryType};
use std::cmp::Ordering;
use std::net::IpAddr;
use std::time::SystemTime;

type Endpoint = (IpAddr, u16);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct DnsRequestId {
    lower_endpoint: Endpoint,
    upper_endpoint: Endpoint,
    request_id: u16,
}

impl DnsRequestId {
    pub fn new(
        source_address: IpAddr,
        source_port: u16,
        target_address: IpAddr,
        target_port: u16,
        request_id: u16,
    ) -> Self {
        let (lower_endpoint, upper_endpoint) = match source_address.cmp(&target_address) {
            Ordering::Less => ((source_address, source_port), (target_address, target_port)),
            _ => ((target_address, target_port), (source_address, source_port)),
        };
        Self {
            lower_endpoint,
            upper_endpoint,
            request_id,
        }
    }
}

#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub query_type: QueryType,
    pub query_class: QueryClass,
}

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: String,
    pub ttl: u32,
    pub resource_class: Class,
    pub data: ResourceData,
}

#[derive(Debug)]
pub enum ResourceData {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
    Unknown,
}

#[derive(Debug)]
pub struct DnsQuery {
    pub timestamp: SystemTime,
    pub questions: Vec<Question>,
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub timestamp: SystemTime,
    pub records: Vec<ResourceRecord>,
}

#[derive(Debug)]
pub enum DnsBody {
    Query(DnsQuery),
    Answer(DnsAnswer),
}
