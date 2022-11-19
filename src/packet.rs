use crate::dns::{
    DnsAnswer, DnsBody, DnsQuery, DnsRequestId, Question, ResourceData, ResourceRecord,
};
use dns_parser::Packet as DnsPacket;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice, UdpHeaderSlice};
use std::net::IpAddr;
use std::time::SystemTime;
use thiserror::Error;

pub struct Packet<'a> {
    ip: InternetSlice<'a>,
    udp: UdpHeaderSlice<'a>,
    dns: DnsPacket<'a>,
    timestamp: SystemTime,
}

impl<'a> Packet<'a> {
    pub fn new(payload: &'a [u8], timestamp: SystemTime) -> Result<Self, Error> {
        let packet = SlicedPacket::from_ethernet(payload)?;
        let ip = match packet.ip {
            Some(ip) => ip,
            None => return Err(Error::NoIpLayer),
        };
        let udp = match packet.transport {
            None => Err(Error::NoTransportLayer),
            Some(TransportSlice::Tcp(_)) => Err(Error::NotUdp),
            Some(TransportSlice::Udp(udp)) => Ok(udp),
        }?;
        let dns = DnsPacket::parse(packet.payload)?;
        Ok(Self {
            ip,
            udp,
            dns,
            timestamp,
        })
    }

    pub fn id(&self) -> DnsRequestId {
        let (source_address, target_address) = match &self.ip {
            InternetSlice::Ipv4(slice) => (
                IpAddr::V4(slice.source_addr()),
                IpAddr::V4(slice.destination_addr()),
            ),
            InternetSlice::Ipv6(slice, _) => (
                IpAddr::V6(slice.source_addr()),
                IpAddr::V6(slice.destination_addr()),
            ),
        };
        DnsRequestId::new(
            source_address,
            self.udp.source_port(),
            target_address,
            self.udp.destination_port(),
            self.dns.header.id,
        )
    }

    pub fn body(self) -> DnsBody {
        match self.dns.header.query {
            true => {
                let questions = self.dns.questions.iter().map(Question::from).collect();
                DnsBody::Query(DnsQuery {
                    questions,
                    timestamp: self.timestamp,
                })
            }
            false => {
                let records = self.dns.answers.iter().map(ResourceRecord::from).collect();
                DnsBody::Answer(DnsAnswer {
                    records,
                    timestamp: self.timestamp,
                })
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("packet parse: {0}")]
    PacketParse(#[from] etherparse::ReadError),

    #[error("DNS parse: {0}")]
    DnsParse(#[from] dns_parser::Error),

    #[error("no IP layer")]
    NoIpLayer,

    #[error("no transport layer")]
    NoTransportLayer,

    #[error("not an UDP packet")]
    NotUdp,
}

impl From<&dns_parser::Question<'_>> for Question {
    fn from(question: &dns_parser::Question) -> Self {
        Self {
            name: question.qname.to_string(),
            query_type: question.qtype,
            query_class: question.qclass,
        }
    }
}

impl From<&dns_parser::ResourceRecord<'_>> for ResourceRecord {
    fn from(record: &dns_parser::ResourceRecord) -> Self {
        Self {
            name: record.name.to_string(),
            ttl: record.ttl,
            resource_class: record.cls,
            data: (&record.data).into(),
        }
    }
}

impl From<&dns_parser::RData<'_>> for ResourceData {
    fn from(data: &dns_parser::RData) -> Self {
        match data {
            dns_parser::RData::A(_) => Self::A,
            dns_parser::RData::AAAA(_) => Self::AAAA,
            dns_parser::RData::CNAME(_) => Self::CNAME,
            dns_parser::RData::MX(_) => Self::MX,
            dns_parser::RData::NS(_) => Self::NS,
            dns_parser::RData::PTR(_) => Self::PTR,
            dns_parser::RData::SOA(_) => Self::SOA,
            dns_parser::RData::SRV(_) => Self::SRV,
            dns_parser::RData::TXT(_) => Self::TXT,
            dns_parser::RData::Unknown(_) => Self::Unknown,
        }
    }
}
