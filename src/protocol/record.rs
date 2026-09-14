use std::net::Ipv4Addr;

use crate::types::{
    bytepacket_buffer::{BytePacketBuffer, Result},
    query_type::QueryType,
};

/// https://www.rfc-editor.org/info/rfc1035/#section-3.2.1
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buf: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buf.read_qname(&mut domain)?;

        let qtype_num = buf.read_u16()?; // two octets
        let _ = buf.read_u16()?; // class we are not using now
        let ttl = buf.read_u32()?; // 32 bit
        let data_len = buf.read_u16()?;

        let qtype = QueryType::from_num(qtype_num);

        match qtype {
            QueryType::UNKNOWN(_) => {
                let _ = buf.step(data_len as usize);
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
            QueryType::A => {
                if data_len != 4 {
                    // Return whatever error type your Result uses
                    // for an invalid A record.
                }

                let raw_addr = buf.read_u32()?;
                let addr = Ipv4Addr::from(raw_addr);

                Ok(DnsRecord::A { domain, addr, ttl })
            }
        }
    }
}
