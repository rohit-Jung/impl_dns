use std::net::{Ipv4Addr, Ipv6Addr};

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
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
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
                    // TODO: handle error here
                }

                let raw_addr = buf.read_u32()?;
                let addr = Ipv4Addr::from(raw_addr);

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buf.read_u32()?;
                let raw_addr2 = buf.read_u32()?;
                let raw_addr3 = buf.read_u32()?;
                let raw_addr4 = buf.read_u32()?;

                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buf.read_qname(&mut ns)?;
                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buf.read_qname(&mut cname)?;
                Ok(DnsRecord::NS {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buf.read_u16()?;
                let mut mx = String::new();
                buf.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buf.pos();

        match *self {
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::A.to_num())?;
                buf.write_u16(1)?;

                buf.write_u32(ttl)?;

                let octets = addr.octets();
                buf.write_u8(octets[0])?;
                buf.write_u8(octets[1])?;
                buf.write_u8(octets[2])?;
                buf.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::NS.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos() - (pos + 2);
                buf.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::CNAME.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos() - (pos + 2);
                buf.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::MX.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?;

                buf.write_u16(priority)?;
                buf.write_qname(host)?;

                let size = buf.pos() - (pos + 2);
                buf.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                addr,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::MX.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                for octet in &addr.segments() {
                    buf.write_u16(*octet)?;
                }
            }
        }

        Ok(buf.pos() - start_pos)
    }
}
