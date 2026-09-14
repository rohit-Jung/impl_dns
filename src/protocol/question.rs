
use crate::types::{
    bytepacket_buffer::{BytePacketBuffer, Result},
    query_type::QueryType,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buf.read_u16()?);

        let _ = buf.read_u16()?; // for class 
        Ok(())
    }
}
