use crate::{
    protocol::{header::DnsHeader, question::DnsQuestion, record::DnsRecord},
    types::{
        bytepacket_buffer::{BytePacketBuffer, Result},
        query_type::QueryType,
    },
};

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buf: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buf)?;

        for _ in 0..result.header.question_count {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buf)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answer_count {
            let ans = DnsRecord::read(buf)?;
            result.answers.push(ans);
        }

        for _ in 0..result.header.authority_count {
            let authority = DnsRecord::read(buf)?;
            result.authorities.push(authority);
        }

        for _ in 0..result.header.additional_count {
            let additional = DnsRecord::read(buf)?;
            result.resources.push(additional);
        }

        Ok(result)
    }

    pub fn write(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.header.question_count = self.questions.len() as u16;
        self.header.answer_count = self.answers.len() as u16;
        self.header.authority_count = self.authorities.len() as u16;
        self.header.additional_count = self.resources.len() as u16;

        self.header.write(buf)?;

        for question in &self.questions {
            question.write(buf)?;
        }

        for ans in &self.answers {
            ans.write(buf)?;
        }

        for ns in &self.authorities {
            ns.write(buf)?;
        }

        for res in &self.resources {
            res.write(buf)?;
        }

        Ok(())
    }
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::new()
    }
}
