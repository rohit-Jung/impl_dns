use crate::types::{
    bytepacket_buffer::{BytePacketBuffer, Result},
    result_code::ResultCode,
};

/// header section ref: https://www.rfc-editor.org/info/rfc1035/#section-4.1
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DnsHeader {
    pub id: u16,

    // Flags
    pub query_or_response: bool,    // QR 1 bit
    pub opcode: u8,                 // 4 bits
    pub authoritative_answer: bool, // AA, 1 bit
    pub truncation: bool,           // TC, 1 bit
    pub recursion_desired: bool,    // RD, 1 bit
    pub recursion_available: bool,  // RA, 1 bit
    pub z: bool,                    // 1 bit, reserved
    pub checking_disabled: bool,    // CD, 1 bit
    pub authenticated_data: bool,   // AD, 1 bit
    pub response_code: ResultCode,  // RCODE, 4 bits

    // Counts
    pub question_count: u16,   // QDCOUNT
    pub answer_count: u16,     // ANCOUNT
    pub authority_count: u16,  // NSCOUNT
    pub additional_count: u16, // ARCOUNT
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            query_or_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,

            recursion_available: false,
            z: false, // default 0
            checking_disabled: false,
            authenticated_data: false,
            response_code: ResultCode::NOERR,

            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        let msb = (flags >> 8) as u8;
        let lsb = (flags & 0xFF) as u8;

        // first octet from last
        self.recursion_desired = (msb & (1 << 0)) != 0;
        self.truncation = (msb & (1 << 1)) > 0;
        self.authoritative_answer = (msb & (1 << 2)) > 0;
        self.opcode = (msb >> 3) & 0x0F; // & with 4 bit ? 
        self.query_or_response = (msb & (1 << 7)) > 0;

        // second octet
        self.response_code = ResultCode::from_num(lsb & 0x0F);
        self.checking_disabled = (lsb & (1 << 4)) > 0;
        self.authenticated_data = (lsb & (1 << 5)) > 0;
        self.z = (lsb & (1 << 6)) > 0;
        self.recursion_available = (lsb & (1 << 7)) > 0;

        self.question_count = buf.read_u16()?;
        self.answer_count = buf.read_u16()?;
        self.authority_count = buf.read_u16()?;
        self.additional_count = buf.read_u16()?;

        Ok(())
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self::new()
    }
}
