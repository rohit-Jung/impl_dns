use crate::{
    protocol::{packet::DnsPacket, question::DnsQuestion},
    types::{
        bytepacket_buffer::{BytePacketBuffer, Result},
        query_type::QueryType,
        result_code::ResultCode,
    },
};
use std::{
    net::{Ipv4Addr, UdpSocket},
    time::Duration,
};

pub fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6969;
    packet.header.question_count = 1;
    packet.header.recursion_desired = false;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // let mut f = File::open("raw_packets/response_packet.txt")?;
    let mut req_buf = BytePacketBuffer::new();

    // write the packet into req_buf  and send to server using socket
    packet.write(&mut req_buf)?;
    socket.send_to(&req_buf.buf[0..req_buf.pos], server)?;

    // socket write response to res_buf
    let mut res_buf = BytePacketBuffer::new();
    socket.recv_from(&mut res_buf.buf)?;

    // validate (src, len) transaction ID, etc

    // parse the recevied response
    DnsPacket::from_buffer(&mut res_buf)
}

pub fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // always start with root servers
    // ref: https://www.internic.net/domain/named.root
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!(
            "attempting to lookup {:?} record of {} with ns {}",
            qtype, qname, ns
        );

        let ns_copy = ns;
        let server = (ns_copy, 53);

        let response = lookup(qname, qtype, server)?;

        // we got the answers: similar to base case ?
        if !response.answers.is_empty() && response.header.response_code == ResultCode::NOERR {
            return Ok(response);
        }

        // got no authoritative name servers NXDOMAIN
        if response.header.response_code == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // getting new server based on ns
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        // get unresolved host and look again
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        // pick a random ip from the result and restart the loop
        let recursive_response = recursive_lookup(new_ns_name, QueryType::A)?;

        // if not found return the last result found
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response); // last result
        }
    }
}
