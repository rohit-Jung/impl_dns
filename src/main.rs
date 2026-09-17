use std::net::UdpSocket;

use dns_resolver::{
    protocol::{packet::DnsPacket, question::DnsQuestion},
    types::{
        bytepacket_buffer::{BytePacketBuffer, Result},
        query_type::QueryType,
        result_code::ResultCode,
    },
};

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // use cloudflare dns
    let cloudflare_dns = ("1.1.1.1", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6969;
    packet.header.question_count = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // let mut f = File::open("raw_packets/response_packet.txt")?;
    let mut req_buf = BytePacketBuffer::new();

    // write the packet into req_buf  and send to server using socket
    packet.write(&mut req_buf)?;
    socket.send_to(&req_buf.buf[0..req_buf.pos], cloudflare_dns)?;

    // socket write response to res_buf
    let mut res_buf = BytePacketBuffer::new();
    socket.recv_from(&mut res_buf.buf)?;

    // parse the recevied response
    DnsPacket::from_buffer(&mut res_buf)
}

fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut req_buf = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buf.buf)?;

    // convert request to packet
    let mut request = DnsPacket::from_buffer(&mut req_buf)?;

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.query_or_response = true; // its a response

    // loop through the available questions
    if let Some(question) = request.questions.pop() {
        println!("received query {:?}", question);

        // forward the query to the target server
        // if anything goes wrong SERVFAIL, else records are copied in response packet
        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);

            for a in result.answers {
                println!("answers: {:#?}", a);
                packet.answers.push(a);
            }

            for ns in result.authorities {
                println!("authorities: {:#?}", ns);
                packet.authorities.push(ns);
            }

            for r in result.resources {
                println!("resources: {:#?}", r);
                packet.resources.push(r);
            }
        } else {
            packet.header.response_code = ResultCode::SERVFAIL;
        }
    } else {
        // if any arbitary (insecure) data is there FORERROR
        packet.header.response_code = ResultCode::FORMERR
    }

    let mut res_buf = BytePacketBuffer::new();
    packet.write(&mut res_buf)?;

    let len = res_buf.pos();
    let data = res_buf.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> Result<()> {
    // bind udp socket
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // for now queries are handled sequentially, so an infinite loop
    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(err) => eprintln!("Error occured while handling the query: {}", err),
        }
    }
}
