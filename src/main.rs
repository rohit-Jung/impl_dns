use std::net::UdpSocket;

use dns_resolver::{
    protocol::{packet::DnsPacket, question::DnsQuestion},
    types::{
        bytepacket_buffer::{BytePacketBuffer, Result},
        query_type::QueryType,
    },
};

fn main() -> Result<()> {
    // a query for rohitjungkathet.com.np
    let qname = "rohitjungkathet.com.np";
    let qtype = QueryType::A;

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
    let packet = DnsPacket::from_buffer(&mut res_buf)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }

    for a in packet.answers {
        println!("{:#?}", a);
    }

    for ns in packet.authorities {
        println!("{:#?}", ns);
    }

    for r in packet.resources {
        println!("{:#?}", r);
    }

    Ok(())
}
