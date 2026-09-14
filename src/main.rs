use std::{fs::File, io::Read};

use dns_resolver::{
    protocol::packet::DnsPacket,
    types::bytepacket_buffer::{BytePacketBuffer, Result},
};

fn main() -> Result<()> {
    let mut f = File::open("raw_packets/response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();

    let _ = f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
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
