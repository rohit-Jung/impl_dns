use std::{io::Result, net::UdpSocket};

fn handle_query(socket: &UdpSocket) -> Result<()> {
    Ok(())
}

fn main() -> Result<()> {
    // dns works on top of udp
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("error occured: {:?}", err)
            }
        }
    }
}
