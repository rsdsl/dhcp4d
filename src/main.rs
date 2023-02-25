use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:67")?;

    sock.set_broadcast(true)?;

    loop {
        let mut buf = [0; 1024];
        let (n, remote) = sock.recv_from(&mut buf)?;
        let buf = &buf[..n];

        let remote = match remote.ip() {
            IpAddr::V4(addr) => addr,
            _ => {
                unreachable!();
            }
        };

        match handle_request(buf, remote) {
            Ok(_) => {}
            Err(e) => eprintln!("erroneous request from {}: {}", remote, e),
        }
    }
}

fn handle_request(buf: &[u8], remote: Ipv4Addr) -> anyhow::Result<()> {
    todo!();
}
