use crate::error::{Error, Result};
use socket2::Socket;
use std::net::Ipv4Addr;

pub fn format_client_id(client_id: &[u8]) -> Result<String> {
    client_id
        .iter()
        .map(|octet| format!("{:x}", octet))
        .reduce(|acc, octet| acc + ":" + &octet)
        .ok_or(Error::EmptyClientId)
}

pub fn local_ip(sock: &Socket) -> Ipv4Addr {
    let local_addr = sock.local_addr().unwrap().as_socket_ipv4().unwrap();
    *local_addr.ip()
}
