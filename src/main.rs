use dhcp4d::lease::{LeaseDummyManager, LeaseManager};

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use anyhow::{anyhow, bail};
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};

fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:67")?;

    sock.set_broadcast(true)?;

    loop {
        let mut buf = [0; 1024];
        let (n, remote) = sock.recv_from(&mut buf)?;
        let buf = &buf[..n];

        let remote = match remote {
            SocketAddr::V4(addr) => addr,
            _ => {
                unreachable!();
            }
        };

        match handle_request(&sock, buf, remote) {
            Ok(_) => {}
            Err(e) => eprintln!("erroneous request from {}: {}", remote, e),
        }
    }
}

fn handle_request(sock: &UdpSocket, buf: &[u8], remote: SocketAddrV4) -> anyhow::Result<()> {
    let chaddr = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let lease_mgr = LeaseDummyManager::new(None);

    let msg = Message::decode(&mut Decoder::new(buf))?;

    let op = msg.opcode();
    match op {
        Opcode::BootRequest => {
            let xid = msg.xid();
            let opts = msg.opts();

            let msg_type = opts.msg_type().ok_or(anyhow!("no message type given"))?;

            match msg_type {
                MessageType::Discover => {
                    let client_id = match opts
                        .get(OptionCode::ClientIdentifier)
                        .ok_or(anyhow!("no client id"))?
                    {
                        DhcpOption::ClientIdentifier(id) => id,
                        _ => bail!("expected ClientIdentifier"),
                    };

                    let free_addr = choose_free_address(lease_mgr, client_id)
                        .ok_or(anyhow!("no free addresses available"))?;

                    let mut resp = Message::default();
                    let opts = resp
                        .set_flags(Flags::default().set_broadcast())
                        .set_opcode(Opcode::BootReply)
                        .set_xid(xid)
                        .set_siaddr(free_addr)
                        .set_chaddr(chaddr)
                        .opts_mut();

                    opts.insert(DhcpOption::MessageType(MessageType::Offer));

                    let mut resp_buf = Vec::new();
                    resp.encode(&mut Encoder::new(&mut resp_buf))?;

                    let n = sock.send_to(&resp_buf, remote)?;

                    if n != resp_buf.len() {
                        Err(anyhow!("partial response"))
                    } else {
                        let cid = client_id
                            .iter()
                            .map(|octet| format!("{:x}", octet))
                            .reduce(|acc, octet| acc + &octet)
                            .ok_or(anyhow!("zero-length client id"))?;

                        println!("offering {} to client ID {}", free_addr, cid);

                        Ok(())
                    }
                }
                _ => Err(anyhow!("invalid message type {:?}", msg_type,)),
            }
        }
        _ => Err(anyhow!("invalid opcode {:?}", op)),
    }
}

fn choose_free_address<T: LeaseManager>(lease_mgr: T, client_id: &[u8]) -> Option<Ipv4Addr> {
    lease_mgr.any_free_address()
}
