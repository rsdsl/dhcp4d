use anyhow::anyhow;
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};

use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};

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

    let msg = Message::decode(&mut Decoder::new(buf))?;

    let op = msg.opcode();
    match op {
        Opcode::BootRequest => {
            let xid = msg.xid();
            let opts = msg.opts();

            let msg_type = opts
                .msg_type()
                .ok_or(anyhow!("no message type given from {}", remote))?;

            match msg_type {
                MessageType::Discover => {
                    let mut resp = Message::default();
                    let opts = resp
                        .set_flags(Flags::default().set_broadcast())
                        .set_chaddr(chaddr)
                        .set_xid(xid)
                        .opts_mut();

                    opts.insert(DhcpOption::MessageType(MessageType::Offer));

                    let mut resp_buf = Vec::new();
                    resp.encode(&mut Encoder::new(&mut resp_buf))?;

                    let n = sock.send_to(&resp_buf, remote)?;

                    if n != resp_buf.len() {
                        Err(anyhow!(
                            "message length inconsistency sending to {}",
                            remote
                        ))
                    } else {
                        Ok(())
                    }
                }
                _ => Err(anyhow!(
                    "invalid message type {:?} from {}",
                    msg_type,
                    remote
                )),
            }
        }
        _ => Err(anyhow!("invalid opcode {:?} from {}", op, remote)),
    }
}
