use dhcp4d::lease::{Lease, LeaseDummyManager, LeaseManager};

use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::thread;

use anyhow::{anyhow, bail};
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Domain, Socket, Type};

fn main() -> anyhow::Result<()> {
    let mut threads = Vec::new();

    for arg in std::env::args().skip(1) {
        threads.push(thread::spawn(|| run(arg)));
    }

    for handle in threads {
        handle.join().unwrap()?;
    }

    Ok(())
}

fn run(link: String) -> anyhow::Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

    let addresses = linkaddrs::ipv4_addresses(link)?;
    let address = addresses.first().expect("interface has no IPv4 addresses");

    let address = SocketAddr::new(IpAddr::V4(address.addr()), 67);
    sock.bind(&address.into())?;

    sock.set_broadcast(true)?;

    loop {
        let mut buf = [MaybeUninit::new(0); 1024];
        let (n, remote) = sock.recv_from(&mut buf)?;
        let buf = &buf
            .iter()
            .take(n)
            .map(|p| unsafe { p.assume_init() })
            .collect::<Vec<u8>>();

        let remote = remote.as_socket_ipv4().unwrap();

        match handle_request(&sock, buf, remote) {
            Ok(_) => {}
            Err(e) => eprintln!("erroneous request from {}: {}", remote, e),
        }
    }
}

fn handle_request(sock: &Socket, buf: &[u8], remote: SocketAddrV4) -> anyhow::Result<()> {
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

                    let lease = obtain_lease(lease_mgr, client_id)
                        .ok_or(anyhow!("no free addresses available"))?;

                    let local_addr = sock.local_addr()?.as_socket_ipv4().unwrap();

                    let mut resp = Message::default();
                    let opts = resp
                        .set_flags(Flags::default().set_broadcast())
                        .set_opcode(Opcode::BootReply)
                        .set_xid(xid)
                        .set_yiaddr(lease.address)
                        .set_siaddr(*local_addr.ip())
                        .set_chaddr(msg.chaddr())
                        .opts_mut();

                    opts.insert(DhcpOption::MessageType(MessageType::Offer));
                    opts.insert(DhcpOption::AddressLeaseTime(
                        lease.lease_time.as_secs() as u32
                    ));

                    let mut resp_buf = Vec::new();
                    resp.encode(&mut Encoder::new(&mut resp_buf))?;

                    let n = sock.send_to(&resp_buf, &remote.into())?;

                    if n != resp_buf.len() {
                        Err(anyhow!("partial response"))
                    } else {
                        let cid = client_id
                            .iter()
                            .map(|octet| format!("{:x}", octet))
                            .reduce(|acc, octet| acc + &octet)
                            .ok_or(anyhow!("zero-length client id"))?;

                        println!(
                            "offering {} to client ID {} for {:?}",
                            lease.address, cid, lease.lease_time
                        );

                        Ok(())
                    }
                }
                _ => Err(anyhow!("invalid message type {:?}", msg_type,)),
            }
        }
        _ => Err(anyhow!("invalid opcode {:?}", op)),
    }
}

fn obtain_lease<T: LeaseManager>(lease_mgr: T, client_id: &[u8]) -> Option<Lease> {
    lease_mgr.persistent_free_address(client_id)
}
