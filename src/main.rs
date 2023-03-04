use dhcp4d::lease::{Lease, LeaseDummyManager, LeaseManager};

use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{anyhow, bail};
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Domain, Socket, Type};

fn main() -> anyhow::Result<()> {
    let lease_mgr = Arc::new(Mutex::new(LeaseDummyManager::new(None)));

    let mut threads = Vec::new();
    for arg in std::env::args().skip(1) {
        let cloned_mgr = Arc::clone(&lease_mgr);
        threads.push(thread::spawn(|| run(arg, cloned_mgr)));
    }

    for handle in threads {
        handle.join().unwrap()?;
    }

    Ok(())
}

fn run(link: String, lease_mgr: Arc<Mutex<LeaseDummyManager>>) -> anyhow::Result<()> {
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

        match handle_request(&sock, lease_mgr.clone(), buf, remote) {
            Ok(_) => {}
            Err(e) => eprintln!("erroneous request from {}: {}", remote, e),
        }
    }
}

fn handle_request(
    sock: &Socket,
    lease_mgr: Arc<Mutex<LeaseDummyManager>>,
    buf: &[u8],
    remote: SocketAddrV4,
) -> anyhow::Result<()> {
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

                    let lease = obtain_lease(lease_mgr.clone(), client_id)
                        .ok_or(anyhow!("no free addresses available"))?;

                    let own_addr = own_address(sock);
                    let lease_mgr = lease_mgr.lock().unwrap();

                    let mut resp = Message::default();
                    let opts = resp
                        .set_flags(Flags::default().set_broadcast())
                        .set_opcode(Opcode::BootReply)
                        .set_xid(xid)
                        .set_yiaddr(lease.address)
                        .set_siaddr(own_addr)
                        .set_chaddr(msg.chaddr())
                        .opts_mut();

                    opts.insert(DhcpOption::MessageType(MessageType::Offer));
                    opts.insert(DhcpOption::SubnetMask(lease_mgr.netmask()));
                    opts.insert(DhcpOption::Router(vec![own_addr]));
                    opts.insert(DhcpOption::AddressLeaseTime(
                        lease.lease_time.as_secs() as u32
                    ));
                    opts.insert(DhcpOption::ServerIdentifier(own_addr));
                    opts.insert(DhcpOption::DomainNameServer(vec![own_addr]));

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
                MessageType::Request => {
                    let mut lease_mgr = lease_mgr.lock().unwrap();

                    let requested_addr = match opts
                        .get(OptionCode::RequestedIpAddress)
                        .ok_or(anyhow!("no address requested"))?
                    {
                        DhcpOption::RequestedIpAddress(addr) => addr,
                        _ => bail!("expected RequestedIpAddress"),
                    };

                    if !lease_mgr.request(*requested_addr) {
                        let own_addr = own_address(sock);

                        let mut resp = Message::default();
                        let opts = resp
                            .set_flags(Flags::default().set_broadcast())
                            .set_opcode(Opcode::BootReply)
                            .set_xid(xid)
                            .set_yiaddr(*requested_addr)
                            .set_siaddr(own_addr)
                            .set_chaddr(msg.chaddr())
                            .opts_mut();

                        opts.insert(DhcpOption::MessageType(MessageType::Nak));
                        opts.insert(DhcpOption::ServerIdentifier(own_addr));

                        let mut resp_buf = Vec::new();
                        resp.encode(&mut Encoder::new(&mut resp_buf))?;

                        let n = sock.send_to(&resp_buf, &remote.into())?;
                        if n != resp_buf.len() {
                            Err(anyhow!("partial response"))
                        } else {
                            println!("not ackknowledging {}", requested_addr);
                            Ok(())
                        }
                    } else {
                        let lease_time = lease_mgr.lease_time();
                        let own_addr = own_address(sock);

                        let mut resp = Message::default();
                        let opts = resp
                            .set_flags(Flags::default().set_broadcast())
                            .set_opcode(Opcode::BootReply)
                            .set_xid(xid)
                            .set_yiaddr(*requested_addr)
                            .set_siaddr(own_addr)
                            .set_chaddr(msg.chaddr())
                            .opts_mut();

                        opts.insert(DhcpOption::MessageType(MessageType::Ack));
                        opts.insert(DhcpOption::SubnetMask(lease_mgr.netmask()));
                        opts.insert(DhcpOption::Router(vec![own_addr]));
                        opts.insert(DhcpOption::AddressLeaseTime(lease_time.as_secs() as u32));
                        opts.insert(DhcpOption::ServerIdentifier(own_addr));
                        opts.insert(DhcpOption::DomainNameServer(vec![own_addr]));

                        let mut resp_buf = Vec::new();
                        resp.encode(&mut Encoder::new(&mut resp_buf))?;

                        let n = sock.send_to(&resp_buf, &remote.into())?;
                        if n != resp_buf.len() {
                            Err(anyhow!("partial response"))
                        } else {
                            println!("ackknowledging {} for {:?}", requested_addr, lease_time);
                            Ok(())
                        }
                    }
                }
                _ => Err(anyhow!("invalid message type {:?}", msg_type,)),
            }
        }
        _ => Err(anyhow!("invalid opcode {:?}", op)),
    }
}

fn obtain_lease<T: LeaseManager>(lease_mgr: Arc<Mutex<T>>, client_id: &[u8]) -> Option<Lease> {
    lease_mgr.lock().unwrap().persistent_free_address(client_id)
}

fn own_address(sock: &Socket) -> Ipv4Addr {
    let local_addr = sock.local_addr().unwrap().as_socket_ipv4().unwrap();
    *local_addr.ip()
}
