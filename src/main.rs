use dhcp4d::error::{Error, Result};
use dhcp4d::lease::{Lease, LeaseDummyManager, LeaseManager};
use dhcp4d::util::format_client_id;

use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::thread;

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Domain, Socket, Type};

fn main() -> Result<()> {
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

fn run(link: String, lease_mgr: Arc<Mutex<LeaseDummyManager>>) -> Result<()> {
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
) -> Result<()> {
    let msg = Message::decode(&mut Decoder::new(buf))?;

    let op = msg.opcode();
    match op {
        Opcode::BootRequest => {
            let xid = msg.xid();
            let opts = msg.opts();

            let msg_type = opts.msg_type().ok_or(Error::NoMsgType)?;

            match msg_type {
                MessageType::Discover => {
                    let client_id = match opts
                        .get(OptionCode::ClientIdentifier)
                        .ok_or(Error::NoClientId)?
                    {
                        DhcpOption::ClientIdentifier(id) => id,
                        _ => unreachable!(),
                    };

                    let lease =
                        obtain_lease(lease_mgr.clone(), client_id).ok_or(Error::PoolExhausted)?;

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
                        Err(Error::PartialResponse)
                    } else {
                        println!(
                            "offering {} to client ID {} for {:?}",
                            lease.address,
                            format_client_id(client_id)?,
                            lease.lease_time
                        );

                        Ok(())
                    }
                }
                MessageType::Request => {
                    let mut lease_mgr = lease_mgr.lock().unwrap();

                    let client_id = match opts
                        .get(OptionCode::ClientIdentifier)
                        .ok_or(Error::NoClientId)?
                    {
                        DhcpOption::ClientIdentifier(id) => id,
                        _ => unreachable!(),
                    };

                    let requested_addr = match opts
                        .get(OptionCode::RequestedIpAddress)
                        .ok_or(Error::NoAddrRequested)?
                    {
                        DhcpOption::RequestedIpAddress(addr) => addr,
                        _ => unreachable!(),
                    };

                    if !lease_mgr.request(*requested_addr, client_id) {
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
                            Err(Error::PartialResponse)
                        } else {
                            println!(
                                "not ackknowledging {} for client ID {}",
                                requested_addr,
                                format_client_id(client_id)?
                            );

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
                            Err(Error::PartialResponse)
                        } else {
                            println!(
                                "ackknowledging {} for client ID {} for {:?}",
                                requested_addr,
                                format_client_id(client_id)?,
                                lease_time
                            );

                            Ok(())
                        }
                    }
                }
                MessageType::Release => {
                    let client_id = match opts
                        .get(OptionCode::ClientIdentifier)
                        .ok_or(Error::NoClientId)?
                    {
                        DhcpOption::ClientIdentifier(id) => id,
                        _ => unreachable!(),
                    };

                    let mut lease_mgr = lease_mgr.lock().unwrap();
                    let released: Vec<String> = lease_mgr
                        .release(client_id)
                        .map(|addr| addr.to_string())
                        .collect();

                    let released_pretty = released.join(", ");

                    println!(
                        "releasing {} for client ID {}",
                        released_pretty,
                        format_client_id(client_id)?
                    );
                    Ok(())
                }
                _ => Err(Error::InvalidMsgType(msg_type)),
            }
        }
        _ => Err(Error::InvalidOpcode(op)),
    }
}

fn obtain_lease<T: LeaseManager>(lease_mgr: Arc<Mutex<T>>, client_id: &[u8]) -> Option<Lease> {
    lease_mgr.lock().unwrap().persistent_free_address(client_id)
}

fn own_address(sock: &Socket) -> Ipv4Addr {
    let local_addr = sock.local_addr().unwrap().as_socket_ipv4().unwrap();
    *local_addr.ip()
}
