use dhcp4d::error::{Error, Result};
use dhcp4d::lease::{LeaseFileManager, LeaseFileManagerConfig, LeaseManager};
use dhcp4d::util::{format_client_id, local_ip, setsockopt};

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Domain, Socket, Type};

const LEASE_FILE: &str = "leases.json";

fn main() -> Result<()> {
    let config = LeaseFileManagerConfig {
        range: (
            "198.51.100.100".parse().unwrap(),
            "198.51.100.249".parse().unwrap(),
        ),
        netmask: "255.255.255.0".parse().unwrap(),
        lease_time: Duration::from_secs(300),
    };

    if fs::metadata(LEASE_FILE).is_err() {
        let mut file = OpenOptions::new()
            .create(true)
            .read(false)
            .write(true)
            .open(LEASE_FILE)?;

        file.write_all(b"[]")?;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(false)
        .open(LEASE_FILE)?;

    let lease_mgr = Arc::new(Mutex::new(LeaseFileManager::new(config, file)?));

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

fn run<T: LeaseManager>(link: String, lease_mgr: Arc<Mutex<T>>) -> Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

    let address = SocketAddr::from_str("0.0.0.0:67")?;
    sock.bind(&address.into())?;

    sock.set_broadcast(true)?;
    sock.set_reuse_port(true)?;

    // Bind socket to interface.
    unsafe {
        let link_index = libc::if_nametoindex(CString::new(link)?.into_raw());

        setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::SO_BINDTODEVICE,
            link_index,
        )?;
    }

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

fn handle_request<T: LeaseManager>(
    sock: &Socket,
    lease_mgr: Arc<Mutex<T>>,
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

                    let lease_mgr = lease_mgr.lock().unwrap();
                    let lease = lease_mgr
                        .persistent_free_address(client_id)
                        .ok_or(Error::PoolExhausted)?;

                    let own_addr = local_ip(sock);

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

                    if !lease_mgr.request(*requested_addr, client_id)? {
                        let own_addr = local_ip(sock);

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
                        let own_addr = local_ip(sock);

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
                        .release(client_id)?
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
