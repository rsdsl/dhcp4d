use rsdsl_dhcp4d::error::{Error, Result};
use rsdsl_dhcp4d::lease::{LeaseFileManager, LeaseFileManagerConfig, LeaseManager};
use rsdsl_dhcp4d::util::{format_client_id, local_ip, setsockopt};

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Domain, Socket, Type};

const BUFSIZE: usize = 1500;

fn main() -> Result<()> {
    run("eth0".into(), 0)?;
    Ok(())
}

fn run(link: String, subnet_id: u8) -> Result<()> {
    println!("[dhcp4d] init interface {}", link);

    let config = LeaseFileManagerConfig {
        range: (
            Ipv4Addr::new(10, 128, subnet_id, 100),
            Ipv4Addr::new(10, 128, subnet_id, 239),
        ),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        lease_time: Duration::from_secs(43200),
    };

    let lease_file = format!("/data/dhcp4d.leases_{}", link);

    if fs::metadata(&lease_file).is_err() {
        let mut file = OpenOptions::new()
            .create(true)
            .read(false)
            .write(true)
            .open(&lease_file)?;

        file.write_all(b"[]")?;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lease_file)?;

    let lease_mgr = Arc::new(Mutex::new(LeaseFileManager::new(config, file)?));

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

    sock.set_broadcast(true)?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;

    // Bind socket to interface.
    unsafe {
        let link_index = CString::new(link.clone())?.into_raw();

        setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            link_index,
            link.len() as i32,
        )?;

        // Prevent memory leak.
        let _ = CString::from_raw(link_index);
    }

    let address = SocketAddr::from_str("0.0.0.0:67")?;
    sock.bind(&address.into())?;

    loop {
        let mut buf = [MaybeUninit::new(0); BUFSIZE];
        let (n, remote) = sock.recv_from(&mut buf)?;
        let buf = &buf
            .iter()
            .take(n)
            .map(|p| unsafe { p.assume_init() })
            .collect::<Vec<u8>>();

        let remote = remote.as_socket_ipv4().unwrap();

        match handle_request(&sock, lease_mgr.clone(), buf, &link) {
            Ok(_) => {}
            Err(e) => println!(
                "[dhcp4d] recv bad request from {} on {}: {}",
                remote, link, e
            ),
        }
    }
}

fn handle_request<T: LeaseManager>(
    sock: &Socket,
    lease_mgr: Arc<Mutex<T>>,
    buf: &[u8],
    link: &str,
) -> Result<()> {
    let dst: SocketAddrV4 = "255.255.255.255:68".parse().unwrap();

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

                    let own_addr = local_ip(link)?;

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

                    let n = sock.send_to(&resp_buf, &dst.into())?;
                    if n != resp_buf.len() {
                        Err(Error::PartialResponse)
                    } else {
                        println!(
                            "[dhcp4d] offer {} to client id {} for {:?} on {}",
                            lease.address,
                            format_client_id(client_id)?,
                            lease.lease_time,
                            link
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

                    let mut renew = false;
                    let requested_addr =
                        match opts.get(OptionCode::RequestedIpAddress).map(|v| match v {
                            DhcpOption::RequestedIpAddress(addr) => addr,
                            _ => unreachable!(),
                        }) {
                            Some(addr) => *addr,
                            None => match lease_mgr.renew(client_id)? {
                                Some(addr) => {
                                    renew = true;
                                    addr
                                }
                                None => return Err(Error::NoAddrRequested),
                            },
                        };

                    if !lease_mgr.request(requested_addr, client_id)? {
                        let own_addr = local_ip(link)?;

                        let mut resp = Message::default();
                        let opts = resp
                            .set_flags(Flags::default().set_broadcast())
                            .set_opcode(Opcode::BootReply)
                            .set_xid(xid)
                            .set_yiaddr(requested_addr)
                            .set_siaddr(own_addr)
                            .set_chaddr(msg.chaddr())
                            .opts_mut();

                        opts.insert(DhcpOption::MessageType(MessageType::Nak));
                        opts.insert(DhcpOption::ServerIdentifier(own_addr));

                        let mut resp_buf = Vec::new();
                        resp.encode(&mut Encoder::new(&mut resp_buf))?;

                        let n = sock.send_to(&resp_buf, &dst.into())?;
                        if n != resp_buf.len() {
                            Err(Error::PartialResponse)
                        } else {
                            if renew {
                                println!(
                                    "[dhcp4d] nak {} (renew) for client id {} on {}",
                                    requested_addr,
                                    format_client_id(client_id)?,
                                    link
                                );
                            } else {
                                println!(
                                    "[dhcp4d] nak {} for client id {} on {}",
                                    requested_addr,
                                    format_client_id(client_id)?,
                                    link
                                );
                            }

                            Ok(())
                        }
                    } else {
                        let lease_time = lease_mgr.lease_time();
                        let own_addr = local_ip(link)?;

                        let mut resp = Message::default();
                        let opts = resp
                            .set_flags(Flags::default().set_broadcast())
                            .set_opcode(Opcode::BootReply)
                            .set_xid(xid)
                            .set_yiaddr(requested_addr)
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

                        let n = sock.send_to(&resp_buf, &dst.into())?;
                        if n != resp_buf.len() {
                            Err(Error::PartialResponse)
                        } else {
                            if renew {
                                println!(
                                    "[dhcp4d] ack {} (renew) for client id {} for {:?} on {}",
                                    requested_addr,
                                    format_client_id(client_id)?,
                                    lease_time,
                                    link
                                );
                            } else {
                                println!(
                                    "[dhcp4d] ack {} for client id {} for {:?} on {}",
                                    requested_addr,
                                    format_client_id(client_id)?,
                                    lease_time,
                                    link
                                );
                            }

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
                        "[dhcp4d] release {} for client id {} on {}",
                        released_pretty,
                        format_client_id(client_id)?,
                        link
                    );
                    Ok(())
                }
                _ => Err(Error::InvalidMsgType(msg_type)),
            }
        }
        _ => Err(Error::InvalidOpcode(op)),
    }
}
