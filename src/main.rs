use rsdsl_dhcp4d::lease::{LeaseFileManager, LeaseFileManagerConfig, LeaseManager};
use rsdsl_dhcp4d::util::{format_client_id, local_ip, setsockopt};
use rsdsl_dhcp4d::{Error, Result};

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use rsdsl_netlinklib::blocking::link;
use socket2::{Domain, Socket, Type};
use sysinfo::{ProcessExt, Signal, System, SystemExt};

const BUFSIZE: usize = 1500;

fn main() -> Result<()> {
    for i in 1..=4 {
        let subnet_id = 10 * i;
        let vlan_name = format!("eth0.{}", subnet_id);

        thread::spawn(move || run_supervised(vlan_name, subnet_id));
    }

    run_supervised("eth0".into(), 0);
}

fn run_supervised(link: String, subnet_id: u8) -> ! {
    loop {
        match run(link.clone(), subnet_id) {
            Ok(_) => {}
            Err(e) => println!("[warn] error on {}: {}", link, e),
        }
    }
}

fn run(link: String, subnet_id: u8) -> Result<()> {
    println!("[info] wait for up {}", link);
    link::wait_up(link.clone())?;

    println!("[info] init {}", link);

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

        match handle_request(&sock, lease_mgr.clone(), buf, link.clone()) {
            Ok(_) => {}
            Err(e) => println!("[info] pkt from {} on {}: {}", remote, link, e),
        }
    }
}

fn handle_request<T: LeaseManager>(
    sock: &Socket,
    lease_mgr: Arc<Mutex<T>>,
    buf: &[u8],
    link: String,
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

                    let hostname = opts
                        .get(OptionCode::Hostname)
                        .map(|hostname| match hostname {
                            DhcpOption::Hostname(hostname) => hostname.clone(),
                            _ => unreachable!(),
                        });

                    let lease_mgr = lease_mgr.lock().unwrap();
                    let lease = lease_mgr
                        .persistent_free_address(client_id, hostname)
                        .ok_or(Error::PoolExhausted)?;

                    let own_addr = local_ip(link.clone())?;

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
                        Err(Error::PartialSend(resp_buf.len(), n))
                    } else {
                        println!(
                            "[info] offer {} client id {} lease time {:?} on {}",
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

                    let hostname = opts
                        .get(OptionCode::Hostname)
                        .map(|hostname| match hostname {
                            DhcpOption::Hostname(hostname) => hostname.clone(),
                            _ => unreachable!(),
                        });

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

                    if !lease_mgr.request(requested_addr, client_id, hostname)? {
                        let own_addr = local_ip(link.clone())?;

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
                            return Err(Error::PartialSend(resp_buf.len(), n));
                        } else if renew {
                            println!(
                                "[info] nak {} client id {} on {} (renew)",
                                requested_addr,
                                format_client_id(client_id)?,
                                link
                            );
                        } else {
                            println!(
                                "[info] nak {} client id {} on {}",
                                requested_addr,
                                format_client_id(client_id)?,
                                link
                            );
                        }
                    } else {
                        let lease_time = lease_mgr.lease_time();
                        let own_addr = local_ip(link.clone())?;

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
                            return Err(Error::PartialSend(resp_buf.len(), n));
                        } else if renew {
                            println!(
                                "[info] ack {} client id {} lease time {:?} on {} (renew)",
                                requested_addr,
                                format_client_id(client_id)?,
                                lease_time,
                                link
                            );
                        } else {
                            println!(
                                "[info] ack {} client id {} lease time {:?} on {}",
                                requested_addr,
                                format_client_id(client_id)?,
                                lease_time,
                                link
                            );
                        }
                    }

                    for dnsd in System::new_all().processes_by_exact_name("rsdsl_dnsd") {
                        dnsd.kill_with(Signal::User1);
                    }

                    Ok(())
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
                        "[info] release {} client id {} on {}",
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
