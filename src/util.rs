use crate::{Error, Result};

use std::ffi::{c_char, c_int};
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use rsdsl_netlinklib::blocking::Connection;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

pub fn format_client_id(client_id: &[u8]) -> Result<String> {
    client_id
        .iter()
        .map(|octet| format!("{:02x}", octet))
        .reduce(|acc, octet| acc + ":" + &octet)
        .ok_or(Error::EmptyClientId)
}

pub fn local_ip(conn: &Connection, link: String) -> Result<Ipv4Addr> {
    conn.address_get(link.clone())?
        .into_iter()
        .filter_map(|addr| {
            if let IpAddr::V4(v4) = addr {
                Some(v4)
            } else {
                None
            }
        })
        .next()
        .ok_or(Error::NoIpv4Addr(link))
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn setsockopt(
    fd: c_int,
    opt: c_int,
    val: c_int,
    payload: *const c_char,
    optlen: c_int,
) -> io::Result<()> {
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload.cast(),
        optlen as libc::socklen_t
    ))
    .map(|_| ())
}
