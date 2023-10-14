use crate::{Error, Result};

use std::ffi::{c_char, c_int};
use std::io;
use std::net::Ipv4Addr;

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

pub fn local_ip(link: &str) -> Result<Ipv4Addr> {
    Ok(linkaddrs::ipv4_addresses(link.to_owned())?
        .first()
        .ok_or(Error::NoIpv4Addr(link.to_owned()))?
        .addr())
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
