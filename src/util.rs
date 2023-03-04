use crate::error::{Error, Result};

use std::ffi::c_int;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr;

use socket2::Socket;

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

pub fn local_ip(sock: &Socket) -> Ipv4Addr {
    let local_addr = sock.local_addr().unwrap().as_socket_ipv4().unwrap();
    *local_addr.ip()
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn setsockopt<T>(fd: c_int, opt: c_int, val: c_int, payload: T) -> io::Result<()> {
    let payload = ptr::addr_of!(payload).cast();
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t
    ))
    .map(|_| ())
}
