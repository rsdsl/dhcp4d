use std::net::Ipv4Addr;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub expires: SystemTime,
}
