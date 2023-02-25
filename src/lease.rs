use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub expires: SystemTime,
}

impl Lease {
    pub fn new(address: Ipv4Addr, lease_time: Duration) -> Self {
        Self {
            address,
            expires: SystemTime::now() + lease_time,
        }
    }
}

#[derive(Debug)]
pub struct LeaseDummyManager {
    leases: Vec<Lease>,
}

impl LeaseDummyManager {
    pub fn new(leases: Option<Vec<Lease>>) -> Self {
        Self {
            leases: leases.unwrap_or(Vec::new()),
        }
    }
}
