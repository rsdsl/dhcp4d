use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, PartialEq)]
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

pub trait LeaseManager {
    fn range(&self) -> (Ipv4Addr, Ipv4Addr);
    fn leases(&self) -> Box<dyn Iterator<Item = Lease>>;
    fn request(&mut self, address: Ipv4Addr) -> bool;

    fn all_addresses(&self) -> Vec<Ipv4Addr> {
        let range = self.range();
        let mut addrs = Vec::new();

        let mut addr = range.0;
        while addr < range.1 {
            addrs.push(addr);
            addr = (u32::from_le_bytes(addr.octets()) + 1).into();
        }

        addrs
    }

    fn taken_addresses(&self) -> Box<dyn Iterator<Item = Ipv4Addr>> {
        Box::new(self.leases().map(|lease| lease.address))
    }

    fn is_taken(&self, address: Ipv4Addr) -> bool {
        self.taken_addresses().any(|addr| addr == address)
    }

    fn free_addresses(&self) -> Vec<Ipv4Addr> {
        let mut taken = self.taken_addresses();

        self.all_addresses()
            .into_iter()
            .filter(|addr| !taken.any(|e| &e == addr))
            .collect()
    }

    fn any_free_address(&self) -> Option<Ipv4Addr> {
        self.free_addresses().into_iter().next()
    }

    // Imperfect implementation. Lease manager implementations
    // should override the default behavior.
    // The lack of guaranteed persistence shouldn't be a concern
    // for our use case.
    fn persistent_free_address(&self, client_id: &[u8]) -> Option<Ipv4Addr> {
        let cid = u32::from_le_bytes(client_id[..4].try_into().unwrap()) as usize;
        let all = self.all_addresses();
        let range = self.range();

        let mut attempts = 0;
        while attempts < self.free_addresses().len() {
            let offset = ((16 * attempts + cid) % all.len()) as u32;

            let addr = (u32::from_le_bytes(range.0.octets()) + offset).into();
            if !self.is_taken(addr) {
                return Some(addr);
            }

            attempts += 1;
        }

        // No more addresses left to try.
        None
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

    pub fn free(&self) -> Option<Ipv4Addr> {
        let mut taken = Vec::new();
        for lease in &self.leases {
            if SystemTime::now().duration_since(lease.expires).is_ok() {
                taken.push(lease.address);
            }
        }

        if !taken.is_empty() {
            for _ in &taken {
                let rand_addr = Ipv4Addr::from(rand::random::<u32>());
                if !taken.contains(&rand_addr) {
                    return Some(rand_addr);
                }
            }

            None
        } else {
            Some(Ipv4Addr::from(rand::random::<u32>()))
        }
    }
}

impl LeaseManager for LeaseDummyManager {
    fn range(&self) -> (Ipv4Addr, Ipv4Addr) {
        (
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        )
    }

    fn leases(&self) -> Box<dyn Iterator<Item = Lease>> {
        Box::new(
            self.leases
                .clone()
                .into_iter()
                .filter(|lease| SystemTime::now().duration_since(lease.expires).is_ok()),
        )
    }

    fn request(&mut self, address: Ipv4Addr) -> bool {
        if self.is_taken(address) {
            false
        } else {
            self.leases.push(Lease {
                address,
                expires: SystemTime::now() + Duration::from_secs(300),
            });

            true
        }
    }
}
