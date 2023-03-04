use crate::error::Result;

use std::fs::File;
use std::io::Seek;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use ipnet::Ipv4AddrRange;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub expires: SystemTime,
    pub lease_time: Duration,
    pub client_id: Vec<u8>,
}

impl Lease {
    pub fn new(address: Ipv4Addr, lease_time: Duration, client_id: Vec<u8>) -> Self {
        Self {
            address,
            expires: SystemTime::now() + lease_time,
            lease_time,
            client_id,
        }
    }
}

pub trait LeaseManager {
    fn range(&self) -> (Ipv4Addr, Ipv4Addr);
    fn netmask(&self) -> Ipv4Addr;
    fn lease_time(&self) -> Duration;
    fn leases(&self) -> Box<dyn Iterator<Item = Lease>>;
    fn request(&mut self, address: Ipv4Addr, client_id: &[u8]) -> Result<bool>;
    fn release(&mut self, client_id: &[u8]) -> Result<Box<dyn Iterator<Item = Ipv4Addr>>>;

    fn all_addresses(&self) -> Vec<Ipv4Addr> {
        let range = self.range();
        Ipv4AddrRange::new(range.0, range.1).collect()
    }

    fn taken_addresses(&self) -> Box<dyn Iterator<Item = Ipv4Addr>> {
        Box::new(self.leases().map(|lease| lease.address))
    }

    fn is_taken(&self, address: Ipv4Addr) -> bool {
        self.taken_addresses().any(|addr| addr == address)
    }

    fn is_unavailable(&self, address: Ipv4Addr, client_id: &[u8]) -> bool {
        self.leases()
            .any(|lease| lease.address == address && lease.client_id != client_id)
    }

    fn free_addresses(&self) -> Vec<Ipv4Addr> {
        let mut taken = self.taken_addresses();

        self.all_addresses()
            .into_iter()
            .filter(|addr| !taken.any(|e| &e == addr))
            .collect()
    }

    fn any_free_address(&self, client_id: Vec<u8>) -> Option<Lease> {
        self.free_addresses()
            .into_iter()
            .next()
            .map(|addr| Lease::new(addr, self.lease_time(), client_id))
    }

    // Imperfect implementation. Lease manager implementations
    // should override the default behavior.
    // The lack of guaranteed persistence shouldn't be a concern
    // for our use case.
    fn persistent_free_address(&self, client_id: &[u8]) -> Option<Lease> {
        let cid = u32::from_be_bytes(client_id[..4].try_into().unwrap()) as usize;
        let all = self.all_addresses();
        let range = self.range();

        let mut attempts = 0;
        while attempts < self.free_addresses().len() {
            let offset = ((16 * attempts + cid) % all.len()) as u32;

            let addr = (u32::from_be_bytes(range.0.octets()) + offset).into();
            if !self.is_taken(addr) {
                return Some(Lease::new(addr, self.lease_time(), client_id.to_vec()));
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
            "198.51.100.1".parse().unwrap(),
            "198.51.100.255".parse().unwrap(),
        )
    }

    fn netmask(&self) -> Ipv4Addr {
        "255.255.255.0".parse().unwrap()
    }

    fn lease_time(&self) -> Duration {
        Duration::from_secs(300)
    }

    fn leases(&self) -> Box<dyn Iterator<Item = Lease>> {
        Box::new(
            self.leases
                .clone()
                .into_iter()
                .filter(|lease| SystemTime::now().duration_since(lease.expires).is_err()),
        )
    }

    fn request(&mut self, address: Ipv4Addr, client_id: &[u8]) -> Result<bool> {
        if self.is_unavailable(address, client_id) {
            Ok(false)
        } else {
            let lease = self
                .leases
                .iter()
                .enumerate()
                .find(|(_, v)| v.client_id == client_id);

            if let Some(lease) = lease {
                self.leases.remove(lease.0);
            }

            self.leases
                .push(Lease::new(address, self.lease_time(), client_id.to_vec()));

            Ok(true)
        }
    }

    fn release(&mut self, client_id: &[u8]) -> Result<Box<dyn Iterator<Item = Ipv4Addr>>> {
        let mut released = Vec::new();

        self.leases
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(_, lease)| lease.client_id == client_id)
            .for_each(|(i, lease)| {
                self.leases.remove(i);
                released.push(lease.address);
            });

        Ok(Box::new(released.into_iter()))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LeaseFileManagerConfig {
    pub range: (Ipv4Addr, Ipv4Addr),
    pub netmask: Ipv4Addr,
    pub lease_time: Duration,
}

#[derive(Debug)]
pub struct LeaseFileManager {
    config: LeaseFileManagerConfig,
    file: File,
    leases: Vec<Lease>,
}

impl LeaseFileManager {
    pub fn new(config: LeaseFileManagerConfig, file: File) -> Result<Self> {
        let mut mgr = Self {
            config,
            file,
            leases: Vec::new(),
        };

        mgr.load()?;
        Ok(mgr)
    }

    fn load(&mut self) -> Result<()> {
        self.file.rewind()?;
        self.leases = serde_json::from_reader(&self.file)?;

        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        self.file.rewind()?;
        self.file.set_len(0)?;

        serde_json::to_writer_pretty(&self.file, &self.leases)?;
        Ok(())
    }

    fn garbage_collect(&mut self) -> Result<()> {
        self.leases = self
            .leases
            .clone()
            .into_iter()
            .filter(|lease| SystemTime::now().duration_since(lease.expires).is_err())
            .collect();

        self.save()?;
        Ok(())
    }
}

impl LeaseManager for LeaseFileManager {
    fn range(&self) -> (Ipv4Addr, Ipv4Addr) {
        self.config.range
    }

    fn netmask(&self) -> Ipv4Addr {
        self.config.netmask
    }

    fn lease_time(&self) -> Duration {
        self.config.lease_time
    }

    fn leases(&self) -> Box<dyn Iterator<Item = Lease>> {
        Box::new(
            self.leases
                .clone()
                .into_iter()
                .filter(|lease| SystemTime::now().duration_since(lease.expires).is_err()),
        )
    }

    fn request(&mut self, address: Ipv4Addr, client_id: &[u8]) -> Result<bool> {
        self.garbage_collect()?;

        if self.is_unavailable(address, client_id) {
            Ok(false)
        } else {
            let lease = self
                .leases
                .iter()
                .enumerate()
                .find(|(_, lease)| lease.client_id == client_id);

            if let Some(lease) = lease {
                self.leases.remove(lease.0);
            }

            self.leases
                .push(Lease::new(address, self.lease_time(), client_id.to_vec()));

            self.save()?;
            Ok(true)
        }
    }

    fn release(&mut self, client_id: &[u8]) -> Result<Box<dyn Iterator<Item = Ipv4Addr>>> {
        self.garbage_collect()?;

        let mut released = Vec::new();

        self.leases
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(_, lease)| lease.client_id == client_id)
            .for_each(|(i, lease)| {
                self.leases.remove(i);
                released.push(lease.address);
            });

        self.save()?;
        Ok(Box::new(released.into_iter()))
    }
}
