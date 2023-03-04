use crate::error::{Error, Result};

pub fn format_client_id(client_id: &[u8]) -> Result<String> {
    client_id
        .iter()
        .map(|octet| format!("{:x}", octet))
        .reduce(|acc, octet| acc + ":" + &octet)
        .ok_or(Error::EmptyClientId)
}
