use std::ffi;
use std::io;
use std::net;

use dhcproto::v4::{MessageType, Opcode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("client sent unhandled or unknown opcode {0:?}")]
    InvalidOpcode(Opcode),
    #[error("client did not send a message type")]
    NoMsgType,
    #[error("client sent unhandled or unknown message type {0:?}")]
    InvalidMsgType(MessageType),
    #[error("client did not send a client id")]
    NoClientId,
    #[error("client sent an empty client id")]
    EmptyClientId,
    #[error("client did not include an IP address in DHCPREQUEST")]
    NoAddrRequested,
    #[error("address pool exhausted")]
    PoolExhausted,
    #[error("bytes transmitted is not equal to response size")]
    PartialResponse,
    #[error("dhcproto encode error")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("dhcproto decode error")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("serde_json error")]
    SerdeJson(#[from] serde_json::Error),
    #[error("error parsing IP address")]
    AddrParseError(#[from] net::AddrParseError),
    #[error("ffi nul error (string contains nul bytes)")]
    FfiNulError(#[from] ffi::NulError),
}

pub type Result<T> = std::result::Result<T, Error>;
