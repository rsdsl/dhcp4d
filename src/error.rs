use std::ffi;
use std::io;
use std::net;

use dhcproto::v4::{MessageType, Opcode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no ipv4 addr on interface {0}")]
    NoIpv4Addr(String),
    #[error("unhandled or unknown opcode {0:?}")]
    InvalidOpcode(Opcode),
    #[error("missing message type")]
    NoMsgType,
    #[error("unhandled or unknown message type {0:?}")]
    InvalidMsgType(MessageType),
    #[error("missing client id")]
    NoClientId,
    #[error("empty client id")]
    EmptyClientId,
    #[error("missing ip address in dhcprequest")]
    NoAddrRequested,
    #[error("addr pool exhausted")]
    PoolExhausted,
    #[error("bytes sent not equal to pkt size")]
    PartialResponse,
    #[error("dhcproto encode error")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("dhcproto decode error")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("linkaddrs error")]
    LinkAddrs(#[from] linkaddrs::Error),
    #[error("serde_json error")]
    SerdeJson(#[from] serde_json::Error),
    #[error("ip addr parse error")]
    AddrParseError(#[from] net::AddrParseError),
    #[error("ffi nul error (string contains nul bytes)")]
    FfiNulError(#[from] ffi::NulError),
}

pub type Result<T> = std::result::Result<T, Error>;
