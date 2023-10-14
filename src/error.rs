use std::ffi;
use std::io;
use std::net;

use dhcproto::v4::{MessageType, Opcode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("empty client id")]
    EmptyClientId,
    #[error("unhandled or unknown message type {0:?}")]
    InvalidMsgType(MessageType),
    #[error("unhandled or unknown opcode {0:?}")]
    InvalidOpcode(Opcode),
    #[error("missing ip address in dhcprequest")]
    NoAddrRequested,
    #[error("missing client id")]
    NoClientId,
    #[error("no ipv4 addr on interface {0}")]
    NoIpv4Addr(String),
    #[error("missing message type")]
    NoMsgType,
    #[error("bytes sent not equal to pkt size")]
    PartialResponse,
    #[error("addr pool exhausted")]
    PoolExhausted,

    #[error("ip addr parse error")]
    AddrParseError(#[from] net::AddrParseError),
    #[error("ffi nul error (string contains nul bytes)")]
    FfiNulError(#[from] ffi::NulError),
    #[error("io error")]
    Io(#[from] io::Error),

    #[error("dhcproto decode error")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("dhcproto encode error")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("linkaddrs error")]
    LinkAddrs(#[from] linkaddrs::Error),
    #[error("rsdsl_netlinkd error")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("serde_json error")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
