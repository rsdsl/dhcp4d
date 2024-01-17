use std::{ffi, io, net};

use dhcproto::v4::{MessageType, Opcode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unhandled or unknown message type {0:?}")]
    InvalidMsgType(MessageType),
    #[error("unhandled or unknown opcode {0:?}")]
    InvalidOpcode(Opcode),
    #[error("missing ip address in dhcprequest")]
    NoAddrRequested,
    #[error("no ipv4 address on interface {0}")]
    NoIpv4Addr(String),
    #[error("missing message type")]
    NoMsgType,
    #[error("failed to send whole packet (expected {0}, got {1})")]
    PartialSend(usize, usize),
    #[error("address pool exhausted")]
    PoolExhausted,

    #[error("can't parse network address: {0}")]
    AddrParseError(#[from] net::AddrParseError),
    #[error("string contains nul bytes: {0}")]
    Nul(#[from] ffi::NulError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("dhcproto decode error: {0}")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("dhcproto encode error: {0}")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("netlinklib error: {0}")]
    Netlinklib(#[from] rsdsl_netlinklib::Error),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
