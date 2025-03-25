use std::{ffi, fmt, io, net};

use dhcproto::v4::{MessageType, Opcode};

#[derive(Debug)]
pub enum Error {
    InvalidMsgType(MessageType),
    InvalidOpcode(Opcode),
    NoAddrRequested,
    NoIpv4Addr(String),
    NoMsgType,
    PartialSend(usize, usize),
    PoolExhausted,

    AddrParseError(net::AddrParseError),
    Nul(ffi::NulError),
    Io(io::Error),

    DhcprotoDecode(dhcproto::error::DecodeError),
    DhcprotoEncode(dhcproto::error::EncodeError),
    Netlinklib(rsdsl_netlinklib::Error),
    SerdeJson(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMsgType(t) => write!(f, "unhandled or unknown message type {:?}", t)?,
            Self::InvalidOpcode(op) => write!(f, "unhandled or unknown opcode {:?}", op)?,
            Self::NoAddrRequested => write!(f, "missing ip address in dhcprequest")?,
            Self::NoIpv4Addr(link) => write!(f, "no ipv4 address on interface {}", link)?,
            Self::NoMsgType => write!(f, "missing message type")?,
            Self::PartialSend(want, got) => write!(
                f,
                "failed to send whole packet (expected {}, got {})",
                want, got
            )?,
            Self::PoolExhausted => write!(f, "address pool exhausted")?,
            Self::AddrParseError(e) => write!(f, "can't parse network address: {}", e)?,
            Self::Nul(e) => write!(f, "string contains nul bytes: {}", e)?,
            Self::Io(e) => write!(f, "io error: {}", e)?,
            Self::DhcprotoDecode(e) => write!(f, "dhcproto decode error: {}", e)?,
            Self::DhcprotoEncode(e) => write!(f, "dhcproto encode error: {}", e)?,
            Self::Netlinklib(e) => write!(f, "netlinklib error: {}", e)?,
            Self::SerdeJson(e) => write!(f, "serde_json error: {}", e)?,
        }

        Ok(())
    }
}

impl From<net::AddrParseError> for Error {
    fn from(e: net::AddrParseError) -> Error {
        Error::AddrParseError(e)
    }
}

impl From<ffi::NulError> for Error {
    fn from(e: ffi::NulError) -> Error {
        Error::Nul(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<dhcproto::error::DecodeError> for Error {
    fn from(e: dhcproto::error::DecodeError) -> Error {
        Error::DhcprotoDecode(e)
    }
}

impl From<dhcproto::error::EncodeError> for Error {
    fn from(e: dhcproto::error::EncodeError) -> Error {
        Error::DhcprotoEncode(e)
    }
}

impl From<rsdsl_netlinklib::Error> for Error {
    fn from(e: rsdsl_netlinklib::Error) -> Error {
        Error::Netlinklib(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJson(e)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
