use runtrue_workflow_ir::NetworkProtocol;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid network authorization configuration")]
    InvalidConfiguration,
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("fencing generation must be greater than zero")]
    InvalidFencingGeneration,
    #[error("job attempt must be greater than zero")]
    InvalidJobAttempt,
    #[error("network policy is not canonical (sorted and unique)")]
    NonCanonicalPolicy,
    #[error("invalid network host")]
    InvalidHost,
    #[error("network port must be between 1 and 65535")]
    InvalidPort,
    #[error("network access is denied")]
    NetworkDenied,
    #[error("network destination {host}:{port}/{protocol:?} is denied")]
    DestinationDenied {
        host: String,
        port: u16,
        protocol: NetworkProtocol,
    },
    #[error("DNS resolution is empty or outside its resource bounds")]
    InvalidResolution,
    #[error("resolved address `{0}` is denied")]
    AddressDenied(IpAddr),
    #[error("listen port `{0}` is denied")]
    ListenDenied(u16),
    #[error("DNS query for `{0}` is denied")]
    DnsDenied(String),
    #[error("network ticket is invalid")]
    InvalidTicket,
    #[error("network ticket carries a stale execution fence")]
    StaleFence,
    #[error("network ticket is expired or not yet valid")]
    TicketExpired,
    #[error("address `{0}` is not in the DNS-pinned ticket")]
    AddressNotPinned(IpAddr),
    #[error("cannot canonicalize network authorization data: {0}")]
    Serialize(#[from] serde_json::Error),
}
