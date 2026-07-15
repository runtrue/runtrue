use crate::NetworkError;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::NetworkProtocol;
use serde::Serialize;
use std::net::IpAddr;

pub(crate) const TICKET_VERSION: u32 = 1;

/// Serializable but not deserializable/constructible outside this crate. The
/// host broker retains the authoritative ticket and compares every connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTicket {
    pub(crate) version: u32,
    pub(crate) ticket_id: ContentDigest,
    pub(crate) policy_digest: ContentDigest,
    pub(crate) run_id: String,
    pub(crate) job_id: String,
    pub(crate) job_attempt: u32,
    pub(crate) step_id: String,
    pub(crate) execution_lease_id: String,
    pub(crate) fencing_generation: u64,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) protocol: NetworkProtocol,
    pub(crate) pinned_addresses: Vec<IpAddr>,
    pub(crate) issued_unix_seconds: u64,
    pub(crate) expires_unix_seconds: u64,
}

impl ConnectionTicket {
    #[must_use]
    pub const fn ticket_id(&self) -> &ContentDigest {
        &self.ticket_id
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn protocol(&self) -> NetworkProtocol {
        self.protocol
    }

    #[must_use]
    pub fn pinned_addresses(&self) -> &[IpAddr] {
        &self.pinned_addresses
    }

    #[must_use]
    pub const fn expires_unix_seconds(&self) -> u64 {
        self.expires_unix_seconds
    }
}

pub(crate) fn ticket_digest(ticket: &ConnectionTicket) -> Result<ContentDigest, NetworkError> {
    #[derive(Serialize)]
    struct Material<'a> {
        version: u32,
        policy_digest: &'a ContentDigest,
        run_id: &'a str,
        job_id: &'a str,
        job_attempt: u32,
        step_id: &'a str,
        execution_lease_id: &'a str,
        fencing_generation: u64,
        host: &'a str,
        port: u16,
        protocol: NetworkProtocol,
        pinned_addresses: &'a [IpAddr],
        issued_unix_seconds: u64,
        expires_unix_seconds: u64,
    }
    let material = Material {
        version: ticket.version,
        policy_digest: &ticket.policy_digest,
        run_id: &ticket.run_id,
        job_id: &ticket.job_id,
        job_attempt: ticket.job_attempt,
        step_id: &ticket.step_id,
        execution_lease_id: &ticket.execution_lease_id,
        fencing_generation: ticket.fencing_generation,
        host: &ticket.host,
        port: ticket.port,
        protocol: ticket.protocol,
        pinned_addresses: &ticket.pinned_addresses,
        issued_unix_seconds: ticket.issued_unix_seconds,
        expires_unix_seconds: ticket.expires_unix_seconds,
    };
    Ok(ContentDigest::sha256(serde_json::to_vec(&material)?))
}
