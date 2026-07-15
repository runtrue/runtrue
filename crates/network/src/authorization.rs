use crate::{
    address_policy::forbidden_address,
    ticket::{ticket_digest, ConnectionTicket, TICKET_VERSION},
    validation::{host_matches, validate_host, validate_policy},
    ConnectRequest, LeaseNetworkBinding, NetworkError, NetworkLimits,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{DnsPolicy, NetworkPermission};
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Debug, Clone)]
pub struct NetworkAuthorizer {
    policy: NetworkPermission,
    policy_digest: ContentDigest,
    limits: NetworkLimits,
}

impl NetworkAuthorizer {
    pub fn new(policy: NetworkPermission, limits: NetworkLimits) -> Result<Self, NetworkError> {
        let limits = limits.validate()?;
        validate_policy(&policy)?;
        let policy_digest = ContentDigest::sha256(serde_json::to_vec(&policy)?);
        Ok(Self {
            policy,
            policy_digest,
            limits,
        })
    }

    #[must_use]
    pub const fn policy_digest(&self) -> &ContentDigest {
        &self.policy_digest
    }

    #[must_use]
    pub fn dns_policy(&self) -> DnsPolicy {
        match &self.policy {
            NetworkPermission::Deny => DnsPolicy::Deny,
            NetworkPermission::Allow { dns, .. } => *dns,
        }
    }

    pub fn authorize_connect(
        &self,
        binding: &LeaseNetworkBinding,
        request: ConnectRequest,
        now_unix_seconds: u64,
    ) -> Result<ConnectionTicket, NetworkError> {
        binding.validate()?;
        validate_host(&request.host)?;
        if request.port == 0 {
            return Err(NetworkError::InvalidPort);
        }
        let (deny_private_ranges, destinations) = match &self.policy {
            NetworkPermission::Deny => return Err(NetworkError::NetworkDenied),
            NetworkPermission::Allow {
                deny_private_ranges,
                destinations,
                ..
            } => (*deny_private_ranges, destinations),
        };
        let host = request.host.to_ascii_lowercase();
        if !destinations.iter().any(|destination| {
            destination.port == request.port
                && destination.protocol == request.protocol
                && host_matches(&destination.host, &host)
        }) {
            return Err(NetworkError::DestinationDenied {
                host,
                port: request.port,
                protocol: request.protocol,
            });
        }
        if request.resolved_addresses.is_empty()
            || request.resolved_addresses.len() > self.limits.max_resolved_addresses
            || request.dns_ttl_seconds == 0
        {
            return Err(NetworkError::InvalidResolution);
        }
        let addresses = request
            .resolved_addresses
            .into_iter()
            .collect::<BTreeSet<_>>();
        if addresses.len() > self.limits.max_resolved_addresses {
            return Err(NetworkError::InvalidResolution);
        }
        for address in &addresses {
            if forbidden_address(*address, deny_private_ranges) {
                return Err(NetworkError::AddressDenied(*address));
            }
        }
        let ttl = request
            .dns_ttl_seconds
            .min(self.limits.maximum_dns_ttl_seconds);
        let expires_unix_seconds = now_unix_seconds
            .checked_add(ttl)
            .ok_or(NetworkError::InvalidResolution)?;
        let mut ticket = ConnectionTicket {
            version: TICKET_VERSION,
            ticket_id: ContentDigest::sha256(b"pending-network-ticket"),
            policy_digest: self.policy_digest.clone(),
            run_id: binding.run_id.clone(),
            job_id: binding.job_id.clone(),
            job_attempt: binding.job_attempt,
            step_id: binding.step_id.clone(),
            execution_lease_id: binding.execution_lease_id.clone(),
            fencing_generation: binding.fencing_generation,
            host,
            port: request.port,
            protocol: request.protocol,
            pinned_addresses: addresses.into_iter().collect(),
            issued_unix_seconds: now_unix_seconds,
            expires_unix_seconds,
        };
        ticket.ticket_id = ticket_digest(&ticket)?;
        Ok(ticket)
    }

    /// Recheck the authoritative ticket immediately before the broker opens a
    /// socket. This prevents stale-fence use and DNS rebinding to an unpinned IP.
    pub fn authorize_ticket_use(
        &self,
        ticket: &ConnectionTicket,
        binding: &LeaseNetworkBinding,
        address: IpAddr,
        now_unix_seconds: u64,
    ) -> Result<(), NetworkError> {
        binding.validate()?;
        if ticket.version != TICKET_VERSION
            || ticket.ticket_id != ticket_digest(ticket)?
            || ticket.policy_digest != self.policy_digest
        {
            return Err(NetworkError::InvalidTicket);
        }
        if ticket.run_id != binding.run_id
            || ticket.job_id != binding.job_id
            || ticket.job_attempt != binding.job_attempt
            || ticket.step_id != binding.step_id
            || ticket.execution_lease_id != binding.execution_lease_id
            || ticket.fencing_generation != binding.fencing_generation
        {
            return Err(NetworkError::StaleFence);
        }
        if now_unix_seconds < ticket.issued_unix_seconds
            || now_unix_seconds >= ticket.expires_unix_seconds
        {
            return Err(NetworkError::TicketExpired);
        }
        if ticket.pinned_addresses.binary_search(&address).is_err() {
            return Err(NetworkError::AddressNotPinned(address));
        }
        Ok(())
    }

    pub fn authorize_listen(&self, port: u16) -> Result<(), NetworkError> {
        if port == 0 {
            return Err(NetworkError::InvalidPort);
        }
        match &self.policy {
            NetworkPermission::Allow { listen, .. } if listen.binary_search(&port).is_ok() => {
                Ok(())
            }
            _ => Err(NetworkError::ListenDenied(port)),
        }
    }

    /// Authorize a raw DNS query from the workload. Restricted DNS permits
    /// only names that could satisfy at least one declared destination.
    pub fn authorize_dns_query(&self, host: &str) -> Result<(), NetworkError> {
        validate_host(host)?;
        match &self.policy {
            NetworkPermission::Deny
            | NetworkPermission::Allow {
                dns: DnsPolicy::Deny,
                ..
            } => Err(NetworkError::DnsDenied(host.to_owned())),
            NetworkPermission::Allow {
                dns: DnsPolicy::Restricted,
                destinations,
                ..
            } if destinations
                .iter()
                .any(|destination| host_matches(&destination.host, host)) =>
            {
                Ok(())
            }
            NetworkPermission::Allow {
                dns: DnsPolicy::Allow,
                ..
            } => Ok(()),
            NetworkPermission::Allow { .. } => Err(NetworkError::DnsDenied(host.to_owned())),
        }
    }
}
