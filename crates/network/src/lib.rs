//! Network capability admission with DNS pinning and lease fencing.
//!
//! This crate does not claim to be a firewall. It produces narrowly scoped,
//! expiring tickets for an executor-side connection broker. The broker must
//! still be the only network path available to the workload (for example via a
//! network namespace or guest proxy); otherwise workflow declarations alone do
//! not enforce egress.

mod address_policy;
mod authorization;
mod error;
mod model;
mod ticket;
mod validation;

pub use authorization::NetworkAuthorizer;
pub use error::NetworkError;
pub use model::{ConnectRequest, LeaseNetworkBinding, NetworkLimits};
pub use ticket::ConnectionTicket;

#[cfg(test)]
mod tests;
