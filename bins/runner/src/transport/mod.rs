mod broker;
mod conversion;
mod error;
mod security;
mod tonic;

pub use error::TransportError;
pub use security::{EndpointSecurity, EnrollmentEndpointSecurity};
pub use tonic::TonicRunnerTransport;

use crate::broker::RunnerBrokerClient;
use async_trait::async_trait;
use runtrue_protocol::{v1, v2};
use std::{sync::Arc, time::Duration};

const STREAM_BUFFER: usize = 64;
const STREAM_SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[async_trait]
pub trait RunnerTransport: Send {
    async fn open(&mut self, hello: v1::RunnerHello) -> Result<v1::ControlHello, TransportError>;
    async fn send(&mut self, message: v1::RunnerMessage) -> Result<(), TransportError>;
    async fn next_control(&mut self) -> Result<Option<v1::ControlMessage>, TransportError>;
    async fn fetch_capsule(
        &mut self,
        request: v1::FetchExecutionCapsuleRequest,
    ) -> Result<v1::FetchExecutionCapsuleResponse, TransportError>;
    async fn complete_lease(
        &mut self,
        request: v1::CompleteLeaseRequest,
    ) -> Result<v1::CompleteLeaseResponse, TransportError>;
    async fn complete_lease_v2(
        &mut self,
        request: v2::CompleteLeaseRequest,
    ) -> Result<v2::CompleteLeaseResponse, TransportError> {
        let legacy = conversion::completion_v2_to_v1(request)?;
        let response = self.complete_lease(legacy).await?;
        Ok(v2::CompleteLeaseResponse {
            accepted: response.accepted,
            resulting_job_state: conversion::completion_state_v1_to_v2(
                &response.resulting_job_state,
            )? as i32,
        })
    }
    async fn rotate_certificate(
        &mut self,
        request: v1::RotateCertificateRequest,
    ) -> Result<v1::RotateCertificateResponse, TransportError>;

    fn broker_client(&self) -> Option<Arc<dyn RunnerBrokerClient>> {
        None
    }
}

#[cfg(test)]
mod tests;
