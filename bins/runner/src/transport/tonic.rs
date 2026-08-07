use super::{
    broker::TonicRunnerBroker, RunnerTransport, TransportError, STREAM_BUFFER, STREAM_SEND_TIMEOUT,
};
use crate::broker::RunnerBrokerClient;
use ::tonic::{transport::Channel, Streaming};
use async_trait::async_trait;
use runtrue_protocol::{v1, v2};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct TonicRunnerTransport {
    pub(super) client: v1::runner_control_client::RunnerControlClient<Channel>,
    pub(super) outbound: Option<mpsc::Sender<v1::RunnerMessage>>,
    pub(super) inbound: Option<Streaming<v1::ControlMessage>>,
    pub(super) broker: Arc<TonicRunnerBroker>,
    pub(super) session_open: Arc<AtomicBool>,
    pub(super) protocol_version: Arc<AtomicU32>,
}

#[async_trait]
impl RunnerTransport for TonicRunnerTransport {
    async fn open(&mut self, hello: v1::RunnerHello) -> Result<v1::ControlHello, TransportError> {
        if self.outbound.is_some() || self.inbound.is_some() {
            return Err(TransportError::AlreadyOpen);
        }
        let protocol_version = hello.protocol_version;
        let (outbound, receiver) = mpsc::channel(STREAM_BUFFER);
        outbound
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::Hello(hello)),
            })
            .await
            .map_err(|_| TransportError::StreamClosed)?;
        let response = self
            .client
            .open(ReceiverStream::new(receiver))
            .await?
            .into_inner();
        self.outbound = Some(outbound);
        self.inbound = Some(response);
        let first = self
            .next_control()
            .await?
            .ok_or(TransportError::MissingControlHello)?;
        match first.body {
            Some(v1::control_message::Body::Hello(hello)) => {
                self.protocol_version
                    .store(protocol_version, Ordering::Release);
                self.session_open.store(true, Ordering::Release);
                Ok(hello)
            }
            _ => Err(TransportError::MissingControlHello),
        }
    }

    async fn send(&mut self, message: v1::RunnerMessage) -> Result<(), TransportError> {
        let sender = self.outbound.as_ref().ok_or(TransportError::NotOpen)?;
        tokio::time::timeout(STREAM_SEND_TIMEOUT, sender.send(message))
            .await
            .map_err(|_| TransportError::StreamBackpressure)?
            .map_err(|_| TransportError::StreamClosed)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.outbound.take().ok_or(TransportError::NotOpen)?;
        let inbound = self.inbound.as_mut().ok_or(TransportError::NotOpen)?;
        loop {
            let message = tokio::time::timeout(STREAM_SEND_TIMEOUT, inbound.message())
                .await
                .map_err(|_| TransportError::StreamBackpressure)??;
            if message.is_none() {
                self.inbound.take();
                return Ok(());
            }
        }
    }

    async fn next_control(&mut self) -> Result<Option<v1::ControlMessage>, TransportError> {
        self.inbound
            .as_mut()
            .ok_or(TransportError::NotOpen)?
            .message()
            .await
            .map_err(TransportError::from)
    }

    async fn fetch_capsule(
        &mut self,
        request: v1::FetchExecutionCapsuleRequest,
    ) -> Result<v1::FetchExecutionCapsuleResponse, TransportError> {
        Ok(self
            .client
            .fetch_execution_capsule(request)
            .await?
            .into_inner())
    }

    async fn complete_lease(
        &mut self,
        request: v1::CompleteLeaseRequest,
    ) -> Result<v1::CompleteLeaseResponse, TransportError> {
        Ok(self.client.complete_lease(request).await?.into_inner())
    }

    async fn complete_lease_v2(
        &mut self,
        request: v2::CompleteLeaseRequest,
    ) -> Result<v2::CompleteLeaseResponse, TransportError> {
        let mut client = self.broker.object_client.clone();
        Ok(client.complete_lease(request).await?.into_inner())
    }

    async fn rotate_certificate(
        &mut self,
        request: v1::RotateCertificateRequest,
    ) -> Result<v1::RotateCertificateResponse, TransportError> {
        Ok(self.client.rotate_certificate(request).await?.into_inner())
    }

    fn broker_client(&self) -> Option<Arc<dyn RunnerBrokerClient>> {
        self.session_open
            .load(Ordering::Acquire)
            .then(|| self.broker.clone() as Arc<dyn RunnerBrokerClient>)
    }
}

impl Drop for TonicRunnerTransport {
    fn drop(&mut self) {
        self.session_open.store(false, Ordering::Release);
        self.protocol_version.store(0, Ordering::Release);
    }
}
