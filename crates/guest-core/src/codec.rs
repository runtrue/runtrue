use crate::{
    bootstrap::{GuestSessionKey, HmacSha256},
    protocol::{
        validate_identifier, AuthenticatedEnvelope, GUEST_PROTOCOL_VERSION, MAX_GUEST_MESSAGE_BYTES,
    },
    GuestError, GuestEvent, HostCommand,
};
use hmac::Mac;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;
use zeroize::Zeroizing;

pub(crate) const HOST_MESSAGE_DOMAIN: &[u8] = b"runtrue.guest.host-command.v1\0";
pub(crate) const GUEST_MESSAGE_DOMAIN: &[u8] = b"runtrue.guest.event.v1\0";

/// Host-side codec for producing commands and validating guest events. It
/// owns a separate copy of the one-time key provisioned into the guest.
pub struct HostSessionCodec {
    session_id: String,
    key: GuestSessionKey,
    next_command_sequence: u64,
    next_event_sequence: u64,
}

impl HostSessionCodec {
    pub fn new(session_id: impl Into<String>, key: GuestSessionKey) -> Result<Self, GuestError> {
        let session_id = session_id.into();
        validate_identifier("session id", &session_id)?;
        Ok(Self {
            session_id,
            key,
            next_command_sequence: 1,
            next_event_sequence: 1,
        })
    }

    pub fn command(&mut self, command: &HostCommand) -> Result<AuthenticatedEnvelope, GuestError> {
        let envelope = sign_envelope(
            &self.key,
            HOST_MESSAGE_DOMAIN,
            &self.session_id,
            self.next_command_sequence,
            command,
        )?;
        self.next_command_sequence = self
            .next_command_sequence
            .checked_add(1)
            .ok_or(GuestError::SequenceExhausted)?;
        Ok(envelope)
    }

    pub fn verify_event(
        &mut self,
        envelope: AuthenticatedEnvelope,
    ) -> Result<GuestEvent, GuestError> {
        let event = verify_envelope(
            &self.key,
            GUEST_MESSAGE_DOMAIN,
            &self.session_id,
            self.next_event_sequence,
            envelope,
        )?;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(GuestError::SequenceExhausted)?;
        Ok(event)
    }
}

impl fmt::Debug for HostSessionCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostSessionCodec")
            .field("session_id", &self.session_id)
            .field("key", &"<redacted>")
            .field("next_command_sequence", &self.next_command_sequence)
            .field("next_event_sequence", &self.next_event_sequence)
            .finish()
    }
}

pub(crate) fn sign_envelope<T: Serialize>(
    key: &GuestSessionKey,
    domain: &[u8],
    session_id: &str,
    sequence: u64,
    payload: &T,
) -> Result<AuthenticatedEnvelope, GuestError> {
    let payload = serde_json::to_vec(payload).map_err(GuestError::Json)?;
    if payload.is_empty() || payload.len() > MAX_GUEST_MESSAGE_BYTES {
        return Err(GuestError::MessageSize(payload.len()));
    }
    let mut mac = key.authenticator()?;
    authenticate_fields(&mut mac, domain, session_id, sequence, &payload)?;
    Ok(AuthenticatedEnvelope {
        protocol_version: GUEST_PROTOCOL_VERSION,
        session_id: session_id.to_owned(),
        sequence,
        payload,
        authentication_tag: mac.finalize().into_bytes().to_vec(),
    })
}

pub(crate) fn verify_envelope<T: DeserializeOwned + Serialize>(
    key: &GuestSessionKey,
    domain: &[u8],
    session_id: &str,
    expected_sequence: u64,
    envelope: AuthenticatedEnvelope,
) -> Result<T, GuestError> {
    if envelope.protocol_version != GUEST_PROTOCOL_VERSION {
        return Err(GuestError::UnsupportedProtocol(envelope.protocol_version));
    }
    if envelope.session_id != session_id {
        return Err(GuestError::WrongSession);
    }
    if envelope.sequence != expected_sequence {
        return Err(GuestError::UnexpectedSequence {
            expected: expected_sequence,
            actual: envelope.sequence,
        });
    }
    if envelope.payload.is_empty() || envelope.payload.len() > MAX_GUEST_MESSAGE_BYTES {
        return Err(GuestError::MessageSize(envelope.payload.len()));
    }
    let payload = Zeroizing::new(envelope.payload);
    let mut mac = key.authenticator()?;
    authenticate_fields(&mut mac, domain, session_id, envelope.sequence, &payload)?;
    mac.verify_slice(&envelope.authentication_tag)
        .map_err(|_| GuestError::AuthenticationFailed)?;
    let value: T = strict_canonical_json(&payload)?;
    let canonical = serde_json::to_vec(&value).map_err(GuestError::Json)?;
    if canonical.as_slice() != payload.as_slice() {
        return Err(GuestError::NonCanonicalMessage);
    }
    Ok(value)
}

fn authenticate_fields(
    mac: &mut HmacSha256,
    domain: &[u8],
    session_id: &str,
    sequence: u64,
    payload: &[u8],
) -> Result<(), GuestError> {
    let session_length = u32::try_from(session_id.len()).map_err(|_| GuestError::MessageSize(0))?;
    let payload_length = u64::try_from(payload.len()).map_err(|_| GuestError::MessageSize(0))?;
    mac.update(domain);
    mac.update(&GUEST_PROTOCOL_VERSION.to_be_bytes());
    mac.update(&session_length.to_be_bytes());
    mac.update(session_id.as_bytes());
    mac.update(&sequence.to_be_bytes());
    mac.update(&payload_length.to_be_bytes());
    mac.update(payload);
    Ok(())
}

pub(crate) fn strict_canonical_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GuestError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(GuestError::Json)?;
    deserializer.end().map_err(GuestError::Json)?;
    Ok(value)
}
