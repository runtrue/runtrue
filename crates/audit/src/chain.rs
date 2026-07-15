use crate::{
    canonical::{canonical_bytes, domain_digest},
    validation::validate_data,
    AuditError, AuditEvent, AuditEventData,
};
use runtrue_model::ContentDigest;
use serde::Serialize;

const AUDIT_DOMAIN: &[u8] = b"runtrue.audit.event.v1\0";

#[derive(Debug, Serialize)]
struct HashableEvent<'a> {
    sequence: u64,
    installation_id: &'a str,
    previous_hash: &'a Option<ContentDigest>,
    data: &'a AuditEventData,
}

impl AuditEvent {
    pub fn create(
        sequence: u64,
        installation_id: String,
        previous_hash: Option<ContentDigest>,
        data: AuditEventData,
    ) -> Result<Self, AuditError> {
        validate_data(&data)?;
        if sequence == 0 || (sequence == 1) != previous_hash.is_none() {
            return Err(AuditError::InvalidSequenceLink(sequence));
        }
        let hashable = HashableEvent {
            sequence,
            installation_id: &installation_id,
            previous_hash: &previous_hash,
            data: &data,
        };
        let event_hash = domain_digest(AUDIT_DOMAIN, &canonical_bytes(&hashable)?);
        Ok(Self {
            sequence,
            installation_id,
            previous_hash,
            data,
            event_hash,
        })
    }

    pub fn verify_hash(&self) -> Result<(), AuditError> {
        validate_data(&self.data)?;
        let hashable = HashableEvent {
            sequence: self.sequence,
            installation_id: &self.installation_id,
            previous_hash: &self.previous_hash,
            data: &self.data,
        };
        let actual = domain_digest(AUDIT_DOMAIN, &canonical_bytes(&hashable)?);
        if actual != self.event_hash {
            return Err(AuditError::EventHashMismatch(self.sequence));
        }
        Ok(())
    }
}

pub fn verify_chain(events: &[AuditEvent]) -> Result<(), AuditError> {
    let mut installation: Option<&str> = None;
    let mut previous: Option<&ContentDigest> = None;
    for (index, event) in events.iter().enumerate() {
        event.verify_hash()?;
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        if event.sequence != expected_sequence {
            return Err(AuditError::UnexpectedSequence {
                expected: expected_sequence,
                actual: event.sequence,
            });
        }
        if let Some(installation) = installation {
            if event.installation_id != installation {
                return Err(AuditError::InstallationChanged(event.sequence));
            }
        } else {
            installation = Some(&event.installation_id);
        }
        if event.previous_hash.as_ref() != previous {
            return Err(AuditError::PreviousHashMismatch(event.sequence));
        }
        previous = Some(&event.event_hash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditPrincipal, AuditResource};
    use std::collections::BTreeMap;

    fn event(action: &str) -> AuditEventData {
        AuditEventData {
            observed_unix_ms: 1,
            tenant_id: "tenant".to_owned(),
            actor: AuditPrincipal {
                kind: "user".to_owned(),
                id: "alice".to_owned(),
            },
            action: action.to_owned(),
            resource: AuditResource {
                kind: "run".to_owned(),
                id: "run-1".to_owned(),
            },
            result: "success".to_owned(),
            request_id: "request-1".to_owned(),
            decision_id: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn content_and_link_tampering_are_detected() {
        let first = AuditEvent::create(1, "installation".to_owned(), None, event("one")).unwrap();
        let second = AuditEvent::create(
            2,
            "installation".to_owned(),
            Some(first.event_hash.clone()),
            event("two"),
        )
        .unwrap();
        let mut events = vec![first, second];
        events[0].data.result = "tampered".to_owned();
        assert!(matches!(
            verify_chain(&events),
            Err(AuditError::EventHashMismatch(1))
        ));
    }
}
