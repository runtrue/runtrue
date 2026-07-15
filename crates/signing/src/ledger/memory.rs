use super::{LedgerState, SigningLedger};
use crate::{SignatureEnvelope, SigningError};
use runtrue_model::ContentDigest;
use std::{collections::BTreeMap, fmt, sync::Mutex};

#[derive(Default)]
pub struct MemorySigningLedger {
    states: Mutex<BTreeMap<String, LedgerState>>,
}
impl fmt::Debug for MemorySigningLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemorySigningLedger(<state redacted>)")
    }
}
impl SigningLedger for MemorySigningLedger {
    fn reserve(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
    ) -> Result<Option<LedgerState>, SigningError> {
        let mut states = self.states.lock().map_err(|_| SigningError::Ledger)?;
        if let Some(state) = states.get(request_id) {
            return Ok(Some(state.clone()));
        }
        states.insert(
            request_id.to_owned(),
            LedgerState::Reserved {
                request_digest: request_digest.clone(),
            },
        );
        Ok(None)
    }
    fn store_signed(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
        envelope: &SignatureEnvelope,
    ) -> Result<(), SigningError> {
        let mut states = self.states.lock().map_err(|_| SigningError::Ledger)?;
        match states.get(request_id) {
            Some(LedgerState::Reserved {
                request_digest: stored,
            }) if stored == request_digest => {
                states.insert(
                    request_id.to_owned(),
                    LedgerState::Signed {
                        request_digest: request_digest.clone(),
                        envelope: envelope.clone(),
                    },
                );
                Ok(())
            }
            _ => Err(SigningError::Ledger),
        }
    }
    fn complete(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
    ) -> Result<(), SigningError> {
        let mut states = self.states.lock().map_err(|_| SigningError::Ledger)?;
        let envelope = match states.get(request_id) {
            Some(LedgerState::Signed {
                request_digest: stored,
                envelope,
            }) if stored == request_digest => envelope.clone(),
            Some(LedgerState::Complete {
                request_digest: stored,
                ..
            }) if stored == request_digest => return Ok(()),
            _ => return Err(SigningError::Ledger),
        };
        states.insert(
            request_id.to_owned(),
            LedgerState::Complete {
                request_digest: request_digest.clone(),
                envelope,
            },
        );
        Ok(())
    }
    fn abort(&self, request_id: &str, request_digest: &ContentDigest) -> Result<(), SigningError> {
        let mut states = self.states.lock().map_err(|_| SigningError::Ledger)?;
        match states.get(request_id) {
            Some(LedgerState::Reserved {
                request_digest: stored,
            }) if stored == request_digest => {
                states.remove(request_id);
                Ok(())
            }
            _ => Err(SigningError::Ledger),
        }
    }
}
