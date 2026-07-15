use super::{
    validation::{
        canonical_envelope_bytes, validate_envelope_for_ledger, MAX_LEDGER_ENVELOPE_BYTES,
    },
    LedgerState, SigningLedger,
};
use crate::{
    canonical_bytes, validate_identifier, SignatureEnvelope, SigningError, ENVELOPE_VERSION,
    MAX_SIGNATURE_BYTES,
};
use runtrue_model::ContentDigest;
use rusqlite::{params, Connection, OptionalExtension as _, Transaction, TransactionBehavior};
use std::{fmt, sync::Mutex};

pub struct SqliteSigningLedger {
    connection: Mutex<Connection>,
}
impl fmt::Debug for SqliteSigningLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteSigningLedger(<connection redacted>)")
    }
}
impl SqliteSigningLedger {
    pub fn from_connection(connection: Connection) -> Result<Self, SigningError> {
        connection.execute_batch("PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS runtrue_signing_operations (
                   request_id TEXT PRIMARY KEY NOT NULL, request_digest TEXT NOT NULL,
                   state TEXT NOT NULL CHECK (state IN ('reserved', 'signed', 'complete')), envelope_json BLOB,
                   CHECK ((state = 'reserved' AND envelope_json IS NULL) OR
                          (state IN ('signed', 'complete') AND envelope_json IS NOT NULL))
                 );").map_err(|_| SigningError::Ledger)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
    pub fn into_connection(self) -> Result<Connection, SigningError> {
        self.connection
            .into_inner()
            .map_err(|_| SigningError::Ledger)
    }
}
impl SigningLedger for SqliteSigningLedger {
    fn reserve(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
    ) -> Result<Option<LedgerState>, SigningError> {
        validate_identifier(request_id)?;
        let mut connection = self.connection.lock().map_err(|_| SigningError::Ledger)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SigningError::Ledger)?;
        if let Some(state) = load_sqlite_state(&transaction, request_id)? {
            transaction.commit().map_err(|_| SigningError::Ledger)?;
            return Ok(Some(state));
        }
        transaction.execute("INSERT INTO runtrue_signing_operations (request_id, request_digest, state, envelope_json) VALUES (?1, ?2, 'reserved', NULL)", params![request_id, request_digest.to_string()]).map_err(|_| SigningError::Ledger)?;
        transaction.commit().map_err(|_| SigningError::Ledger)?;
        Ok(None)
    }
    fn store_signed(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
        envelope: &SignatureEnvelope,
    ) -> Result<(), SigningError> {
        validate_envelope_for_ledger(request_id, request_digest, envelope)?;
        let bytes = canonical_envelope_bytes(envelope)?;
        let mut connection = self.connection.lock().map_err(|_| SigningError::Ledger)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SigningError::Ledger)?;
        let changed = transaction.execute("UPDATE runtrue_signing_operations SET state = 'signed', envelope_json = ?3 WHERE request_id = ?1 AND request_digest = ?2 AND state = 'reserved' AND envelope_json IS NULL", params![request_id, request_digest.to_string(), bytes]).map_err(|_| SigningError::Ledger)?;
        if changed != 1 {
            return Err(SigningError::Ledger);
        }
        transaction.commit().map_err(|_| SigningError::Ledger)
    }
    fn complete(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
    ) -> Result<(), SigningError> {
        let mut connection = self.connection.lock().map_err(|_| SigningError::Ledger)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SigningError::Ledger)?;
        match load_sqlite_state(&transaction, request_id)? {
            Some(LedgerState::Signed {
                request_digest: stored,
                ..
            }) if stored == *request_digest => {
                let changed = transaction.execute("UPDATE runtrue_signing_operations SET state = 'complete' WHERE request_id = ?1 AND request_digest = ?2 AND state = 'signed'", params![request_id, request_digest.to_string()]).map_err(|_| SigningError::Ledger)?;
                if changed != 1 {
                    return Err(SigningError::Ledger);
                }
            }
            Some(LedgerState::Complete {
                request_digest: stored,
                ..
            }) if stored == *request_digest => {}
            _ => return Err(SigningError::Ledger),
        }
        transaction.commit().map_err(|_| SigningError::Ledger)
    }
    fn abort(&self, request_id: &str, request_digest: &ContentDigest) -> Result<(), SigningError> {
        let mut connection = self.connection.lock().map_err(|_| SigningError::Ledger)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SigningError::Ledger)?;
        let changed = transaction.execute("DELETE FROM runtrue_signing_operations WHERE request_id = ?1 AND request_digest = ?2 AND state = 'reserved' AND envelope_json IS NULL", params![request_id, request_digest.to_string()]).map_err(|_| SigningError::Ledger)?;
        if changed != 1 {
            return Err(SigningError::Ledger);
        }
        transaction.commit().map_err(|_| SigningError::Ledger)
    }
}
fn load_sqlite_state(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<LedgerState>, SigningError> {
    let row = transaction.query_row("SELECT request_digest, state, envelope_json FROM runtrue_signing_operations WHERE request_id = ?1", [request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<Vec<u8>>>(2)?))).optional().map_err(|_| SigningError::Ledger)?;
    let Some((request_digest, state, envelope)) = row else {
        return Ok(None);
    };
    let request_digest = ContentDigest::parse(request_digest).map_err(|_| SigningError::Ledger)?;
    match (state.as_str(), envelope) {
        ("reserved", None) => Ok(Some(LedgerState::Reserved { request_digest })),
        ("signed" | "complete", Some(bytes)) => {
            if bytes.len() > MAX_LEDGER_ENVELOPE_BYTES {
                return Err(SigningError::Ledger);
            }
            let envelope: SignatureEnvelope =
                serde_json::from_slice(&bytes).map_err(|_| SigningError::Ledger)?;
            if canonical_bytes(&envelope)? != bytes
                || envelope.version != ENVELOPE_VERSION
                || envelope.request_id != request_id
                || envelope.request_digest != request_digest
                || envelope.signature.is_empty()
                || envelope.signature.len() > MAX_SIGNATURE_BYTES
            {
                return Err(SigningError::Ledger);
            }
            if state == "signed" {
                Ok(Some(LedgerState::Signed {
                    request_digest,
                    envelope,
                }))
            } else {
                Ok(Some(LedgerState::Complete {
                    request_digest,
                    envelope,
                }))
            }
        }
        _ => Err(SigningError::Ledger),
    }
}
