use crate::{validate_identifier, NonExportableSigner, RawSignature, SigningError};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use runtrue_model::ContentDigest;
use rusqlite::{params, Connection, OptionalExtension as _, Transaction, TransactionBehavior};
use std::fmt;
use zeroize::Zeroizing;

pub const MAX_LOCAL_SIGNER_PAYLOAD_BYTES: usize = 1024 * 1024;
const LOCAL_SIGNER_ALGORITHM: &str = "Ed25519";
const LOCAL_SIGNER_KEY_ID_DOMAIN: &[u8] = b"runtrue.local-ed25519-key-id.v1\0";

pub struct LocalSigningKey(SigningKey);

impl LocalSigningKey {
    #[must_use]
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
}

impl fmt::Debug for LocalSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalSigningKey(<non-exportable>)")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalSignerMetrics {
    pub signatures_created: u64,
    pub exact_replays: u64,
    pub reserved_recoveries: u64,
    pub idempotency_conflicts: u64,
}

enum LocalSignerEffect {
    Reserved {
        payload_digest: ContentDigest,
        key_id: String,
        algorithm: String,
    },
    Signed {
        payload_digest: ContentDigest,
        key_id: String,
        algorithm: String,
        signature: Vec<u8>,
    },
}

pub struct LocalEd25519Signer {
    pub(crate) connection: Connection,
    signing_key: LocalSigningKey,
    verifying_key: VerifyingKey,
    key_id: String,
    purpose: String,
    metrics: LocalSignerMetrics,
}

impl fmt::Debug for LocalEd25519Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalEd25519Signer")
            .field("key_id", &self.key_id)
            .field("algorithm", &LOCAL_SIGNER_ALGORITHM)
            .field("purpose", &self.purpose)
            .field("metrics", &self.metrics)
            .field("signing_key", &"<non-exportable>")
            .field("connection", &"<redacted>")
            .finish()
    }
}

impl LocalEd25519Signer {
    pub fn from_connection(
        connection: Connection,
        signing_key: LocalSigningKey,
        purpose: impl Into<String>,
    ) -> Result<Self, SigningError> {
        let purpose = purpose.into();
        validate_identifier(&purpose).map_err(|_| SigningError::InvalidConfiguration)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS runtrue_local_signer_effects (
                   request_id TEXT PRIMARY KEY NOT NULL,
                   payload_digest TEXT NOT NULL,
                   key_id TEXT NOT NULL,
                   algorithm TEXT NOT NULL,
                   state TEXT NOT NULL CHECK (state IN ('reserved', 'signed')),
                   signature BLOB,
                   CHECK ((state = 'reserved' AND signature IS NULL) OR
                          (state = 'signed' AND signature IS NOT NULL))
                 );",
            )
            .map_err(|_| SigningError::Ledger)?;
        let verifying_key = signing_key.0.verifying_key();
        let mut identity = Vec::with_capacity(LOCAL_SIGNER_KEY_ID_DOMAIN.len() + 32);
        identity.extend_from_slice(LOCAL_SIGNER_KEY_ID_DOMAIN);
        identity.extend_from_slice(verifying_key.as_bytes());
        let key_id = format!("local-ed25519:{}", ContentDigest::sha256(identity));
        Ok(Self {
            connection,
            signing_key,
            verifying_key,
            key_id,
            purpose,
            metrics: LocalSignerMetrics::default(),
        })
    }
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
    #[must_use]
    pub const fn metrics(&self) -> LocalSignerMetrics {
        self.metrics
    }
    fn exact_signature(
        &self,
        payload: &[u8],
        signature: Vec<u8>,
    ) -> Result<RawSignature, SigningError> {
        let signature_bytes: [u8; 64] = signature
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::Ledger)?;
        let signature = Signature::from_bytes(&signature_bytes);
        self.verifying_key
            .verify_strict(payload, &signature)
            .map_err(|_| SigningError::Ledger)?;
        Ok(RawSignature {
            key_id: self.key_id.clone(),
            algorithm: LOCAL_SIGNER_ALGORITHM.to_owned(),
            bytes: signature_bytes.to_vec(),
        })
    }
    fn effect_matches(&self, effect: &LocalSignerEffect, payload_digest: &ContentDigest) -> bool {
        match effect {
            LocalSignerEffect::Reserved {
                payload_digest: stored,
                key_id,
                algorithm,
            }
            | LocalSignerEffect::Signed {
                payload_digest: stored,
                key_id,
                algorithm,
                ..
            } => {
                stored == payload_digest
                    && key_id == &self.key_id
                    && algorithm == LOCAL_SIGNER_ALGORITHM
            }
        }
    }
    fn record_conflict(&mut self) -> SigningError {
        self.metrics.idempotency_conflicts = self.metrics.idempotency_conflicts.saturating_add(1);
        SigningError::IdempotencyConflict
    }
}

impl NonExportableSigner for LocalEd25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn algorithm(&self) -> &str {
        LOCAL_SIGNER_ALGORITHM
    }
    fn purpose(&self) -> &str {
        &self.purpose
    }
    fn sign(
        &mut self,
        request_id: &str,
        domain_separated_payload: &[u8],
    ) -> Result<RawSignature, SigningError> {
        validate_identifier(request_id)?;
        if domain_separated_payload.is_empty()
            || domain_separated_payload.len() > MAX_LOCAL_SIGNER_PAYLOAD_BYTES
        {
            return Err(SigningError::InvalidRequest);
        }
        let payload_digest = ContentDigest::sha256(domain_separated_payload);
        let existing = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| SigningError::Ledger)?;
            let existing = load_local_signer_effect(&transaction, request_id)?;
            if existing.is_none() {
                transaction
                    .execute(
                        "INSERT INTO runtrue_local_signer_effects
                         (request_id, payload_digest, key_id, algorithm, state, signature)
                         VALUES (?1, ?2, ?3, ?4, 'reserved', NULL)",
                        params![
                            request_id,
                            payload_digest.to_string(),
                            self.key_id,
                            LOCAL_SIGNER_ALGORITHM
                        ],
                    )
                    .map_err(|_| SigningError::Ledger)?;
            }
            transaction.commit().map_err(|_| SigningError::Ledger)?;
            existing
        };
        if let Some(effect) = existing {
            if !self.effect_matches(&effect, &payload_digest) {
                return Err(self.record_conflict());
            }
            match effect {
                LocalSignerEffect::Signed { signature, .. } => {
                    let signature = self.exact_signature(domain_separated_payload, signature)?;
                    self.metrics.exact_replays = self.metrics.exact_replays.saturating_add(1);
                    return Ok(signature);
                }
                LocalSignerEffect::Reserved { .. } => {
                    self.metrics.reserved_recoveries =
                        self.metrics.reserved_recoveries.saturating_add(1)
                }
            }
        }
        let signature = self.signing_key.0.sign(domain_separated_payload).to_bytes();
        let stored_signature = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| SigningError::Ledger)?;
            let changed = transaction.execute("UPDATE runtrue_local_signer_effects SET state = 'signed', signature = ?5
                     WHERE request_id = ?1 AND payload_digest = ?2 AND key_id = ?3 AND algorithm = ?4
                       AND state = 'reserved' AND signature IS NULL", params![request_id, payload_digest.to_string(), self.key_id, LOCAL_SIGNER_ALGORITHM, signature.as_slice()]).map_err(|_| SigningError::Ledger)?;
            let stored = if changed == 1 {
                signature.to_vec()
            } else {
                match load_local_signer_effect(&transaction, request_id)? {
                    Some(LocalSignerEffect::Signed {
                        payload_digest: stored_digest,
                        key_id,
                        algorithm,
                        signature,
                    }) if stored_digest == payload_digest
                        && key_id == self.key_id
                        && algorithm == LOCAL_SIGNER_ALGORITHM =>
                    {
                        signature
                    }
                    _ => return Err(SigningError::Ledger),
                }
            };
            transaction.commit().map_err(|_| SigningError::Ledger)?;
            stored
        };
        let signature = self.exact_signature(domain_separated_payload, stored_signature)?;
        self.metrics.signatures_created = self.metrics.signatures_created.saturating_add(1);
        Ok(signature)
    }
}

fn load_local_signer_effect(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<LocalSignerEffect>, SigningError> {
    let row = transaction.query_row("SELECT payload_digest, key_id, algorithm, state, signature FROM runtrue_local_signer_effects WHERE request_id = ?1", [request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<Vec<u8>>>(4)?))).optional().map_err(|_| SigningError::Ledger)?;
    let Some((payload_digest, key_id, algorithm, state, signature)) = row else {
        return Ok(None);
    };
    let payload_digest = ContentDigest::parse(payload_digest).map_err(|_| SigningError::Ledger)?;
    match (state.as_str(), signature) {
        ("reserved", None) => Ok(Some(LocalSignerEffect::Reserved {
            payload_digest,
            key_id,
            algorithm,
        })),
        ("signed", Some(signature)) if signature.len() == 64 => {
            Ok(Some(LocalSignerEffect::Signed {
                payload_digest,
                key_id,
                algorithm,
                signature,
            }))
        }
        _ => Err(SigningError::Ledger),
    }
}
