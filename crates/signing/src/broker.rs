use crate::{
    audit_event, validate_approval, validate_grant, validate_identifier, validate_request_shape,
    validate_request_time, LedgerState, NonExportableSigner, SignatureEnvelope, SignerPayload,
    SigningAuditKind, SigningAuditSink, SigningAuthorizer, SigningError, SigningLedger,
    SigningRequest, ENVELOPE_VERSION, MAX_APPROVERS, MAX_SIGNATURE_BYTES,
};
use runtrue_model::ContentDigest;
use std::fmt;

pub struct SigningBroker<S, A, L, U> {
    signer: S,
    authorizer: A,
    ledger: L,
    audit: U,
    required_approvers: usize,
}
impl<S, A, L, U> fmt::Debug for SigningBroker<S, A, L, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningBroker")
            .field("signer", &"<non-exportable>")
            .field("authorizer", &"<policy boundary>")
            .field("ledger", &"<durable state>")
            .field("audit", &"<audit sink>")
            .field("required_approvers", &self.required_approvers)
            .finish()
    }
}
impl<S, A, L, U> SigningBroker<S, A, L, U>
where
    S: NonExportableSigner,
    A: SigningAuthorizer,
    L: SigningLedger,
    U: SigningAuditSink,
{
    pub fn new(
        signer: S,
        authorizer: A,
        ledger: L,
        audit: U,
        required_approvers: usize,
    ) -> Result<Self, SigningError> {
        if required_approvers == 0 || required_approvers > MAX_APPROVERS {
            return Err(SigningError::InvalidConfiguration);
        }
        validate_identifier(signer.key_id()).map_err(|_| SigningError::InvalidConfiguration)?;
        validate_identifier(signer.algorithm()).map_err(|_| SigningError::InvalidConfiguration)?;
        validate_identifier(signer.purpose()).map_err(|_| SigningError::InvalidConfiguration)?;
        Ok(Self {
            signer,
            authorizer,
            ledger,
            audit,
            required_approvers,
        })
    }
    pub fn sign(
        &mut self,
        request: &SigningRequest,
        now_unix_seconds: u64,
    ) -> Result<SignatureEnvelope, SigningError> {
        validate_request_shape(request)?;
        let request_digest = request.request_digest()?;
        match self.ledger.reserve(&request.request_id, &request_digest)? {
            Some(LedgerState::Complete {
                request_digest: stored,
                envelope,
            }) if stored == request_digest => return Ok(envelope),
            Some(LedgerState::Signed {
                request_digest: stored,
                envelope,
            }) if stored == request_digest => {
                self.finish_audit(request, &request_digest, &envelope)?;
                return Ok(envelope);
            }
            Some(LedgerState::Reserved {
                request_digest: stored,
            }) if stored == request_digest => return Err(SigningError::InProgress),
            Some(_) => return Err(SigningError::IdempotencyConflict),
            None => {}
        }
        if let Err(error) = validate_request_time(request, now_unix_seconds) {
            let _ = self.ledger.abort(&request.request_id, &request_digest);
            return Err(error);
        }
        let result = self.sign_new(request, &request_digest, now_unix_seconds);
        if result.is_err() {
            let _ = self.ledger.abort(&request.request_id, &request_digest);
        }
        result
    }
    fn sign_new(
        &mut self,
        request: &SigningRequest,
        request_digest: &ContentDigest,
        now_unix_seconds: u64,
    ) -> Result<SignatureEnvelope, SigningError> {
        if request.purpose != self.signer.purpose() {
            return Err(SigningError::Unauthorized);
        }
        let (grant, approval) = self.authorizer.authorize(request, now_unix_seconds)?;
        validate_grant(request, &grant, now_unix_seconds)?;
        validate_approval(
            request,
            &approval,
            self.required_approvers,
            now_unix_seconds,
        )?;
        self.audit
            .record(&audit_event(
                SigningAuditKind::Requested,
                request,
                request_digest,
                None,
                now_unix_seconds,
            )?)
            .map_err(|_| SigningError::Audit)?;
        let subject_digest = request.approval_subject()?.digest()?;
        let payload = SignerPayload {
            request_id: request.request_id.clone(),
            tenant_id: request.tenant_id.clone(),
            repository_id: request.repository_id.clone(),
            run_id: request.run_id.clone(),
            job_id: request.job_id.clone(),
            step_id: request.step_id.clone(),
            execution_lease_id: request.execution_lease_id.clone(),
            fencing_generation: request.fencing_generation,
            installation_fencing_epoch: request.installation_fencing_epoch,
            requester_identity: request.requester_identity.clone(),
            subject_digest: subject_digest.clone(),
            request_digest: request_digest.clone(),
            artifact_digest: request.artifact_digest.clone(),
            provenance_digest: request.provenance_digest.clone(),
            capsule_digest: request.capsule_digest.clone(),
            purpose: request.purpose.clone(),
            operation: request.operation,
            approval_id: approval.approval_id.clone(),
            policy_version_ids: request.policy_version_ids.clone(),
        };
        let raw = match self
            .signer
            .sign(&request.request_id, &payload.signing_bytes()?)
        {
            Ok(raw) => raw,
            Err(_) => {
                let _ = self.audit.record(&audit_event(
                    SigningAuditKind::Failed,
                    request,
                    request_digest,
                    None,
                    now_unix_seconds,
                )?);
                return Err(SigningError::Signer);
            }
        };
        if raw.key_id != self.signer.key_id()
            || raw.algorithm != self.signer.algorithm()
            || raw.bytes.is_empty()
            || raw.bytes.len() > MAX_SIGNATURE_BYTES
        {
            let _ = self.audit.record(&audit_event(
                SigningAuditKind::Failed,
                request,
                request_digest,
                None,
                now_unix_seconds,
            )?);
            return Err(SigningError::InvalidSignatureResponse);
        }
        let envelope = SignatureEnvelope {
            version: ENVELOPE_VERSION,
            request_id: request.request_id.clone(),
            request_digest: request_digest.clone(),
            subject_digest,
            tenant_id: request.tenant_id.clone(),
            repository_id: request.repository_id.clone(),
            run_id: request.run_id.clone(),
            job_id: request.job_id.clone(),
            step_id: request.step_id.clone(),
            artifact_digest: request.artifact_digest.clone(),
            provenance_digest: request.provenance_digest.clone(),
            capsule_digest: request.capsule_digest.clone(),
            purpose: request.purpose.clone(),
            operation: request.operation,
            signer_key_id: raw.key_id,
            algorithm: raw.algorithm,
            signature: raw.bytes,
            approval_id: approval.approval_id,
            approver_identities: approval.approver_identities,
            policy_version_ids: request.policy_version_ids.clone(),
            signed_at_unix_seconds: now_unix_seconds,
        };
        self.ledger
            .store_signed(&request.request_id, request_digest, &envelope)?;
        self.finish_audit(request, request_digest, &envelope)?;
        Ok(envelope)
    }
    fn finish_audit(
        &self,
        request: &SigningRequest,
        request_digest: &ContentDigest,
        envelope: &SignatureEnvelope,
    ) -> Result<(), SigningError> {
        self.audit
            .record(&audit_event(
                SigningAuditKind::Completed,
                request,
                request_digest,
                Some(envelope.digest()?),
                envelope.signed_at_unix_seconds,
            )?)
            .map_err(|_| SigningError::Audit)?;
        self.ledger.complete(&request.request_id, request_digest)
    }
    pub fn into_parts(self) -> (S, A, L, U) {
        (self.signer, self.authorizer, self.ledger, self.audit)
    }
}
