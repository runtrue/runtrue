use crate::{
    debug_audit_event, generate_tunnel_token, valid_token_text, validate_client_identity,
    validate_open, ClientIdentityRequest, DebugApproval, DebugAuditKind, DebugAuditSink,
    DebugRelay, DebugSecretGate, DebugSessionError, DebugSessionPolicy, DebugSessionRecord,
    DebugSessionRequest, DebugSessionState, EphemeralIdentityIssuer, IssuedDebugSession,
    PromotionGate, RelayRegistration, SecretBlockRequest, SecretState, TunnelDirection,
    TunnelTokenKey, SESSION_VERSION,
};
use runtrue_auth::AuthContext;
use runtrue_model::ContentDigest;
use std::fmt;

pub struct DebugSessionBroker<I, G, R, A> {
    policy: DebugSessionPolicy,
    token_key: TunnelTokenKey,
    pub(crate) identity_issuer: I,
    secret_gate: G,
    relay: R,
    pub(crate) audit: A,
}

impl<I, G, R, A> fmt::Debug for DebugSessionBroker<I, G, R, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugSessionBroker")
            .field("policy", &self.policy)
            .field("token_key", &"[REDACTED]")
            .field("identity_issuer", &"<issuer>")
            .field("secret_gate", &"<secret gate>")
            .field("relay", &"<reverse relay>")
            .field("audit", &"<audit sink>")
            .finish()
    }
}

impl<I, G, R, A> DebugSessionBroker<I, G, R, A>
where
    I: EphemeralIdentityIssuer,
    G: DebugSecretGate,
    R: DebugRelay,
    A: DebugAuditSink,
{
    pub fn new(
        policy: DebugSessionPolicy,
        token_key: TunnelTokenKey,
        identity_issuer: I,
        secret_gate: G,
        relay: R,
        audit: A,
    ) -> Result<Self, DebugSessionError> {
        Ok(Self {
            policy: policy.validate()?,
            token_key,
            identity_issuer,
            secret_gate,
            relay,
            audit,
        })
    }

    pub fn open(
        &mut self,
        auth: &AuthContext,
        request: &DebugSessionRequest,
        approval: &DebugApproval,
        now_unix_ms: u64,
    ) -> Result<IssuedDebugSession, DebugSessionError> {
        validate_open(auth, request, approval, self.policy, now_unix_ms)?;
        let approval_subject = request.approval_subject()?;
        let subject_digest = approval_subject.digest()?;
        let expires_unix_ms = now_unix_ms
            .checked_add(request.requested_duration_ms)
            .ok_or(DebugSessionError::InvalidRequest)?;
        let secret_request = SecretBlockRequest {
            session_id: request.session_id.clone(),
            tenant_id: request.tenant_id.clone(),
            run_id: request.run_id.clone(),
            job_id: request.job_id.clone(),
            execution_lease_id: request.execution_lease_id.clone(),
            fencing_generation: request.fencing_generation,
            installation_fencing_epoch: request.installation_fencing_epoch,
            expires_unix_ms,
        };
        let future_secret_block_receipt = self
            .secret_gate
            .block_future_release(&secret_request)
            .map_err(|_| DebugSessionError::SecretGate)?;
        let retain_existing_secrets = request.retain_existing_secrets;
        let existing_secret_revocation_receipt =
            if request.secret_state == SecretState::Released && !retain_existing_secrets {
                Some(
                    self.secret_gate
                        .revoke_existing(&secret_request)
                        .map_err(|_| DebugSessionError::SecretGate)?,
                )
            } else {
                None
            };

        let tunnel_token = generate_tunnel_token()?;
        let tunnel_token_digest = self
            .token_key
            .digest(&request.session_id, tunnel_token.expose());
        let client_identity = self
            .identity_issuer
            .issue(&ClientIdentityRequest {
                session_id: request.session_id.clone(),
                tenant_id: request.tenant_id.clone(),
                actor_id: request.actor_id.clone(),
                approval_id: approval.approval_id.clone(),
                subject_digest: subject_digest.clone(),
                expires_unix_ms,
            })
            .map_err(|_| DebugSessionError::IdentityIssuer)?;
        validate_client_identity(&client_identity)?;
        let registration = RelayRegistration {
            session_id: request.session_id.clone(),
            tenant_id: request.tenant_id.clone(),
            run_id: request.run_id.clone(),
            job_id: request.job_id.clone(),
            direction: TunnelDirection::ReverseOnly,
            public_runner_listener: false,
            tunnel_token_digest: tunnel_token_digest.clone(),
            certificate_serial: client_identity.certificate_serial.clone(),
            expires_unix_ms,
        };
        let relay_registration_digest = self
            .relay
            .register_reverse_tunnel(&registration)
            .map_err(|_| DebugSessionError::Relay)?;
        let record = DebugSessionRecord {
            version: SESSION_VERSION,
            session_id: request.session_id.clone(),
            tenant_id: request.tenant_id.clone(),
            repository_id: request.repository_id.clone(),
            run_id: request.run_id.clone(),
            job_id: request.job_id.clone(),
            execution_lease_id: request.execution_lease_id.clone(),
            fencing_generation: request.fencing_generation,
            installation_fencing_epoch: request.installation_fencing_epoch,
            capsule_digest: request.capsule_digest.clone(),
            actor_id: request.actor_id.clone(),
            approver_id: approval.approver_id.clone(),
            approval_id: approval.approval_id.clone(),
            approval_subject,
            approval_subject_digest: subject_digest,
            reason_digest: ContentDigest::sha256(request.reason.as_bytes()),
            state: DebugSessionState::Active,
            tunnel_token_digest,
            token_used: false,
            certificate_serial: client_identity.certificate_serial.clone(),
            tunnel_direction: TunnelDirection::ReverseOnly,
            public_runner_listener: false,
            relay_registration_digest,
            future_secret_block_receipt,
            existing_secret_revocation_receipt,
            retained_existing_secrets: retain_existing_secrets,
            transcript_mode: self.policy.transcript_mode,
            promotion_gate: PromotionGate::FreshTrustedRebuildOrPolicyException,
            created_unix_ms: now_unix_ms,
            expires_unix_ms,
            connected_unix_ms: None,
            revoked_unix_ms: None,
            terminal_audit_recorded: false,
        };
        record.verify_integrity()?;
        if let Err(error) = self.record_audit(DebugAuditKind::Opened, &record, now_unix_ms) {
            let _ = self.relay.revoke(&request.session_id);
            return Err(error);
        }
        Ok(IssuedDebugSession {
            record,
            tunnel_token,
            client_identity,
        })
    }

    pub fn connect(
        &mut self,
        record: &mut DebugSessionRecord,
        tunnel_token: &str,
        certificate_serial: &str,
        now_unix_ms: u64,
    ) -> Result<(), DebugSessionError> {
        record.verify_integrity()?;
        if now_unix_ms >= record.expires_unix_ms {
            self.terminate(record, DebugSessionState::Expired, now_unix_ms)?;
            return Err(DebugSessionError::Expired);
        }
        if record.state != DebugSessionState::Active || record.token_used {
            return Err(DebugSessionError::TokenUsed);
        }
        if certificate_serial != record.certificate_serial
            || !valid_token_text(tunnel_token)
            || !self.token_key.verify(
                &record.session_id,
                tunnel_token,
                &record.tunnel_token_digest,
            )
        {
            return Err(DebugSessionError::InvalidCredential);
        }
        record.token_used = true;
        record.state = DebugSessionState::Connected;
        record.connected_unix_ms = Some(now_unix_ms);
        if let Err(error) = self.record_audit(DebugAuditKind::Connected, record, now_unix_ms) {
            let _ = self.relay.revoke(&record.session_id);
            record.state = DebugSessionState::Revoked;
            record.revoked_unix_ms = Some(now_unix_ms);
            record.terminal_audit_recorded = false;
            return Err(error);
        }
        record.verify_integrity()
    }

    pub fn revoke(
        &mut self,
        record: &mut DebugSessionRecord,
        now_unix_ms: u64,
    ) -> Result<(), DebugSessionError> {
        record.verify_integrity()?;
        if matches!(
            record.state,
            DebugSessionState::Revoked | DebugSessionState::Expired
        ) {
            return self.finish_terminal_audit(record);
        }
        self.terminate(record, DebugSessionState::Revoked, now_unix_ms)
    }

    pub fn expire(
        &mut self,
        record: &mut DebugSessionRecord,
        now_unix_ms: u64,
    ) -> Result<(), DebugSessionError> {
        record.verify_integrity()?;
        if now_unix_ms < record.expires_unix_ms {
            return Err(DebugSessionError::NotExpired);
        }
        if record.state == DebugSessionState::Expired {
            return self.finish_terminal_audit(record);
        }
        self.terminate(record, DebugSessionState::Expired, now_unix_ms)
    }

    fn terminate(
        &mut self,
        record: &mut DebugSessionRecord,
        state: DebugSessionState,
        now_unix_ms: u64,
    ) -> Result<(), DebugSessionError> {
        self.relay
            .revoke(&record.session_id)
            .map_err(|_| DebugSessionError::Relay)?;
        record.state = state;
        record.revoked_unix_ms = Some(now_unix_ms);
        record.terminal_audit_recorded = false;
        let kind = if state == DebugSessionState::Expired {
            DebugAuditKind::Expired
        } else {
            DebugAuditKind::Revoked
        };
        self.record_audit(kind, record, now_unix_ms)?;
        record.terminal_audit_recorded = true;
        record.verify_integrity()
    }

    fn finish_terminal_audit(
        &mut self,
        record: &mut DebugSessionRecord,
    ) -> Result<(), DebugSessionError> {
        if record.terminal_audit_recorded {
            return Ok(());
        }
        let occurred_unix_ms = record.revoked_unix_ms.ok_or(DebugSessionError::Integrity)?;
        let kind = if record.state == DebugSessionState::Expired {
            DebugAuditKind::Expired
        } else {
            DebugAuditKind::Revoked
        };
        self.record_audit(kind, record, occurred_unix_ms)?;
        record.terminal_audit_recorded = true;
        record.verify_integrity()
    }

    fn record_audit(
        &mut self,
        kind: DebugAuditKind,
        record: &DebugSessionRecord,
        now_unix_ms: u64,
    ) -> Result<(), DebugSessionError> {
        let event = debug_audit_event(kind, record, now_unix_ms)?;
        self.audit
            .record(&event)
            .map_err(|_| DebugSessionError::Audit)
    }

    pub fn into_parts(self) -> (I, G, R, A) {
        (
            self.identity_issuer,
            self.secret_gate,
            self.relay,
            self.audit,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::DEBUG_SCOPE;
    use crate::*;
    use std::collections::BTreeSet;
    use zeroize::Zeroizing;

    const NOW: u64 = 10_000;

    fn auth() -> AuthContext {
        AuthContext {
            principal_id: "user:developer".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            authentication: runtrue_auth::AuthenticationKind::BrowserSession,
            scopes: BTreeSet::from([DEBUG_SCOPE.to_owned()]),
            credential_id: None,
            credential_expires_unix_ms: None,
            mfa_authenticated_unix_ms: Some(NOW - 100),
            reauthenticated_unix_ms: Some(NOW - 100),
        }
    }

    fn request() -> DebugSessionRequest {
        DebugSessionRequest {
            session_id: "debug-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            repository_id: "repo-1".to_owned(),
            run_id: "run-1".to_owned(),
            job_id: "job-1".to_owned(),
            execution_lease_id: "lease-1".to_owned(),
            fencing_generation: 3,
            installation_fencing_epoch: 8,
            capsule_digest: ContentDigest::sha256(b"capsule"),
            actor_id: "user:developer".to_owned(),
            environment: EnvironmentClass::NonProduction,
            workload_trust: WorkloadTrust::InternalUntrusted,
            secret_state: SecretState::NeverReleased,
            retain_existing_secrets: false,
            requested_duration_ms: 5 * 60 * 1000,
            reason: "inspect a failing integration test".to_owned(),
            requested_unix_ms: NOW - 50,
        }
    }

    fn approval(request: &DebugSessionRequest) -> DebugApproval {
        DebugApproval {
            approval_id: "debug-approval-1".to_owned(),
            subject_digest: request.approval_subject().unwrap().digest().unwrap(),
            approver_id: "user:reviewer".to_owned(),
            allow_production: false,
            allow_public_untrusted: false,
            allow_secret_retention: false,
            approved_unix_ms: NOW - 25,
            expires_unix_ms: NOW + 60_000,
        }
    }

    #[derive(Default)]
    struct FakeIssuer {
        requests: Vec<ClientIdentityRequest>,
        invalid: bool,
    }

    impl EphemeralIdentityIssuer for FakeIssuer {
        fn issue(
            &mut self,
            request: &ClientIdentityRequest,
        ) -> Result<EphemeralClientIdentity, DebugSessionError> {
            self.requests.push(request.clone());
            Ok(EphemeralClientIdentity {
                certificate_serial: "serial-1".to_owned(),
                certificate_pem: Zeroizing::new(if self.invalid {
                    "invalid".to_owned()
                } else {
                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_owned()
                }),
                private_key_pem: Zeroizing::new(
                    "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_owned(),
                ),
            })
        }
    }

    #[derive(Default)]
    struct FakeSecretGate {
        blocked: Vec<SecretBlockRequest>,
        revoked: Vec<SecretBlockRequest>,
    }

    impl DebugSecretGate for FakeSecretGate {
        fn block_future_release(
            &mut self,
            request: &SecretBlockRequest,
        ) -> Result<ContentDigest, DebugSessionError> {
            self.blocked.push(request.clone());
            Ok(ContentDigest::sha256(b"blocked"))
        }

        fn revoke_existing(
            &mut self,
            request: &SecretBlockRequest,
        ) -> Result<ContentDigest, DebugSessionError> {
            self.revoked.push(request.clone());
            Ok(ContentDigest::sha256(b"revoked"))
        }
    }

    #[derive(Default)]
    struct FakeRelay {
        registrations: Vec<RelayRegistration>,
        revoked: Vec<String>,
    }

    impl DebugRelay for FakeRelay {
        fn register_reverse_tunnel(
            &mut self,
            registration: &RelayRegistration,
        ) -> Result<ContentDigest, DebugSessionError> {
            if registration.direction != TunnelDirection::ReverseOnly
                || registration.public_runner_listener
            {
                return Err(DebugSessionError::Relay);
            }
            self.registrations.push(registration.clone());
            canonical_digest(&(&registration.session_id, &registration.certificate_serial))
        }

        fn revoke(&mut self, session_id: &str) -> Result<(), DebugSessionError> {
            self.revoked.push(session_id.to_owned());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeAudit {
        events: Vec<DebugAuditEvent>,
        fail_kind: Option<DebugAuditKind>,
        failed: bool,
    }

    impl DebugAuditSink for FakeAudit {
        fn record(&mut self, event: &DebugAuditEvent) -> Result<(), DebugSessionError> {
            if self.fail_kind == Some(event.kind) && !self.failed {
                self.failed = true;
                return Err(DebugSessionError::Audit);
            }
            if !self
                .events
                .iter()
                .any(|stored| stored.event_id == event.event_id)
            {
                self.events.push(event.clone());
            }
            Ok(())
        }
    }

    type Broker = DebugSessionBroker<FakeIssuer, FakeSecretGate, FakeRelay, FakeAudit>;

    fn broker(policy: DebugSessionPolicy) -> Broker {
        DebugSessionBroker::new(
            policy,
            TunnelTokenKey::from_key([7; 32]),
            FakeIssuer::default(),
            FakeSecretGate::default(),
            FakeRelay::default(),
            FakeAudit::default(),
        )
        .unwrap()
    }

    #[test]
    fn opens_reverse_only_with_one_use_credentials_and_no_direct_promotion() {
        let request = request();
        let mut broker = broker(DebugSessionPolicy::default());
        let mut issued = broker
            .open(&auth(), &request, &approval(&request), NOW)
            .unwrap();
        assert!(!issued.record.public_runner_listener);
        assert_eq!(issued.record.tunnel_direction, TunnelDirection::ReverseOnly);
        assert!(!issued.record.permits_direct_artifact_promotion());
        assert!(format!("{issued:?}").contains("[REDACTED]"));
        assert!(!format!("{issued:?}").contains(issued.tunnel_token.expose()));
        let token = issued.tunnel_token.expose().to_owned();
        broker
            .connect(&mut issued.record, &token, "serial-1", NOW + 1)
            .unwrap();
        assert_eq!(issued.record.state, DebugSessionState::Connected);
        assert!(matches!(
            broker.connect(&mut issued.record, &token, "serial-1", NOW + 2),
            Err(DebugSessionError::TokenUsed)
        ));
        let (_, gate, relay, audit) = broker.into_parts();
        assert_eq!(gate.blocked.len(), 1);
        assert!(gate.revoked.is_empty());
        assert_eq!(relay.registrations.len(), 1);
        assert_eq!(audit.events.len(), 2);
    }

    #[test]
    fn released_secrets_are_revoked_unless_explicitly_retained() {
        let mut request = request();
        request.secret_state = SecretState::Released;
        let mut revoking_broker = broker(DebugSessionPolicy::default());
        let issued = revoking_broker
            .open(&auth(), &request, &approval(&request), NOW)
            .unwrap();
        assert!(issued.record.existing_secret_revocation_receipt.is_some());
        let (_, gate, _, _) = revoking_broker.into_parts();
        assert_eq!(gate.revoked.len(), 1);

        "debug-retain".clone_into(&mut request.session_id);
        request.retain_existing_secrets = true;
        let mut approval = approval(&request);
        approval.allow_secret_retention = true;
        let policy = DebugSessionPolicy {
            secret_retention_enabled: true,
            ..DebugSessionPolicy::default()
        };
        let mut retaining_broker = broker(policy);
        let issued = retaining_broker
            .open(&auth(), &request, &approval, NOW)
            .unwrap();
        assert!(issued.record.retained_existing_secrets);
        assert!(issued.record.existing_secret_revocation_receipt.is_none());
        let (_, gate, _, _) = retaining_broker.into_parts();
        assert!(gate.revoked.is_empty());
        assert_eq!(gate.blocked.len(), 1);
    }

    #[test]
    fn production_and_public_untrusted_are_disabled_by_default() {
        let mut request = request();
        request.environment = EnvironmentClass::Production;
        let mut production_approval = approval(&request);
        production_approval.allow_production = true;
        assert!(matches!(
            broker(DebugSessionPolicy::default()).open(
                &auth(),
                &request,
                &production_approval,
                NOW
            ),
            Err(DebugSessionError::PolicyDenied)
        ));

        request.environment = EnvironmentClass::NonProduction;
        request.workload_trust = WorkloadTrust::PublicUntrusted;
        let mut public_approval = approval(&request);
        public_approval.allow_public_untrusted = true;
        assert!(matches!(
            broker(DebugSessionPolicy::default()).open(&auth(), &request, &public_approval, NOW),
            Err(DebugSessionError::PolicyDenied)
        ));
    }

    #[test]
    fn stale_auth_self_approval_and_subject_changes_are_denied() {
        let request = request();
        let mut stale = auth();
        stale.mfa_authenticated_unix_ms = None;
        assert!(matches!(
            broker(DebugSessionPolicy::default()).open(&stale, &request, &approval(&request), NOW),
            Err(DebugSessionError::Authentication)
        ));
        let mut self_approval = approval(&request);
        self_approval.approver_id.clone_from(&request.actor_id);
        assert!(matches!(
            broker(DebugSessionPolicy::default()).open(&auth(), &request, &self_approval, NOW),
            Err(DebugSessionError::InvalidApproval)
        ));
        let mut changed = request.clone();
        changed.fencing_generation += 1;
        assert!(matches!(
            broker(DebugSessionPolicy::default()).open(&auth(), &changed, &approval(&request), NOW),
            Err(DebugSessionError::InvalidApproval)
        ));
    }

    #[test]
    fn expiration_revokes_relay_and_records_terminal_event() {
        let request = request();
        let mut broker = broker(DebugSessionPolicy::default());
        let mut issued = broker
            .open(&auth(), &request, &approval(&request), NOW)
            .unwrap();
        let expires_unix_ms = issued.record.expires_unix_ms;
        broker.expire(&mut issued.record, expires_unix_ms).unwrap();
        assert_eq!(issued.record.state, DebugSessionState::Expired);
        assert!(issued.record.terminal_audit_recorded);
        let (_, _, relay, audit) = broker.into_parts();
        assert_eq!(relay.revoked, vec![request.session_id]);
        assert_eq!(audit.events.last().unwrap().kind, DebugAuditKind::Expired);
    }

    #[test]
    fn audit_failure_closes_relay_and_terminal_audit_can_retry() {
        let request = request();
        let mut open_failure = broker(DebugSessionPolicy::default());
        open_failure.audit.fail_kind = Some(DebugAuditKind::Opened);
        assert!(matches!(
            open_failure.open(&auth(), &request, &approval(&request), NOW),
            Err(DebugSessionError::Audit)
        ));
        let (_, _, relay, _) = open_failure.into_parts();
        assert_eq!(relay.revoked, vec![request.session_id.clone()]);

        let mut valid_broker = broker(DebugSessionPolicy::default());
        let mut issued = valid_broker
            .open(&auth(), &request, &approval(&request), NOW)
            .unwrap();
        valid_broker.audit.fail_kind = Some(DebugAuditKind::Connected);
        let token = issued.tunnel_token.expose().to_owned();
        assert!(matches!(
            valid_broker.connect(&mut issued.record, &token, "serial-1", NOW + 1),
            Err(DebugSessionError::Audit)
        ));
        assert_eq!(issued.record.state, DebugSessionState::Revoked);
        assert!(!issued.record.terminal_audit_recorded);
        valid_broker.revoke(&mut issued.record, NOW + 2).unwrap();
        assert!(issued.record.terminal_audit_recorded);
    }

    #[test]
    fn persisted_record_rejects_public_listener_and_invalid_identity() {
        let request = request();
        let mut valid_broker = broker(DebugSessionPolicy::default());
        let mut issued = valid_broker
            .open(&auth(), &request, &approval(&request), NOW)
            .unwrap();
        issued.record.public_runner_listener = true;
        assert!(matches!(
            issued.record.verify_integrity(),
            Err(DebugSessionError::Integrity)
        ));

        let mut invalid = broker(DebugSessionPolicy::default());
        invalid.identity_issuer.invalid = true;
        assert!(matches!(
            invalid.open(&auth(), &request, &approval(&request), NOW),
            Err(DebugSessionError::IdentityIssuer)
        ));
    }
}
