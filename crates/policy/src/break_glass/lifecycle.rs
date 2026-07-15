use super::{
    validation::{subject_digest, validate_recent_mfa, validate_text},
    BreakGlassApproval, BreakGlassError, BreakGlassNotificationReceipt, BreakGlassRequest,
    BreakGlassStatus, BreakGlassUse, NewBreakGlassRequest, MAX_BREAK_GLASS_APPROVERS,
    MAX_BREAK_GLASS_DURATION_MS, NEVER_BREAK_GLASS_ACTIONS,
};
use runtrue_model::ContentDigest;
impl BreakGlassRequest {
    pub fn create(new: NewBreakGlassRequest) -> Result<Self, BreakGlassError> {
        for (kind, value) in [
            ("request id", new.id.as_str()),
            ("tenant id", new.tenant_id.as_str()),
            ("requester id", new.requester_id.as_str()),
            ("action", new.action.as_str()),
            ("resource kind", new.resource_kind.as_str()),
            ("resource id", new.resource_id.as_str()),
            ("reason", new.reason.as_str()),
            ("incident reference", new.incident_reference.as_str()),
        ] {
            validate_text(kind, value)?;
        }
        if NEVER_BREAK_GLASS_ACTIONS.contains(&new.action.as_str()) {
            return Err(BreakGlassError::PermanentlyForbiddenAction(new.action));
        }
        if new.requested_unix_ms >= new.expires_unix_ms
            || new.expires_unix_ms.saturating_sub(new.requested_unix_ms)
                > MAX_BREAK_GLASS_DURATION_MS
        {
            return Err(BreakGlassError::InvalidDuration);
        }
        validate_recent_mfa(new.requester_mfa_unix_ms, new.requested_unix_ms)?;
        if new.eligible_approvers.len() > MAX_BREAK_GLASS_APPROVERS
            || new.eligible_approvers.contains(&new.requester_id)
            || (new.require_second_approver && new.eligible_approvers.is_empty())
        {
            return Err(BreakGlassError::InvalidApproverSet);
        }
        for approver in &new.eligible_approvers {
            validate_text("eligible approver", approver)?;
        }
        let subject_digest = subject_digest(&new);
        Ok(Self {
            id: new.id,
            tenant_id: new.tenant_id,
            requester_id: new.requester_id,
            action: new.action,
            resource_kind: new.resource_kind,
            resource_id: new.resource_id,
            reason: new.reason,
            incident_reference: new.incident_reference,
            requested_unix_ms: new.requested_unix_ms,
            requester_mfa_unix_ms: new.requester_mfa_unix_ms,
            expires_unix_ms: new.expires_unix_ms,
            require_second_approver: new.require_second_approver,
            eligible_approvers: new.eligible_approvers,
            subject_digest,
            status: if new.require_second_approver {
                BreakGlassStatus::PendingApproval
            } else {
                BreakGlassStatus::PendingNotification
            },
            approval: None,
            notification: None,
            use_record: None,
        })
    }

    pub fn decide(
        &mut self,
        decision: BreakGlassApproval,
        now_unix_ms: u64,
    ) -> Result<BreakGlassStatus, BreakGlassError> {
        self.refresh_expiry(now_unix_ms);
        if self.status != BreakGlassStatus::PendingApproval {
            return Err(BreakGlassError::InvalidState(self.status));
        }
        validate_text("approval actor", &decision.actor_id)?;
        validate_text("approval reason", &decision.reason)?;
        if decision.subject_digest != self.subject_digest {
            return Err(BreakGlassError::SubjectMismatch);
        }
        if !self.eligible_approvers.contains(&decision.actor_id)
            || decision.actor_id == self.requester_id
        {
            return Err(BreakGlassError::IneligibleApprover);
        }
        if decision.decided_unix_ms < self.requested_unix_ms
            || decision.decided_unix_ms > now_unix_ms
        {
            return Err(BreakGlassError::InvalidDecisionTime);
        }
        validate_recent_mfa(decision.actor_mfa_unix_ms, decision.decided_unix_ms)?;
        self.status = if decision.approve {
            BreakGlassStatus::PendingNotification
        } else {
            BreakGlassStatus::Denied
        };
        self.approval = Some(decision);
        Ok(self.status)
    }

    pub fn record_notification(
        &mut self,
        receipt: BreakGlassNotificationReceipt,
        now_unix_ms: u64,
    ) -> Result<(), BreakGlassError> {
        self.refresh_expiry(now_unix_ms);
        if self.status != BreakGlassStatus::PendingNotification {
            return Err(BreakGlassError::InvalidState(self.status));
        }
        if receipt.subject_digest != self.subject_digest {
            return Err(BreakGlassError::SubjectMismatch);
        }
        validate_text("notification channel", &receipt.channel)?;
        validate_text("notification delivery id", &receipt.delivery_id)?;
        let earliest_notification = self
            .approval
            .as_ref()
            .map_or(self.requested_unix_ms, |approval| approval.decided_unix_ms);
        if receipt.notified_unix_ms < earliest_notification
            || receipt.notified_unix_ms > now_unix_ms
        {
            return Err(BreakGlassError::InvalidNotificationTime);
        }
        self.notification = Some(receipt);
        self.status = BreakGlassStatus::Active;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_once(
        &mut self,
        actor_id: &str,
        action: &str,
        resource_kind: &str,
        resource_id: &str,
        subject_digest: &ContentDigest,
        reauthenticated_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<BreakGlassUse, BreakGlassError> {
        self.refresh_expiry(now_unix_ms);
        if self.status != BreakGlassStatus::Active {
            return Err(BreakGlassError::InvalidState(self.status));
        }
        if subject_digest != &self.subject_digest
            || actor_id != self.requester_id
            || action != self.action
            || resource_kind != self.resource_kind
            || resource_id != self.resource_id
        {
            return Err(BreakGlassError::SubjectMismatch);
        }
        validate_recent_mfa(reauthenticated_unix_ms, now_unix_ms)?;
        let use_record = BreakGlassUse {
            subject_digest: self.subject_digest.clone(),
            actor_id: actor_id.to_owned(),
            action: action.to_owned(),
            resource_kind: resource_kind.to_owned(),
            resource_id: resource_id.to_owned(),
            incident_reference: self.incident_reference.clone(),
            used_unix_ms: now_unix_ms,
            reauthenticated_unix_ms,
        };
        self.use_record = Some(use_record.clone());
        self.status = BreakGlassStatus::Consumed;
        Ok(use_record)
    }

    pub fn refresh_expiry(&mut self, now_unix_ms: u64) {
        if matches!(
            self.status,
            BreakGlassStatus::PendingApproval
                | BreakGlassStatus::PendingNotification
                | BreakGlassStatus::Active
        ) && now_unix_ms >= self.expires_unix_ms
        {
            self.status = BreakGlassStatus::Expired;
        }
    }

    /// Rebuild the state machine from its immutable request and recorded
    /// evidence. Persistence adapters must call this after deserialization so
    /// editing a status field cannot manufacture an active emergency grant.
    pub fn verify_integrity(&self) -> Result<(), BreakGlassError> {
        let new = NewBreakGlassRequest {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            requester_id: self.requester_id.clone(),
            action: self.action.clone(),
            resource_kind: self.resource_kind.clone(),
            resource_id: self.resource_id.clone(),
            reason: self.reason.clone(),
            incident_reference: self.incident_reference.clone(),
            requested_unix_ms: self.requested_unix_ms,
            requester_mfa_unix_ms: self.requester_mfa_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
            require_second_approver: self.require_second_approver,
            eligible_approvers: self.eligible_approvers.clone(),
        };
        let mut replay = Self::create(new).map_err(|_| BreakGlassError::IntegrityMismatch)?;
        if replay.subject_digest != self.subject_digest {
            return Err(BreakGlassError::IntegrityMismatch);
        }
        if let Some(approval) = &self.approval {
            replay
                .decide(approval.clone(), approval.decided_unix_ms)
                .map_err(|_| BreakGlassError::IntegrityMismatch)?;
        }
        if let Some(notification) = &self.notification {
            replay
                .record_notification(notification.clone(), notification.notified_unix_ms)
                .map_err(|_| BreakGlassError::IntegrityMismatch)?;
        }
        if let Some(use_record) = &self.use_record {
            let replayed = replay
                .authorize_once(
                    &use_record.actor_id,
                    &use_record.action,
                    &use_record.resource_kind,
                    &use_record.resource_id,
                    &use_record.subject_digest,
                    use_record.reauthenticated_unix_ms,
                    use_record.used_unix_ms,
                )
                .map_err(|_| BreakGlassError::IntegrityMismatch)?;
            if &replayed != use_record {
                return Err(BreakGlassError::IntegrityMismatch);
            }
        }
        if self.status == BreakGlassStatus::Expired {
            replay.refresh_expiry(self.expires_unix_ms);
        }
        if &replay != self {
            return Err(BreakGlassError::IntegrityMismatch);
        }
        Ok(())
    }
}
