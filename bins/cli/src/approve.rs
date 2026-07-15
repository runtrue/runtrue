use super::{
    print_json,
    remote::{valid_api_identifier, AuthenticatedRemote},
    CliError, EXIT_OK,
};
use clap::{Args, Subcommand};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_REASON_BYTES: usize = 2_000;
const MAX_RULE_ID_BYTES: usize = 8_192;

#[derive(Debug, Args)]
pub(super) struct SealArgs {
    #[command(subcommand)]
    command: SealCommand,
}

impl SealArgs {
    pub(super) const fn wants_json(&self) -> bool {
        match &self.command {
            SealCommand::Approve(args) | SealCommand::Deny(args) => args.json,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SealCommand {
    /// Approve and create Seal evidence for an exact Capsule digest.
    Approve(DecisionArgs),
    /// Deny approval for an exact Capsule digest; no Seal is created.
    Deny(DecisionArgs),
}

#[derive(Debug, Args)]
struct DecisionArgs {
    /// Exact approval-request id returned by the control plane.
    #[arg(value_name = "APPROVAL_ID")]
    approval_id: String,
    /// Exact subject digest shown by the capsule/risk review.
    #[arg(long, value_name = "SHA256")]
    subject_digest: String,
    /// Human review reason recorded in the tamper-evident decision history.
    #[arg(long)]
    reason: String,
    /// Approval rule being satisfied, such as workflow-security-owner.
    #[arg(long)]
    rule_id: String,
    /// Runtrue server origin. Paths, credentials, queries, and fragments are rejected.
    #[arg(long, value_name = "URL")]
    server: String,
    /// Private mode-0600 file containing the bearer token.
    #[arg(long, value_name = "PATH")]
    token_file: PathBuf,
    /// Permit plaintext HTTP only for an IP-literal loopback evaluation server.
    #[arg(long)]
    allow_loopback_http: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub(super) json: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum ApprovalDecision {
    Approve,
    Deny,
}

impl std::fmt::Display for ApprovalDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionRequest {
    decision: ApprovalDecision,
    subject_digest: String,
    reason: String,
    rule_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalResponse {
    id: String,
    subject_digest: String,
    approval_kind: String,
    status: String,
    risk_score: u32,
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApprovalReport {
    approval: ApprovalResponse,
    idempotency_replayed: bool,
}

pub(super) fn execute(workspace: &Path, args: SealArgs) -> Result<u8, CliError> {
    let (args, decision) = match args.command {
        SealCommand::Approve(args) => (args, ApprovalDecision::Approve),
        SealCommand::Deny(args) => (args, ApprovalDecision::Deny),
    };
    if !valid_api_identifier(&args.approval_id) {
        return Err(super::remote::SubmitError::InvalidApprovalId.into());
    }
    let subject = ContentDigest::parse(&args.subject_digest)
        .map_err(|_| super::remote::SubmitError::InvalidApprovalSubject)?;
    validate_text(&args.reason, MAX_REASON_BYTES)
        .map_err(|_| super::remote::SubmitError::InvalidApprovalReason)?;
    validate_text(&args.rule_id, MAX_RULE_ID_BYTES)
        .map_err(|_| super::remote::SubmitError::InvalidApprovalRule)?;

    let request = ApprovalDecisionRequest {
        decision,
        subject_digest: subject.to_string(),
        reason: args.reason,
        rule_id: args.rule_id,
    };
    let path = format!("/api/v1/approval-requests/{}/decisions", args.approval_id);
    let remote = AuthenticatedRemote::new(
        workspace,
        &args.server,
        args.allow_loopback_http,
        args.token_file,
    )?;
    let (approval, replayed): (ApprovalResponse, bool) =
        remote.post_json("record Seal decision", &path, "seal", &request)?;
    if approval.id != args.approval_id
        || approval.subject_digest != subject.to_string()
        || approval.risk_score > 100
        || !matches!(
            approval.status.as_str(),
            "pending" | "approved" | "denied" | "expired" | "consumed"
        )
        || approval.approval_kind.is_empty()
        || approval.expires_at.as_deref() == Some("")
    {
        return Err(super::remote::SubmitError::MalformedResponse.into());
    }

    let report = ApprovalReport {
        approval,
        idempotency_replayed: replayed,
    };
    if args.json {
        print_json(&report)?;
    } else {
        println!(
            "approval {}: {} ({})",
            report.approval.id, report.approval.status, report.approval.approval_kind
        );
        println!("subject {}", report.approval.subject_digest);
    }
    Ok(EXIT_OK)
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_text_is_nonempty_bounded_and_control_free() {
        assert!(validate_text("reviewed exact risk diff", MAX_REASON_BYTES).is_ok());
        assert!(validate_text("", MAX_REASON_BYTES).is_err());
        assert!(validate_text("bad\nreason", MAX_REASON_BYTES).is_err());
        assert!(validate_text(&"x".repeat(MAX_REASON_BYTES + 1), MAX_REASON_BYTES).is_err());
    }
}
