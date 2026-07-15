use crate::runner_certificates::RunnerCertificateError;
use runtrue_control_plane::ControlPlaneError;
use tonic::Status;
pub(super) fn control_plane_status(error: ControlPlaneError) -> Status {
    match error {
        ControlPlaneError::NotFound { .. } => {
            Status::not_found("durable runner resource not found")
        }
        ControlPlaneError::WrongRunner => {
            Status::permission_denied("lease belongs to another runner")
        }
        ControlPlaneError::StaleLeaseGeneration { .. }
        | ControlPlaneError::StaleInstallationEpoch { .. }
        | ControlPlaneError::LeaseOfferExpired
        | ControlPlaneError::LeaseExpired
        | ControlPlaneError::InvalidLeaseState { .. }
        | ControlPlaneError::InvalidTransition { .. } => {
            Status::failed_precondition("durable runner lease is stale or in the wrong state")
        }
        ControlPlaneError::RunnerBrokerBindingMismatch => {
            Status::failed_precondition("runner broker execution binding is stale")
        }
        ControlPlaneError::RunnerBrokerCapabilityDenied => {
            Status::permission_denied("runner broker capability is not declared")
        }
        ControlPlaneError::RunnerBrokerReplay => {
            Status::already_exists("runner broker request was already consumed")
        }
        ControlPlaneError::ApprovalRequired => {
            Status::permission_denied("runner broker approval is not authorized")
        }
        ControlPlaneError::ConflictingCompletion => {
            Status::already_exists("lease already has a different terminal completion")
        }
        ControlPlaneError::InstallationSafeMode => {
            Status::unavailable("installation restore safe mode blocks runner operations")
        }
        ControlPlaneError::RunnerCertificateUnauthorized
        | ControlPlaneError::CertificateIdentityMismatch => {
            Status::permission_denied("runner certificate is not authorized")
        }
        ControlPlaneError::RunnerCertificateRotationConflict => {
            Status::already_exists("runner certificate is bound to a different rotation CSR")
        }
        ControlPlaneError::RunnerInventoryMismatch
        | ControlPlaneError::RunnerReenrollmentRequired => Status::failed_precondition(
            "runner inventory or deployment posture changed and requires re-enrollment",
        ),
        ControlPlaneError::InvalidRunnerCertificateChain => {
            Status::invalid_argument("runner certificate chain is invalid")
        }
        ControlPlaneError::InvalidInput(_) => Status::invalid_argument("invalid runner operation"),
        _ => Status::internal("durable runner control operation failed"),
    }
}

pub(super) fn enrollment_status(error: ControlPlaneError) -> Status {
    match error {
        ControlPlaneError::InvalidEnrollmentToken
        | ControlPlaneError::EnrollmentTokenExpired
        | ControlPlaneError::EnrollmentTokenConsumed => {
            Status::permission_denied("runner enrollment token is not valid")
        }
        ControlPlaneError::CertificateIdentityMismatch => {
            Status::permission_denied("runner enrollment identity does not match its token")
        }
        ControlPlaneError::InvalidInput(_) => {
            Status::failed_precondition("runner enrollment pool is unavailable")
        }
        _ => Status::internal("durable runner enrollment failed"),
    }
}

pub(super) fn certificate_status(error: RunnerCertificateError) -> Status {
    match error {
        RunnerCertificateError::CsrSize => {
            Status::resource_exhausted("runner certificate signing request exceeds its bound")
        }
        RunnerCertificateError::InvalidCsr
        | RunnerCertificateError::UnsupportedCsrKey
        | RunnerCertificateError::InvalidIdentity => {
            Status::invalid_argument("runner certificate signing request is invalid")
        }
        RunnerCertificateError::CaNotValid => {
            Status::unavailable("runner certificate authority is not currently valid")
        }
        _ => Status::internal("runner certificate issuance failed"),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerServiceError {
    #[error("invalid runner-control configuration")]
    InvalidConfiguration,
    #[error("runner data-plane configuration failed: {0}")]
    DataPlane(String),
}
