use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum StartupError {
    #[error("configure --endpoint or RUNTRUE_RUNNER_ENDPOINT")]
    MissingEndpoint,
    #[error("configure --enrollment-endpoint or RUNTRUE_RUNNER_ENROLLMENT_ENDPOINT")]
    MissingEnrollmentEndpoint,
    #[error("configure --ca-certificate or RUNTRUE_RUNNER_CA_CERTIFICATE")]
    MissingCaCertificate,
    #[error("configure --enrollment-token-file or RUNTRUE_RUNNER_ENROLLMENT_TOKEN_FILE")]
    MissingEnrollmentTokenFile,
    #[error("configure --launch-claim-file or RUNTRUE_RUNNER_LAUNCH_CLAIM_FILE")]
    MissingLaunchClaimFile,
    #[error("configure exactly one of --launch-claim-file or --update-claim-file")]
    InvalidAutomaticEnrollmentClaim,
    #[error("directly provisioned runners require runner id, client certificate, and client private key together")]
    IncompleteDirectCredentials,
    #[error("directly provisioned or legacy credentials require --protocol-version or RUNTRUE_RUNNER_PROTOCOL_VERSION")]
    MissingProtocolVersion,
    #[error("runner protocol version must be a supported positive generation")]
    InvalidProtocolVersion,
    #[error("enrollment cannot be combined with runner id, client certificate/private key, or insecure loopback")]
    InvalidEnrollmentOptions,
    #[error("--ephemeral or RUNTRUE_RUNNER_EPHEMERAL is valid only with enrollment")]
    EphemeralRequiresEnrollment,
    #[error(
        "runner credentials are already installed; refusing to replace the identity with enroll"
    )]
    CredentialsAlreadyInstalled,
    #[error("environment flag {name} must be one of true, false, 1, or 0")]
    InvalidEnvironmentFlag { name: &'static str },
    #[error("environment value {name} must be an unsigned integer")]
    InvalidUnsignedInteger { name: &'static str },
    #[error("OCI execution requires all seven --oci-* paths (or none)")]
    IncompleteOciConfiguration,
    #[error("Wasm execution requires all five --wasm-* paths (or none)")]
    IncompleteWasmConfiguration,
    #[error(
        "Wasm concurrency must be between 1 and 64 and greater than one requires the Wasm backend"
    )]
    InvalidWasmConcurrency,
    #[error("Firecracker execution requires all eleven --firecracker-* paths (or none)")]
    IncompleteFirecrackerConfiguration,
    #[error("configure at least one explicit execution backend")]
    NoExecutionBackend,
}
