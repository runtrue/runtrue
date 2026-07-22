use super::{RunnerControlConfig, RunnerDataPlane, RunnerProtocolMetrics};
use crate::runner_certificates::RunnerCertificateAuthority;
use runtrue_control_plane::ControlPlaneStore;
use runtrue_model::ContentDigest;
use runtrue_oidc::OidcIssuer;
use runtrue_protocol::v1;
use runtrue_secrets::MasterKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::mpsc;
use tonic::Status;
#[derive(Debug)]
pub(super) struct SessionState {
    pub(super) offered: BTreeMap<String, u64>,
    pub(super) accepted: BTreeMap<String, u64>,
    pub(super) cancellation_acks: BTreeSet<(String, u64)>,
    pub(super) log_sequences: BTreeMap<(String, u32, String, String), u64>,
    pub(super) running_steps: BTreeMap<(String, u32), String>,
    pub(super) terminal_steps: BTreeSet<(String, u32, String)>,
    pub(super) scm_credential_leases: BTreeSet<String>,
    pub(super) current_attempts: BTreeMap<String, u32>,
    pub(super) rotation_notice_sent: bool,
}

#[derive(Debug)]
pub(super) struct RunnerSession {
    pub(super) runner_id: String,
    pub(super) connection_id: String,
    pub(super) protocol_version: u32,
    pub(super) max_concurrent_wasm_jobs: usize,
    pub(super) posture_digest: ContentDigest,
    pub(super) runner_image_digest: ContentDigest,
    pub(super) certificate_fingerprint: Option<ContentDigest>,
    pub(super) certificate_expires_unix_ms: Option<u64>,
    pub(super) outbound: mpsc::Sender<Result<v1::ControlMessage, Status>>,
    pub(super) state: Mutex<SessionState>,
    pub(super) offer_lock: tokio::sync::Mutex<()>,
    pub(super) broker_lock: tokio::sync::Mutex<()>,
}

impl RunnerSession {
    pub(super) fn state(&self) -> Result<MutexGuard<'_, SessionState>, Status> {
        self.state
            .lock()
            .map_err(|_| Status::internal("runner session state is unavailable"))
    }
}

pub(super) struct RunnerControlInner {
    pub(super) control_plane: Arc<dyn ControlPlaneStore>,
    pub(super) certificate_authority: Option<Arc<RunnerCertificateAuthority>>,
    pub(super) secret_master_key: Option<Arc<MasterKey>>,
    pub(super) oidc_issuer: Option<Arc<OidcIssuer>>,
    pub(super) data_plane: Option<Arc<RunnerDataPlane>>,
    pub(super) scm_credential_provider:
        Option<Arc<dyn crate::scm_worker::GitHubInstallationTokenProvider>>,
    pub(super) config: RunnerControlConfig,
    pub(super) protocol_metrics: RunnerProtocolMetrics,
    pub(super) connections: Mutex<BTreeMap<String, Arc<RunnerSession>>>,
}
