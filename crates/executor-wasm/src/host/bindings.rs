use super::{CapabilityCallContext, FilesystemAdapter};
use runtrue_model::SecretReference;
use runtrue_workflow_ir::NetworkPermission;
use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};
use thiserror::Error;
use zeroize::Zeroizing;
const MAX_BLOCKING_ADAPTER_CALLS: usize = 64;
pub(super) const REDACTION_MARKER: &[u8] = b"[REDACTED]";
static ACTIVE_ADAPTER_CALLS: AtomicUsize = AtomicUsize::new(0);

pub trait NetworkAdapter: Send + Sync {
    fn http_request(
        &self,
        context: &CapabilityCallContext,
        grant: &NetworkPermission,
        request: &[u8],
    ) -> Result<Vec<u8>, CapabilityAdapterError>;
}

pub trait SecretAdapter: Send + Sync {
    fn read_secret(
        &self,
        context: &CapabilityCallContext,
        grant: &SecretReference,
    ) -> Result<SecretValue, CapabilityAdapterError>;
}

pub trait OidcAdapter: Send + Sync {
    fn mint_token(
        &self,
        context: &CapabilityCallContext,
        audience: &str,
    ) -> Result<OidcToken, CapabilityAdapterError>;
}

pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct OidcToken(Zeroizing<Vec<u8>>);

impl OidcToken {
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OidcToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcToken(<redacted>)")
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(<redacted>)")
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityAdapterError {
    #[error("capability request denied: {0}")]
    Denied(String),
    #[error("capability adapter failed: {0}")]
    Failed(String),
    #[error("capability request was canceled")]
    Canceled,
    #[error("capability request deadline was exceeded")]
    DeadlineExceeded,
}

impl CapabilityAdapterError {
    pub(super) fn guest_code(&self) -> &'static str {
        match self {
            Self::Denied(_) => "capability-denied",
            Self::Failed(_) => "capability-adapter-failed",
            Self::Canceled => "capability-canceled",
            Self::DeadlineExceeded => "capability-deadline-exceeded",
        }
    }
}

pub(super) fn invoke_adapter<T, F>(
    context: &CapabilityCallContext,
    operation: F,
) -> Result<T, CapabilityAdapterError>
where
    T: Send + 'static,
    F: FnOnce(CapabilityCallContext) -> Result<T, CapabilityAdapterError> + Send + 'static,
{
    context.check()?;
    let permit = AdapterCallPermit::acquire()?;
    let worker_context = context.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("runtrue-wasm-adapter".to_owned())
        .spawn(move || {
            let _permit = permit;
            let _ = sender.send(operation(worker_context));
        })
        .map_err(|error| CapabilityAdapterError::Failed(error.to_string()))?;
    loop {
        context.check()?;
        let wait = context.remaining().min(Duration::from_millis(5));
        match receiver.recv_timeout(wait) {
            Ok(result) => {
                context.check()?;
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(CapabilityAdapterError::Failed(
                    "capability adapter worker stopped".to_owned(),
                ))
            }
        }
    }
}

struct AdapterCallPermit;

impl AdapterCallPermit {
    fn acquire() -> Result<Self, CapabilityAdapterError> {
        ACTIVE_ADAPTER_CALLS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_BLOCKING_ADAPTER_CALLS).then_some(active + 1)
            })
            .map_err(|_| {
                CapabilityAdapterError::Failed(
                    "capability adapter concurrency limit reached".to_owned(),
                )
            })?;
        Ok(Self)
    }
}

impl Drop for AdapterCallPermit {
    fn drop(&mut self) {
        ACTIVE_ADAPTER_CALLS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Default)]
pub struct CapabilityAdapters {
    pub(crate) filesystem: Option<Arc<dyn FilesystemAdapter>>,
    pub(crate) network: Option<Arc<dyn NetworkAdapter>>,
    pub(crate) secrets: Option<Arc<dyn SecretAdapter>>,
    pub(crate) oidc: Option<Arc<dyn OidcAdapter>>,
}

impl CapabilityAdapters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_filesystem(mut self, adapter: Arc<dyn FilesystemAdapter>) -> Self {
        self.filesystem = Some(adapter);
        self
    }

    #[must_use]
    pub fn with_network(mut self, adapter: Arc<dyn NetworkAdapter>) -> Self {
        self.network = Some(adapter);
        self
    }

    #[must_use]
    pub fn with_secrets(mut self, adapter: Arc<dyn SecretAdapter>) -> Self {
        self.secrets = Some(adapter);
        self
    }

    #[must_use]
    pub fn with_oidc(mut self, adapter: Arc<dyn OidcAdapter>) -> Self {
        self.oidc = Some(adapter);
        self
    }

    #[must_use]
    pub const fn has_filesystem(&self) -> bool {
        self.filesystem.is_some()
    }

    #[must_use]
    pub const fn has_network(&self) -> bool {
        self.network.is_some()
    }

    #[must_use]
    pub const fn has_secrets(&self) -> bool {
        self.secrets.is_some()
    }

    #[must_use]
    pub const fn has_oidc(&self) -> bool {
        self.oidc.is_some()
    }
}

impl fmt::Debug for CapabilityAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityAdapters")
            .field("filesystem", &self.has_filesystem())
            .field("network", &self.has_network())
            .field("secrets", &self.has_secrets())
            .field("oidc", &self.has_oidc())
            .finish()
    }
}
