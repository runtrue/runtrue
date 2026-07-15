#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInvocationKind {
    Run,
    NetworkCreate,
    ServiceStart,
    HealthCheck,
    Remove,
    Exists,
    NetworkRemove,
    NetworkExists,
    RecoveryRemoveContainers,
    RecoveryListContainers,
    RecoveryPruneVolumes,
    RecoveryListVolumes,
    RecoveryPruneNetworks,
    RecoveryListNetworks,
    ImageExists,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInvocation {
    pub(crate) kind: RuntimeInvocationKind,
    pub(crate) program: PathBuf,
    pub(crate) arguments: Vec<String>,
    pub(crate) environment: BTreeMap<String, String>,
}

impl RuntimeInvocation {
    #[must_use]
    pub const fn kind(&self) -> RuntimeInvocationKind {
        self.kind
    }

    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeControl {
    pub timeout: Duration,
    pub cancellation: CancellationToken,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub canceled: bool,
    pub duration: Duration,
    pub process_group_clean: bool,
}

impl RuntimeResult {
    #[must_use]
    pub fn success() -> Self {
        Self {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            canceled: false,
            duration: Duration::ZERO,
            process_group_clean: true,
        }
    }
}

pub trait RuntimeCommandRunner: Send {
    fn invoke(
        &mut self,
        invocation: &RuntimeInvocation,
        control: &RuntimeControl,
    ) -> Result<RuntimeResult, OciError>;
}

impl<R> RuntimeCommandRunner for Box<R>
where
    R: RuntimeCommandRunner + ?Sized,
{
    fn invoke(
        &mut self,
        invocation: &RuntimeInvocation,
        control: &RuntimeControl,
    ) -> Result<RuntimeResult, OciError> {
        (**self).invoke(invocation, control)
    }
}
use crate::{BTreeMap, CancellationToken, Duration, OciError, Path, PathBuf};
