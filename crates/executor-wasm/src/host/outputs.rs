use runtrue_engine::CredentialTaint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostOutput {
    pub output: Option<Vec<u8>>,
    pub stdout: String,
    pub stderr: String,
    pub credential_taint: CredentialTaint,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}
