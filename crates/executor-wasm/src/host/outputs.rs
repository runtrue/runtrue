#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostOutput {
    pub output: Option<Vec<u8>>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}
