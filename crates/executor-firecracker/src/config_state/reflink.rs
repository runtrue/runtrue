use crate::{FirecrackerError, ProcessVmLauncher, VmControl, VmInvocation, VmLauncher};
use runtrue_engine::CancellationToken;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
const REFLINK_TIMEOUT: Duration = Duration::from_secs(30);
pub trait ReflinkProvisioner: Send + Sync {
    fn reflink(&self, source: &Path, destination: &Path) -> Result<(), FirecrackerError>;
}

#[derive(Debug, Clone)]
pub struct ProcessReflinkProvisioner {
    program: PathBuf,
}

impl ProcessReflinkProvisioner {
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl ReflinkProvisioner for ProcessReflinkProvisioner {
    fn reflink(&self, source: &Path, destination: &Path) -> Result<(), FirecrackerError> {
        if destination.exists() {
            return Err(FirecrackerError::InvalidConfiguration(
                "COW destination already exists".to_owned(),
            ));
        }
        let invocation = VmInvocation {
            program: self.program.clone(),
            arguments: vec![
                "--reflink=always".to_owned(),
                "--sparse=always".to_owned(),
                "--".to_owned(),
                source.display().to_string(),
                destination.display().to_string(),
            ],
            environment: BTreeMap::new(),
        };
        let mut process = ProcessVmLauncher.launch(&invocation)?;
        let exit = process.wait(&VmControl {
            timeout: REFLINK_TIMEOUT,
            cancellation: CancellationToken::default(),
        })?;
        if exit.exit_code != Some(0) || exit.timed_out || exit.canceled || !exit.process_group_clean
        {
            let _ = fs::remove_file(destination);
            return Err(FirecrackerError::InvalidConfiguration(
                "filesystem refused an exact reflink COW clone".to_owned(),
            ));
        }
        Ok(())
    }
}
