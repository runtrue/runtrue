use crate::{validate_bounded_text, WasmError};
use runtrue_workflow_ir::{Architecture, OperatingSystem};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmTarget {
    pub(crate) target_triple: String,
    pub(crate) operating_system: OperatingSystem,
    pub(crate) architecture: Architecture,
    pub(crate) cpu_feature_floor: String,
}

impl WasmTarget {
    pub fn new(
        target_triple: impl Into<String>,
        operating_system: OperatingSystem,
        architecture: Architecture,
        cpu_feature_floor: impl Into<String>,
    ) -> Result<Self, WasmError> {
        let target_triple = target_triple.into();
        let cpu_feature_floor = cpu_feature_floor.into();
        validate_bounded_text("target triple", &target_triple, 256)?;
        validate_bounded_text("CPU feature floor", &cpu_feature_floor, 128)?;
        if cpu_feature_floor != "baseline" {
            return Err(WasmError::UnsupportedCpuFeatureFloor(cpu_feature_floor));
        }
        if operating_system == OperatingSystem::Windows && architecture == Architecture::Arm64 {
            return Err(WasmError::InvalidConfiguration(
                "the Windows ARM64 execution target is not supported by this executor".to_owned(),
            ));
        }
        let expected_arch = match architecture {
            Architecture::Amd64 => "x86_64",
            Architecture::Arm64 => "aarch64",
        };
        let expected_os = match operating_system {
            OperatingSystem::Linux => "linux",
            OperatingSystem::Windows => "windows",
            OperatingSystem::Macos => "darwin",
        };
        if !target_triple.starts_with(expected_arch) || !target_triple.contains(expected_os) {
            return Err(WasmError::InvalidConfiguration(format!(
                "target triple `{target_triple}` does not match {operating_system:?}/{architecture:?}"
            )));
        }
        Ok(Self {
            target_triple,
            operating_system,
            architecture,
            cpu_feature_floor,
        })
    }

    pub fn host_baseline() -> Result<Self, WasmError> {
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        let values = (
            if cfg!(target_env = "musl") {
                "x86_64-unknown-linux-musl"
            } else {
                "x86_64-unknown-linux-gnu"
            },
            OperatingSystem::Linux,
            Architecture::Amd64,
        );
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        let values = (
            if cfg!(target_env = "musl") {
                "aarch64-unknown-linux-musl"
            } else {
                "aarch64-unknown-linux-gnu"
            },
            OperatingSystem::Linux,
            Architecture::Arm64,
        );
        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        let values = (
            "x86_64-apple-darwin",
            OperatingSystem::Macos,
            Architecture::Amd64,
        );
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        let values = (
            "aarch64-apple-darwin",
            OperatingSystem::Macos,
            Architecture::Arm64,
        );
        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        let values = (
            if cfg!(target_env = "gnu") {
                "x86_64-pc-windows-gnu"
            } else {
                "x86_64-pc-windows-msvc"
            },
            OperatingSystem::Windows,
            Architecture::Amd64,
        );
        #[cfg(not(any(
            all(target_arch = "x86_64", target_os = "linux"),
            all(target_arch = "aarch64", target_os = "linux"),
            all(target_arch = "x86_64", target_os = "macos"),
            all(target_arch = "aarch64", target_os = "macos"),
            all(target_arch = "x86_64", target_os = "windows")
        )))]
        {
            Err(WasmError::UnsupportedHostPlatform)
        }
        #[cfg(any(
            all(target_arch = "x86_64", target_os = "linux"),
            all(target_arch = "aarch64", target_os = "linux"),
            all(target_arch = "x86_64", target_os = "macos"),
            all(target_arch = "aarch64", target_os = "macos"),
            all(target_arch = "x86_64", target_os = "windows")
        ))]
        {
            Self::new(values.0, values.1, values.2, "baseline")
        }
    }

    #[must_use]
    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    #[must_use]
    pub const fn operating_system(&self) -> OperatingSystem {
        self.operating_system
    }

    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    #[must_use]
    pub fn cpu_feature_floor(&self) -> &str {
        &self.cpu_feature_floor
    }

    pub(crate) fn manifest_architecture(&self) -> &'static str {
        match self.architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
        }
    }
}
