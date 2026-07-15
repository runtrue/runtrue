use crate::{canonical, validation, ContentDigest, ExecutionModelError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const RUNTIME_PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeFamily {
    WasmtimeComponent,
    FirecrackerMicrovm,
    RootlessOci,
    OciInMicrovm,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Linux,
    Windows,
    Macos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    Amd64,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePlatform {
    pub operating_system: OperatingSystem,
    pub architecture: Architecture,
    pub cpu_feature_floor: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeComponents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmm: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_runtime: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler: Option<ContentDigest>,
}

/// Exact runtime compatibility tuple. Optional component fields are closed by
/// [`RuntimeFamily`]; validation rejects both missing required components and
/// components that are not applicable to the selected family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCompatibilityProfile {
    pub schema_version: u32,
    pub family: RuntimeFamily,
    pub implementation_generation: String,
    pub platform: RuntimePlatform,
    pub components: RuntimeComponents,
    pub program_abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wit_world: Option<String>,
    pub syscall_contract: String,
    pub memory_model: String,
    pub task_model: String,
    pub filesystem_model: String,
    pub network_model: String,
    pub device_model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aot_compatibility: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_compatibility: Option<ContentDigest>,
    pub mitigation_profile: String,
    pub capability_adapter_generation: String,
    pub guest_protocol_generation: String,
    pub security_patch_generation: u64,
    pub revocation_generation: u64,
}

impl RuntimeCompatibilityProfile {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "runtime profile schema version",
            self.schema_version,
            RUNTIME_PROFILE_SCHEMA_VERSION,
        )?;
        for value in [
            &self.implementation_generation,
            &self.program_abi,
            &self.syscall_contract,
            &self.memory_model,
            &self.task_model,
            &self.filesystem_model,
            &self.network_model,
            &self.device_model,
            &self.mitigation_profile,
            &self.capability_adapter_generation,
            &self.guest_protocol_generation,
        ] {
            validation::identifier("runtime compatibility field", value)?;
        }
        validation::identifiers("CPU feature floor", &self.platform.cpu_feature_floor, false)?;
        if self.security_patch_generation == 0 || self.revocation_generation == 0 {
            return Err(ExecutionModelError::InvalidField {
                field: "runtime security generation",
                reason: "must be greater than zero",
            });
        }
        self.validate_family_components()?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }

    fn validate_family_components(&self) -> Result<(), ExecutionModelError> {
        let c = &self.components;
        let valid = match self.family {
            RuntimeFamily::WasmtimeComponent => {
                c.engine.is_some()
                    && c.vmm.is_none()
                    && c.container_runtime.is_none()
                    && c.kernel.is_none()
                    && c.rootfs.is_none()
                    && c.guest.is_none()
                    && self.wit_world.is_some()
            }
            RuntimeFamily::FirecrackerMicrovm => {
                c.engine.is_none()
                    && c.vmm.is_some()
                    && c.container_runtime.is_none()
                    && c.kernel.is_some()
                    && c.rootfs.is_some()
                    && c.guest.is_some()
                    && self.wit_world.is_none()
            }
            RuntimeFamily::RootlessOci => {
                c.engine.is_none()
                    && c.vmm.is_none()
                    && c.container_runtime.is_some()
                    && c.kernel.is_some()
                    && c.rootfs.is_some()
                    && c.guest.is_none()
                    && self.wit_world.is_none()
            }
            RuntimeFamily::OciInMicrovm => {
                c.engine.is_none()
                    && c.vmm.is_some()
                    && c.container_runtime.is_some()
                    && c.kernel.is_some()
                    && c.rootfs.is_some()
                    && c.guest.is_some()
                    && self.wit_world.is_none()
            }
            RuntimeFamily::Native => {
                c.engine.is_none()
                    && c.vmm.is_none()
                    && c.container_runtime.is_none()
                    && c.kernel.is_some()
                    && c.guest.is_none()
                    && self.wit_world.is_none()
            }
        };
        if !valid {
            return Err(ExecutionModelError::InvalidField {
                field: "runtime components",
                reason: "required or inapplicable components do not match the runtime family",
            });
        }
        if let Some(wit_world) = &self.wit_world {
            validation::identifier("WIT world", wit_world)?;
        }
        Ok(())
    }
}
