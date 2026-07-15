use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runner {
    #[serde(default)]
    pub os: OperatingSystem,
    #[serde(default)]
    pub arch: Architecture,
    #[serde(default)]
    pub isolation: Isolation,
    /// Logical OCI base image reference. Compilation resolves it through the
    /// platform-specific lock entry before it enters an execution capsule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default = "default_cpu")]
    pub cpu: u16,
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default)]
    pub storage: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl Default for Runner {
    fn default() -> Self {
        Self {
            os: OperatingSystem::default(),
            arch: Architecture::default(),
            isolation: Isolation::default(),
            image: None,
            cpu: default_cpu(),
            memory: default_memory(),
            storage: None,
            region: None,
            capabilities: Vec::new(),
        }
    }
}

const fn default_cpu() -> u16 {
    2
}

fn default_memory() -> String {
    "4GiB".to_owned()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    #[default]
    Linux,
    Windows,
    Macos,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    #[default]
    Amd64,
    Arm64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Isolation {
    Wasm,
    Oci,
    #[default]
    Microvm,
    Native,
}
