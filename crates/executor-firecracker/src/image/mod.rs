mod compatibility;
mod copy;
mod model;
pub use compatibility::{SnapshotRuntimeCompatibility, SnapshotRuntimeRequirements};
pub use model::{FirecrackerImageSet, ImageArtifact, ImageTrustStore, SnapshotImageSet};
mod secure_open;
mod verification;
use crate::FirecrackerError;
pub(crate) use copy::copy_verified_payload;
use runtrue_attest::{ImageKind, SignedImageManifest};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::Architecture;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use verification::verify_artifact;
pub(crate) use verification::verify_payload;

const COPY_BUFFER_BYTES: usize = 1024 * 1024;
const SNAPSHOT_STATE_MEDIA_TYPE: &str = "application/vnd.firecracker.snapshot-state";
const SNAPSHOT_MEMORY_MEDIA_TYPE: &str = "application/vnd.firecracker.snapshot-memory";
const COMPAT_FIRECRACKER_VERSION: &str = "firecracker-version";
const COMPAT_FIRECRACKER_BINARY: &str = "firecracker-binary-digest";
const COMPAT_FIRECRACKER_BINARY_SIZE: &str = "firecracker-binary-size-bytes";
const COMPAT_SNAPSHOT_FORMAT: &str = "snapshot-format-version";
const COMPAT_CPU_TEMPLATE: &str = "cpu-template";
const COMPAT_CPU_FEATURES: &str = "cpu-feature-digest";
const COMPAT_VCPU_COUNT: &str = "vcpu-count";
const COMPAT_MEMORY_BYTES: &str = "memory-bytes";
const COMPAT_GUEST_CID: &str = "guest-cid";
const COMPAT_MITIGATIONS: &str = "mitigation-profile-digest";
const COMPAT_NETWORK_PROFILE: &str = "network-profile";
const COMPAT_ROOTFS_PATH: &str = "rootfs-path";
const COMPAT_BOOT_CONFIG_PATH: &str = "boot-config-path";
const COMPAT_VSOCK_PATH: &str = "vsock-path";
const COMPAT_SNAPSHOT_ROLE: &str = "snapshot-role";
const SNAPSHOT_STATE_ROLE: &str = "state";
const SNAPSHOT_MEMORY_ROLE: &str = "memory";
const SNAPSHOT_NETWORK_PROFILE: &str = "disconnected";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub(crate) signed: SignedImageManifest,
    pub(crate) payload_path: PathBuf,
}

impl VerifiedArtifact {
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.signed.manifest.payload_digest
    }

    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedImageManifest {
        &self.signed
    }

    #[must_use]
    pub fn payload_path(&self) -> &Path {
        &self.payload_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedImageSet {
    pub(crate) kernel: VerifiedArtifact,
    pub(crate) rootfs: VerifiedArtifact,
    pub(crate) guest: VerifiedArtifact,
    pub(crate) snapshot: Option<VerifiedSnapshotImageSet>,
    pub(crate) architecture: Architecture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshotImageSet {
    pub(crate) state: VerifiedArtifact,
    pub(crate) memory: VerifiedArtifact,
    pub(crate) compatibility: SnapshotRuntimeCompatibility,
}

impl VerifiedImageSet {
    #[must_use]
    pub const fn kernel(&self) -> &VerifiedArtifact {
        &self.kernel
    }

    #[must_use]
    pub const fn rootfs(&self) -> &VerifiedArtifact {
        &self.rootfs
    }

    #[must_use]
    pub const fn guest(&self) -> &VerifiedArtifact {
        &self.guest
    }

    #[must_use]
    pub const fn snapshot(&self) -> Option<&VerifiedSnapshotImageSet> {
        self.snapshot.as_ref()
    }

    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }
}

impl VerifiedSnapshotImageSet {
    #[must_use]
    pub const fn state(&self) -> &VerifiedArtifact {
        &self.state
    }

    #[must_use]
    pub const fn memory(&self) -> &VerifiedArtifact {
        &self.memory
    }

    #[must_use]
    pub const fn compatibility(&self) -> &SnapshotRuntimeCompatibility {
        &self.compatibility
    }
}

impl FirecrackerImageSet {
    /// Verify signatures, expiry, exact file bytes, platform, and component
    /// bindings. A warm snapshot is admitted only when its signed phase is
    /// explicitly sterile and it binds this exact kernel/rootfs/guest tuple.
    pub fn verify(
        &self,
        trust: &ImageTrustStore,
        architecture: Architecture,
        now_unix_ms: u64,
        snapshot_runtime: Option<&SnapshotRuntimeCompatibility>,
    ) -> Result<VerifiedImageSet, FirecrackerError> {
        if trust.keys.is_empty() {
            return Err(FirecrackerError::InvalidConfiguration(
                "image trust store is empty".to_owned(),
            ));
        }
        let kernel = verify_artifact(
            trust,
            &self.kernel,
            ImageKind::FirecrackerKernel,
            architecture,
            now_unix_ms,
        )?;
        let rootfs = verify_artifact(
            trust,
            &self.rootfs,
            ImageKind::FirecrackerRootFilesystem,
            architecture,
            now_unix_ms,
        )?;
        let guest = verify_artifact(
            trust,
            &self.guest,
            ImageKind::GuestAgent,
            architecture,
            now_unix_ms,
        )?;
        require_component(&rootfs.signed.manifest.components, "guest", guest.digest())?;
        require_component(
            &rootfs.signed.manifest.components,
            "kernel",
            kernel.digest(),
        )?;

        let snapshot = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                let runtime = snapshot_runtime.ok_or_else(|| {
                    FirecrackerError::InvalidConfiguration(
                        "snapshot runtime compatibility was not supplied".to_owned(),
                    )
                })?;
                let state = verify_artifact(
                    trust,
                    &snapshot.state,
                    ImageKind::FirecrackerSnapshot,
                    architecture,
                    now_unix_ms,
                )?;
                let memory = verify_artifact(
                    trust,
                    &snapshot.memory,
                    ImageKind::FirecrackerSnapshot,
                    architecture,
                    now_unix_ms,
                )?;
                state
                    .signed
                    .manifest
                    .authorize_warm_snapshot_publication()?;
                memory
                    .signed
                    .manifest
                    .authorize_warm_snapshot_publication()?;
                if state.digest() == memory.digest() {
                    return Err(FirecrackerError::InvalidConfiguration(
                        "snapshot state and memory payloads must be distinct".to_owned(),
                    ));
                }
                verify_snapshot_manifest(
                    &state,
                    SNAPSHOT_STATE_ROLE,
                    SNAPSHOT_STATE_MEDIA_TYPE,
                    runtime,
                    BTreeMap::from([
                        ("kernel".to_owned(), kernel.digest().clone()),
                        ("rootfs".to_owned(), rootfs.digest().clone()),
                        ("guest".to_owned(), guest.digest().clone()),
                        ("snapshot-memory".to_owned(), memory.digest().clone()),
                    ]),
                )?;
                verify_snapshot_manifest(
                    &memory,
                    SNAPSHOT_MEMORY_ROLE,
                    SNAPSHOT_MEMORY_MEDIA_TYPE,
                    runtime,
                    BTreeMap::from([
                        ("kernel".to_owned(), kernel.digest().clone()),
                        ("rootfs".to_owned(), rootfs.digest().clone()),
                        ("guest".to_owned(), guest.digest().clone()),
                        ("snapshot-state".to_owned(), state.digest().clone()),
                    ]),
                )?;
                Ok::<VerifiedSnapshotImageSet, FirecrackerError>(VerifiedSnapshotImageSet {
                    state,
                    memory,
                    compatibility: runtime.clone(),
                })
            })
            .transpose()?;

        Ok(VerifiedImageSet {
            kernel,
            rootfs,
            guest,
            snapshot,
            architecture,
        })
    }
}

fn require_component(
    components: &BTreeMap<String, ContentDigest>,
    name: &'static str,
    expected: &ContentDigest,
) -> Result<(), FirecrackerError> {
    if components.get(name) != Some(expected) {
        return Err(FirecrackerError::ComponentBinding { component: name });
    }
    Ok(())
}

fn verify_snapshot_manifest(
    artifact: &VerifiedArtifact,
    role: &'static str,
    media_type: &'static str,
    runtime: &SnapshotRuntimeCompatibility,
    expected_components: BTreeMap<String, ContentDigest>,
) -> Result<(), FirecrackerError> {
    let manifest = &artifact.signed.manifest;
    if manifest.payload_media_type != media_type
        || manifest.compatibility != runtime.signed_map(role)
        || manifest.components != expected_components
    {
        return Err(FirecrackerError::InvalidConfiguration(format!(
            "snapshot {role} does not bind the exact state/memory/image/runtime tuple"
        )));
    }
    Ok(())
}

const fn architecture_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}

#[cfg(test)]
mod tests;
