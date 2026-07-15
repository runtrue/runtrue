use super::*;
use runtrue_attest::{CapsuleSigningKey, ImageKind, ImageManifest, ImageSigningKey};
use runtrue_engine::CancellationToken;
use runtrue_executor_wasm::{
    COMPONENT_MEDIA_TYPE, WASI_VERSION, WASMTIME_VERSION, WIT_SOURCE, WIT_WORLD,
};
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ParityGrade, PermissionSet, PlannedJob,
    PlannedService, PlannedStep, RunnerRequirements, SourceTrust, StepCapabilitySet, Trust,
    WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{collections::BTreeMap, fs};
use tempfile::TempDir;

struct Fixture {
    _directory: TempDir,
    paths: WasmRuntimePaths,
    signing: ImageSigningKey,
    component: Vec<u8>,
    reference: String,
    manifest_path: PathBuf,
    payload_path: PathBuf,
    target: WasmTarget,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let component_directory = directory.path().join("components");
        let manifest_directory = directory.path().join("manifests");
        let keyring_directory = directory.path().join("keys");
        for path in [
            &component_directory,
            &manifest_directory,
            &keyring_directory,
        ] {
            fs::create_dir(path).unwrap();
            private_directory(path);
        }
        let aot_cache = directory.path().join("aot");
        let runtime_key = directory.path().join("runtime-key");
        let mut runtime_keys = [7_u8; 64];
        runtime_keys[32..].fill(8);
        private_file(&runtime_key, &runtime_keys);

        let component = wat::parse_str(
            r#"(component
                    (core module $m
                        (func (export "run")))
                    (core instance $i (instantiate $m))
                    (func (export "run") (canon lift (core func $i "run"))))"#,
        )
        .unwrap();
        let digest = ContentDigest::sha256(&component);
        let reference = format!("wasm://registry.example/runtrue/test@{digest}");
        let digest_hex = digest.as_str().strip_prefix("sha256:").unwrap();
        let payload_path = component_directory.join(format!("{digest_hex}.wasm"));
        private_file(&payload_path, &component);

        let signing = ImageSigningKey::from_seed([41; 32]);
        private_file(
            &keyring_directory.join("release.pub"),
            &signing.verifying_key().to_bytes(),
        );
        let manifest_path = manifest_directory.join("component.json");
        let target = WasmTarget::host_baseline().unwrap();
        let fixture = Self {
            _directory: directory,
            paths: WasmRuntimePaths {
                component_directory,
                manifest_directory,
                keyring_directory,
                aot_cache,
                runtime_key,
            },
            signing,
            component,
            reference,
            manifest_path,
            payload_path,
            target,
        };
        fixture.write_manifest(&fixture.signing, |_| {});
        fixture
    }

    fn write_manifest(&self, signing: &ImageSigningKey, mutate: impl FnOnce(&mut ImageManifest)) {
        let mut manifest = ImageManifest {
            manifest_version: 1,
            kind: ImageKind::WasmComponent,
            name: self.reference.clone(),
            payload_digest: ContentDigest::sha256(&self.component),
            payload_size_bytes: u64::try_from(self.component.len()).unwrap(),
            payload_media_type: COMPONENT_MEDIA_TYPE.to_owned(),
            operating_system: "wasm".to_owned(),
            architecture: architecture_text(self.target.architecture()).to_owned(),
            builder_id: "test-builder".to_owned(),
            build_provenance_digest: ContentDigest::sha256(b"provenance"),
            sbom_digest: ContentDigest::sha256(b"sbom"),
            created_unix_ms: 1,
            expires_unix_ms: None,
            snapshot_phase: None,
            components: BTreeMap::from([("wit".to_owned(), ContentDigest::sha256(WIT_SOURCE))]),
            compatibility: BTreeMap::from([
                ("cpu_feature_floor".to_owned(), "baseline".to_owned()),
                (
                    "target_triple".to_owned(),
                    self.target.target_triple().to_owned(),
                ),
                ("wasi_version".to_owned(), WASI_VERSION.to_owned()),
                ("wasmtime_version".to_owned(), WASMTIME_VERSION.to_owned()),
                ("wit_world".to_owned(), WIT_WORLD.to_owned()),
            ]),
        };
        mutate(&mut manifest);
        let signed = signing.sign_manifest(&manifest).unwrap();
        private_file(&self.manifest_path, &serde_json::to_vec(&signed).unwrap());
    }

    fn capsule(&self) -> ExecutionCapsule {
        ExecutionCapsule {
            schema_version: CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: "test".to_owned(),
            workflow: WorkflowIdentity {
                name: "wasm-test".to_owned(),
                digest: ContentDigest::sha256(b"workflow"),
                source_path: ".runtrue/workflows/wasm.yaml".to_owned(),
            },
            context: CapsuleContext {
                source_commit: "a".repeat(40),
                source_tree_digest: None,
                base_commit: None,
                source_trust: SourceTrust::Trusted,
                normalized_event_digest: ContentDigest::sha256(b"event"),
                normalized_event_json: None,
                scm: None,
                event_context: BTreeMap::new(),
                lockfile_digest: Some(ContentDigest::sha256(b"lock")),
                policy_version_ids: vec!["policy".to_owned()],
            },
            variables: BTreeMap::new(),
            permissions: PermissionSet::default(),
            jobs: vec![PlannedJob {
                id: "job".to_owned(),
                base_id: "job".to_owned(),
                name: "job".to_owned(),
                needs: Vec::new(),
                matrix: BTreeMap::new(),
                condition: None,
                trust: Trust::TrustedOnly,
                environment: None,
                runner: RunnerRequirements {
                    os: self.target.operating_system(),
                    arch: self.target.architecture(),
                    isolation: Isolation::Wasm,
                    image: None,
                    cpu: 1,
                    memory_bytes: 64 * 1024 * 1024,
                    storage_bytes: None,
                    region: None,
                    capabilities: Vec::new(),
                },
                permissions: PermissionSet::default(),
                timeout_ms: 60_000,
                retries: 0,
                concurrency: None,
                variables: BTreeMap::new(),
                services: Vec::new(),
                steps: vec![PlannedStep {
                    id: "step".to_owned(),
                    name: "step".to_owned(),
                    condition: None,
                    action: StepAction::Component {
                        reference: self.reference.clone(),
                    },
                    inputs: BTreeMap::new(),
                    environment: BTreeMap::new(),
                    capabilities: StepCapabilitySet::default(),
                    cache: None,
                    timeout_ms: None,
                    continue_on_error: false,
                    outputs: BTreeMap::new(),
                    working_directory: None,
                }],
                finalizers: Vec::new(),
                finalizer_timeout_ms: 120_000,
                value_outputs: BTreeMap::new(),
                outputs: BTreeMap::new(),
            }],
            dynamic_jobs: Vec::new(),
            approval: ApprovalRequirements {
                workflow_definition: true,
                privileged_execution: false,
                reasons: Vec::new(),
            },
            expected_parity: ParityGrade::AExact,
        }
    }

    fn lease(&self) -> AdmittedLease {
        let capsule = self.capsule();
        let capsule_signature = CapsuleSigningKey::from_seed([91; 32])
            .sign_capsule(&capsule)
            .unwrap();
        AdmittedLease {
            lease_id: "lease-wasm".to_owned(),
            job_id: "job".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            issued_unix_ms: 1,
            accept_by_unix_ms: u64::MAX - 1,
            expires_unix_ms: u64::MAX,
            hard_deadline_unix_ms: u64::MAX,
            capsule_digest: capsule.digest().unwrap(),
            signing_key_id: capsule_signature.key_id.clone(),
            capsule_signature,
            capsule,
        }
    }
}

#[cfg(unix)]
fn private_directory(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) {}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
mod components;
mod execution;
mod validation;
use execution::architecture_text;
