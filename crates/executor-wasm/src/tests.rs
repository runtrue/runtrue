use super::*;
use crate::executor::into_executor_output;
use runtrue_attest::{ImageKind, ImageManifest, ImageSigningKey};
use runtrue_engine::{
    CancellationToken, Executor, ExecutorOutput, PreparedAction, StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    Access, ApprovalRequirements, CapsuleContext, ExecutionCapsule, Isolation, ParityGrade,
    PermissionSet, PlannedJob, PlannedStep, RunnerRequirements, StepAction, StepCapabilitySet,
    Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::{collections::BTreeMap, fs, path::Path, thread, time::Duration};
use tempfile::{tempdir, TempDir};

fn component(wat_source: &str) -> Vec<u8> {
    wat::parse_str(wat_source).unwrap()
}

fn empty_component() -> Vec<u8> {
    component(
        r#"(component
                (core module $m
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    )
}

fn infinite_component() -> Vec<u8> {
    component(
        r#"(component
                (core module $m
                    (func (export "run")
                        (loop $forever (br $forever))))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    )
}

fn ambient_random_component() -> Vec<u8> {
    component(
        r#"(component
                (type $random-func (func (result u64)))
                (type $ambient (instance
                    (export "get-random-u64" (func (type $random-func)))))
                (import "wasi:random/random@0.2.0" (instance $random (type $ambient)))
                (core module $m
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    )
}

fn wasi_03_environment_component() -> Vec<u8> {
    component(include_str!(
        "../../../examples/actions/wasi-0.3-hello/component.wat"
    ))
}

fn declared_host_component() -> Vec<u8> {
    component(
        r#"(component
                (type $get-input (func (result (list u8))))
                (type $host (instance
                    (export "get-input" (func (type $get-input)))))
                (import "runtrue:action/host@1.0.0" (instance $host-import (type $host)))
                (core module $m
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    )
}

fn memory_component(pages: u32) -> Vec<u8> {
    component(&format!(
        r#"(component
                (core module $m
                    (memory {pages})
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    ))
}

fn table_component(elements: u32) -> Vec<u8> {
    component(&format!(
        r#"(component
                (core module $m
                    (table {elements} funcref)
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    ))
}

fn two_memory_component() -> Vec<u8> {
    component(
        r#"(component
                (core module $first (memory 1))
                (core module $second (memory 1))
                (core module $run (func (export "run")))
                (core instance $first-instance (instantiate $first))
                (core instance $second-instance (instantiate $second))
                (core instance $run-instance (instantiate $run))
                (func (export "run") (canon lift (core func $run-instance "run"))))"#,
    )
}

fn parameterized_run_component() -> Vec<u8> {
    component(
        r#"(component
                (type $run-type (func (param "value" u32)))
                (core module $m
                    (func (export "run") (param i32)))
                (core instance $i (instantiate $m))
                (func (export "run") (type $run-type)
                    (canon lift (core func $i "run"))))"#,
    )
}

fn result_run_component() -> Vec<u8> {
    component(
        r#"(component
                (type $run-type (func (result u32)))
                (core module $m
                    (func (export "run") (result i32) i32.const 0))
                (core instance $i (instantiate $m))
                (func (export "run") (type $run-type)
                    (canon lift (core func $i "run"))))"#,
    )
}

fn target() -> WasmTarget {
    WasmTarget::host_baseline().unwrap()
}

fn signed_artifact(bytes: &[u8], mutate: impl FnOnce(&mut ImageManifest)) -> WasmComponentArtifact {
    let target = target();
    let digest = ContentDigest::sha256(bytes);
    let reference = format!("wasm://registry.example/runtrue/test@{digest}");
    let signing = ImageSigningKey::from_seed([41; 32]);
    let mut manifest = ImageManifest {
        manifest_version: 1,
        kind: ImageKind::WasmComponent,
        name: "runtrue-test-component".to_owned(),
        payload_digest: digest,
        payload_size_bytes: u64::try_from(bytes.len()).unwrap(),
        payload_media_type: COMPONENT_MEDIA_TYPE.to_owned(),
        operating_system: "wasm".to_owned(),
        architecture: target.manifest_architecture().to_owned(),
        builder_id: "test-builder".to_owned(),
        build_provenance_digest: ContentDigest::sha256(b"provenance"),
        sbom_digest: ContentDigest::sha256(b"sbom"),
        created_unix_ms: 1,
        expires_unix_ms: None,
        snapshot_phase: None,
        components: BTreeMap::from([("wit".to_owned(), ContentDigest::sha256(WIT_SOURCE))]),
        compatibility: expected_compatibility(&target),
    };
    mutate(&mut manifest);
    let signed = signing.sign_manifest(&manifest).unwrap();
    WasmComponentArtifact::new(reference, bytes.to_vec(), signed, signing.verifying_key()).unwrap()
}

fn executor_at(
    cache_root: &Path,
    bytes: &[u8],
    limits: WasmLimits,
    mutate: impl FnOnce(&mut ImageManifest),
) -> WasmExecutor {
    let artifact = signed_artifact(bytes, mutate);
    let mut config = WasmExecutorConfig::new(
        target(),
        AotCacheConfig::new(cache_root, AotAuthenticationKey::new([7; 32])),
        HandleAuthenticationKey::new([8; 32]),
    );
    config.limits = limits;
    config.register_component(artifact).unwrap();
    WasmExecutor::new(config, CapabilityAdapters::new()).unwrap()
}

fn executor(bytes: &[u8], limits: WasmLimits) -> (TempDir, WasmExecutor) {
    let temporary = tempdir().unwrap();
    let cache_root = temporary.path().join("cache");
    let executor = executor_at(&cache_root, bytes, limits, |_| {});
    (temporary, executor)
}

fn request(bytes: &[u8]) -> StepExecutionRequest {
    let target = target();
    StepExecutionRequest {
        job_id: "job".to_owned(),
        step_id: "step".to_owned(),
        job_attempt: 1,
        runner: RunnerRequirements {
            os: target.operating_system(),
            arch: target.architecture(),
            isolation: Isolation::Wasm,
            image: None,
            cpu: 1,
            memory_bytes: 64 * 1024 * 1024,
            storage_bytes: None,
            region: None,
            capabilities: Vec::new(),
        },
        action: PreparedAction::Component {
            reference: format!(
                "wasm://registry.example/runtrue/test@{}",
                ContentDigest::sha256(bytes)
            ),
            inputs: BTreeMap::from([("name".to_owned(), "runtrue".to_owned())]),
        },
        environment: BTreeMap::new(),
        working_directory: None,
        capabilities: StepCapabilitySet::default(),
        // Component compilation is intentionally charged to the step
        // deadline. Keep the shared fixture generous enough for parallel
        // debug-build tests; timeout-specific tests override this value.
        timeout_ms: Some(60_000),
        cancellation: CancellationToken::default(),
    }
}

fn capsule(bytes: &[u8]) -> ExecutionCapsule {
    let request = request(bytes);
    let reference = match request.action {
        PreparedAction::Component { reference, .. } => reference,
        _ => unreachable!(),
    };
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "test".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "source".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: runtrue_workflow_ir::SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: Some(ContentDigest::sha256(b"lock")),
            workflow_frontend: None,
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
            runner: request.runner,
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
                action: StepAction::Component { reference },
                inputs: BTreeMap::new(),
                environment: BTreeMap::new(),
                capabilities: StepCapabilitySet::default(),
                cache: None,
                timeout_ms: Some(1_000),
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
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::BEnvironmentEquivalent,
    }
}

#[test]
fn executes_component_without_ambient_imports() {
    let bytes = empty_component();
    let (_temporary, mut executor) = executor(&bytes, WasmLimits::default());
    let output = executor.execute_request(&request(&bytes)).unwrap();
    assert!(output.executor.succeeded());
    assert_eq!(output.aot_cache_status, AotCacheStatus::Miss);
    assert_eq!(output.component_output, None);
}

#[test]
fn declared_versioned_host_interface_is_linked() {
    let bytes = declared_host_component();
    let (_temporary, mut executor) = executor(&bytes, WasmLimits::default());
    assert!(executor
        .execute_request(&request(&bytes))
        .unwrap()
        .executor
        .succeeded());
}

#[test]
fn admission_rejects_run_with_parameters_or_results_without_instantiating() {
    for bytes in [parameterized_run_component(), result_run_component()] {
        let (_temporary, mut executor) = executor(&bytes, WasmLimits::default());
        assert!(matches!(
            executor.execute_request(&request(&bytes)),
            Err(WasmError::Link(_))
        ));
    }
}

#[test]
fn executor_preflight_verifies_and_compiles_complete_capsule() {
    let bytes = empty_component();
    let (_temporary, executor) = executor(&bytes, WasmLimits::default());
    Executor::preflight(&executor, &capsule(&bytes)).unwrap();
}

#[test]
fn preflight_fails_closed_on_unsupported_capability() {
    let bytes = empty_component();
    let (_temporary, executor) = executor(&bytes, WasmLimits::default());
    let mut capsule = capsule(&bytes);
    capsule.jobs[0].steps[0].capabilities.checks = Access::Write;
    assert!(matches!(
        executor.preflight_capsule(&capsule),
        Err(WasmError::UnsupportedCapability(_))
    ));
}

#[test]
fn duplicate_filesystem_entries_never_escalate_access() {
    let bytes = empty_component();
    let (_temporary, executor) = executor(&bytes, WasmLimits::default());
    let mut read_request = request(&bytes);
    read_request.capabilities.fs_read = vec!["src".to_owned(), "src".to_owned()];
    let read_grants = executor.build_grants(&read_request).unwrap();
    assert_eq!(
        read_grants.directories.values().next().unwrap().access(),
        FilesystemAccess::Read
    );

    let mut write_request = request(&bytes);
    write_request.capabilities.fs_write = vec!["target".to_owned(), "target".to_owned()];
    let write_grants = executor.build_grants(&write_request).unwrap();
    assert_eq!(
        write_grants.directories.values().next().unwrap().access(),
        FilesystemAccess::Write
    );
}

#[test]
fn infinite_loop_is_stopped_by_fuel() {
    let bytes = infinite_component();
    let limits = WasmLimits {
        fuel: 1_000,
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    let output = executor.execute_request(&request(&bytes)).unwrap();
    assert_eq!(output.executor.exit_code, Some(1));
    assert!(!output.executor.timed_out);
    assert!(output.executor.stderr.contains("fuel exhausted"));
}

#[test]
fn infinite_loop_is_stopped_by_epoch_wall_timeout() {
    let bytes = infinite_component();
    let limits = WasmLimits {
        fuel: u64::MAX,
        max_timeout: Duration::from_millis(100),
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    let mut request = request(&bytes);
    request.timeout_ms = Some(10);
    let output = executor.execute_request(&request).unwrap();
    assert!(output.executor.timed_out);
    assert!(!output.executor.canceled);
    assert_eq!(output.executor.exit_code, None);
}

#[test]
fn cancellation_interrupts_component() {
    let bytes = infinite_component();
    let limits = WasmLimits {
        fuel: u64::MAX,
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    let request = request(&bytes);
    let cancellation = request.cancellation.clone();
    let canceler = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        cancellation.cancel();
    });
    let output = executor.execute_request(&request).unwrap();
    canceler.join().unwrap();
    assert!(output.executor.canceled);
    assert!(!output.executor.timed_out);
}

#[test]
fn precancellation_and_zero_timeout_skip_component_admission() {
    let bytes = b"not-a-component".to_vec();
    let temporary = tempdir().unwrap();
    let cache_root = temporary.path().join("cache");
    let mut executor = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});

    let canceled = request(&bytes);
    canceled.cancellation.cancel();
    let output = executor.execute_request(&canceled).unwrap();
    assert!(output.executor.canceled);
    assert!(!output.executor.timed_out);

    let mut zero_timeout = request(&bytes);
    zero_timeout.timeout_ms = Some(0);
    let output = executor.execute_request(&zero_timeout).unwrap();
    assert!(output.executor.timed_out);
    assert!(!output.executor.canceled);
}

#[test]
fn initial_memory_over_limit_traps_during_instantiation() {
    let bytes = memory_component(2);
    let limits = WasmLimits {
        max_memory_bytes: 64 * 1024,
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    let mut request = request(&bytes);
    request.runner.memory_bytes = 64 * 1024;
    let output = executor.execute_request(&request).unwrap();
    assert_eq!(output.executor.exit_code, Some(1));
    assert!(output.executor.stderr.contains("component trapped"));
}

#[test]
fn memory_limit_is_aggregate_across_linear_memories() {
    let bytes = two_memory_component();
    let limits = WasmLimits {
        max_memory_bytes: 64 * 1024,
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    let mut request = request(&bytes);
    request.runner.memory_bytes = 64 * 1024;
    let output = executor.execute_request(&request).unwrap();
    assert_eq!(output.executor.exit_code, Some(1));
    assert!(output.executor.stderr.contains("component trapped"));
}

#[test]
fn initial_table_over_limit_traps_during_instantiation() {
    let bytes = table_component(11);
    let limits = WasmLimits {
        max_table_elements: 10,
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    let output = executor.execute_request(&request(&bytes)).unwrap();
    assert_eq!(output.executor.exit_code, Some(1));
    assert!(output.executor.stderr.contains("component trapped"));
}

#[test]
fn component_inputs_are_bounded_before_instantiation() {
    let bytes = empty_component();
    let limits = WasmLimits {
        max_input_bytes: 8,
        ..WasmLimits::default()
    };
    let (_temporary, mut executor) = executor(&bytes, limits);
    assert!(matches!(
        executor.execute_request(&request(&bytes)),
        Err(WasmError::LimitExceeded("component input"))
    ));
}

#[test]
fn undeclared_wasi_random_import_is_not_linked() {
    let bytes = ambient_random_component();
    let (_temporary, mut executor) = executor(&bytes, WasmLimits::default());
    assert!(matches!(
        executor.execute_request(&request(&bytes)),
        Err(WasmError::Link(_))
    ));
}

#[test]
fn wasi_03_example_executes_end_to_end() {
    let bytes = wasi_03_environment_component();
    let (_temporary, mut executor) = executor(&bytes, WasmLimits::default());
    let output = executor.execute_request(&request(&bytes)).unwrap();
    assert!(output.executor.succeeded());
}

#[test]
fn inherited_environment_and_process_fallback_are_denied() {
    let bytes = empty_component();
    let (_temporary, mut executor) = executor(&bytes, WasmLimits::default());
    let mut with_environment = request(&bytes);
    with_environment
        .environment
        .insert("PATH".to_owned(), "/bin".to_owned());
    assert!(matches!(
        executor.execute_request(&with_environment),
        Err(WasmError::AmbientEnvironmentDenied)
    ));

    let mut command = request(&bytes);
    command.action = PreparedAction::Command {
        program: "sh".to_owned(),
        args: Vec::new(),
    };
    assert!(matches!(
        executor.execute_request(&command),
        Err(WasmError::NoFallback)
    ));
}

#[test]
fn manifest_compatibility_is_rejected_before_invalid_bytes_are_compiled() {
    let bytes = b"not-a-component".to_vec();
    let temporary = tempdir().unwrap();
    let cache_root = temporary.path().join("cache");
    let mut executor = executor_at(&cache_root, &bytes, WasmLimits::default(), |manifest| {
        manifest
            .compatibility
            .insert("wasmtime_version".to_owned(), "18.0.0".to_owned());
    });
    assert!(matches!(
        executor.execute_request(&request(&bytes)),
        Err(WasmError::ManifestCompatibilityMismatch)
    ));
}

#[test]
fn exact_expected_signer_is_required() {
    let bytes = empty_component();
    let mut artifact = signed_artifact(&bytes, |_| {});
    artifact.expected_signer = ImageSigningKey::from_seed([99; 32]).verifying_key();
    let temporary = tempdir().unwrap();
    let mut config = WasmExecutorConfig::new(
        target(),
        AotCacheConfig::new(
            temporary.path().join("cache"),
            AotAuthenticationKey::new([7; 32]),
        ),
        HandleAuthenticationKey::new([8; 32]),
    );
    config.register_component(artifact).unwrap();
    let mut executor = WasmExecutor::new(config, CapabilityAdapters::new()).unwrap();
    assert!(matches!(
        executor.execute_request(&request(&bytes)),
        Err(WasmError::SignerMismatch)
    ));
}

#[test]
fn rejected_duplicate_registration_does_not_replace_original() {
    let bytes = empty_component();
    let original = signed_artifact(&bytes, |_| {});
    let expected_key = original.expected_signer.key_id();
    let mut replacement = original.clone();
    replacement.expected_signer = ImageSigningKey::from_seed([99; 32]).verifying_key();
    let temporary = tempdir().unwrap();
    let mut config = WasmExecutorConfig::new(
        target(),
        AotCacheConfig::new(
            temporary.path().join("cache"),
            AotAuthenticationKey::new([7; 32]),
        ),
        HandleAuthenticationKey::new([8; 32]),
    );
    config.register_component(original).unwrap();
    assert!(matches!(
        config.register_component(replacement),
        Err(WasmError::DuplicateComponent(_))
    ));
    assert_eq!(
        config
            .components()
            .values()
            .next()
            .unwrap()
            .expected_signer
            .key_id(),
        expected_key
    );
}

#[test]
fn authenticated_aot_cache_is_reused_by_fresh_executor() {
    let bytes = empty_component();
    let temporary = tempdir().unwrap();
    let cache_root = temporary.path().join("cache");
    {
        let mut first = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
        assert_eq!(
            first
                .execute_request(&request(&bytes))
                .unwrap()
                .aot_cache_status,
            AotCacheStatus::Miss
        );
    }
    assert_eq!(
        regular_file_count_recursive(&cache_root.join("wasmtime")),
        0
    );
    let mut second = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
    assert_eq!(
        second
            .execute_request(&request(&bytes))
            .unwrap()
            .aot_cache_status,
        AotCacheStatus::Hit
    );
}

#[test]
fn tampered_aot_authentication_tag_is_quarantined_and_rebuilt() {
    let bytes = empty_component();
    let temporary = tempdir().unwrap();
    let cache_root = temporary.path().join("cache");
    {
        let mut first = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
        first.execute_request(&request(&bytes)).unwrap();
    }
    let metadata_path = fs::read_dir(cache_root.join("authenticated"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    replace_json_string_value(&metadata_path, "authentication_tag", &"00".repeat(32));

    let mut second = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
    let output = second.execute_request(&request(&bytes)).unwrap();
    assert!(output.executor.succeeded());
    assert_eq!(output.aot_cache_status, AotCacheStatus::QuarantinedMiss);
    assert_eq!(
        second.aot_cache_events().unwrap()[0].kind,
        AotCacheEventKind::AuthenticationFailed
    );
    assert!(fs::read_dir(cache_root.join("quarantine")).unwrap().count() >= 2);
    drop(second);
    let mut healed = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
    assert_eq!(
        healed
            .execute_request(&request(&bytes))
            .unwrap()
            .aot_cache_status,
        AotCacheStatus::Hit
    );
}

#[test]
fn incompatible_runtime_metadata_is_quarantined_and_rebuilt() {
    let bytes = empty_component();
    let temporary = tempdir().unwrap();
    let cache_root = temporary.path().join("cache");
    {
        let mut first = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
        first.execute_request(&request(&bytes)).unwrap();
    }
    let metadata_path = fs::read_dir(cache_root.join("authenticated"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    replace_json_string_value(&metadata_path, "wasmtime_version", "18.0.0");

    let mut second = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
    let output = second.execute_request(&request(&bytes)).unwrap();
    assert!(output.executor.succeeded());
    assert_eq!(output.aot_cache_status, AotCacheStatus::QuarantinedMiss);
    assert_eq!(
        second.aot_cache_events().unwrap()[0].kind,
        AotCacheEventKind::Incompatible
    );
    drop(second);
    let mut healed = executor_at(&cache_root, &bytes, WasmLimits::default(), |_| {});
    assert_eq!(
        healed
            .execute_request(&request(&bytes))
            .unwrap()
            .aot_cache_status,
        AotCacheStatus::Hit
    );
}

fn replace_json_string_value(path: &Path, field: &str, replacement: &str) {
    let mut metadata = String::from_utf8(fs::read(path).unwrap()).unwrap();
    let prefix = format!(r#""{field}":""#);
    let value_start = metadata.find(&prefix).unwrap() + prefix.len();
    let value_end = value_start + metadata[value_start..].find('"').unwrap();
    metadata.replace_range(value_start..value_end, replacement);
    fs::write(path, metadata).unwrap();
}

fn regular_file_count_recursive(path: &Path) -> usize {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .map(|path| {
            if path.is_dir() {
                regular_file_count_recursive(&path)
            } else {
                usize::from(path.is_file())
            }
        })
        .sum()
}

#[test]
fn executor_trait_retains_canonical_component_output() {
    let output = into_executor_output(WasmExecutionOutput {
        executor: ExecutorOutput::success(),
        component_output: Some(r#"{"answer":42}"#.to_owned()),
        aot_cache_status: AotCacheStatus::Miss,
    });
    assert_eq!(
        output.structured_output.as_deref(),
        Some(r#"{"answer":42}"#)
    );
}
