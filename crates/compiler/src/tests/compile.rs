use super::super::*;

fn compile(source: &str) -> Result<Compilation, CompileError> {
    Compiler::default().compile_yaml(source, CompileContext::default())
}

#[test]
fn trusted_secret_resolution_is_bound_before_capsule_sealing() {
    let source = r#"
version: 1
permissions:
  repository: deny
  network: deny
  secrets: [{ name: TOKEN, purpose: publish }]
jobs:
  publish:
    permissions:
      secrets: [{ name: TOKEN, purpose: publish }]
    steps:
      - capabilities:
          secrets: [{ name: TOKEN, purpose: publish }]
        run: { command: ["true"] }
"#;
    let mut compilation = compile(source).unwrap();
    let local_digest = compilation.capsule_digest.clone();
    let local_approval = compilation.approval_subject_digest.clone();
    let resolution_digest = ContentDigest::sha256(b"resolution");
    compilation
        .bind_secret_resolutions(&BTreeMap::from([(
            "TOKEN".to_owned(),
            ResolvedSecretMetadata {
                metadata_id: "secret-production".to_owned(),
                binding: runtrue_model::SecretResolutionBinding {
                    scope: "project:release".to_owned(),
                    metadata_version: Some(7),
                    resolution_digest: resolution_digest.clone(),
                    project_versions: vec![runtrue_model::SecretProjectVersion {
                        project_id: "release".to_owned(),
                        version: 3,
                    }],
                },
            },
        )]))
        .unwrap();

    assert_ne!(compilation.capsule_digest, local_digest);
    assert_ne!(compilation.approval_subject_digest, local_approval);
    assert_eq!(
        compilation.approval_subject.secret_metadata_ids,
        ["secret-production"]
    );
    let reference = &compilation.capsule.jobs[0].steps[0].capabilities.secrets[0];
    assert_eq!(reference.metadata_id, "secret-production");
    let binding = reference.resolution.as_ref().unwrap();
    assert_eq!(binding.metadata_version, Some(7));
    assert_eq!(binding.resolution_digest, resolution_digest);
    assert_eq!(binding.project_versions[0].version, 3);
    assert_eq!(
        compilation.capsule_digest,
        compilation.capsule.digest().unwrap()
    );
    assert_eq!(
        compilation.approval_subject_digest,
        compilation.approval_subject.digest().unwrap()
    );
}

#[test]
fn trusted_secret_binding_requires_the_exact_declared_name_set() {
    let source = r#"
version: 1
permissions:
  secrets: [{ name: TOKEN }]
jobs:
  test:
    steps: [{ run: { command: ["true"] } }]
"#;
    let mut compilation = compile(source).unwrap();
    assert!(compilation
        .bind_secret_resolutions(&BTreeMap::new())
        .is_err());
}

fn workflow(body: &str) -> String {
    format!(
        "version: 1\nname: test\npermissions:\n  network: deny\n  repository: deny\njobs:\n{body}"
    )
}

fn reusable_context(sources: &[(&str, &str, &str)], selected_job: Option<&str>) -> CompileContext {
    let mut lock = "lock_version = 1\n".to_owned();
    let mut bundle = BTreeMap::new();
    for (reference, commit, source) in sources {
        let digest = ContentDigest::sha256(source.as_bytes());
        lock.push_str(&format!(
                "\n[[workflow]]\nsource = \"{reference}\"\ncommit = \"{commit}\"\ndigest = \"{digest}\"\n"
            ));
        bundle.insert(
            (*reference).to_owned(),
            ReusableWorkflowSource::new(*commit, source.as_bytes().to_vec()).unwrap(),
        );
    }
    CompileContext {
        lockfile: Some(LockFile::parse(lock.as_bytes()).unwrap()),
        reusable_workflows: ReusableWorkflowSources::new(bundle).unwrap(),
        selected_job: selected_job.map(str::to_owned),
        ..CompileContext::default()
    }
}

#[test]
fn semantically_equivalent_yaml_has_same_digest() {
    let first = workflow(
            "  build:\n    runner: { isolation: microvm }\n    steps:\n      - id: test\n        run: { command: [\"echo\", \"ok\"] }\n",
        );
    let second = r#"# comments and mapping order do not affect a capsule
jobs:
  build:
    steps:
      - run:
          command: [echo, ok]
        id: test
    runner:
      isolation: microvm
permissions: { repository: deny, network: deny }
name: test
version: 1
"#;
    assert_eq!(
        compile(&first).unwrap().capsule_digest,
        compile(second).unwrap().capsule_digest
    );
}

#[test]
fn signed_step_signing_is_exact_bounded_and_canonical_capsule_material() {
    let first = r#"
version: 1
permissions:
  signing:
    - { purpose: provenance, operation: sign-attestation, key-policy: attest-v1 }
    - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
jobs:
  publish:
    steps:
      - id: sign
        capabilities:
          signing:
            - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
            - { purpose: provenance, operation: sign-attestation, key-policy: attest-v1 }
        run: { command: ["true"] }
"#;
    let reordered = r#"
version: 1
permissions:
  signing:
    - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
    - { purpose: provenance, operation: sign-attestation, key-policy: attest-v1 }
jobs:
  publish:
    steps:
      - id: sign
        capabilities:
          signing:
            - { purpose: provenance, operation: sign-attestation, key-policy: attest-v1 }
            - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
        run: { command: ["true"] }
"#;
    let first = compile(first).unwrap();
    let reordered = compile(reordered).unwrap();
    assert_eq!(first.capsule_digest, reordered.capsule_digest);
    assert_eq!(
        first.capsule.jobs[0].steps[0].capabilities.signing,
        first.capsule.jobs[0].permissions.signing
    );
    assert!(first
        .risk_report
        .findings
        .iter()
        .any(|finding| finding.code == "step-signing-access"));

    let one_step_capability = r#"
version: 1
permissions:
  signing:
    - { purpose: provenance, operation: sign-attestation, key-policy: attest-v1 }
    - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
jobs:
  publish:
    steps:
      - id: sign
        capabilities:
          signing:
            - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
        run: { command: ["true"] }
"#;
    let changed = compile(one_step_capability).unwrap();
    assert_ne!(first.capsule_digest, changed.capsule_digest);
    assert_ne!(
        first.approval_subject_digest,
        changed.approval_subject_digest
    );
}

#[test]
fn signing_defaults_to_deny_and_rejects_substitution_or_raw_key_references() {
    let missing_step_grant = r#"
version: 1
jobs:
  publish:
    steps:
      - capabilities:
          signing:
            - { purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }
        run: { command: ["true"] }
"#;
    let error = compile(missing_step_grant).unwrap_err().to_string();
    assert!(error.contains("outside the job permission set"), "{error}");

    let grant = "{ purpose: release-artifact, operation: sign-digest, key-policy: release-v1 }";
    for substituted in [
        "{ purpose: another-purpose, operation: sign-digest, key-policy: release-v1 }",
        "{ purpose: release-artifact, operation: sign-attestation, key-policy: release-v1 }",
        "{ purpose: release-artifact, operation: sign-digest, key-policy: another-policy }",
    ] {
        let source = format!(
                "version: 1\npermissions:\n  signing: [{grant}]\njobs:\n  publish:\n    steps:\n      - capabilities:\n          signing: [{substituted}]\n        run: {{ command: [\"true\"] }}\n"
            );
        let error = compile(&source).unwrap_err().to_string();
        assert!(error.contains("outside the job permission set"), "{error}");
    }

    let raw_key_reference = r#"
version: 1
permissions:
  signing:
    - { purpose: release-artifact, operation: sign-digest, key-policy: "vault://keys/release" }
jobs:
  publish:
    steps: [{ run: { command: ["true"] } }]
"#;
    let error = compile(raw_key_reference).unwrap_err().to_string();
    assert!(error.contains("signing identifier"), "{error}");

    let historical_missing_policy = r#"
version: 1
permissions:
  signing:
    - { purpose: release-artifact, operation: sign-digest }
jobs:
  publish:
    steps: [{ run: { command: ["true"] } }]
"#;
    let error = compile(historical_missing_policy).unwrap_err().to_string();
    assert!(error.contains("signing identifier"), "{error}");
}

#[test]
fn signing_capability_count_and_duplicates_are_rejected_before_capsule_creation() {
    let requests = (0..=MAX_SIGNING_CAPABILITIES)
        .map(|index| ast::SigningRequest {
            purpose: format!("release-{index}"),
            operation: ast::SigningOperation::SignDigest,
            key_policy: "release-v1".to_owned(),
        })
        .collect::<Vec<_>>();
    let error = validate_signing_requests(&requests, "capabilities.signing")
        .unwrap_err()
        .to_string();
    assert!(error.contains("entry limit"), "{error}");

    let duplicate = ast::SigningRequest {
        purpose: "release-artifact".to_owned(),
        operation: ast::SigningOperation::SignDigest,
        key_policy: "release-v1".to_owned(),
    };
    let error = validate_signing_requests(&[duplicate.clone(), duplicate], "capabilities.signing")
        .unwrap_err()
        .to_string();
    assert!(error.contains("exact and unique"), "{error}");
}

#[test]
fn expression_formatting_does_not_change_capsule_identity() {
    let first = workflow(
            "  build:\n    if: event.type=='manual'\n    steps:\n      - if: \"event.type == 'manual'\"\n        run: { command: [\"true\"] }\n",
        );
    let second = workflow(
            "  build:\n    if: ' ( event.type == \"manual\" ) '\n    steps:\n      - if: \"event.type=='manual'\"\n        run: { command: [\"true\"] }\n",
        );
    let first = compile(&first).unwrap();
    let second = compile(&second).unwrap();
    assert_eq!(first.capsule_digest, second.capsule_digest);
    assert_eq!(
        first.capsule.jobs[0].condition.as_deref(),
        Some("(event.type == \"manual\")")
    );
}

#[test]
fn shipped_example_has_a_generation_local_golden_capsule_digest() {
    let context = CompileContext {
        workflow_path: "examples/workflows/secure-ci.yaml".to_owned(),
        ..CompileContext::default()
    };
    let compilation = Compiler::default()
        .compile_yaml(
            include_str!("../../../../examples/workflows/secure-ci.yaml"),
            context,
        )
        .unwrap();
    assert_eq!(
        compilation.capsule_digest.to_string(),
        "sha256:4a86aca9ac95c05e0d17ccbb25b57c45876b53c65f3b5a6ad4677629471258f2"
    );
}

#[test]
fn shipped_oci_example_resolves_its_locked_runner_image() {
    let lock = LockFile::parse(include_bytes!(
        "../../../../examples/workflows/oci-job.runtrue.lock"
    ))
    .unwrap();
    let compilation = Compiler::default()
        .compile_yaml(
            include_str!("../../../../examples/workflows/oci-job.yaml"),
            CompileContext {
                workflow_path: "examples/workflows/oci-job.yaml".to_owned(),
                lockfile: Some(lock),
                ..CompileContext::default()
            },
        )
        .unwrap();
    assert_eq!(
            compilation.capsule.jobs[0].runner.image.as_deref(),
            Some("registry.example/runtrue/build-tools@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    assert_eq!(
        compilation.approval_subject.resolved_image_digests,
        vec!["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
}

#[test]
fn shipped_wasm_example_resolves_its_locked_component() {
    let lock = LockFile::parse(include_bytes!(
        "../../../../examples/workflows/wasm-job.runtrue.lock"
    ))
    .unwrap();
    let compilation = Compiler::default()
        .compile_yaml(
            include_str!("../../../../examples/workflows/wasm-job.yaml"),
            CompileContext {
                workflow_path: "examples/workflows/wasm-job.yaml".to_owned(),
                lockfile: Some(lock),
                ..CompileContext::default()
            },
        )
        .unwrap();
    assert_eq!(
        compilation.capsule.jobs[0].runner.isolation,
        ir::Isolation::Wasm
    );
    assert_eq!(
        compilation.capsule.jobs[0].runner.memory_bytes,
        128 * 1024 * 1024
    );
    assert_eq!(
            compilation.capsule.jobs[0].steps[0].action,
            ir::StepAction::Component {
                reference: "wasm://registry.example/runtrue/analyze@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            }
        );
}

#[test]
fn set_like_order_and_empty_network_policy_are_canonicalized() {
    let first = r#"
version: 1
on:
  push: { branches: [main, release] }
permissions:
  network: deny
jobs:
  a:
    matrix: { mode: [debug, release] }
    steps: [{ run: { command: ["true"] } }]
  b:
    steps: [{ run: { command: ["true"] } }]
  c:
    needs: [a, b]
    steps: [{ run: { command: ["true"] } }]
"#;
    let second = r#"
version: 1
on:
  push: { branches: [release, main] }
permissions:
  network: {}
jobs:
  a:
    matrix: { mode: [release, debug] }
    steps: [{ run: { command: ["true"] } }]
  b:
    steps: [{ run: { command: ["true"] } }]
  c:
    needs: [b, a]
    steps: [{ run: { command: ["true"] } }]
"#;
    let first = compile(first).unwrap();
    let second = compile(second).unwrap();
    assert_eq!(
        first.capsule.workflow.digest,
        second.capsule.workflow.digest
    );
    assert_eq!(first.capsule_digest, second.capsule_digest);
    assert_eq!(
        first.approval_subject_digest,
        second.approval_subject_digest
    );
}

#[test]
fn source_commit_changes_capsule_and_approval_digest() {
    let source = workflow("  build:\n    steps:\n      - run: { command: [\"true\"] }\n");
    let first = Compiler::default()
        .compile_yaml(&source, CompileContext::default())
        .unwrap();
    let context = CompileContext {
        source_commit: "different".to_owned(),
        ..CompileContext::default()
    };
    let second = Compiler::default().compile_yaml(&source, context).unwrap();
    assert_ne!(first.capsule_digest, second.capsule_digest);
    assert_ne!(
        first.approval_subject_digest,
        second.approval_subject_digest
    );
}

#[test]
fn source_snapshot_changes_capsule_and_approval_digest() {
    let source = workflow("  build:\n    steps:\n      - run: { command: [\"true\"] }\n");
    let compiler = Compiler::default();
    let first_digest = ContentDigest::sha256(b"tree one");
    let second_digest = ContentDigest::sha256(b"tree two");
    let first = compiler
        .compile_yaml_with_source_snapshot(&source, CompileContext::default(), first_digest.clone())
        .unwrap();
    let second = compiler
        .compile_yaml_with_source_snapshot(&source, CompileContext::default(), second_digest)
        .unwrap();
    assert_eq!(
        first.capsule.context.source_tree_digest,
        Some(first_digest.clone())
    );
    assert_eq!(
        first.approval_subject.source_tree_digest,
        Some(first_digest)
    );
    assert_ne!(first.capsule_digest, second.capsule_digest);
    assert_ne!(
        first.approval_subject_digest,
        second.approval_subject_digest
    );
}

#[test]
fn authenticated_normalized_event_digest_overrides_local_json_hash() {
    let source = workflow("  build:\n    steps:\n      - run: { command: [\"true\"] }\n");
    let authoritative = ContentDigest::sha256(b"authenticated normalized event");
    let compilation = Compiler::default()
        .compile_yaml(
            &source,
            CompileContext {
                event: serde_json::json!({"provider": "typed-projection"}),
                normalized_event_digest: Some(authoritative.clone()),
                ..CompileContext::default()
            },
        )
        .unwrap();
    assert_eq!(
        compilation.capsule.context.normalized_event_digest,
        authoritative
    );
    assert_eq!(
        compilation.approval_subject.normalized_event_digest,
        authoritative
    );
}

#[test]
fn rejects_cycles_and_missing_dependencies() {
    let cyclic = workflow(
            "  a:\n    needs: [b]\n    steps: [{ run: { command: [\"true\"] } }]\n  b:\n    needs: [a]\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    assert!(compile(&cyclic).unwrap_err().to_string().contains("cycle"));
    let missing =
        workflow("  a:\n    needs: [absent]\n    steps: [{ run: { command: [\"true\"] } }]\n");
    assert!(compile(&missing)
        .unwrap_err()
        .to_string()
        .contains("unknown dependency"));
}

#[test]
fn rejects_unsafe_interpolation_and_traversal() {
    let interpolation = workflow(
            "  build:\n    steps:\n      - run:\n          shell: bash\n          script: 'echo ${{ event.pull_request.title }}'\n",
        );
    assert!(compile(&interpolation)
        .unwrap_err()
        .to_string()
        .contains("interpolation"));
    let traversal = workflow(
            "  build:\n    outputs:\n      leak: { path: ../secret }\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    assert!(compile(&traversal)
        .unwrap_err()
        .to_string()
        .contains("safe repository-relative"));
    let unknown_context = workflow(
        "  build:\n    if: typo.ref == 'main'\n    steps: [{ run: { command: [\"true\"] } }]\n",
    );
    assert!(compile(&unknown_context)
        .unwrap_err()
        .to_string()
        .contains("unknown expression context root"));
    let non_boolean = workflow(
        "  build:\n    if: \"'not-a-boolean'\"\n    steps: [{ run: { command: [\"true\"] } }]\n",
    );
    assert!(compile(&non_boolean)
        .unwrap_err()
        .to_string()
        .contains("must evaluate to a boolean"));
    let nul_value = workflow(
            "  build:\n    steps:\n      - env: { BAD: \"\\0\" }\n        run: { command: [\"true\"] }\n",
        );
    assert!(compile(&nul_value)
        .unwrap_err()
        .to_string()
        .contains("NUL bytes"));
}

#[test]
fn untrusted_values_cannot_be_injected_through_environment() {
    for name in ["MESSAGE", "BASH_ENV", "MAKEFLAGS"] {
        let source = workflow(&format!(
                "  build:\n    steps:\n      - env:\n          {name}: {{ from: event.type }}\n        run: {{ shell: bash, script: 'echo safe' }}\n"
            ));
        let error = compile(&source).unwrap_err().to_string();
        assert!(
            error.contains("cannot be injected through the process environment"),
            "{name}: {error}"
        );
        assert!(!error.contains("command argument"), "{name}: {error}");
    }

    let safe = r#"
version: 1
vars: { MESSAGE: reviewed }
permissions: { network: deny }
jobs:
  build:
    steps:
      - env: { MESSAGE: { from: vars.MESSAGE } }
        run: { shell: bash, script: 'printf %s "$MESSAGE"' }
"#;
    assert!(compile(safe).is_ok());
}

#[test]
fn untrusted_values_cannot_become_process_arguments() {
    for program in ["/bin/echo", "sh", "timeout", "python3", "make"] {
        let source = workflow(&format!(
                "  build:\n    steps:\n      - run:\n          command: [\"{program}\", \"-c\"]\n          args: [{{ from: event.type }}]\n"
            ));
        let error = compile(&source).unwrap_err().to_string();
        assert!(
            error.contains("cannot be passed to process arguments"),
            "{program}: {error}"
        );
    }

    let safe = r#"
version: 1
vars: { MESSAGE: reviewed }
permissions: { network: deny }
jobs:
  build:
    steps:
      - run:
          command: ["/bin/echo"]
          args: [{ from: vars.MESSAGE }]
"#;
    assert!(compile(safe).is_ok());
}

#[test]
fn external_references_require_a_validated_lock_and_reject_truncated_pins() {
    let mutable = workflow("  build:\n    steps:\n      - uses: wasm://example/action@v1\n");
    assert!(compile(&mutable)
        .unwrap_err()
        .to_string()
        .contains("validated lockfile is required"));
    let short = workflow("  build:\n    steps:\n      - uses: wasm://example/action@sha256:abcd\n");
    assert!(compile(&short)
        .unwrap_err()
        .to_string()
        .contains("64 lowercase"));
    for selector in ["sha256".to_owned(), format!("SHA256:{}", "a".repeat(64))] {
        let malformed = workflow(&format!(
            "  build:\n    steps:\n      - uses: 'wasm://example/action@{selector}'\n"
        ));
        assert!(compile(&malformed).is_err(), "{selector}");
    }
    let missing_source = workflow(&format!(
        "  build:\n    steps:\n      - uses: '@sha256:{}'\n",
        "a".repeat(64)
    ));
    assert!(compile(&missing_source)
        .unwrap_err()
        .to_string()
        .contains("source must be non-empty"));
    let whitespace = workflow(&format!(
        "  build:\n    steps:\n      - uses: 'bad ref@sha256:{}'\n",
        "a".repeat(64)
    ));
    assert!(compile(&whitespace)
        .unwrap_err()
        .to_string()
        .contains("no whitespace"));
}

#[test]
fn validated_lock_resolves_capsule_and_binds_canonical_digest() {
    let digest = "a".repeat(64);
    let lock = LockFile::parse(
        format!(
            r#"lock_version = 1
[[component]]
source = "wasm://example/action@v1"
resolved = "sha256:{digest}"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"
"#
        )
        .as_bytes(),
    )
    .unwrap();
    let expected_lock_digest = lock.digest().unwrap();
    let source = workflow("  build:\n    steps:\n      - uses: wasm://example/action@v1\n");
    let compilation = Compiler::default()
        .compile_yaml(
            &source,
            CompileContext {
                lockfile: Some(lock),
                ..CompileContext::default()
            },
        )
        .unwrap();
    assert_eq!(
        compilation.capsule.jobs[0].steps[0].action,
        ir::StepAction::Component {
            reference: format!("wasm://example/action@sha256:{digest}")
        }
    );
    assert_eq!(
        compilation.capsule.context.lockfile_digest,
        Some(expected_lock_digest)
    );
}

#[test]
fn dynamic_and_finalizer_dependencies_are_locked_and_approval_bound() {
    let component_digest = "a".repeat(64);
    let finalizer_digest = "b".repeat(64);
    let image_digest = "c".repeat(64);
    let lock = LockFile::parse(
        format!(
            r#"lock_version = 1
[[component]]
source = "wasm://example/dynamic@v1"
resolved = "sha256:{component_digest}"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"

[[component]]
source = "wasm://example/cleanup@v1"
resolved = "sha256:{finalizer_digest}"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"

[[image]]
source = "registry.example/build:v1"
resolved = "registry.example/build@sha256:{image_digest}"
platform = "linux/amd64"
"#
        )
        .as_bytes(),
    )
    .unwrap();
    let source = r#"version: 1
jobs:
  generate:
    steps:
      - id: matrix
        run: { command: ["true"] }
        outputs:
          axes: { type: json, required: true }
    value-outputs:
      axes: { from: steps.matrix.outputs.axes }
  build:
    needs: [generate]
    dynamic-matrix: { from: needs.generate.outputs.axes, max-jobs: 2 }
    environment: production
    runner:
      isolation: oci
      image: registry.example/build:v1
    steps:
      - uses: wasm://example/dynamic@v1
    finalizers:
      - id: cleanup
        uses: wasm://example/cleanup@v1
        required: true
        run-on-cancel: true
"#;
    let compilation = Compiler::default()
        .compile_yaml(
            source,
            CompileContext {
                lockfile: Some(lock),
                ..CompileContext::default()
            },
        )
        .unwrap();
    let template = &compilation.capsule.dynamic_jobs[0].template;
    assert_eq!(
        template.runner.image.as_deref(),
        Some(format!("registry.example/build@sha256:{image_digest}").as_str())
    );
    assert_eq!(
        template.steps[0].action,
        ir::StepAction::Component {
            reference: format!("wasm://example/dynamic@sha256:{component_digest}")
        }
    );
    assert_eq!(
        template.finalizers[0].step.action,
        ir::StepAction::Component {
            reference: format!("wasm://example/cleanup@sha256:{finalizer_digest}")
        }
    );
    assert_eq!(
        compilation.approval_subject.resolved_action_digests,
        vec![
            format!("sha256:{component_digest}"),
            format!("sha256:{finalizer_digest}")
        ]
    );
    assert_eq!(
        compilation.approval_subject.resolved_image_digests,
        vec![format!("sha256:{image_digest}")]
    );
    assert_eq!(compilation.approval_subject.runner_profiles.len(), 2);
    assert_eq!(compilation.approval_subject.environment_ids.len(), 1);
    assert_eq!(
        compilation.capsule.expected_parity,
        ir::ParityGrade::DNonReplayable
    );
}

#[test]
fn validated_lock_resolves_service_images_for_the_job_platform() {
    let digest = "b".repeat(64);
    let lock = LockFile::parse(
        format!(
            r#"lock_version = 1
[[image]]
source = "registry.example/postgres:17"
resolved = "registry.example/postgres@sha256:{digest}"
platform = "linux/amd64"
"#
        )
        .as_bytes(),
    )
    .unwrap();
    let source = workflow(
            "  build:\n    services:\n      db:\n        image: registry.example/postgres:17\n    steps:\n      - run: { command: [\"true\"] }\n",
        );
    let compilation = Compiler::default()
        .compile_yaml(
            &source,
            CompileContext {
                lockfile: Some(lock),
                ..CompileContext::default()
            },
        )
        .unwrap();
    assert_eq!(
        compilation.capsule.jobs[0].services[0].image,
        format!("registry.example/postgres@sha256:{digest}")
    );
}

#[test]
fn oci_runner_images_are_required_and_exclusive_to_oci_isolation() {
    let missing = workflow(
            "  build:\n    runner: { isolation: oci }\n    steps:\n      - run: { command: [\"true\"] }\n",
        );
    let error = compile(&missing).unwrap_err().to_string();
    assert!(
        error.contains("jobs.build.runner.image")
            && error.contains("OCI isolation requires an explicit runner image"),
        "{error}"
    );

    let non_oci = workflow(
            "  build:\n    runner: { isolation: microvm, image: registry.example/build:v1 }\n    steps:\n      - run: { command: [\"true\"] }\n",
        );
    let error = compile(&non_oci).unwrap_err().to_string();
    assert!(
        error.contains("jobs.build.runner.image")
            && error.contains("valid only with isolation: oci"),
        "{error}"
    );
}

#[test]
fn oci_runner_images_require_a_platform_specific_lock_entry() {
    let source = workflow(
            "  build:\n    runner: { isolation: oci, image: registry.example/build:v1 }\n    steps:\n      - run: { command: [\"true\"] }\n",
        );
    let error = compile(&source).unwrap_err().to_string();
    assert!(error.contains("validated lockfile is required"), "{error}");

    let digest = "c".repeat(64);
    let amd64_only = LockFile::parse(
        format!(
            r#"lock_version = 1
[[image]]
source = "registry.example/build:v1"
resolved = "registry.example/build@sha256:{digest}"
platform = "linux/amd64"
"#
        )
        .as_bytes(),
    )
    .unwrap();
    let arm64_source = workflow(
            "  build:\n    runner: { arch: arm64, isolation: oci, image: registry.example/build:v1 }\n    steps:\n      - run: { command: [\"true\"] }\n",
        );
    let error = Compiler::default()
        .compile_yaml(
            &arm64_source,
            CompileContext {
                lockfile: Some(amd64_only),
                ..CompileContext::default()
            },
        )
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("missing image lock entry") && error.contains("linux/arm64"),
        "{error}"
    );
}

#[test]
fn immutable_oci_runner_and_service_images_do_not_require_a_lockfile() {
    let runner_digest = "c".repeat(64);
    let service_digest = "d".repeat(64);
    let source = workflow(&format!(
        "  build:\n    runner: {{ isolation: oci, image: 'registry.example/build@sha256:{runner_digest}' }}\n    services:\n      db:\n        image: 'registry.example/db@sha256:{service_digest}'\n    steps:\n      - run: {{ command: [\"true\"] }}\n"
    ));

    let compilation = compile(&source).expect("immutable OCI references should self-resolve");
    assert_eq!(compilation.approval_subject.lockfile_digest, None);
    assert_eq!(
        compilation.approval_subject.resolved_image_digests,
        vec![
            format!("sha256:{runner_digest}"),
            format!("sha256:{service_digest}"),
        ]
    );
}

#[test]
fn oci_runner_digest_changes_rebind_the_capsule_approval_and_risk_diff() {
    let source = workflow(
            "  build:\n    runner: { isolation: oci, image: registry.example/build:v1 }\n    steps:\n      - run: { command: [\"true\"] }\n",
        );
    let compile_with_digest = |digest: char| {
        let digest = digest.to_string().repeat(64);
        let lock = LockFile::parse(
            format!(
                r#"lock_version = 1
[[image]]
source = "registry.example/build:v1"
resolved = "registry.example/build@sha256:{digest}"
platform = "linux/amd64"
"#
            )
            .as_bytes(),
        )
        .unwrap();
        Compiler::default()
            .compile_yaml(
                &source,
                CompileContext {
                    lockfile: Some(lock),
                    ..CompileContext::default()
                },
            )
            .unwrap()
    };
    let base = compile_with_digest('d');
    let proposed = compile_with_digest('e');
    let base_reference = format!("registry.example/build@sha256:{}", "d".repeat(64));

    assert_eq!(
        base.capsule.jobs[0].runner.image.as_deref(),
        Some(base_reference.as_str())
    );
    assert_eq!(
        base.approval_subject.resolved_image_digests,
        vec![format!("sha256:{}", "d".repeat(64))]
    );
    assert_ne!(base.capsule_digest, proposed.capsule_digest);
    assert_ne!(
        base.approval_subject_digest,
        proposed.approval_subject_digest
    );
    assert!(semantic_risk_diff(&base.capsule, &proposed.capsule)
        .findings
        .iter()
        .any(|finding| finding.code == "runner-image-changed"));
}

#[test]
fn lock_capsule_mismatch_and_unused_entries_fail_closed() {
    let digest = "a".repeat(64);
    let lock_source = format!(
        r#"lock_version = 1
[[component]]
source = "wasm://example/action@v1"
resolved = "sha256:{digest}"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"
"#
    );
    let lock = LockFile::parse(lock_source.as_bytes()).unwrap();
    let mismatch = workflow("  build:\n    steps:\n      - uses: wasm://example/action@v2\n");
    let error = Compiler::default()
        .compile_yaml(
            &mismatch,
            CompileContext {
                lockfile: Some(lock.clone()),
                ..CompileContext::default()
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing component lock entry"), "{error}");

    let no_external = workflow("  build:\n    steps:\n      - run: { command: [\"true\"] }\n");
    let error = Compiler::default()
        .compile_yaml(
            &no_external,
            CompileContext {
                lockfile: Some(lock),
                ..CompileContext::default()
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("unused component lock entry"), "{error}");
}

#[test]
fn lock_metadata_only_changes_are_security_sensitive_capsule_risks() {
    let digest = "a".repeat(64);
    let lock_source = format!(
        r#"lock_version = 1
[[component]]
source = "wasm://example/action@v1"
resolved = "sha256:{digest}"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"
"#
    );
    let source = workflow("  build:\n    steps:\n      - uses: wasm://example/action@v1\n");
    let compile_with = |lock_source: &str| {
        Compiler::default()
            .compile_yaml(
                &source,
                CompileContext {
                    lockfile: Some(LockFile::parse(lock_source.as_bytes()).unwrap()),
                    ..CompileContext::default()
                },
            )
            .unwrap()
    };
    let base = compile_with(&lock_source);
    let proposed =
        compile_with(&lock_source.replace("release@runtrue.example", "security@runtrue.example"));
    assert_eq!(base.capsule.jobs, proposed.capsule.jobs);
    let report = semantic_risk_diff(&base.capsule, &proposed.capsule);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "lockfile-digest-changed"
            && finding.severity == RiskSeverity::High));
}

#[test]
fn service_healthcheck_limits_are_semantically_enforced() {
    let source = workflow(&format!(
            "  build:\n    services:\n      db:\n        image: 'db@sha256:{}'\n        healthcheck:\n          command: [check]\n          retries: 0\n    steps: [{{ run: {{ command: [\"true\"] }} }}]\n",
            "a".repeat(64)
        ));
    assert!(compile(&source)
        .unwrap_err()
        .to_string()
        .contains("between 1 and 100"));
}

#[test]
fn matrices_expand_deterministically_and_needs_all_variants() {
    let source = workflow(
            "  build:\n    matrix:\n      arch: [amd64, arm64]\n      mode: [debug, release]\n    steps: [{ run: { command: [\"true\"] } }]\n  report:\n    needs: [build]\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    let compilation = compile(&source).unwrap();
    assert_eq!(compilation.capsule.jobs.len(), 5);
    let report = compilation
        .capsule
        .jobs
        .iter()
        .find(|job| job.id == "report")
        .unwrap();
    assert_eq!(
        report.needs,
        vec!["build[0]", "build[1]", "build[2]", "build[3]"]
    );
}

#[test]
fn matrix_variants_do_not_multiply_identical_risk_findings() {
    let source = r#"
version: 1
permissions:
  repository: write
jobs:
  build:
    matrix:
      arch: [amd64, arm64]
      mode: [debug, release]
    steps: [{ run: { command: ["true"] } }]
"#;
    let compilation = compile(source).unwrap();
    let findings = compilation
        .risk_report
        .findings
        .iter()
        .filter(|finding| finding.code == "repository-write")
        .count();
    assert_eq!(findings, 1);
    assert_eq!(compilation.risk_report.score, 30);
}

#[test]
fn native_requires_trust_and_privileged_approval() {
    let denied = workflow(
            "  build:\n    runner: { isolation: native }\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    assert!(compile(&denied)
        .unwrap_err()
        .to_string()
        .contains("trusted-only"));
    let allowed = workflow(
            "  build:\n    trust: trusted-only\n    runner: { isolation: native }\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    let compilation = compile(&allowed).unwrap();
    assert!(compilation.capsule.approval.privileged_execution);
}

#[test]
fn authenticated_brokered_status_dispatch_does_not_require_per_run_approval() {
    let source = r#"
version: 1
permissions:
  repository: deny
  scm:
    contents: read
    statuses: write
  network: deny
  secrets:
    - { name: runtrue-scm-provider-token, purpose: provider-api }
jobs:
  review:
    steps:
      - capabilities:
          secrets:
            - { name: runtrue-scm-provider-token, purpose: provider-api }
        run: { command: ["/usr/local/bin/runtrue-action"] }
"#;
    let context = CompileContext {
        normalized_event_digest: Some(ContentDigest::sha256(b"authenticated-event")),
        scm_api_url: Some("https://github.example/api/v3".to_owned()),
        event: serde_json::json!({
            "provider": "git_hub",
            "repository": { "full_name": "ci/test" }
        }),
        ..CompileContext::default()
    };
    let compilation = Compiler::default().compile_yaml(source, context).unwrap();
    assert!(!compilation.capsule.approval.privileged_execution);
    assert_eq!(
        compilation.capsule.approval.reasons,
        vec![
            "scm-statuses-write".to_owned(),
            "secret-access".to_owned(),
            "step-secret-access".to_owned()
        ]
    );
    assert_eq!(compilation.risk_report.score, 90);

    let other_secret = source.replace("runtrue-scm-provider-token", "internal-api-key");
    let context = CompileContext {
        normalized_event_digest: Some(ContentDigest::sha256(b"authenticated-event")),
        scm_api_url: Some("https://github.example/api/v3".to_owned()),
        event: serde_json::json!({
            "provider": "git_hub",
            "repository": { "full_name": "ci/test" }
        }),
        ..CompileContext::default()
    };
    assert!(
        Compiler::default()
            .compile_yaml(&other_secret, context)
            .unwrap()
            .capsule
            .approval
            .privileged_execution
    );
}

#[test]
fn authenticated_brokered_repository_automation_does_not_require_per_run_approval() {
    let source = r#"
version: 1
permissions:
  repository: deny
  scm:
    contents: write
    issues: write
    pull-requests: write
    checks: read
  network: deny
  secrets:
    - { name: runtrue-scm-provider-token, purpose: provider-api }
jobs:
  reconcile:
    steps:
      - capabilities:
          secrets:
            - { name: runtrue-scm-provider-token, purpose: provider-api }
        run: { command: ["/usr/local/bin/runtrue-action"] }
"#;
    let context = CompileContext {
        normalized_event_digest: Some(ContentDigest::sha256(b"authenticated-event")),
        scm_api_url: Some("https://github.example/api/v3".to_owned()),
        event: serde_json::json!({
            "provider": "git_hub",
            "repository": { "full_name": "ci/test" }
        }),
        ..CompileContext::default()
    };
    let compilation = Compiler::default().compile_yaml(source, context).unwrap();
    assert!(!compilation.capsule.approval.privileged_execution);
    assert_eq!(
        compilation.capsule.approval.reasons,
        vec![
            "scm-contents-write".to_owned(),
            "scm-issues-write".to_owned(),
            "scm-pull-requests-write".to_owned(),
            "secret-access".to_owned(),
            "step-secret-access".to_owned()
        ]
    );
    assert_eq!(compilation.risk_report.score, 100);

    let status_write = source.replace("    checks: read", "    checks: read\n    statuses: write");
    let context = CompileContext {
        normalized_event_digest: Some(ContentDigest::sha256(b"authenticated-event")),
        scm_api_url: Some("https://github.example/api/v3".to_owned()),
        event: serde_json::json!({
            "provider": "git_hub",
            "repository": { "full_name": "ci/test" }
        }),
        ..CompileContext::default()
    };
    assert!(
        Compiler::default()
            .compile_yaml(&status_write, context)
            .unwrap()
            .capsule
            .approval
            .privileged_execution
    );
}

#[test]
fn job_permissions_cannot_exceed_workflow_maximum() {
    let source = r#"
version: 1
permissions:
  repository: read
  network: deny
jobs:
  build:
    permissions:
      repository: write
      network: deny
    steps:
      - run: { command: ["true"] }
"#;
    let compilation = compile(source).unwrap();
    assert_eq!(
        compilation.capsule.jobs[0].permissions.repository,
        ir::Access::Read
    );
}

#[test]
fn secret_purpose_cannot_escalate_through_name_only_matching() {
    let job_escalation = r#"
version: 1
permissions:
  secrets: [{ name: TOKEN, purpose: read }]
jobs:
  build:
    permissions:
      secrets: [{ name: TOKEN, purpose: deploy }]
    steps: [{ run: { command: ["true"] } }]
"#;
    let compilation = compile(job_escalation).unwrap();
    assert!(compilation.capsule.jobs[0].permissions.secrets.is_empty());

    let step_escalation = r#"
version: 1
permissions:
  secrets: [{ name: TOKEN, purpose: read }]
jobs:
  build:
    steps:
      - capabilities:
          secrets: [{ name: TOKEN, purpose: deploy }]
        run: { command: ["true"] }
"#;
    assert!(compile(step_escalation)
        .unwrap_err()
        .to_string()
        .contains("ungranted purpose"));
}

#[test]
fn workflow_change_gate_does_not_change_canonical_workflow_identity() {
    let source = workflow("  build:\n    steps:\n      - run: { command: [\"true\"] }\n");
    let unchanged = compile(&source).unwrap();
    let context = CompileContext {
        workflow_changed: true,
        ..CompileContext::default()
    };
    let changed = Compiler::default().compile_yaml(&source, context).unwrap();
    assert_eq!(
        unchanged.capsule.workflow.digest,
        changed.capsule.workflow.digest
    );
    assert!(!unchanged.capsule.approval.workflow_definition);
    assert!(changed.capsule.approval.workflow_definition);
}

#[test]
fn frontend_provenance_is_bound_to_capsule_and_approval_subject() {
    let provenance = ir::WorkflowFrontendProvenance {
        frontend_id: "runtrue.github-actions".to_owned(),
        contract_generation: 1,
        frontend_generation: 2,
        configuration_digest: ContentDigest::sha256(b"frontend config"),
        input_digest: ContentDigest::sha256(b"source"),
        native_digest: ContentDigest::sha256(b"native"),
        report_digest: Some(ContentDigest::sha256(b"compatibility report")),
    };
    let source = workflow("  build:\n    steps: [{ run: { command: [\"true\"] } }]\n");
    let compilation = Compiler::default()
        .compile_yaml(
            &source,
            CompileContext {
                workflow_frontend: Some(provenance.clone()),
                ..CompileContext::default()
            },
        )
        .unwrap();
    assert_eq!(
        compilation.capsule.context.workflow_frontend,
        Some(provenance.clone())
    );
    assert_eq!(
        compilation.approval_subject.workflow_frontend,
        Some(provenance)
    );
    assert!(compilation.workflow_frontend_report.is_none());
}

#[test]
fn selected_job_capsule_includes_dependencies_only() {
    let source = workflow(
            "  build:\n    steps: [{ run: { command: [\"true\"] } }]\n  test:\n    needs: [build]\n    steps: [{ run: { command: [\"true\"] } }]\n  dangerous:\n    trust: trusted-only\n    environment: production\n    runner: { isolation: native }\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    let context = CompileContext {
        selected_job: Some("test".to_owned()),
        ..CompileContext::default()
    };
    let compilation = Compiler::default().compile_yaml(&source, context).unwrap();
    assert_eq!(
        compilation
            .capsule
            .jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect::<Vec<_>>(),
        vec!["build", "test"]
    );
    assert!(!compilation.capsule.approval.privileged_execution);
    assert!(compilation.risk_report.findings.is_empty());
}

#[test]
fn trigger_and_manual_input_changes_change_workflow_identity() {
    let main = r#"
version: 1
on:
  push: { branches: [main] }
  manual:
    inputs:
      suite: { type: string, default: fast }
jobs:
  build:
    steps: [{ run: { command: ["true"] } }]
"#;
    let release = main
        .replace("branches: [main]", "branches: [release]")
        .replace("default: fast", "default: full");
    let main = compile(main).unwrap();
    let release = compile(&release).unwrap();
    assert_ne!(
        main.capsule.workflow.digest,
        release.capsule.workflow.digest
    );
    assert_ne!(main.capsule_digest, release.capsule_digest);
    assert_ne!(
        main.approval_subject_digest,
        release.approval_subject_digest
    );
}

#[test]
fn semantic_risk_diff_reports_privilege_and_isolation_increases() {
    let base = workflow(
            "  build:\n    trust: trusted-only\n    runner: { isolation: microvm }\n    steps: [{ run: { command: [\"true\"] } }]\n",
        );
    let proposed = r#"
version: 1
permissions:
  repository: write
  network:
    dns: restricted
    allow:
      - { host: "*.example.com", port: 443 }
jobs:
  build:
    trust: trusted-only
    runner: { isolation: native }
    steps: [{ run: { command: ["true"] } }]
"#;
    let base = compile(&base).unwrap();
    let proposed = compile(proposed).unwrap();
    let report = semantic_risk_diff(&base.capsule, &proposed.capsule);
    let codes = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("repository-access-increased"));
    assert!(codes.contains("wildcard-network-added"));
    assert!(codes.contains("isolation-weakened"));
    assert_eq!(report.highest_severity, RiskSeverity::High);
}

const OUTER_REF: &str = "git+https://example.test/workflows.git//outer.yaml@v1";
const INNER_REF: &str = "git+https://example.test/workflows.git//inner.yaml@v1";
const OUTER_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INNER_COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn inner_reusable() -> &'static str {
    r#"version: 1
inputs:
  enabled: { type: boolean, default: true }
  label: { type: string, required: true }
outputs:
  bundle: { from: needs.build.outputs.bundle }
jobs:
  build:
    if: inputs.enabled == false
    steps:
      - run:
          command: [echo]
          args: [{ from: inputs.label }]
    outputs:
      bundle: { path: dist/bundle.tar }
"#
}

fn outer_reusable() -> &'static str {
    r#"version: 1
inputs:
  flavor: { type: string, default: debug }
outputs:
  bundle: { from: needs.inner.outputs.bundle }
jobs:
  inner:
    uses: git+https://example.test/workflows.git//inner.yaml@v1
    with: { enabled: false, label: nested }
  post:
    needs: [inner]
    steps:
      - run:
          command: [echo]
          args: [{ from: inputs.flavor }]
"#
}

#[test]
fn nested_reusable_workflows_bind_inputs_bridge_needs_and_outputs() {
    let root = r#"version: 1
jobs:
  prepare:
    steps: [{ run: { command: ["true"] } }]
  reuse:
    needs: [prepare]
    uses: git+https://example.test/workflows.git//outer.yaml@v1
    with: { flavor: release }
  finish:
    needs: [reuse]
    if: needs.reuse.outputs.bundle == needs.reuse.outputs.bundle
    steps: [{ run: { command: ["true"] } }]
"#;
    let context = reusable_context(
        &[
            (OUTER_REF, OUTER_COMMIT, outer_reusable()),
            (INNER_REF, INNER_COMMIT, inner_reusable()),
        ],
        None,
    );
    let compilation = Compiler::default().compile_yaml(root, context).unwrap();
    let by_id = compilation
        .capsule
        .jobs
        .iter()
        .map(|job| (job.id.as_str(), job))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        by_id.keys().copied().collect::<Vec<_>>(),
        vec!["finish", "prepare", "reuse__inner__build", "reuse__post"]
    );
    assert_eq!(by_id["reuse__inner__build"].needs, vec!["prepare"]);
    assert_eq!(by_id["reuse__post"].needs, vec!["reuse__inner__build"]);
    assert_eq!(by_id["finish"].needs, vec!["reuse__post"]);
    assert_eq!(
            by_id["finish"].condition.as_deref(),
            Some("(needs.reuse__inner__build.outputs.bundle == needs.reuse__inner__build.outputs.bundle)")
        );
    assert_eq!(
        by_id["reuse__post"].steps[0].action,
        ir::StepAction::Command {
            program: "echo".to_owned(),
            args: vec![ir::ValueBinding::Literal(ir::ScalarValue::String(
                "release".to_owned()
            ))],
        }
    );
    assert_eq!(
        by_id["reuse__inner__build"].condition.as_deref(),
        Some("(false == false)")
    );
    assert_eq!(
        compilation.approval_subject.reusable_workflow_digests,
        vec![
            ContentDigest::sha256(outer_reusable().as_bytes()).to_string(),
            ContentDigest::sha256(inner_reusable().as_bytes()).to_string(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
}

#[test]
fn reusable_input_defaults_types_and_required_values_are_enforced() {
    let reusable = r#"version: 1
inputs:
  count: { type: integer, required: true }
  mode: { type: choice, options: [fast, full], default: fast }
jobs:
  run:
    steps:
      - run:
          command: [echo]
          args: [{ from: inputs.mode }, { from: inputs.count }]
"#;
    let root = |with: &str| format!("version: 1\njobs:\n  call:\n    uses: {OUTER_REF}\n{with}");
    let context = || reusable_context(&[(OUTER_REF, OUTER_COMMIT, reusable)], None);
    let compilation = Compiler::default()
        .compile_yaml(&root("    with: { count: 3 }\n"), context())
        .unwrap();
    let args = match &compilation.capsule.jobs[0].steps[0].action {
        ir::StepAction::Command { args, .. } => args,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(
        args,
        &vec![
            ir::ValueBinding::Literal(ir::ScalarValue::String("fast".to_owned())),
            ir::ValueBinding::Literal(ir::ScalarValue::Integer(3)),
        ]
    );

    for (with, expected) in [
        ("", "required reusable workflow input `count` is missing"),
        (
            "    with: { count: wrong }\n",
            "does not match its declared input type",
        ),
        (
            "    with: { count: 1, mode: invalid }\n",
            "is not an allowed option",
        ),
        (
            "    with: { count: 1, typo: true }\n",
            "does not declare input `typo`",
        ),
    ] {
        let error = Compiler::default()
            .compile_yaml(&root(with), context())
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn reusable_source_lock_commit_and_digest_mismatches_fail_closed() {
    let child = "version: 1\njobs:\n  run:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let root = format!("version: 1\njobs:\n  call:\n    uses: {OUTER_REF}\n");

    let mut missing_source = reusable_context(&[(OUTER_REF, OUTER_COMMIT, child)], None);
    missing_source.reusable_workflows = ReusableWorkflowSources::default();
    let error = Compiler::default()
        .compile_yaml(&root, missing_source)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("missing authenticated source bytes"),
        "{error}"
    );

    let mut tampered = reusable_context(&[(OUTER_REF, OUTER_COMMIT, child)], None);
    tampered.reusable_workflows = ReusableWorkflowSources::new(BTreeMap::from([(
        OUTER_REF.to_owned(),
        ReusableWorkflowSource::new(OUTER_COMMIT, child.replace("true", "false").into_bytes())
            .unwrap(),
    )]))
    .unwrap();
    let error = Compiler::default()
        .compile_yaml(&root, tampered)
        .unwrap_err()
        .to_string();
    assert!(error.contains("source digest"), "{error}");

    let mut wrong_commit = reusable_context(&[(OUTER_REF, OUTER_COMMIT, child)], None);
    wrong_commit.reusable_workflows = ReusableWorkflowSources::new(BTreeMap::from([(
        OUTER_REF.to_owned(),
        ReusableWorkflowSource::new(INNER_COMMIT, child.as_bytes().to_vec()).unwrap(),
    )]))
    .unwrap();
    let error = Compiler::default()
        .compile_yaml(&root, wrong_commit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("source commit"), "{error}");

    let error = Compiler::default()
        .compile_yaml(
            &root,
            CompileContext {
                reusable_workflows: reusable_context(&[(OUTER_REF, OUTER_COMMIT, child)], None)
                    .reusable_workflows,
                ..CompileContext::default()
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("validated lockfile"), "{error}");
}

#[test]
fn reusable_sources_reject_triggers_and_non_artifact_output_contexts() {
    let root = format!("version: 1\njobs:\n  call:\n    uses: {OUTER_REF}\n");
    let triggered = "version: 1\non:\n  manual: {}\njobs:\n  run:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let error = Compiler::default()
        .compile_yaml(
            &root,
            reusable_context(&[(OUTER_REF, OUTER_COMMIT, triggered)], None),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("cannot declare event triggers"), "{error}");

    let secret_output = "version: 1\noutputs:\n  leak: { from: secrets.DEPLOY_TOKEN }\njobs:\n  run:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let error = Compiler::default()
        .compile_yaml(
            &root,
            reusable_context(&[(OUTER_REF, OUTER_COMMIT, secret_output)], None),
        )
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("must use `needs.<job-id>.outputs"),
        "{error}"
    );
}

#[test]
fn reusable_cycles_depth_fanout_and_namespace_collisions_are_bounded() {
    let first = format!("version: 1\njobs:\n  next:\n    uses: {INNER_REF}\n");
    let second = format!("version: 1\njobs:\n  next:\n    uses: {OUTER_REF}\n");
    let root = format!("version: 1\njobs:\n  call:\n    uses: {OUTER_REF}\n");
    let error = Compiler::default()
        .compile_yaml(
            &root,
            reusable_context(
                &[
                    (OUTER_REF, OUTER_COMMIT, &first),
                    (INNER_REF, INNER_COMMIT, &second),
                ],
                None,
            ),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("call cycle"), "{error}");

    let leaf_ref = "git+https://example.test/workflows.git//leaf.yaml@v1";
    let leaf_commit = "cccccccccccccccccccccccccccccccccccccccc";
    let middle = format!("version: 1\njobs:\n  leaf:\n    uses: {leaf_ref}\n");
    let leaf = "version: 1\njobs:\n  run:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let context = reusable_context(
        &[
            (OUTER_REF, OUTER_COMMIT, &first),
            (INNER_REF, INNER_COMMIT, &middle),
            (leaf_ref, leaf_commit, leaf),
        ],
        None,
    );
    let error = Compiler::new(CompilerSettings {
        max_reusable_depth: 2,
        ..CompilerSettings::default()
    })
    .compile_yaml(&root, context)
    .unwrap_err()
    .to_string();
    assert!(error.contains("depth limit"), "{error}");

    let fanout = "version: 1\njobs:\n  a:\n    steps: [{ run: { command: [\"true\"] } }]\n  b:\n    steps: [{ run: { command: [\"true\"] } }]\n  c:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let error = Compiler::new(CompilerSettings {
        max_reusable_jobs: 2,
        ..CompilerSettings::default()
    })
    .compile_yaml(
        &root,
        reusable_context(&[(OUTER_REF, OUTER_COMMIT, fanout)], None),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("fan-out limit"), "{error}");

    let collision_root = format!(
            "version: 1\njobs:\n  call:\n    uses: {OUTER_REF}\n  call__run:\n    steps: [{{ run: {{ command: [\"true\"] }} }}]\n"
        );
    let error = Compiler::default()
        .compile_yaml(
            &collision_root,
            reusable_context(&[(OUTER_REF, OUTER_COMMIT, leaf)], None),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("namespace collision"), "{error}");
}

#[test]
fn reusable_expansion_is_deterministic_and_selected_call_keeps_its_closure() {
    let child = "version: 1\njobs:\n  build:\n    steps: [{ run: { command: [\"true\"] } }]\n  test:\n    needs: [build]\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let root = format!(
            "version: 1\njobs:\n  prep:\n    steps: [{{ run: {{ command: [\"true\"] }} }}]\n  call:\n    needs: [prep]\n    uses: {OUTER_REF}\n  unrelated:\n    steps: [{{ run: {{ command: [\"false\"] }} }}]\n"
        );
    let first = Compiler::default()
        .compile_yaml(
            &root,
            reusable_context(&[(OUTER_REF, OUTER_COMMIT, child)], Some("call")),
        )
        .unwrap();
    let second = Compiler::default()
        .compile_yaml(
            &root,
            reusable_context(&[(OUTER_REF, OUTER_COMMIT, child)], Some("call")),
        )
        .unwrap();
    assert_eq!(first.capsule_digest, second.capsule_digest);
    assert_eq!(
        first.capsule.canonical_bytes().unwrap(),
        second.capsule.canonical_bytes().unwrap()
    );
    assert_eq!(
        first
            .capsule
            .jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect::<Vec<_>>(),
        vec!["call__build", "call__test", "prep"]
    );
}

#[test]
fn root_runtime_input_contexts_are_not_substituted_as_reusable_inputs() {
    let root = r#"version: 1
on:
  manual:
    inputs:
      release: { type: boolean, default: false }
jobs:
  build:
    if: inputs.release == true
    steps: [{ run: { command: ["true"] } }]
"#;
    let compilation = compile(root).unwrap();
    assert_eq!(
        compilation.capsule.jobs[0].condition.as_deref(),
        Some("(inputs.release == true)")
    );
}

#[test]
fn compiles_distinct_finalizers_and_typed_output_provenance_contract() {
    let compilation = compile(
        r#"version: 1
jobs:
  build:
    steps:
      - id: produce
        run: { command: ["true"] }
        outputs:
          count: { type: integer, required: true }
    value-outputs:
      count: { from: steps.produce.outputs.count }
    finalizer-timeout: 30s
    finalizers:
      - id: cleanup
        run: { command: ["true"] }
        required: true
        run-on-cancel: true
"#,
    )
    .unwrap();
    let job = &compilation.capsule.jobs[0];
    assert_eq!(job.finalizer_timeout_ms, 30_000);
    assert_eq!(job.finalizers.len(), 1);
    assert!(job.finalizers[0].required);
    assert!(job.finalizers[0].run_on_cancel);
    assert_eq!(job.value_outputs["count"].step_id, "produce");
    assert_eq!(
        job.steps[0].outputs["count"].kind,
        ir::StepOutputType::Integer
    );
}

#[test]
fn dynamic_matrix_is_a_signed_terminal_template_with_a_hard_ceiling() {
    let source = r#"version: 1
jobs:
  generate:
    steps:
      - id: matrix
        run: { command: ["true"] }
        outputs:
          axes: { type: json, required: true }
    value-outputs:
      axes: { from: steps.matrix.outputs.axes }
  build:
    needs: [generate]
    dynamic-matrix:
      from: needs.generate.outputs.axes
      max-jobs: 4
    steps:
      - run: { command: ["true"] }
"#;
    let compilation = compile(source).unwrap();
    assert_eq!(compilation.capsule.jobs.len(), 1);
    assert_eq!(compilation.capsule.dynamic_jobs.len(), 1);
    let template = &compilation.capsule.dynamic_jobs[0];
    assert_eq!(template.id, "build");
    assert_eq!(template.source.maximum_jobs, 4);
    assert_eq!(
        template.template.permissions,
        compilation.capsule.permissions
    );
    assert!(compilation
        .capsule
        .canonical_bytes()
        .unwrap()
        .windows(b"dynamic_jobs".len())
        .any(|window| window == b"dynamic_jobs"));

    let exceeded = source.replace("max-jobs: 4", "max-jobs: 257");
    assert!(compile(&exceeded)
        .unwrap_err()
        .to_string()
        .contains("dynamic matrix limit"));
}

#[test]
fn rejects_dynamic_permission_or_dependency_shape_changes_before_execution() {
    let source = r#"version: 1
jobs:
  generate:
    matrix: { shard: [1, 2] }
    steps:
      - id: matrix
        run: { command: ["true"] }
        outputs:
          axes: { type: json, required: true }
    value-outputs:
      axes: { from: steps.matrix.outputs.axes }
  build:
    needs: [generate]
    dynamic-matrix: { from: needs.generate.outputs.axes, max-jobs: 2 }
    steps: [{ run: { command: ["true"] } }]
"#;
    assert!(compile(source).is_err());

    let both = source.replace(
            "dynamic-matrix: { from: needs.generate.outputs.axes, max-jobs: 2 }",
            "matrix: { mode: [debug] }\n    dynamic-matrix: { from: needs.generate.outputs.axes, max-jobs: 2 }",
        );
    assert!(compile(&both)
        .unwrap_err()
        .to_string()
        .contains("mutually exclusive"));

    let valid = source.replace("matrix: { shard: [1, 2] }\n    ", "");
    let optional_source = valid.replace("type: json, required: true", "type: json");
    assert!(compile(&optional_source)
        .unwrap_err()
        .to_string()
        .contains("required JSON structured output"));

    let base = compile(&valid).unwrap().capsule;
    let mut changed = base.clone();
    let template = &mut changed.dynamic_jobs[0];
    template.template.permissions.repository = ir::Access::Write;
    template.template.needs.clear();
    template.source.output_name = "substituted".to_owned();
    let report = semantic_risk_diff(&base, &changed);
    let codes = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("repository-access-increased"));
    assert!(codes.contains("job-dependency-removed"));
    assert!(codes.contains("dynamic-matrix-source-changed"));
}
