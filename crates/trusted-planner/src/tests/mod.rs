use super::*;
use crate::{ReusableWorkflowProviderError, SecretResolutionError};
use runtrue_scm::{
    ActorIdentity, EventType, GitRevision, IssueCommentAction, IssueCommentEvent, ProviderKind,
    PullRequestAction, PullRequestEvent, RepositoryIdentity, WorkflowSourceError,
};
use runtrue_workflow_frontend::{
    PreparedWorkflowSource, ResolvedProgram, ResolvedSourceAction, WorkflowFrontendError,
    WorkflowFrontendOptions, WorkflowFrontendRegistry, WorkflowFrontendReport,
    WorkflowSourceFrontend, WORKFLOW_FRONTEND_CONTRACT_GENERATION,
};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

const NOW: u64 = 10_000;
const WORKFLOW_PATH: &str = ".runtrue/workflows/ci.yaml";

struct Fixture {
    directory: tempfile::TempDir,
    base: String,
    source: String,
}

impl Fixture {
    fn create(proposed: &[u8]) -> Self {
        Self::create_with_proposed_lock(proposed, None)
    }

    fn create_with_proposed_lock(proposed: &[u8], lockfile: Option<&[u8]>) -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        git(directory.path(), &["init", "--quiet"]);
        git(
            directory.path(),
            &["config", "user.email", "planner@runtrue.invalid"],
        );
        git(directory.path(), &["config", "user.name", "Planner Test"]);
        fs::create_dir_all(directory.path().join(".runtrue/workflows")).expect("workflow dir");
        fs::write(
            directory.path().join(WORKFLOW_PATH),
            workflow("trusted-base", "microvm"),
        )
        .expect("base workflow");
        git(directory.path(), &["add", "."]);
        git(directory.path(), &["commit", "--quiet", "-m", "base"]);
        let base = output(directory.path(), &["rev-parse", "HEAD"]);

        fs::write(directory.path().join(WORKFLOW_PATH), proposed).expect("proposed workflow");
        if let Some(lockfile) = lockfile {
            fs::write(directory.path().join(DEFAULT_LOCKFILE_PATH), lockfile)
                .expect("proposed lockfile");
        }
        git(directory.path(), &["add", "."]);
        git(directory.path(), &["commit", "--quiet", "-m", "proposed"]);
        let source = output(directory.path(), &["rev-parse", "HEAD"]);
        Self {
            directory,
            base,
            source,
        }
    }

    fn repository(&self) -> GitRepository {
        GitRepository::open(self.directory.path(), runtrue_git::GitLimits::default())
            .expect("repository")
    }

    fn pull_event(&self) -> EventEnvelope {
        event(
            EventType::PullRequest {
                action: PullRequestAction::Synchronize,
            },
            self.source.clone(),
            Some(self.base.clone()),
        )
    }
}

struct Verifier(bool);

struct FixedFrontend {
    generation: u32,
    invalid_report_media_type: bool,
}

impl WorkflowSourceFrontend for FixedFrontend {
    fn frontend_id(&self) -> &'static str {
        "runtrue.test-frontend"
    }

    fn frontend_generation(&self) -> u32 {
        self.generation
    }

    fn discovery_roots(&self) -> &'static [&'static str] {
        &[".runtrue/workflows"]
    }

    fn supports(&self, _workflow_path: &str) -> bool {
        true
    }

    fn prepare(
        &self,
        _source: &str,
        _workflow_path: &str,
        _options: &WorkflowFrontendOptions,
    ) -> Result<PreparedWorkflowSource, WorkflowFrontendError> {
        let native_yaml =
            String::from_utf8(workflow("translated", "microvm")).expect("native test workflow");
        let report_bytes = br#"{"status":"translated"}"#.to_vec();
        Ok(PreparedWorkflowSource {
            native_yaml,
            generated_lockfile_toml: None,
            report: Some(WorkflowFrontendReport {
                media_type: if self.invalid_report_media_type {
                    "invalid media type"
                } else {
                    "application/vnd.runtrue.test-frontend+json"
                }
                .to_owned(),
                bytes: report_bytes,
            }),
        })
    }
}

impl WorkflowDefinitionApprovalVerifier for Verifier {
    fn verify(
        &self,
        _evidence: &WorkflowDefinitionApprovalEvidence,
    ) -> Result<(), WorkflowSourceError> {
        if self.0 {
            Ok(())
        } else {
            Err(WorkflowSourceError::ApprovalInvalid)
        }
    }
}

struct FixedReusableProvider {
    reference: String,
    commit: String,
    digest: ContentDigest,
    bytes: Vec<u8>,
}

struct UnavailableReusableProvider;

struct FixedSecretResolver;

impl SecretMetadataResolver for FixedSecretResolver {
    fn bind_exact(&self, compilation: &mut Compilation) -> Result<(), SecretResolutionError> {
        compilation
            .bind_secret_resolutions(&BTreeMap::from([(
                "TOKEN".to_owned(),
                runtrue_compiler::ResolvedSecretMetadata {
                    metadata_id: "secret-1".to_owned(),
                    binding: runtrue_model::SecretResolutionBinding {
                        scope: "project:release".to_owned(),
                        metadata_version: Some(4),
                        resolution_digest: ContentDigest::sha256(b"resolution"),
                        project_versions: vec![runtrue_model::SecretProjectVersion {
                            project_id: "release".to_owned(),
                            version: 2,
                        }],
                    },
                },
            )]))
            .map_err(|_| SecretResolutionError::Unavailable)
    }
}

impl ReusableWorkflowSourceProvider for UnavailableReusableProvider {
    fn load_exact(
        &self,
        _reference: &str,
        _commit: &str,
        _digest: &ContentDigest,
    ) -> Result<Vec<u8>, ReusableWorkflowProviderError> {
        Err(ReusableWorkflowProviderError::Unavailable)
    }
}

impl ReusableWorkflowSourceProvider for FixedReusableProvider {
    fn load_exact(
        &self,
        reference: &str,
        commit: &str,
        digest: &ContentDigest,
    ) -> Result<Vec<u8>, ReusableWorkflowProviderError> {
        assert_eq!(reference, self.reference);
        assert_eq!(commit, self.commit);
        assert_eq!(digest, &self.digest);
        Ok(self.bytes.clone())
    }
}

fn workflow(name: &str, isolation: &str) -> Vec<u8> {
    format!(
        "version: 1\nname: {name}\njobs:\n  build:\n    runner:\n      isolation: {isolation}\n    steps:\n      - run:\n          command: [\"true\"]\n"
    )
    .into_bytes()
}

fn secret_workflow() -> Vec<u8> {
    b"version: 1\npermissions:\n  secrets: [{ name: TOKEN }]\njobs:\n  build:\n    steps:\n      - capabilities:\n          secrets: [{ name: TOKEN }]\n        run: { command: [\"true\"] }\n".to_vec()
}

#[test]
fn trusted_planner_requires_and_seals_exact_secret_resolution() {
    let fixture = Fixture::create(&secret_workflow());
    let repository = fixture.repository();
    let push = event(EventType::Push, fixture.source.clone(), None);
    let without = TrustedPlanner::new(&repository).capsule(
        &push,
        WORKFLOW_PATH,
        "installation-1",
        "tenant-1",
        "repo-1",
        "main",
        vec!["policy-v1".to_owned()],
        None,
        &Verifier(true),
        NOW,
    );
    assert!(matches!(
        without,
        Err(TrustedPlannerError::SecretResolution(
            SecretResolutionError::Missing
        ))
    ));

    let resolver = FixedSecretResolver;
    let execution = TrustedPlanner::new(&repository)
        .with_secret_metadata_resolver(&resolver)
        .capsule(
            &push,
            WORKFLOW_PATH,
            "installation-1",
            "tenant-1",
            "repo-1",
            "main",
            vec!["policy-v1".to_owned()],
            None,
            &Verifier(true),
            NOW,
        )
        .unwrap()
        .execution;
    let secret = &execution.capsule.jobs[0].steps[0].capabilities.secrets[0];
    assert_eq!(secret.metadata_id, "secret-1");
    assert_eq!(
        secret.resolution.as_ref().unwrap().metadata_version,
        Some(4)
    );
    assert_eq!(execution.approval_subject.secret_metadata_ids, ["secret-1"]);
}

fn event(event_type: EventType, source: String, base: Option<String>) -> EventEnvelope {
    let is_pull = matches!(event_type, EventType::PullRequest { .. });
    let is_push = matches!(event_type, EventType::Push);
    let source_ref = if is_pull {
        "feature"
    } else if is_push {
        "refs/heads/main"
    } else {
        "main"
    };
    let mut event = EventEnvelope {
        version: 1,
        provider: ProviderKind::GitHub,
        installation_id: "installation-1".to_owned(),
        repository: RepositoryIdentity {
            external_id: "42".to_owned(),
            owner: "octo".to_owned(),
            name: "runtrue".to_owned(),
            full_name: "octo/runtrue".to_owned(),
            private: false,
            default_branch: Some("main".to_owned()),
        },
        event_id: "delivery-1".to_owned(),
        event_type,
        actor: ActorIdentity {
            external_id: "7".to_owned(),
            login: "contributor".to_owned(),
            is_bot: false,
        },
        source: GitRevision {
            commit: source,
            ref_name: Some(source_ref.to_owned()),
            repository_full_name: Some("octo/runtrue".to_owned()),
        },
        base: base.map(|commit| GitRevision {
            commit,
            ref_name: Some("main".to_owned()),
            repository_full_name: Some("octo/runtrue".to_owned()),
        }),
        ref_name: Some(if is_push { source_ref } else { "main" }.to_owned()),
        pull_request: is_pull.then_some(PullRequestEvent {
            number: 17,
            draft: false,
            merged: false,
        }),
        issue_comment: None,
        check_run: None,
        changed_paths: vec![WORKFLOW_PATH.to_owned()],
        received_unix_ms: NOW - 100,
        raw_payload_digest: ContentDigest::sha256(b"raw"),
        normalized_digest: ContentDigest::sha256(b"placeholder"),
    };
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    event
}

fn capsule(
    fixture: &Fixture,
    approval: Option<&WorkflowDefinitionApprovalEvidence>,
) -> Result<TrustedCapsuleResult, TrustedPlannerError> {
    let repository = fixture.repository();
    TrustedPlanner::new(&repository).capsule(
        &fixture.pull_event(),
        WORKFLOW_PATH,
        "installation-1",
        "tenant-1",
        "repo-1",
        "main",
        vec!["policy-v1".to_owned()],
        approval,
        &Verifier(true),
        NOW,
    )
}

fn approval(fixture: &Fixture, proposed: &Compilation) -> WorkflowDefinitionApprovalEvidence {
    let repository = fixture.repository();
    let event = fixture.pull_event();
    WorkflowDefinitionApprovalEvidence {
        approval_id: "approval-1".to_owned(),
        normalized_event_digest: event.normalized_digest,
        event_received_unix_ms: event.received_unix_ms,
        repository_full_name: event.repository.full_name,
        source_commit: fixture.source.clone(),
        base_commit: fixture.base.clone(),
        workflow_path: WORKFLOW_PATH.to_owned(),
        proposed_workflow_digest: repository
            .read_blob(&fixture.source, WORKFLOW_PATH)
            .expect("proposed blob")
            .digest,
        base_workflow_digest: repository
            .read_blob(&fixture.base, WORKFLOW_PATH)
            .expect("base blob")
            .digest,
        proposed_lockfile_digest: None,
        base_lockfile_digest: None,
        proposed_approval_subject_digest: proposed.approval_subject_digest.clone(),
        policy_version_ids: vec!["policy-v1".to_owned()],
        approved_unix_ms: NOW - 10,
        expires_unix_ms: NOW + 60_000,
    }
}

#[test]
fn pull_request_executes_base_and_only_analyzes_proposed_by_default() {
    let fixture = Fixture::create(&workflow("proposed", "wasm"));
    let result = capsule(&fixture, None).expect("trusted capsule");
    assert_eq!(result.execution.capsule.workflow.name, "trusted-base");
    assert_eq!(
        result.execution.capsule.context.source_commit, fixture.source,
        "base workflow must still test exact pull-request code"
    );
    assert_eq!(
        result.execution.capsule.context.normalized_event_digest,
        fixture.pull_event().normalized_digest
    );
    assert!(result.selection.trusted_base_workflow_executed);
    assert!(result.selection.workflow_definition_approval_required);
    let ProposedWorkflowAnalysis::Valid { semantic_risk, .. } = result.proposed_analysis else {
        panic!("expected valid proposed analysis");
    };
    assert!(semantic_risk
        .findings
        .iter()
        .any(|finding| finding.path.contains("runner.isolation")));
}

#[test]
fn issue_comment_executes_exact_trusted_default_revision_without_mutating_event_identity() {
    let fixture = Fixture::create(&workflow("new-default", "microvm"));
    let repository = fixture.repository();
    let mut event = event(
        EventType::IssueComment {
            action: IssueCommentAction::Edited,
        },
        "0".repeat(40),
        None,
    );
    event.issue_comment = Some(IssueCommentEvent {
        issue_number: 17,
        issue_is_pull_request: true,
        comment_id: 99,
        body: "- [x] Run managed repository automation now".to_owned(),
        previous_body: Some("- [ ] Run managed repository automation now".to_owned()),
    });
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    let event_digest = event.normalized_digest.clone();
    let trusted_revision = GitRevision {
        commit: fixture.source.clone(),
        ref_name: Some("refs/heads/main".to_owned()),
        repository_full_name: Some("octo/runtrue".to_owned()),
    };
    let result = TrustedPlanner::new(&repository)
        .capsule_trusted_default_revision(
            &event,
            &trusted_revision,
            WORKFLOW_PATH,
            "installation-1",
            "tenant-1",
            "repo-1",
            "main",
            vec!["policy-v1".to_owned()],
        )
        .expect("trusted default capsule");
    assert_eq!(result.execution.capsule.workflow.name, "new-default");
    assert_eq!(
        result.execution.capsule.context.source_commit,
        trusted_revision.commit
    );
    assert_eq!(
        result.execution.capsule.context.normalized_event_digest,
        event_digest
    );
    assert_eq!(event.source.commit, "0".repeat(40));
    assert!(result.selection.trusted_base_workflow_executed);
}

#[test]
fn trusted_planner_rejects_invalid_frontend_output() {
    let fixture = Fixture::create(&workflow("source", "microvm"));
    let repository = fixture.repository();
    let push = event(EventType::Push, fixture.source.clone(), None);
    let frontend = FixedFrontend {
        generation: 1,
        invalid_report_media_type: true,
    };
    let frontends = WorkflowFrontendRegistry::new(&[&frontend]).unwrap();

    let error = TrustedPlanner::new(&repository)
        .with_source_frontends(&frontends)
        .capsule(
            &push,
            WORKFLOW_PATH,
            "installation-1",
            "tenant-1",
            "repo-1",
            "main",
            vec!["policy-v1".to_owned()],
            None,
            &Verifier(true),
            NOW,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        TrustedPlannerError::InvalidWorkflowFrontendOutput("invalid report media type")
    ));
}

#[test]
fn frontend_outputs_are_bounded_before_consumption() {
    let prepared = |native_yaml: String| PreparedWorkflowSource {
        native_yaml,
        generated_lockfile_toml: None,
        report: None,
    };

    assert!(matches!(
        validate_frontend_output(&prepared(String::new())),
        Err(TrustedPlannerError::InvalidWorkflowFrontendOutput(
            "empty native workflow"
        ))
    ));
    assert!(matches!(
        validate_frontend_output(&prepared("x".repeat(MAX_NATIVE_WORKFLOW_BYTES + 1))),
        Err(TrustedPlannerError::InvalidWorkflowFrontendOutput(
            "oversized native workflow"
        ))
    ));

    let mut oversized_lockfile = prepared("version: 1\njobs: {}\n".to_owned());
    oversized_lockfile.generated_lockfile_toml = Some("x".repeat(MAX_GENERATED_LOCKFILE_BYTES + 1));
    assert!(matches!(
        validate_frontend_output(&oversized_lockfile),
        Err(TrustedPlannerError::InvalidWorkflowFrontendOutput(
            "oversized generated lockfile"
        ))
    ));

    let mut oversized_report = prepared("version: 1\njobs: {}\n".to_owned());
    oversized_report.report = Some(WorkflowFrontendReport {
        media_type: "application/json".to_owned(),
        bytes: vec![b'x'; MAX_FRONTEND_REPORT_BYTES + 1],
    });
    assert!(matches!(
        validate_frontend_output(&oversized_report),
        Err(TrustedPlannerError::InvalidWorkflowFrontendOutput(
            "oversized report"
        ))
    ));
}

#[test]
fn frontend_generation_is_bound_into_capsule_and_approval_identity() {
    let fixture = Fixture::create(&workflow("source", "microvm"));
    let repository = fixture.repository();
    let push = event(EventType::Push, fixture.source.clone(), None);
    let compile_with_generation = |generation| {
        let frontend = FixedFrontend {
            generation,
            invalid_report_media_type: false,
        };
        let frontends = WorkflowFrontendRegistry::new(&[&frontend]).unwrap();
        TrustedPlanner::new(&repository)
            .with_source_frontends(&frontends)
            .capsule(
                &push,
                WORKFLOW_PATH,
                "installation-1",
                "tenant-1",
                "repo-1",
                "main",
                vec!["policy-v1".to_owned()],
                None,
                &Verifier(true),
                NOW,
            )
            .unwrap()
            .execution
    };

    let first = compile_with_generation(1);
    let second = compile_with_generation(2);
    assert_eq!(
        first.capsule.workflow.digest,
        second.capsule.workflow.digest
    );
    assert_ne!(first.capsule_digest, second.capsule_digest);
    assert_ne!(
        first.approval_subject_digest,
        second.approval_subject_digest
    );
    assert_eq!(
        first
            .capsule
            .context
            .workflow_frontend
            .as_ref()
            .unwrap()
            .frontend_generation,
        1
    );
    assert_eq!(
        second
            .approval_subject
            .workflow_frontend
            .as_ref()
            .unwrap()
            .frontend_generation,
        2
    );

    let provenance = first.capsule.context.workflow_frontend.as_ref().unwrap();
    assert_eq!(provenance.frontend_id, "runtrue.test-frontend");
    assert_eq!(
        provenance.contract_generation,
        WORKFLOW_FRONTEND_CONTRACT_GENERATION
    );
    assert_eq!(
        provenance.configuration_digest,
        WorkflowFrontendOptions::default().digest()
    );
    assert_eq!(
        provenance.input_digest,
        ContentDigest::sha256(workflow("source", "microvm"))
    );
    assert_eq!(
        provenance.native_digest,
        ContentDigest::sha256(workflow("translated", "microvm"))
    );
    let report_bytes = br#"{"status":"translated"}"#;
    assert_eq!(
        provenance.report_digest,
        Some(ContentDigest::sha256(report_bytes))
    );
    let report = first.workflow_frontend_report.as_ref().unwrap();
    assert_eq!(report.digest, ContentDigest::sha256(report_bytes));
    assert_eq!(report.bytes, report_bytes);
}

#[test]
fn resolved_action_configuration_is_bound_into_capsule_identity() {
    let fixture = Fixture::create(&workflow("source", "microvm"));
    let repository = fixture.repository();
    let push = event(EventType::Push, fixture.source.clone(), None);
    let compile_with_image = |image: &str| {
        let frontend = FixedFrontend {
            generation: 1,
            invalid_report_media_type: false,
        };
        let frontends = WorkflowFrontendRegistry::new(&[&frontend]).unwrap();
        let mut options = WorkflowFrontendOptions::default();
        options
            .insert_resolved_action(
                "source/action@revision",
                ResolvedSourceAction::new(ResolvedProgram::container(image, None, None).unwrap()),
            )
            .unwrap();
        let expected_configuration_digest = options.digest();
        let execution = TrustedPlanner::new(&repository)
            .with_source_frontends(&frontends)
            .with_source_frontend_options(options)
            .capsule(
                &push,
                WORKFLOW_PATH,
                "installation-1",
                "tenant-1",
                "repo-1",
                "main",
                vec!["policy-v1".to_owned()],
                None,
                &Verifier(true),
                NOW,
            )
            .unwrap()
            .execution;
        (execution, expected_configuration_digest)
    };

    let (first, first_configuration_digest) = compile_with_image(
        "registry.invalid/tool@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let (second, _) = compile_with_image(
        "registry.invalid/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert_eq!(
        first
            .capsule
            .context
            .workflow_frontend
            .as_ref()
            .unwrap()
            .configuration_digest,
        first_configuration_digest
    );
    assert_ne!(first.capsule_digest, second.capsule_digest);
    assert_ne!(
        first.approval_subject_digest,
        second.approval_subject_digest
    );
}

#[test]
fn malformed_proposed_workflow_does_not_block_trusted_base_execution() {
    let fixture = Fixture::create(b"version: [definitely invalid");
    let result = capsule(&fixture, None).expect("base still capsules");
    assert_eq!(result.execution.capsule.workflow.name, "trusted-base");
    assert!(matches!(
        result.proposed_analysis,
        ProposedWorkflowAnalysis::Invalid {
            failure: ProposedAnalysisFailure::WorkflowInvalid,
            ..
        }
    ));
}

#[test]
fn unavailable_proposed_reusable_source_does_not_block_trusted_base_execution() {
    let reference = "git+https://github.com/octo/shared.git//ci.yaml@v1";
    let proposed = format!("version: 1\njobs:\n  shared:\n    uses: {reference}\n");
    let lockfile = format!(
        "lock_version = 1\n[[workflow]]\nsource = \"{reference}\"\ncommit = \"{}\"\ndigest = \"{}\"\n",
        "a".repeat(40),
        ContentDigest::sha256(b"unavailable reusable source")
    );
    let fixture =
        Fixture::create_with_proposed_lock(proposed.as_bytes(), Some(lockfile.as_bytes()));
    let repository = fixture.repository();
    let result = TrustedPlanner::new(&repository)
        .with_reusable_source_provider(&UnavailableReusableProvider)
        .capsule(
            &fixture.pull_event(),
            WORKFLOW_PATH,
            "installation-1",
            "tenant-1",
            "repo-1",
            "main",
            vec!["policy-v1".to_owned()],
            None,
            &Verifier(true),
            NOW,
        )
        .expect("trusted base still capsules");
    assert_eq!(result.execution.capsule.workflow.name, "trusted-base");
    assert!(matches!(
        result.proposed_analysis,
        ProposedWorkflowAnalysis::Invalid {
            failure: ProposedAnalysisFailure::WorkflowInvalid,
            ..
        }
    ));
}

#[test]
fn exact_full_subject_approval_selects_proposed_and_tampering_fails() {
    let fixture = Fixture::create(&workflow("proposed", "wasm"));
    let initial = capsule(&fixture, None).expect("analysis");
    let ProposedWorkflowAnalysis::Valid { compilation, .. } = &initial.proposed_analysis else {
        panic!("valid analysis");
    };
    let evidence = approval(&fixture, compilation);
    let approved = capsule(&fixture, Some(&evidence)).expect("approved proposed capsule");
    assert_eq!(approved.execution.capsule.workflow.name, "proposed");
    assert!(!approved.selection.trusted_base_workflow_executed);

    let mut changed = evidence;
    changed.proposed_approval_subject_digest = ContentDigest::sha256(b"substituted subject");
    assert!(matches!(
        capsule(&fixture, Some(&changed)),
        Err(TrustedPlannerError::Source(
            WorkflowSourceError::ApprovalMismatch
        ))
    ));
}

#[test]
fn push_uses_only_the_exact_source_commit_and_rejects_approval() {
    let fixture = Fixture::create(&workflow("source", "microvm"));
    let repository = fixture.repository();
    let push = event(EventType::Push, fixture.source.clone(), None);
    let result = TrustedPlanner::new(&repository)
        .capsule(
            &push,
            WORKFLOW_PATH,
            "installation-1",
            "tenant-1",
            "repo-1",
            "main",
            vec!["policy-v1".to_owned()],
            None,
            &Verifier(true),
            NOW,
        )
        .expect("push capsule");
    assert_eq!(result.execution.capsule.workflow.name, "source");
    assert!(matches!(
        result.proposed_analysis,
        ProposedWorkflowAnalysis::NotApplicable
    ));
    assert_eq!(
        result.execution.capsule.context.source_trust,
        SourceTrust::ProtectedBranch
    );
}

#[test]
fn source_trust_derivation_uses_exact_authenticated_event_and_durable_default() {
    let push = event(EventType::Push, "a".repeat(40), None);
    assert_eq!(
        derive_source_trust(&push, "main").unwrap(),
        SourceTrust::ProtectedBranch
    );

    let mut branch = push.clone();
    branch.source.ref_name = Some("refs/heads/feature".to_owned());
    branch.ref_name = Some("refs/heads/feature".to_owned());
    assert_eq!(
        derive_source_trust(&branch, "main").unwrap(),
        SourceTrust::Trusted
    );

    let pull = event(
        EventType::PullRequest {
            action: PullRequestAction::Synchronize,
        },
        "b".repeat(40),
        Some("c".repeat(40)),
    );
    assert_eq!(
        derive_source_trust(&pull, "main").unwrap(),
        SourceTrust::Untrusted
    );
    let merge = event(EventType::MergeGroup, "d".repeat(40), None);
    assert_eq!(
        derive_source_trust(&merge, "main").unwrap(),
        SourceTrust::Untrusted
    );

    let mut foreign_push = push;
    foreign_push.source.repository_full_name = Some("fork/runtrue".to_owned());
    assert!(matches!(
        derive_source_trust(&foreign_push, "main"),
        Err(TrustedPlannerError::InvalidEvent)
    ));
}

#[test]
fn exact_locked_reusable_sources_are_hydrated_before_trusted_planning() {
    let directory = tempfile::tempdir().expect("tempdir");
    git(directory.path(), &["init", "--quiet"]);
    git(
        directory.path(),
        &["config", "user.email", "planner@runtrue.invalid"],
    );
    git(directory.path(), &["config", "user.name", "Planner Test"]);
    fs::create_dir_all(directory.path().join(".runtrue/workflows")).unwrap();
    let reference = "git+https://github.com/octo/shared.git//ci.yaml@v1";
    let reusable_commit = "a".repeat(40);
    let reusable =
        b"version: 1\njobs:\n  build:\n    steps: [{ run: { command: [\"true\"] } }]\n".to_vec();
    let reusable_digest = ContentDigest::sha256(&reusable);
    fs::write(
        directory.path().join(WORKFLOW_PATH),
        format!("version: 1\njobs:\n  shared:\n    uses: {reference}\n"),
    )
    .unwrap();
    fs::write(
        directory.path().join(DEFAULT_LOCKFILE_PATH),
        format!(
            "lock_version = 1\n[[workflow]]\nsource = \"{reference}\"\ncommit = \"{reusable_commit}\"\ndigest = \"{reusable_digest}\"\n"
        ),
    )
    .unwrap();
    git(directory.path(), &["add", "."]);
    git(directory.path(), &["commit", "--quiet", "-m", "reusable"]);
    let source = output(directory.path(), &["rev-parse", "HEAD"]);
    let repository = GitRepository::open(directory.path(), runtrue_git::GitLimits::default())
        .expect("repository");
    let provider = FixedReusableProvider {
        reference: reference.to_owned(),
        commit: reusable_commit,
        digest: reusable_digest.clone(),
        bytes: reusable.clone(),
    };
    let push = event(EventType::Push, source, None);
    let result = TrustedPlanner::new(&repository)
        .with_reusable_source_provider(&provider)
        .capsule(
            &push,
            WORKFLOW_PATH,
            "installation-1",
            "tenant-1",
            "repo-1",
            "main",
            vec!["policy-v1".to_owned()],
            None,
            &Verifier(true),
            NOW,
        )
        .expect("trusted reusable capsule");
    assert_eq!(result.execution.capsule.jobs[0].id, "shared__build");
    assert_eq!(
        result.execution.approval_subject.reusable_workflow_digests,
        vec![reusable_digest.to_string()]
    );

    let tampered = FixedReusableProvider {
        bytes: b"tampered".to_vec(),
        ..provider
    };
    assert!(matches!(
        TrustedPlanner::new(&repository)
            .with_reusable_source_provider(&tampered)
            .capsule(
                &push,
                WORKFLOW_PATH,
                "installation-1",
                "tenant-1",
                "repo-1",
                "main",
                vec!["policy-v1".to_owned()],
                None,
                &Verifier(true),
                NOW,
            ),
        Err(TrustedPlannerError::ReusableSource(
            ReusableWorkflowProviderError::DigestMismatch
        ))
    ));
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .status()
        .expect("git");
    assert!(status.success(), "git {arguments:?}");
}

fn output(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git");
    assert!(output.status.success(), "git {arguments:?}");
    String::from_utf8(output.stdout)
        .expect("UTF-8")
        .trim()
        .to_owned()
}
