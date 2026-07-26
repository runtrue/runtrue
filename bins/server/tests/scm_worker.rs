use runtrue_control_plane::{
    ControlPlane, DurableTask, DurableTaskStatus, RepositoryRecord, ScmCheckPublicationState,
    ScmCheckPublishTask, ScmInstallationRecord, ScmRepositoryLinkRecord, ScmSourceFetchState,
    SCM_EVENT_RECOVERY_WINDOW_MS,
};
#[cfg(any())]
use runtrue_control_plane::{
    GitHubAccountKind as ControlPlaneGitHubAccountKind, GitHubInstallationRecord,
    GitHubRepositorySelection as ControlPlaneGitHubRepositorySelection,
    ReconcileGitHubInstallation, TenantIdentityRecord,
};
use runtrue_git::{GitLimits, GitRepository};
use runtrue_model::ContentDigest;
#[cfg(any())]
use runtrue_policy::{ApprovalDecision, ApprovalKind, ApprovalStatus, Decision};
use runtrue_scm::{
    ActorIdentity, CheckRunRequest, EventEnvelope, EventType, GitRevision, ProviderKind,
    PullRequestAction, PullRequestEvent, RepositoryIdentity,
};
#[cfg(any())]
use runtrue_scm::{
    GitHubAccount, GitHubAccountKind, GitHubError, GitHubInstallationProvider,
    GitHubInstallationRepository, GitHubInstallationSnapshot, GitHubPermission,
    GitHubPermissionLevel, GitHubProviderEndpoints, GitHubRepositorySelection,
    GitHubRepositoryVisibility,
};
#[cfg(any())]
use runtrue_scm::{IssueCommentAction, IssueCommentEvent};
use runtrue_server::{
    AppState, FetchedScmRepository, GitHubCheckPublisher, PublishedScmCheck, ScmCheckPublishError,
    ScmSourceFetchError, ScmSourceFetchRequest, ScmSourceFetcher, ScmWorkerConfig, ScmWorkerTick,
};
#[cfg(any())]
use runtrue_server::{
    GitHubRepositoryActionResolver, PreparedRepositoryAction, RepositoryActionBuildRequest,
    RepositoryActionBuilder, RepositoryActionResolveError, RepositoryActionResolver,
};
#[cfg(any())]
use runtrue_workflow_frontend::{
    ResolvedProgram, ResolvedProgramRef, ResolvedSourceAction, SourceActionResolutionRequest,
    WorkflowSourceFrontend,
};
use runtrue_workflow_ir::{ExecutionCapsule, Isolation};
#[cfg(any())]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

const NOW: u64 = 100_000;
const DEFAULT_TEST_WORKFLOW_PATH: &str = ".runtrue/workflows/ci.yaml";

struct MirrorFixture {
    _root: TempDir,
    root: PathBuf,
    base: String,
    source: String,
}

#[derive(Debug)]
struct FixtureSourceFetcher {
    repository: PathBuf,
    requests: Arc<Mutex<Vec<ScmSourceFetchRequest>>>,
}

#[derive(Debug)]
struct UnavailableSourceFetcher;

#[derive(Debug)]
#[cfg(any())]
struct FixtureRepositoryActionResolver {
    requests: Mutex<Vec<(String, String, String)>>,
    image: String,
    available: AtomicBool,
}

#[cfg(any())]
#[derive(Debug)]
struct RecoveringRepositoryActionResolver {
    available: AtomicBool,
    requests: Mutex<Vec<String>>,
    image: String,
}

#[cfg(any())]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedRepositoryActionBuild {
    tenant_id: String,
    repository_id: String,
    reference: String,
    commit: String,
    metadata_digest: ContentDigest,
    dockerfile: String,
    dockerfile_bytes: Vec<u8>,
}

#[cfg(any())]
#[derive(Debug)]
struct FixtureRepositoryActionBuilder {
    requests: Mutex<Vec<RecordedRepositoryActionBuild>>,
    image: String,
}

#[cfg(any())]
#[derive(Debug)]
struct FixtureGitHubInstallationProvider {
    snapshots: Vec<GitHubInstallationSnapshot>,
}

#[cfg(any())]
impl GitHubInstallationProvider for FixtureGitHubInstallationProvider {
    fn inspect_installation(
        &self,
        installation_id: u64,
        _now_unix_seconds: u64,
    ) -> Result<GitHubInstallationSnapshot, GitHubError> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.installation_id == installation_id)
            .cloned()
            .ok_or(GitHubError::InvalidInstallation)
    }
}

#[cfg(any())]
impl RepositoryActionBuilder for FixtureRepositoryActionBuilder {
    fn build(
        &self,
        request: RepositoryActionBuildRequest<'_>,
    ) -> Result<String, RepositoryActionResolveError> {
        let dockerfile = request
            .repository
            .read_blob(request.commit, request.dockerfile)
            .map_err(|_| RepositoryActionResolveError::Rejected)?;
        self.requests
            .lock()
            .unwrap()
            .push(RecordedRepositoryActionBuild {
                tenant_id: request.tenant_id.to_owned(),
                repository_id: request.repository_id.to_owned(),
                reference: request.reference.to_owned(),
                commit: request.commit.to_owned(),
                metadata_digest: request.metadata_digest.clone(),
                dockerfile: request.dockerfile.to_owned(),
                dockerfile_bytes: dockerfile.bytes,
            });
        Ok(self.image.clone())
    }
}

#[cfg(any())]
impl RepositoryActionResolver for FixtureRepositoryActionResolver {
    fn resolve(
        &self,
        tenant_id: &str,
        installation_id: &str,
        request: &SourceActionResolutionRequest,
        _frontend: &dyn WorkflowSourceFrontend,
    ) -> Result<PreparedRepositoryAction, RepositoryActionResolveError> {
        let reference = request.source_reference();
        if !self.available.load(Ordering::SeqCst) {
            return Err(RepositoryActionResolveError::Unavailable);
        }
        self.requests.lock().unwrap().push((
            tenant_id.to_owned(),
            installation_id.to_owned(),
            reference.to_owned(),
        ));
        Ok(PreparedRepositoryAction {
            reference: reference.to_owned(),
            action: ResolvedSourceAction::new(
                ResolvedProgram::container(self.image.clone(), None, None).unwrap(),
            ),
            metadata_digest: ContentDigest::sha256(b"exact action.yml"),
        })
    }
}

#[cfg(any())]
impl RepositoryActionResolver for RecoveringRepositoryActionResolver {
    fn resolve(
        &self,
        _tenant_id: &str,
        _installation_id: &str,
        request: &SourceActionResolutionRequest,
        _frontend: &dyn WorkflowSourceFrontend,
    ) -> Result<PreparedRepositoryAction, RepositoryActionResolveError> {
        let reference = request.source_reference().to_owned();
        self.requests.lock().unwrap().push(reference.clone());
        if !self.available.load(Ordering::Relaxed) {
            return Err(RepositoryActionResolveError::Unavailable);
        }
        Ok(PreparedRepositoryAction {
            reference,
            action: ResolvedSourceAction::new(
                ResolvedProgram::container(self.image.clone(), None, None).unwrap(),
            ),
            metadata_digest: ContentDigest::sha256(b"recovered exact action.yml"),
        })
    }
}

#[derive(Debug)]
struct FixtureCheckPublisher {
    outcomes: Mutex<VecDeque<Result<PublishedScmCheck, ScmCheckPublishError>>>,
    requests: Mutex<Vec<CheckRunRequest>>,
}

impl GitHubCheckPublisher for FixtureCheckPublisher {
    fn reconcile_or_publish(
        &self,
        _installation: &ScmInstallationRecord,
        _repository: &ScmRepositoryLinkRecord,
        request: &CheckRunRequest,
    ) -> Result<PublishedScmCheck, ScmCheckPublishError> {
        self.requests.lock().unwrap().push(request.clone());
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(ScmCheckPublishError::Unavailable))
    }
}

impl ScmSourceFetcher for UnavailableSourceFetcher {
    fn fetch(
        &self,
        _request: &ScmSourceFetchRequest,
    ) -> Result<FetchedScmRepository, ScmSourceFetchError> {
        Err(ScmSourceFetchError::Unavailable)
    }
}

impl ScmSourceFetcher for FixtureSourceFetcher {
    fn resolve_default_branch_head(
        &self,
        _request: &ScmSourceFetchRequest,
        _default_branch: &str,
    ) -> Result<String, ScmSourceFetchError> {
        Ok(output(&self.repository, &["rev-parse", "HEAD"]))
    }

    fn fetch(
        &self,
        request: &ScmSourceFetchRequest,
    ) -> Result<FetchedScmRepository, ScmSourceFetchError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(FetchedScmRepository {
            repository: GitRepository::open(&self.repository, GitLimits::default())
                .map_err(|_| ScmSourceFetchError::Unavailable)?,
            token_scope_digest: ContentDigest::sha256(b"exact repository-read token scope"),
            mirror_identity_digest: ContentDigest::sha256(format!(
                "{}:{}",
                request.tenant_id, request.repository_id
            )),
        })
    }
}

impl MirrorFixture {
    fn pull_request(proposed: &[u8]) -> Self {
        let root = tempfile::tempdir().expect("mirror root");
        secure_mode(root.path());
        let repository = root.path().join("octo").join("runtrue");
        fs::create_dir_all(&repository).expect("repository path");
        secure_mode(&root.path().join("octo"));
        secure_mode(&repository);
        git(&repository, &["init", "--quiet"]);
        git(
            &repository,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository, &["config", "user.name", "SCM Worker Test"]);
        fs::create_dir_all(repository.join(".runtrue/workflows")).expect("workflow directory");
        fs::write(
            repository.join(DEFAULT_TEST_WORKFLOW_PATH),
            workflow("trusted-base", "microvm"),
        )
        .expect("base workflow");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "base"]);
        let base = output(&repository, &["rev-parse", "HEAD"]);

        fs::write(repository.join(DEFAULT_TEST_WORKFLOW_PATH), proposed)
            .expect("proposed workflow");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "proposed"]);
        let source = output(&repository, &["rev-parse", "HEAD"]);
        Self {
            root: root.path().to_owned(),
            _root: root,
            base,
            source,
        }
    }

    fn push() -> Self {
        Self::pull_request(&workflow("source", "microvm"))
    }

    fn lockfile_only_pull_request() -> Self {
        let root = tempfile::tempdir().expect("mirror root");
        secure_mode(root.path());
        let repository = root.path().join("octo").join("runtrue");
        fs::create_dir_all(repository.join(".runtrue/workflows")).expect("workflow directory");
        secure_mode(&root.path().join("octo"));
        secure_mode(&repository);
        git(&repository, &["init", "--quiet"]);
        git(
            &repository,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository, &["config", "user.name", "SCM Worker Test"]);
        fs::write(
            repository.join(DEFAULT_TEST_WORKFLOW_PATH),
            b"version: 1\nname: unchanged\non:\n  pull_request: {}\njobs:\n  build:\n    runner:\n      isolation: oci\n      image: containers.example/tool:1\n    steps:\n      - run:\n          command: [\"true\"]\n",
        )
        .expect("workflow");
        fs::write(
            repository.join(".runtrue.lock"),
            format!(
                "lock_version = 1\n\n[[image]]\nsource = \"containers.example/tool:1\"\nresolved = \"containers.example/tool@sha256:{}\"\nplatform = \"linux/amd64\"\n",
                "a".repeat(64)
            ),
        )
        .expect("base lockfile");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "base"]);
        let base = output(&repository, &["rev-parse", "HEAD"]);
        fs::write(
            repository.join(".runtrue.lock"),
            format!(
                "lock_version = 1\n\n[[image]]\nsource = \"containers.example/tool:1\"\nresolved = \"containers.example/tool@sha256:{}\"\nplatform = \"linux/amd64\"\n",
                "b".repeat(64)
            ),
        )
        .expect("proposed lockfile");
        git(&repository, &["add", ".runtrue.lock"]);
        git(&repository, &["commit", "--quiet", "-m", "update lockfile"]);
        let source = output(&repository, &["rev-parse", "HEAD"]);
        Self {
            root: root.path().to_owned(),
            _root: root,
            base,
            source,
        }
    }

    #[cfg(any())]
    fn github_actions_pull_request() -> Self {
        let root = tempfile::tempdir().expect("mirror root");
        secure_mode(root.path());
        let repository = root.path().join("octo").join("runtrue");
        fs::create_dir_all(repository.join(".github/workflows")).expect("workflow directory");
        secure_mode(&root.path().join("octo"));
        secure_mode(&repository);
        git(&repository, &["init", "--quiet"]);
        git(
            &repository,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository, &["config", "user.name", "SCM Worker Test"]);
        let workflow_path = ".github/workflows/ci.yml";
        fs::write(
            repository.join(workflow_path),
            "name: CI\non: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo base\n",
        )
        .expect("base workflow");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "base"]);
        let base = output(&repository, &["rev-parse", "HEAD"]);
        fs::write(
            repository.join(workflow_path),
            "name: CI\non: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo proposed\n",
        )
        .expect("proposed workflow");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "proposed"]);
        let source = output(&repository, &["rev-parse", "HEAD"]);
        Self {
            root: root.path().to_owned(),
            _root: root,
            base,
            source,
        }
    }

    #[cfg(any())]
    fn repository_action_pull_request(reference: &str) -> Self {
        Self::repository_action_pull_request_with_access(reference, "read")
    }

    #[cfg(any())]
    fn privileged_repository_action_pull_request(reference: &str) -> Self {
        Self::repository_action_pull_request_with_access(reference, "write")
    }

    #[cfg(any())]
    fn repository_action_pull_request_with_access(reference: &str, contents: &str) -> Self {
        let root = tempfile::tempdir().expect("mirror root");
        secure_mode(root.path());
        let repository = root.path().join("octo").join("runtrue");
        fs::create_dir_all(repository.join(".github/workflows")).expect("workflow directory");
        secure_mode(&root.path().join("octo"));
        secure_mode(&repository);
        git(&repository, &["init", "--quiet"]);
        git(
            &repository,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository, &["config", "user.name", "SCM Worker Test"]);
        let workflow_path = ".github/workflows/backport.yml";
        fs::write(
            repository.join(workflow_path),
            format!(
                "name: Backport\non: [pull_request]\npermissions:\n  contents: {contents}\njobs:\n  reconcile:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: {reference}\n        with:\n          config-path: .github/backport.yml\n"
            ),
        )
        .expect("workflow");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "base"]);
        let base = output(&repository, &["rev-parse", "HEAD"]);
        fs::write(repository.join("change.txt"), b"change\n").expect("source change");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "source"]);
        let source = output(&repository, &["rev-parse", "HEAD"]);
        Self {
            root: root.path().to_owned(),
            _root: root,
            base,
            source,
        }
    }

    fn multi_push() -> Self {
        let root = tempfile::tempdir().expect("mirror root");
        secure_mode(root.path());
        let repository = root.path().join("octo").join("runtrue");
        fs::create_dir_all(repository.join(".runtrue/workflows")).expect("workflow directory");
        secure_mode(&root.path().join("octo"));
        secure_mode(&repository);
        git(&repository, &["init", "--quiet"]);
        git(
            &repository,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository, &["config", "user.name", "SCM Worker Test"]);
        fs::write(
            repository.join(DEFAULT_TEST_WORKFLOW_PATH),
            workflow("primary", "microvm"),
        )
        .expect("primary workflow");
        fs::write(
            repository.join(".runtrue/workflows/smoke.yaml"),
            workflow("smoke", "microvm"),
        )
        .expect("smoke workflow");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "workflows"]);
        let base = output(&repository, &["rev-parse", "HEAD"]);
        fs::write(repository.join("source.txt"), b"source\n").expect("source file");
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "source"]);
        let source = output(&repository, &["rev-parse", "HEAD"]);
        Self {
            root: root.path().to_owned(),
            _root: root,
            base,
            source,
        }
    }

    #[cfg(any())]
    fn interaction() -> (Self, String) {
        let root = tempfile::tempdir().expect("mirror root");
        secure_mode(root.path());
        let repository = root.path().join("octo").join("runtrue");
        fs::create_dir_all(&repository).expect("repository path");
        secure_mode(&root.path().join("octo"));
        secure_mode(&repository);
        git(&repository, &["init", "--quiet"]);
        git(
            &repository,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository, &["config", "user.name", "SCM Worker Test"]);
        let workflow_path = ".runtrue/workflows/interaction.github.yml";
        fs::create_dir_all(repository.join(".runtrue/workflows")).expect("workflow directory");
        fs::write(
            repository.join(workflow_path),
            format!(
                "name: Interaction action\non:\n  issue_comment:\n    types: [created, edited]\npermissions:\n  contents: write\n  pull-requests: write\n  issues: write\n  checks: read\njobs:\n  reconcile:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: docker://containers.example/actions/interaction@sha256:{}\n",
                "a".repeat(64)
            ),
        )
        .expect("interaction workflow");
        git(&repository, &["add", "."]);
        git(
            &repository,
            &["commit", "--quiet", "-m", "interaction workflow"],
        );
        let source = output(&repository, &["rev-parse", "HEAD"]);
        (
            Self {
                root: root.path().to_owned(),
                _root: root,
                base: source.clone(),
                source,
            },
            workflow_path.to_owned(),
        )
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

    fn push_event(&self) -> EventEnvelope {
        event(
            EventType::Push,
            self.source.clone(),
            Some(self.base.clone()),
        )
    }
}

fn setup(root: &Path, worker_id: &str) -> (Arc<ControlPlane>, AppState, ScmWorkerConfig) {
    let control_plane = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    register_repository(&control_plane);
    let state = test_state(Arc::clone(&control_plane));
    let mut config = ScmWorkerConfig::new(root, worker_id);
    config.max_attempts = 2;
    config.retry_base = Duration::from_millis(10);
    config.retry_max = Duration::from_millis(20);
    (control_plane, state, config)
}

fn register_repository(control_plane: &ControlPlane) {
    control_plane
        .create_repository(&RepositoryRecord {
            id: "repo-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            owner: "octo".to_owned(),
            name: "runtrue".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: 1,
        })
        .unwrap();
}

fn register_github_link(control_plane: &ControlPlane) {
    control_plane
        .create_scm_installation(&ScmInstallationRecord {
            id: "github-installation-record-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            provider: "github".to_owned(),
            external_id: "9001".to_owned(),
            credential_reference: "provider://github-app/installations/1".to_owned(),
            permissions: serde_json::json!({
                "checks": "write",
                "contents": "read",
                "metadata": "read",
                "pull_requests": "read"
            }),
            status: "active".to_owned(),
            created_unix_ms: 1,
            updated_unix_ms: 1,
        })
        .unwrap();
    control_plane
        .link_scm_repository(&ScmRepositoryLinkRecord {
            repository_id: "repo-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            installation_id: "github-installation-record-1".to_owned(),
            external_repository_id: "42".to_owned(),
            clone_url: "https://github.com/octo/runtrue.git".to_owned(),
            status: "active".to_owned(),
            created_unix_ms: 1,
            updated_unix_ms: 1,
        })
        .unwrap();
}

fn test_state(control_plane: Arc<ControlPlane>) -> AppState {
    AppState::new_with_security_seed(
        control_plane,
        "bootstrap-token",
        None,
        [9_u8; 32],
        "https://runtrue.invalid/oidc".to_owned(),
    )
    .unwrap()
}

#[test]
fn duplicate_delivery_and_worker_restart_create_exactly_one_remote_run() {
    let fixture = MirrorFixture::push();
    let database_directory = tempfile::tempdir().unwrap();
    secure_mode(database_directory.path());
    let database = database_directory.path().join("control-plane.sqlite");
    let control_plane = Arc::new(ControlPlane::open(&database, "installation-1", 1).unwrap());
    register_repository(&control_plane);
    let state = test_state(Arc::clone(&control_plane));
    let event = fixture.push_event();
    enqueue(&control_plane, "event-first", &event, NOW);
    let worker = state
        .scm_task_worker(ScmWorkerConfig::new(&fixture.root, "worker-first"))
        .unwrap();
    let first = worker.process_once_at(NOW).unwrap();
    let first_run = completed_run(first, false);
    drop(worker);
    drop(state);
    drop(control_plane);

    // Reopen the durable database and replay the exact normalized event under
    // a second task ID, covering both process restart and duplicate delivery.
    let control_plane = Arc::new(
        ControlPlane::open(&database, "installation-1", NOW + 1).expect("reopen database"),
    );
    let state = test_state(Arc::clone(&control_plane));
    enqueue(&control_plane, "event-after-restart", &event, NOW + 1);
    let restarted = state
        .scm_task_worker(ScmWorkerConfig::new(&fixture.root, "worker-restarted"))
        .unwrap();
    let replay = restarted.process_once_at(NOW + 1).unwrap();
    let replayed_run = completed_run(replay, true);
    assert_eq!(replayed_run, first_run);

    let runs = control_plane
        .list_runs_page(Some("repo-1"), None, 100)
        .unwrap();
    assert_eq!(runs.len(), 1);
    assert!(runs[0].remote);
    assert_eq!(control_plane.jobs_for_run(&first_run).unwrap().len(), 1);
    assert_eq!(
        control_plane.task("event-after-restart").unwrap().status,
        DurableTaskStatus::Completed
    );
}

#[test]
fn trusted_workflow_discovery_fans_out_independent_idempotent_runs() {
    let fixture = MirrorFixture::multi_push();
    let control = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    register_repository(&control);
    let state = test_state(Arc::clone(&control));
    let event = fixture.push_event();
    enqueue(&control, "event-multi", &event, NOW);
    let worker = state
        .scm_task_worker(ScmWorkerConfig::new(&fixture.root, "multi-worker"))
        .unwrap();

    assert!(matches!(
        worker.process_once_at(NOW).unwrap(),
        ScmWorkerTick::Completed { run_id: None, .. }
    ));
    let first_tick = worker.process_once_at(NOW + 1).unwrap();
    if let ScmWorkerTick::Failed { task_id, .. } = &first_tick {
        panic!(
            "first workflow failed: {:?}",
            control.task(task_id).unwrap()
        );
    }
    let first = completed_run(first_tick, false);
    let second_tick = worker.process_once_at(NOW + 2).unwrap();
    if let ScmWorkerTick::Failed { task_id, .. } = &second_tick {
        panic!(
            "second workflow failed: {:?}",
            control.task(task_id).unwrap()
        );
    }
    let second = completed_run(second_tick, false);
    assert_ne!(first, second);

    let runs = control.list_runs_page(Some("repo-1"), None, 10).unwrap();
    assert_eq!(runs.len(), 2);
    let mut paths = runs
        .iter()
        .map(|run| {
            let capsule = control.signed_capsule(&run.capsule_id).unwrap();
            serde_json::from_slice::<ExecutionCapsule>(&capsule.canonical_capsule)
                .unwrap()
                .workflow
                .source_path
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            ".runtrue/workflows/ci.yaml".to_owned(),
            ".runtrue/workflows/smoke.yaml".to_owned(),
        ]
    );

    enqueue(&control, "event-multi-replay", &event, NOW + 3);
    assert!(matches!(
        worker.process_once_at(NOW + 3).unwrap(),
        ScmWorkerTick::Completed { run_id: None, .. }
    ));
    assert!(matches!(
        worker.process_once_at(NOW + 4).unwrap(),
        ScmWorkerTick::Idle
    ));
    assert_eq!(
        control
            .list_runs_page(Some("repo-1"), None, 10)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn repository_workflow_directory_overrides_the_server_default() {
    let fixture = MirrorFixture::push();
    let control = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    register_repository(&control);
    control
        .set_repository_workflow_directory("tenant-1", "repo-1", ".runtrue/workflows", NOW)
        .unwrap();
    let state = test_state(Arc::clone(&control));
    enqueue(
        &control,
        "event-repository-workflow",
        &fixture.push_event(),
        NOW,
    );
    let mut config = ScmWorkerConfig::new(&fixture.root, "repository-workflow-worker");
    config.workflow_directory = "server/default/does-not-exist".to_owned();
    let worker = state.scm_task_worker(config).unwrap();

    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);
    let run = control.run(&run_id).unwrap();
    let capsule = control.signed_capsule(&run.capsule_id).unwrap();
    let decoded: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule).unwrap();
    assert_eq!(decoded.workflow.source_path, ".runtrue/workflows/ci.yaml");
}

#[test]
fn authenticated_github_fetch_builds_and_atomically_binds_exact_source_snapshot() {
    let fixture = MirrorFixture::push();
    let database_directory = tempfile::tempdir().unwrap();
    secure_mode(database_directory.path());
    let database = database_directory.path().join("control-plane.sqlite");
    let control_plane = Arc::new(ControlPlane::open(&database, "installation-1", 1).unwrap());
    register_repository(&control_plane);
    register_github_link(&control_plane);
    let data_root = database_directory.path().join("objects");
    let state = test_state(Arc::clone(&control_plane))
        .with_runner_data_plane(&data_root)
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests: Arc::clone(&requests),
    });
    let mut event = fixture.push_event();
    event.installation_id = "9001".to_owned();
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    enqueue(&control_plane, "event-authenticated-fetch", &event, NOW);
    let mirror_manager_root = database_directory.path().join("managed-mirrors");
    let worker = state
        .scm_task_worker_with_source_fetcher(
            ScmWorkerConfig::new(&mirror_manager_root, "github-fetch-worker"),
            fetcher,
        )
        .unwrap();
    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);

    let seen = requests.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].installation.external_id, "9001");
    assert_eq!(seen[0].repository.external_repository_id, "42");
    assert_eq!(seen[0].source_commit, fixture.source);
    drop(seen);

    let run = control_plane.run(&run_id).unwrap();
    let capsule = control_plane.signed_capsule(&run.capsule_id).unwrap();
    let decoded: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule).unwrap();
    let tree_digest = decoded
        .context
        .source_tree_digest
        .clone()
        .expect("authenticated source digest is signed into the capsule");
    let binding = control_plane
        .run_source_snapshot("tenant-1", &run_id)
        .unwrap();
    let snapshot = control_plane
        .source_snapshot("tenant-1", &binding.source_snapshot_id)
        .unwrap();
    assert_eq!(snapshot.commit_sha, fixture.source);
    assert_eq!(snapshot.tree_manifest_digest, tree_digest);
    assert_eq!(binding.capsule_digest, capsule.digest);
    assert_eq!(
        control_plane
            .job(&control_plane.jobs_for_run(&run_id).unwrap()[0].id)
            .unwrap()
            .status,
        runtrue_lifecycle::JobState::Queued
    );

    let task = control_plane.task("event-authenticated-fetch").unwrap();
    let fetch = control_plane
        .scm_source_fetch_for_task("tenant-1", "event-authenticated-fetch")
        .unwrap();
    let fetch_id = fetch.id.clone();
    assert_eq!(fetch.state, ScmSourceFetchState::Committed);
    assert_eq!(fetch.origin_task_id, task.id);
    assert!(fetch.token_scope_digest.is_some());
    let audit = control_plane.audit_events().unwrap();
    let source_audit = audit
        .iter()
        .find(|event| event.data.action == "scm.source-fetch.commit")
        .expect("source fetch audit event");
    assert_eq!(source_audit.data.tenant_id, "tenant-1");
    assert_eq!(source_audit.data.resource.id, fetch_id);
    assert!(!serde_json::to_string(source_audit)
        .unwrap()
        .contains("installation-token"));
    drop(control_plane);

    let reopened = ControlPlane::open(&database, "installation-1", NOW + 1).unwrap();
    let durable = reopened.run_source_snapshot("tenant-1", &run_id).unwrap();
    assert_eq!(durable, binding);
    assert_eq!(
        reopened
            .scm_source_fetch("tenant-1", &fetch_id)
            .unwrap()
            .state,
        ScmSourceFetchState::Committed
    );
}

#[cfg(any())]
#[test]
fn issue_comment_gate_reuses_the_trusted_default_revision_through_continuation() {
    let (fixture, workflow_path) = MirrorFixture::interaction();
    let directory = tempfile::tempdir().unwrap();
    secure_mode(directory.path());
    let control = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    register_repository(&control);
    register_github_link(&control);
    let state = test_state(Arc::clone(&control))
        .with_runner_data_plane(directory.path().join("objects"))
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests: Arc::clone(&requests),
    });
    let mut event = event(
        EventType::IssueComment {
            action: IssueCommentAction::Edited,
        },
        "0".repeat(40),
        None,
    );
    event.installation_id = "9001".to_owned();
    event.issue_comment = Some(IssueCommentEvent {
        issue_number: 17,
        issue_is_pull_request: true,
        comment_id: 99,
        body: "- [x] Run the interaction action".to_owned(),
        previous_body: Some("- [ ] Run the interaction action".to_owned()),
    });
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    enqueue(&control, "event-issue-comment", &event, NOW);
    let mut config = ScmWorkerConfig::new(directory.path().join("mirrors"), "comment-worker");
    config.workflow_directory = workflow_path.rsplit_once('/').unwrap().0.to_owned();
    let worker = state
        .scm_task_worker_with_source_fetcher(config, fetcher)
        .unwrap();
    assert!(matches!(
        worker.process_once_at(NOW).unwrap(),
        ScmWorkerTick::Completed {
            run_id: None,
            replayed: false,
            ..
        }
    ));

    let approvals = control
        .list_approval_requests_page(Some("pending"), None, 10)
        .unwrap();
    assert_eq!(approvals.len(), 1);
    let approval = &approvals[0];
    control
        .decide_approval_idempotent(
            "approve-comment-action",
            &approval.id,
            ApprovalDecision {
                actor_id: "bootstrap".to_owned(),
                decision: Decision::Approve,
                reason: "approve exact trusted interaction action".to_owned(),
                rule_id: "bootstrap-security-review".to_owned(),
                subject_digest: approval.subject_digest.clone(),
                decided_unix_ms: NOW + 1,
            },
            NOW + 1,
        )
        .unwrap();
    let run_id = completed_run(worker.process_once_at(NOW + 2).unwrap(), false);
    let run = control.run(&run_id).unwrap();
    let capsule = control.signed_capsule(&run.capsule_id).unwrap();
    let decoded: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule).unwrap();
    assert_eq!(decoded.context.source_commit, fixture.source);
    assert_ne!(decoded.context.source_commit, event.source.commit);
    assert_eq!(
        control
            .run_source_snapshot("tenant-1", &run_id)
            .unwrap()
            .source_snapshot_id,
        control
            .scm_source_fetch_for_task("tenant-1", "event-issue-comment")
            .unwrap()
            .source_snapshot_id
            .unwrap()
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.source_commit == fixture.source));
}

#[test]
fn github_check_rate_limit_survives_restart_and_reconciles_lost_create_response() {
    let fixture = MirrorFixture::push();
    let directory = tempfile::tempdir().unwrap();
    secure_mode(directory.path());
    let database = directory.path().join("checks.sqlite");
    let data_root = directory.path().join("objects");
    let mirror_root = directory.path().join("mirrors");
    let control = Arc::new(ControlPlane::open(&database, "installation-1", 1).unwrap());
    register_repository(&control);
    register_github_link(&control);
    let mut event = fixture.push_event();
    event.installation_id = "9001".to_owned();
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    enqueue(&control, "event-check-publication", &event, NOW);
    let state = test_state(Arc::clone(&control))
        .with_runner_data_plane(&data_root)
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests,
    });
    let first_publisher = Arc::new(FixtureCheckPublisher {
        outcomes: Mutex::new(VecDeque::from([Err(ScmCheckPublishError::RateLimited(17))])),
        requests: Mutex::new(Vec::new()),
    });
    let mut config = ScmWorkerConfig::new(&mirror_root, "check-before-restart");
    config.retry_base = Duration::from_millis(10);
    config.retry_max = Duration::from_secs(30);
    let worker = state
        .scm_task_worker_with_adapters(config, fetcher, first_publisher)
        .unwrap();
    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);
    let (check_task_id, retry_at) = match worker.process_once_at(NOW).unwrap() {
        ScmWorkerTick::Retried {
            task_id,
            retry_at_unix_ms,
            ..
        } => (task_id, retry_at_unix_ms),
        other => panic!("expected durable check retry, got {other:?}"),
    };
    assert_eq!(retry_at, NOW + 17_000);
    assert_eq!(worker.metrics().check_rate_limits, 1);
    let payload: ScmCheckPublishTask =
        serde_json::from_value(control.task(&check_task_id).unwrap().payload).unwrap();
    let reserved = control
        .scm_check_publication("tenant-1", &payload.publication_id)
        .unwrap();
    assert_eq!(reserved.state, ScmCheckPublicationState::Reconciling);
    assert_eq!(reserved.provider_check_run_id, None);
    drop(worker);
    drop(state);
    drop(control);

    let control = Arc::new(ControlPlane::open(&database, "installation-1", retry_at).unwrap());
    let state = test_state(Arc::clone(&control))
        .with_runner_data_plane(&data_root)
        .unwrap();
    let second_publisher = Arc::new(FixtureCheckPublisher {
        outcomes: Mutex::new(VecDeque::from([Ok(PublishedScmCheck {
            provider_check_run_id: 77,
            confirmed_annotations: 0,
            reconciled: true,
        })])),
        requests: Mutex::new(Vec::new()),
    });
    let observed = Arc::clone(&second_publisher);
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests: Arc::new(Mutex::new(Vec::new())),
    });
    let worker = state
        .scm_task_worker_with_adapters(
            ScmWorkerConfig::new(&mirror_root, "check-after-restart"),
            fetcher,
            second_publisher,
        )
        .unwrap();
    assert!(matches!(
        worker.process_once_at(retry_at).unwrap(),
        ScmWorkerTick::Completed {
            task_id,
            run_id: Some(completed_run),
            replayed: true,
        } if task_id == check_task_id && completed_run == run_id
    ));
    let published = control
        .scm_check_publication("tenant-1", &payload.publication_id)
        .unwrap();
    assert_eq!(published.state, ScmCheckPublicationState::Published);
    assert_eq!(published.provider_check_run_id, Some(77));
    assert_eq!(published.attempts, 2);
    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].head_sha, fixture.source);
    assert!(requests[0]
        .external_id
        .starts_with(&format!("runtrue:{run_id}:job:")));
    assert_eq!(requests[0].repository_id, 42);
    assert_eq!(worker.metrics().check_reconciliations, 1);
}

#[test]
fn completed_job_reconciles_the_same_github_check_with_detailed_status() {
    let fixture = MirrorFixture::push();
    let directory = tempfile::tempdir().unwrap();
    secure_mode(directory.path());
    let control = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    register_repository(&control);
    register_github_link(&control);
    let mut event = fixture.push_event();
    event.installation_id = "9001".to_owned();
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    enqueue(&control, "event-terminal-check", &event, NOW);
    let state = test_state(Arc::clone(&control))
        .with_runner_data_plane(directory.path().join("objects"))
        .unwrap();
    let publisher = Arc::new(FixtureCheckPublisher {
        outcomes: Mutex::new(VecDeque::from([
            Ok(PublishedScmCheck {
                provider_check_run_id: 88,
                confirmed_annotations: 0,
                reconciled: false,
            }),
            Ok(PublishedScmCheck {
                provider_check_run_id: 88,
                confirmed_annotations: 0,
                reconciled: true,
            }),
        ])),
        requests: Mutex::new(Vec::new()),
    });
    let observed = Arc::clone(&publisher);
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests: Arc::new(Mutex::new(Vec::new())),
    });
    let worker = state
        .scm_task_worker_with_adapters(
            ScmWorkerConfig::new(directory.path().join("mirrors"), "terminal-check-worker"),
            fetcher,
            publisher,
        )
        .unwrap();
    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);
    assert!(matches!(
        worker.process_once_at(NOW + 1).unwrap(),
        ScmWorkerTick::Completed { .. }
    ));

    control
        .transition_run_state(&run_id, runtrue_lifecycle::RunState::Running, NOW + 2)
        .unwrap();
    let job = control.jobs_for_run(&run_id).unwrap().remove(0);
    for (offset, status) in [
        runtrue_lifecycle::JobState::Preparing,
        runtrue_lifecycle::JobState::Running,
        runtrue_lifecycle::JobState::Finalizing,
        runtrue_lifecycle::JobState::Succeeded,
    ]
    .into_iter()
    .enumerate()
    {
        control
            .transition_job_state(&job.id, status, NOW + 3 + offset as u64)
            .unwrap();
    }
    assert!(matches!(
        worker.process_once_at(NOW + 10).unwrap(),
        ScmWorkerTick::Completed { .. }
    ));

    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].status, runtrue_scm::CheckStatus::Queued);
    assert_eq!(requests[1].status, runtrue_scm::CheckStatus::Completed);
    assert_eq!(
        requests[1].conclusion,
        Some(runtrue_scm::CheckConclusion::Success)
    );
    assert_eq!(requests[0].external_id, requests[1].external_id);
    assert_eq!(requests[0].head_sha, requests[1].head_sha);
    assert!(requests[1]
        .summary
        .contains(&format!("| **Run** | `{run_id}` |")));
    assert!(requests[1].summary.contains("attempt 1"));
    assert!(requests[1].summary.contains("**succeeded**"));
    assert!(requests[1].summary.contains("<strong>Logs</strong>"));
    assert!(requests[1].render_markdown);
}

#[test]
fn github_repository_mismatch_is_rejected_before_fetch_or_existence_disclosure() {
    let fixture = MirrorFixture::push();
    let directory = tempfile::tempdir().unwrap();
    secure_mode(directory.path());
    let control_plane = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    register_repository(&control_plane);
    register_github_link(&control_plane);
    let state = test_state(Arc::clone(&control_plane))
        .with_runner_data_plane(directory.path().join("objects"))
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests: Arc::clone(&requests),
    });
    let mut event = fixture.push_event();
    event.installation_id = "9001".to_owned();
    event.repository.external_id = "cross-tenant-or-absent".to_owned();
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    enqueue(&control_plane, "event-mismatched-link", &event, NOW);
    let mut config = ScmWorkerConfig::new(directory.path().join("mirrors"), "mismatch-worker");
    config.max_attempts = 1;
    let worker = state
        .scm_task_worker_with_source_fetcher(config, fetcher)
        .unwrap();
    assert!(matches!(
        worker.process_once_at(NOW).unwrap(),
        ScmWorkerTick::Failed { attempts: 1, .. }
    ));
    assert!(requests.lock().unwrap().is_empty());
    assert!(control_plane
        .list_runs_page(Some("repo-1"), None, 100)
        .unwrap()
        .is_empty());
    let error = control_plane
        .task("event-mismatched-link")
        .unwrap()
        .last_error
        .unwrap();
    assert_eq!(error, "SCM repository is not registered");
}

#[test]
fn github_fetch_reservation_survives_server_restart_and_replays_exactly() {
    let fixture = MirrorFixture::push();
    let directory = tempfile::tempdir().unwrap();
    secure_mode(directory.path());
    let database = directory.path().join("restart.sqlite");
    let data_root = directory.path().join("objects");
    let mirror_root = directory.path().join("mirrors");
    let control = Arc::new(ControlPlane::open(&database, "installation-1", 1).unwrap());
    register_repository(&control);
    register_github_link(&control);
    let mut event = fixture.push_event();
    event.installation_id = "9001".to_owned();
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    enqueue(&control, "event-restart-fetch", &event, NOW);
    let state = test_state(Arc::clone(&control))
        .with_runner_data_plane(&data_root)
        .unwrap();
    let mut config = ScmWorkerConfig::new(&mirror_root, "fetch-before-restart");
    config.retry_base = Duration::from_millis(10);
    config.retry_max = Duration::from_millis(10);
    let retry_at = match state
        .scm_task_worker_with_source_fetcher(config, Arc::new(UnavailableSourceFetcher))
        .unwrap()
        .process_once_at(NOW)
        .unwrap()
    {
        ScmWorkerTick::Retried {
            retry_at_unix_ms, ..
        } => retry_at_unix_ms,
        other => panic!("expected durable retry, got {other:?}"),
    };
    assert_eq!(
        control
            .scm_source_fetch_for_task("tenant-1", "event-restart-fetch")
            .unwrap()
            .state,
        ScmSourceFetchState::Reserved
    );
    drop(state);
    drop(control);

    let control = Arc::new(
        ControlPlane::open(&database, "installation-1", retry_at).expect("reopen database"),
    );
    let state = test_state(Arc::clone(&control))
        .with_runner_data_plane(&data_root)
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Arc::new(FixtureSourceFetcher {
        repository: fixture.root.join("octo/runtrue"),
        requests,
    });
    let worker = state
        .scm_task_worker_with_source_fetcher(
            ScmWorkerConfig::new(&mirror_root, "fetch-after-restart"),
            fetcher,
        )
        .unwrap();
    let run_id = completed_run(worker.process_once_at(retry_at).unwrap(), false);
    assert_eq!(
        control
            .run_source_snapshot("tenant-1", &run_id)
            .unwrap()
            .run_id,
        run_id
    );
    let fetch = control
        .scm_source_fetch_for_task("tenant-1", "event-restart-fetch")
        .unwrap();
    assert_eq!(fetch.state, ScmSourceFetchState::Committed);
    assert_eq!(fetch.attempts, 2);
    assert_eq!(worker.metrics().source_fetch_replays, 1);
}

#[test]
fn pull_request_executes_base_workflow_while_testing_proposed_code() {
    let fixture = MirrorFixture::pull_request(&workflow("proposed", "oci"));
    let (control_plane, state, config) = setup(&fixture.root, "worker-base");
    let event = fixture.pull_event();
    enqueue(&control_plane, "event-base", &event, NOW);
    let worker = state.scm_task_worker(config).unwrap();
    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);

    let run = control_plane.run(&run_id).unwrap();
    let signed = control_plane.signed_capsule(&run.capsule_id).unwrap();
    let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule).unwrap();
    assert_eq!(capsule.workflow.name, "trusted-base");
    assert_eq!(capsule.context.source_commit, fixture.source);
    assert_eq!(
        capsule.context.base_commit.as_deref(),
        Some(fixture.base.as_str())
    );
    assert_eq!(
        capsule.context.normalized_event_digest,
        event.normalized_digest
    );
    assert_eq!(capsule.jobs[0].runner.isolation, Isolation::Microvm);
}

#[cfg(any())]
#[test]
fn standard_github_actions_workflow_is_discovered_planned_and_replanned_after_approval() {
    let fixture = MirrorFixture::github_actions_pull_request();
    let (control_plane, state, mut config) = setup(&fixture.root, "worker-proposed-approval");
    let default_image = "docker.io/library/node@sha256:d9f850096136edbc402debdd8729579a288aac64574ada0ff4db26b6ae58b0b2".to_owned();
    config.default_job_container_image = Some(default_image.clone());
    config.workflow_directory = ".github/workflows".to_owned();
    enqueue(
        &control_plane,
        "event-proposed-approval",
        &fixture.pull_event(),
        NOW,
    );
    let worker = state.scm_task_worker(config).unwrap();
    completed_run(worker.process_once_at(NOW).unwrap(), false);

    let proposed_analysis = control_plane
        .scm_proposed_analysis_for_task("event-proposed-approval")
        .unwrap();
    let workflow_diff = proposed_analysis
        .analysis
        .as_ref()
        .and_then(|analysis| analysis.get("workflow_diff"))
        .and_then(serde_json::Value::as_str)
        .expect("bounded workflow diff");
    assert!(workflow_diff.contains("-      - run: echo base"));
    assert!(workflow_diff.contains("+      - run: echo proposed"));

    let pending_approvals = control_plane
        .list_approval_requests_page(Some("pending"), None, 10)
        .unwrap();
    let approval = pending_approvals
        .into_iter()
        .find(|approval| approval.kind == ApprovalKind::WorkflowDefinition)
        .unwrap_or_else(|| {
            panic!(
                "workflow-definition approval; proposed analysis: {:?}",
                control_plane
                    .scm_proposed_analysis_for_task("event-proposed-approval")
                    .unwrap()
            )
        });
    control_plane
        .decide_approval_idempotent(
            "approve-proposed-with-default-image",
            &approval.id,
            ApprovalDecision {
                actor_id: "bootstrap".to_owned(),
                decision: Decision::Approve,
                reason: "approve exact proposed workflow".to_owned(),
                rule_id: "bootstrap-security-review".to_owned(),
                subject_digest: approval.subject_digest,
                decided_unix_ms: NOW + 1,
            },
            NOW + 1,
        )
        .unwrap();

    let run_id = completed_run(worker.process_once_at(NOW + 2).unwrap(), false);
    let run = control_plane.run(&run_id).unwrap();
    let signed = control_plane.signed_capsule(&run.capsule_id).unwrap();
    let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule).unwrap();
    assert_eq!(capsule.workflow.name, "CI");
    assert_eq!(
        capsule.jobs[0].runner.image.as_deref(),
        Some(default_image.as_str())
    );
}

#[cfg(any())]
#[test]
fn github_repository_action_resolution_is_exact_authorized_and_builder_agnostic() {
    let root = tempfile::tempdir().expect("repository action root");
    secure_mode(root.path());
    git(root.path(), &["init", "--quiet"]);
    git(
        root.path(),
        &["config", "user.email", "worker@runtrue.invalid"],
    );
    git(
        root.path(),
        &["config", "user.name", "Repository Action Test"],
    );
    let metadata = b"name: Backport\ndescription: Backport merged changes\ninputs:\n  config-path:\n    description: Policy path\n    required: false\n    default: .github/backport.yml\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /bin/backport\n  args: [--config, '${{ inputs.config-path }}']\n";
    let dockerfile = b"FROM scratch\nCOPY runtrue-action /usr/local/bin/runtrue-action\n";
    fs::write(root.path().join("action.yml"), metadata).expect("action metadata");
    fs::write(root.path().join("Dockerfile"), dockerfile).expect("Dockerfile");
    fs::write(root.path().join("runtrue-action"), b"fixture").expect("entrypoint");
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "action"]);
    let commit = output(root.path(), &["rev-parse", "HEAD"]);
    let reference = format!("ci/backport@{commit}");
    let image = format!(
        "containers.example.test/ci/runtrue-action-cache@sha256:{}",
        "c".repeat(64)
    );

    let control = Arc::new(ControlPlane::open_in_memory("action-test", NOW).unwrap());
    control
        .put_tenant_identity(
            &TenantIdentityRecord {
                id: "tenant-1".to_owned(),
                slug: "tenant-1".to_owned(),
                name: "Tenant 1".to_owned(),
                status: "active".to_owned(),
                settings: serde_json::json!({}),
                created_unix_ms: NOW,
                updated_unix_ms: NOW,
                version: 1,
            },
            None,
        )
        .unwrap();
    let repository = RepositoryRecord {
        id: "repository-action-backport".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        owner: "ci".to_owned(),
        name: "backport".to_owned(),
        default_branch: "main".to_owned(),
        visibility: "private".to_owned(),
        created_unix_ms: NOW,
    };
    control.create_repository(&repository).unwrap();
    let consumer_installation = ScmInstallationRecord {
        id: "github-installation-agentops".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        provider: "github".to_owned(),
        external_id: "9001".to_owned(),
        credential_reference: "provider://github-app/9001".to_owned(),
        permissions: serde_json::json!({
            "checks": "write",
            "contents": "read",
            "metadata": "read",
            "pull_requests": "read"
        }),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
    };
    let source_installation = ScmInstallationRecord {
        id: "github-installation-ci".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        provider: "github".to_owned(),
        external_id: "9002".to_owned(),
        credential_reference: "provider://github-app/9002".to_owned(),
        permissions: consumer_installation.permissions.clone(),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
    };
    for (installation, account_login) in [
        (consumer_installation.clone(), "AgentOps"),
        (source_installation.clone(), "ci"),
    ] {
        control.create_scm_installation(&installation).unwrap();
        control
            .reconcile_github_installation(&ReconcileGitHubInstallation {
                installation: GitHubInstallationRecord {
                    account_external_id: installation.external_id.clone(),
                    account_login: account_login.to_owned(),
                    account_kind: ControlPlaneGitHubAccountKind::Organization,
                    repository_selection: ControlPlaneGitHubRepositorySelection::All,
                    web_origin: "https://github.example.test".to_owned(),
                    api_origin: "https://github.example.test/api/v3".to_owned(),
                    lifecycle_generation: 1,
                    synchronized_unix_ms: NOW,
                    suspended_unix_ms: None,
                    revoked_unix_ms: None,
                    version: 1,
                    installation,
                },
                selected_repositories: Vec::new(),
                expected_version: None,
                now_unix_ms: NOW,
            })
            .unwrap();
    }
    assert_eq!(
        control
            .github_installation_for_tenant("tenant-1", &consumer_installation.id)
            .unwrap()
            .installation,
        consumer_installation
    );
    let fetch_requests = Arc::new(Mutex::new(Vec::new()));
    let fetcher: Arc<dyn ScmSourceFetcher> = Arc::new(FixtureSourceFetcher {
        repository: root.path().to_owned(),
        requests: Arc::clone(&fetch_requests),
    });
    let builder = Arc::new(FixtureRepositoryActionBuilder {
        requests: Mutex::new(Vec::new()),
        image: image.clone(),
    });
    let installation_provider = Arc::new(FixtureGitHubInstallationProvider {
        snapshots: vec![
            GitHubInstallationSnapshot {
                installation_id: 9001,
                app_id: 7,
                account: GitHubAccount {
                    id: 98,
                    login: "AgentOps".to_owned(),
                    kind: GitHubAccountKind::Organization,
                },
                target_id: 98,
                target_kind: GitHubAccountKind::Organization,
                repository_selection: GitHubRepositorySelection::All,
                permissions: std::collections::BTreeMap::from([
                    (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                    (GitHubPermission::Contents, GitHubPermissionLevel::Read),
                ]),
                suspended_at: None,
                repository_catalog_complete: true,
                repositories: Vec::new(),
            },
            GitHubInstallationSnapshot {
                installation_id: 9002,
                app_id: 7,
                account: GitHubAccount {
                    id: 99,
                    login: "ci".to_owned(),
                    kind: GitHubAccountKind::Organization,
                },
                target_id: 99,
                target_kind: GitHubAccountKind::Organization,
                repository_selection: GitHubRepositorySelection::All,
                permissions: std::collections::BTreeMap::from([
                    (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                    (GitHubPermission::Contents, GitHubPermissionLevel::Read),
                ]),
                suspended_at: None,
                repository_catalog_complete: true,
                repositories: vec![GitHubInstallationRepository {
                    id: 4242,
                    owner: GitHubAccount {
                        id: 99,
                        login: "ci".to_owned(),
                        kind: GitHubAccountKind::Organization,
                    },
                    name: "backport".to_owned(),
                    full_name: "ci/backport".to_owned(),
                    visibility: GitHubRepositoryVisibility::Private,
                    default_branch: Some("main".to_owned()),
                    archived: false,
                    disabled: false,
                }],
            },
        ],
    });
    let resolver = GitHubRepositoryActionResolver::new(
        Arc::clone(&control),
        fetcher.clone(),
        installation_provider.clone(),
        GitHubProviderEndpoints::new("https://github.example.test", "https://github.example.test/api/v3")
            .unwrap(),
        builder.clone(),
    );
    let request = SourceActionResolutionRequest::new(
        reference.clone(),
        "ci/backport",
        commit.clone(),
        "",
        vec![
            "runtrue-action.yml".to_owned(),
            "action.yml".to_owned(),
            "action.yaml".to_owned(),
        ],
    )
    .unwrap();

    let prepared = resolver
        .resolve(
            "tenant-1",
            &consumer_installation.id,
            &request,
            &GithubActionsFrontend,
        )
        .unwrap();
    assert_eq!(prepared.reference, reference);
    let ResolvedProgramRef::Container {
        image: prepared_image,
        entrypoint,
        arguments,
    } = prepared.action.program()
    else {
        panic!("expected a container action");
    };
    assert_eq!(prepared_image, image);
    assert_eq!(prepared.metadata_digest, ContentDigest::sha256(metadata));
    assert_eq!(
        prepared
            .action
            .input("config-path")
            .and_then(|input| input.default_value()),
        Some(".github/backport.yml")
    );
    assert_eq!(entrypoint, Some("/bin/backport"));
    assert_eq!(
        arguments,
        Some(
            [
                "--config".to_owned(),
                "${{ inputs.config-path }}".to_owned()
            ]
            .as_slice()
        )
    );
    let fetched = fetch_requests.lock().unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].tenant_id, "tenant-1");
    assert_eq!(fetched[0].installation.id, source_installation.id);
    assert_eq!(
        fetched[0].repository.installation_id,
        source_installation.id
    );
    assert_eq!(fetched[0].repository_id, "github-action-source-4242");
    assert_eq!(fetched[0].source_commit, commit);
    assert_eq!(fetched[0].base_commit, None);
    drop(fetched);
    assert_eq!(
        builder.requests.lock().unwrap().as_slice(),
        &[RecordedRepositoryActionBuild {
            tenant_id: "tenant-1".to_owned(),
            repository_id: "github-action-source-4242".to_owned(),
            reference: reference.clone(),
            commit: commit.clone(),
            metadata_digest: ContentDigest::sha256(metadata),
            dockerfile: "Dockerfile".to_owned(),
            dockerfile_bytes: dockerfile.to_vec(),
        }]
    );

    let component_digest = "d".repeat(64);
    let runtrue_metadata = format!(
        "name: Backport\ndescription: Backport merged changes\ninputs:\n  config-path:\n    description: Policy path\n    required: false\n    default: .github/backport.yml\nruns:\n  using: wasm\n  component: wasm://ghcr.io/runtrue/backport@sha256:{component_digest}\n  signature-identity: release@runtrue.dev\n  wit-world: runtrue:action/run@1.0.0\n"
    );
    fs::write(root.path().join("runtrue-action.yml"), &runtrue_metadata)
        .expect("Runtrue action metadata");
    git(root.path(), &["add", "-A"]);
    git(
        root.path(),
        &["commit", "--quiet", "-m", "component action"],
    );
    let component_commit = output(root.path(), &["rev-parse", "HEAD"]);
    let component_reference = format!("ci/backport@{component_commit}");
    let component_request = SourceActionResolutionRequest::new(
        component_reference.clone(),
        "ci/backport",
        component_commit,
        "",
        vec![
            "runtrue-action.yml".to_owned(),
            "action.yml".to_owned(),
            "action.yaml".to_owned(),
        ],
    )
    .unwrap();
    let prepared_component = resolver
        .resolve(
            "tenant-1",
            &consumer_installation.id,
            &component_request,
            &GithubActionsFrontend,
        )
        .unwrap();
    let ResolvedProgramRef::Component {
        reference: resolved_component,
        api_url,
        signature_identity,
        interface,
    } = prepared_component.action.program()
    else {
        panic!("expected a component action");
    };
    assert_eq!(
        resolved_component,
        format!("wasm://ghcr.io/runtrue/backport@sha256:{component_digest}")
    );
    assert_eq!(api_url, "https://github.example.test/api/v3");
    assert_eq!(signature_identity, "release@runtrue.dev");
    assert_eq!(interface, "runtrue:action/run@1.0.0");
    assert_eq!(
        prepared_component.metadata_digest,
        ContentDigest::sha256(runtrue_metadata.as_bytes())
    );
    assert_eq!(builder.requests.lock().unwrap().len(), 1);

    let component_only_resolver = GitHubRepositoryActionResolver::without_builder(
        Arc::clone(&control),
        fetcher,
        installation_provider,
        GitHubProviderEndpoints::new("https://github.example.test", "https://github.example.test/api/v3")
            .unwrap(),
    );
    assert!(component_only_resolver
        .resolve(
            "tenant-1",
            &consumer_installation.id,
            &component_request,
            &GithubActionsFrontend,
        )
        .is_ok());
    assert!(matches!(
        component_only_resolver.resolve(
            "tenant-1",
            &consumer_installation.id,
            &request,
            &GithubActionsFrontend,
        ),
        Err(RepositoryActionResolveError::Rejected)
    ));

    assert!(matches!(
        resolver.resolve(
            "tenant-other",
            &consumer_installation.id,
            &request,
            &GithubActionsFrontend,
        ),
        Err(RepositoryActionResolveError::Unauthorized)
    ));
    let invalid_request = SourceActionResolutionRequest::new(
        "ci/backport@main",
        "ci/backport",
        "main",
        "",
        vec!["action.yml".to_owned()],
    )
    .unwrap();
    assert!(matches!(
        resolver.resolve(
            "tenant-1",
            &consumer_installation.id,
            &invalid_request,
            &GithubActionsFrontend,
        ),
        Err(RepositoryActionResolveError::Rejected)
    ));
    assert_eq!(fetch_requests.lock().unwrap().len(), 4);
}

#[cfg(any())]
#[test]
fn trusted_full_commit_repository_action_is_prepared_and_locked_generically() {
    let reference = format!("ci/backport@{}", "a".repeat(40));
    let image = format!(
        "containers.example/runtrue/action-cache@sha256:{}",
        "b".repeat(64)
    );
    let fixture = MirrorFixture::repository_action_pull_request(&reference);
    let (control, state, mut config) = setup(&fixture.root, "repository-action-worker");
    config.workflow_directory = ".github/workflows".to_owned();
    enqueue(
        &control,
        "event-repository-action",
        &fixture.pull_event(),
        NOW,
    );
    let resolver = Arc::new(FixtureRepositoryActionResolver {
        requests: Mutex::new(Vec::new()),
        image: image.clone(),
        available: AtomicBool::new(true),
    });
    let worker = state
        .scm_task_worker(config)
        .unwrap()
        .with_repository_action_resolver(resolver.clone());
    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);
    assert_eq!(
        resolver.requests.lock().unwrap().as_slice(),
        &[(
            "tenant-1".to_owned(),
            "installation-1".to_owned(),
            reference,
        )]
    );
    let run = control.run(&run_id).unwrap();
    let signed = control.signed_capsule(&run.capsule_id).unwrap();
    let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule).unwrap();
    assert_eq!(
        capsule.jobs[0].runner.image.as_deref(),
        Some(image.as_str())
    );
    assert!(capsule.jobs[0].steps.iter().any(|step| {
        matches!(
            &step.action,
            runtrue_workflow_ir::StepAction::Container { entrypoint, args }
                if entrypoint.is_none() && args.is_none()
        )
    }));
}

#[cfg(any())]
#[test]
fn merged_pull_request_recovers_after_repository_action_service_outage() {
    let reference = format!("ci/backport@{}", "a".repeat(40));
    let fixture = MirrorFixture::repository_action_pull_request(&reference);
    let (control, state, mut config) = setup(&fixture.root, "backport-recovery-worker");
    config.workflow_directory = ".github/workflows".to_owned();
    config.max_attempts = 1;
    let mut event = fixture.pull_event();
    event.event_type = EventType::PullRequest {
        action: PullRequestAction::Closed,
    };
    event.pull_request.as_mut().unwrap().merged = true;
    event.normalized_digest = ContentDigest::sha256(event.canonical_normalized_bytes().unwrap());
    enqueue(&control, "event-backport-recovery", &event, NOW);
    let resolver = Arc::new(RecoveringRepositoryActionResolver {
        available: AtomicBool::new(false),
        requests: Mutex::new(Vec::new()),
        image: format!(
            "containers.example/runtrue/action-cache@sha256:{}",
            "b".repeat(64)
        ),
    });
    let worker = state
        .scm_task_worker(config)
        .unwrap()
        .with_repository_action_resolver(resolver.clone());

    let retry_at = match worker.process_once_at(NOW).unwrap() {
        ScmWorkerTick::Retried {
            attempt,
            retry_at_unix_ms,
            ..
        } => {
            assert_eq!(attempt, 1);
            retry_at_unix_ms
        }
        other => panic!("expected recoverable outage, got {other:?}"),
    };
    let retained = control.task("event-backport-recovery").unwrap();
    assert_eq!(retained.status, DurableTaskStatus::Pending);
    assert_eq!(retained.payload, serde_json::to_value(&event).unwrap());

    resolver.available.store(true, Ordering::Relaxed);
    let run_id = completed_run(worker.process_once_at(retry_at).unwrap(), false);
    assert!(matches!(
        worker.process_once_at(retry_at + 1).unwrap(),
        ScmWorkerTick::Idle
    ));
    assert_eq!(
        control
            .list_runs_page(Some("repo-1"), None, 100)
            .unwrap()
            .iter()
            .filter(|run| run.id == run_id)
            .count(),
        1
    );
    assert_eq!(resolver.requests.lock().unwrap().len(), 2);
}

#[test]
#[cfg(any())]
fn approved_repository_action_reuses_immutable_preparation_when_resolver_is_unavailable() {
    let reference = format!("ci/backport@{}", "a".repeat(40));
    let image = format!(
        "containers.example/runtrue/action-cache@sha256:{}",
        "b".repeat(64)
    );
    let fixture = MirrorFixture::privileged_repository_action_pull_request(&reference);
    let (control, state, mut config) = setup(&fixture.root, "repository-action-continuation");
    config.workflow_directory = ".github/workflows".to_owned();
    enqueue(
        &control,
        "event-repository-action-approval",
        &fixture.pull_event(),
        NOW,
    );
    let resolver = Arc::new(FixtureRepositoryActionResolver {
        requests: Mutex::new(Vec::new()),
        image,
        available: AtomicBool::new(true),
    });
    let worker = state
        .scm_task_worker(config.clone())
        .unwrap()
        .with_repository_action_resolver(resolver.clone());

    let first = worker.process_once_at(NOW).unwrap();
    assert!(matches!(
        first,
        ScmWorkerTick::Completed { run_id: None, .. }
    ));
    assert_eq!(resolver.requests.lock().unwrap().len(), 1);
    let mut shared_event = fixture.pull_event();
    shared_event.event_id = "delivery-shared-approval".to_owned();
    shared_event.raw_payload_digest = ContentDigest::sha256(b"shared approval event");
    shared_event.normalized_digest = ContentDigest::sha256(
        shared_event
            .canonical_normalized_bytes()
            .expect("canonical shared event"),
    );
    enqueue(
        &control,
        "event-repository-action-shared-approval",
        &shared_event,
        NOW + 1,
    );
    let mut shared_ticks = Vec::new();
    let shared_completed = (1..20).any(|offset| {
        let tick = worker.process_once_at(NOW + offset).unwrap();
        let completed = matches!(
            &tick,
            ScmWorkerTick::Completed { task_id, run_id: None, .. }
                if task_id == "event-repository-action-shared-approval"
        );
        shared_ticks.push(tick);
        completed
    });
    assert!(
        shared_completed,
        "unexpected ticks: {shared_ticks:#?}; task: {:#?}",
        control
            .task("event-repository-action-shared-approval")
            .unwrap()
    );
    let approvals = control
        .list_approval_requests_page_for_tenant("tenant-1", Some("pending"), None, 10)
        .unwrap();
    assert_eq!(approvals.len(), 1);
    let approval = &approvals[0];
    assert!(!approval.rule.one_shot);
    control
        .decide_approval_idempotent(
            "approve-repository-action",
            &approval.id,
            ApprovalDecision {
                actor_id: "bootstrap".to_owned(),
                decision: Decision::Approve,
                reason: "reviewed exact repository action".to_owned(),
                rule_id: approval.rule.id.clone(),
                subject_digest: approval.subject_digest.clone(),
                decided_unix_ms: NOW + 10,
            },
            NOW + 10,
        )
        .unwrap();
    resolver.available.store(false, Ordering::SeqCst);

    let mut run_ids = Vec::new();
    for offset in 11..25 {
        if let ScmWorkerTick::Completed {
            run_id: Some(run_id),
            ..
        } = worker.process_once_at(NOW + offset).unwrap()
        {
            run_ids.push(run_id);
            if run_ids.len() == 2 {
                break;
            }
        }
    }
    assert_eq!(run_ids.len(), 2, "one decision must release both waiters");
    assert_eq!(resolver.requests.lock().unwrap().len(), 2);
    assert_eq!(
        control.approval_request(&approval.id).unwrap().status,
        ApprovalStatus::Approved,
    );

    resolver.available.store(true, Ordering::SeqCst);
    let mut approved_event = fixture.pull_event();
    approved_event.event_id = "delivery-approved-grant".to_owned();
    approved_event.raw_payload_digest = ContentDigest::sha256(b"approved grant event");
    approved_event.normalized_digest = ContentDigest::sha256(
        approved_event
            .canonical_normalized_bytes()
            .expect("canonical approved event"),
    );
    enqueue(
        &control,
        "event-repository-action-approved-grant",
        &approved_event,
        NOW + 25,
    );
    let approved_grant_completed = (25..35).any(|offset| {
        matches!(
            worker.process_once_at(NOW + offset).unwrap(),
            ScmWorkerTick::Completed { task_id, run_id: None, .. }
                if task_id == "event-repository-action-approved-grant"
        )
    });
    assert!(approved_grant_completed);
    resolver.available.store(false, Ordering::SeqCst);
    let third_run = (35..45)
        .find_map(
            |offset| match worker.process_once_at(NOW + offset).unwrap() {
                ScmWorkerTick::Completed {
                    run_id: Some(run_id),
                    ..
                } => Some(run_id),
                _ => None,
            },
        )
        .expect("an approved capability grant must release a new matching execution");
    assert!(control.run(&third_run).is_ok());
    assert_eq!(
        control
            .list_approval_requests_page_for_tenant("tenant-1", None, None, 10)
            .unwrap()
            .len(),
        1,
    );

    let changed_resolver = Arc::new(FixtureRepositoryActionResolver {
        requests: Mutex::new(Vec::new()),
        image: format!(
            "containers.example/runtrue/action-cache@sha256:{}",
            "c".repeat(64)
        ),
        available: AtomicBool::new(true),
    });
    let changed_worker = state
        .scm_task_worker(config)
        .unwrap()
        .with_repository_action_resolver(changed_resolver);
    let mut changed_event = fixture.pull_event();
    changed_event.event_id = "delivery-changed-capability".to_owned();
    changed_event.raw_payload_digest = ContentDigest::sha256(b"changed capability event");
    changed_event.normalized_digest = ContentDigest::sha256(
        changed_event
            .canonical_normalized_bytes()
            .expect("canonical changed capability event"),
    );
    enqueue(
        &control,
        "event-repository-action-changed-capability",
        &changed_event,
        NOW + 45,
    );
    let changed_completed = (45..55).any(|offset| {
        matches!(
            changed_worker.process_once_at(NOW + offset).unwrap(),
            ScmWorkerTick::Completed { task_id, run_id: None, .. }
                if task_id == "event-repository-action-changed-capability"
        )
    });
    assert!(changed_completed);
    assert_eq!(
        control
            .list_approval_requests_page_for_tenant("tenant-1", Some("pending"), None, 10)
            .unwrap()
            .len(),
        1,
        "a changed action resolution must require a new capability approval",
    );
}

#[test]
fn lockfile_only_change_records_real_lock_diff_and_no_workflow_diff() {
    let fixture = MirrorFixture::lockfile_only_pull_request();
    let (control_plane, state, config) = setup(&fixture.root, "worker-lockfile-diff");
    enqueue(
        &control_plane,
        "event-lockfile-diff",
        &fixture.pull_event(),
        NOW,
    );
    let worker = state.scm_task_worker(config).unwrap();
    let tick = worker.process_once_at(NOW).unwrap();
    assert!(
        matches!(
            tick,
            ScmWorkerTick::Completed {
                run_id: Some(_),
                ..
            }
        ),
        "unexpected worker result {tick:?}; task: {:?}",
        control_plane.task("event-lockfile-diff").unwrap()
    );

    let proposed_analysis = control_plane
        .scm_proposed_analysis_for_task("event-lockfile-diff")
        .unwrap();
    let analysis = proposed_analysis.analysis.as_ref().unwrap();
    assert!(analysis
        .get("workflow_diff")
        .is_some_and(serde_json::Value::is_null));
    let lockfile_diff = analysis
        .get("lockfile_diff")
        .and_then(serde_json::Value::as_str)
        .expect("bounded lockfile diff");
    assert!(lockfile_diff.contains(&format!(
        "-resolved = \"containers.example/tool@sha256:{}\"",
        "a".repeat(64)
    )));
    assert!(lockfile_diff.contains(&format!(
        "+resolved = \"containers.example/tool@sha256:{}\"",
        "b".repeat(64)
    )));
}

#[test]
fn invalid_proposed_workflow_does_not_block_base_capsule() {
    let fixture = MirrorFixture::pull_request(b"version: [not valid workflow");
    let (control_plane, state, config) = setup(&fixture.root, "worker-invalid-proposed");
    enqueue(
        &control_plane,
        "event-invalid-proposed",
        &fixture.pull_event(),
        NOW,
    );
    let worker = state.scm_task_worker(config).unwrap();
    let run_id = completed_run(worker.process_once_at(NOW).unwrap(), false);
    let run = control_plane.run(&run_id).unwrap();
    let signed = control_plane.signed_capsule(&run.capsule_id).unwrap();
    let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule).unwrap();
    assert_eq!(capsule.workflow.name, "trusted-base");
    assert_eq!(capsule.context.source_commit, fixture.source);
}

#[test]
fn missing_mirror_remains_recoverable_until_the_one_day_deadline() {
    let root = tempfile::tempdir().unwrap();
    secure_mode(root.path());
    let (control_plane, state, config) = setup(root.path(), "worker-missing");
    let event = event(EventType::Push, "a".repeat(40), Some("b".repeat(40)));
    enqueue(&control_plane, "event-missing", &event, NOW);
    let worker = state.scm_task_worker(config).unwrap();

    let retry_at = match worker.process_once_at(NOW).unwrap() {
        ScmWorkerTick::Retried {
            attempt,
            retry_at_unix_ms,
            ..
        } => {
            assert_eq!(attempt, 1);
            retry_at_unix_ms
        }
        other => panic!("expected retry, got {other:?}"),
    };
    assert!(matches!(
        worker.process_once_at(retry_at).unwrap(),
        ScmWorkerTick::Retried { attempt: 2, .. }
    ));
    assert!(matches!(
        worker
            .process_once_at(NOW + SCM_EVENT_RECOVERY_WINDOW_MS)
            .unwrap(),
        ScmWorkerTick::Idle
    ));
    let task = control_plane.task("event-missing").unwrap();
    assert_eq!(task.status, DurableTaskStatus::Failed);
    assert!(task.last_error.unwrap().contains("mirror"));
    assert!(control_plane
        .list_runs_page(Some("repo-1"), None, 100)
        .unwrap()
        .is_empty());
}

#[test]
fn restore_safe_mode_pauses_without_claiming_or_creating_a_run() {
    let fixture = MirrorFixture::push();
    let (control_plane, state, config) = setup(&fixture.root, "worker-safe-mode");
    enqueue(
        &control_plane,
        "event-safe-mode",
        &fixture.push_event(),
        NOW,
    );
    control_plane.enter_restore_safe_mode(NOW - 1).unwrap();
    let worker = state.scm_task_worker(config).unwrap();
    assert_eq!(
        worker.process_once_at(NOW).unwrap(),
        ScmWorkerTick::PausedSafeMode
    );
    let task = control_plane.task("event-safe-mode").unwrap();
    assert_eq!(task.status, DurableTaskStatus::Pending);
    assert_eq!(task.attempts, 0);
    assert!(control_plane
        .list_runs_page(Some("repo-1"), None, 100)
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
#[test]
fn insecure_or_symlinked_mirror_roots_are_rejected_at_configuration_time() {
    use std::os::unix::fs::symlink;

    let control_plane = Arc::new(ControlPlane::open_in_memory("installation-1", 1).unwrap());
    let state = AppState::new_with_security_seed(
        control_plane,
        "bootstrap-token",
        None,
        [9_u8; 32],
        "https://runtrue.invalid/oidc".to_owned(),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(state
        .scm_task_worker(ScmWorkerConfig::new(root.path(), "insecure"))
        .is_err());

    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("mirror-link");
    symlink(root.path(), &link).unwrap();
    assert!(state
        .scm_task_worker(ScmWorkerConfig::new(link, "symlinked"))
        .is_err());
}

fn completed_run(tick: ScmWorkerTick, replayed: bool) -> String {
    match tick {
        ScmWorkerTick::Completed {
            run_id: Some(run_id),
            replayed: actual,
            ..
        } => {
            assert_eq!(actual, replayed);
            run_id
        }
        other => panic!("expected completed run, got {other:?}"),
    }
}

fn enqueue(control_plane: &ControlPlane, id: &str, event: &EventEnvelope, created_unix_ms: u64) {
    control_plane
        .enqueue_task(&DurableTask {
            id: id.to_owned(),
            kind: "scm.event".to_owned(),
            payload: serde_json::to_value(event).unwrap(),
            status: DurableTaskStatus::Pending,
            available_unix_ms: created_unix_ms,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms,
            completed_unix_ms: None,
        })
        .unwrap();
}

fn event(event_type: EventType, source: String, base: Option<String>) -> EventEnvelope {
    let is_pull = matches!(event_type, EventType::PullRequest { .. });
    let mut event = EventEnvelope {
        version: 1,
        provider: ProviderKind::GitHub,
        installation_id: "installation-1".to_owned(),
        repository: RepositoryIdentity {
            external_id: "42".to_owned(),
            owner: "octo".to_owned(),
            name: "runtrue".to_owned(),
            full_name: "octo/runtrue".to_owned(),
            private: true,
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
            ref_name: Some(if is_pull { "feature" } else { "main" }.to_owned()),
            repository_full_name: Some("octo/runtrue".to_owned()),
        },
        base: base.map(|commit| GitRevision {
            commit,
            ref_name: Some("main".to_owned()),
            repository_full_name: Some("octo/runtrue".to_owned()),
        }),
        ref_name: Some("main".to_owned()),
        pull_request: is_pull.then_some(PullRequestEvent {
            number: 17,
            draft: false,
            merged: false,
        }),
        issue_comment: None,
        check_run: None,
        changed_paths: vec![DEFAULT_TEST_WORKFLOW_PATH.to_owned()],
        received_unix_ms: NOW - 100,
        raw_payload_digest: ContentDigest::sha256(b"raw webhook bytes"),
        normalized_digest: ContentDigest::sha256(b"placeholder"),
    };
    event.normalized_digest =
        ContentDigest::sha256(event.canonical_normalized_bytes().expect("canonical event"));
    event
}

fn workflow(name: &str, isolation: &str) -> Vec<u8> {
    format!(
        "version: 1\nname: {name}\non:\n  push: {{}}\n  pull_request: {{}}\njobs:\n  build:\n    runner:\n      isolation: {isolation}\n    steps:\n      - run:\n          command: [\"true\"]\n"
    )
    .into_bytes()
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .status()
        .expect("git command");
    assert!(status.success(), "git {arguments:?}");
}

fn output(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git command");
    assert!(output.status.success(), "git {arguments:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn secure_mode(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
