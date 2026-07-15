use crate::*;
use runtrue_model::ContentDigest;
use runtrue_storage::{CasLimits, FsCas, StorageError, TreeEntryKind, TreeSnapshot};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use tempfile::tempdir;

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}

fn main_domain() -> TrustDomain {
    TrustDomain::RepositoryMainVerified {
        installation_id: "installation".to_owned(),
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
    }
}

fn branch_domain() -> TrustDomain {
    TrustDomain::RepositoryBranchVerified {
        installation_id: "installation".to_owned(),
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        branch: "feature".to_owned(),
    }
}

fn quarantine_domain() -> TrustDomain {
    TrustDomain::PullRequestQuarantine {
        installation_id: "installation".to_owned(),
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        change_id: "pr-7".to_owned(),
    }
}

fn identity(trust_domain: TrustDomain) -> CacheIdentity {
    CacheIdentity {
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        purpose: "rust-target".to_owned(),
        trust_domain,
        platform: CachePlatform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
        },
        compiler_or_toolchain: Some(digest("rust-1.75")),
        definition: digest("Cargo.toml"),
        declared_inputs: digest("Cargo.lock"),
        policy_epoch: 1,
        user_suffix: None,
    }
}

fn material() -> CacheKeyMaterial {
    CacheKeyMaterial::from(&identity(main_domain()))
}

fn access(
    source: CacheSourceTrust,
    read: CacheReadPolicy,
    write: CacheWritePolicy,
) -> CacheAccessContext {
    CacheAccessContext {
        installation_id: "installation".to_owned(),
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        run_id: "run-1".to_owned(),
        default_branch: "main".to_owned(),
        source,
        read,
        write,
        verified_write_authorized: true,
    }
}

fn producer() -> CacheProducer {
    CacheProducer {
        capsule_digest: digest("capsule"),
        job_id: "build".to_owned(),
        step_id: "compile".to_owned(),
        lease_id: "lease-1".to_owned(),
    }
}

const TICKET_NOW: u64 = 10_000;

fn ticket_request(
    cache_identity: CacheIdentity,
    snapshot: &TreeSnapshot,
    expected_head: Option<CacheHead>,
    max_total_bytes: u64,
) -> CacheWriteTicketRequest {
    CacheWriteTicketRequest {
        operation: CacheTicketOperation::Commit,
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        job_id: "build".to_owned(),
        job_attempt: 1,
        step_id: "compile".to_owned(),
        lease_id: "lease-1".to_owned(),
        producer_capsule_digest: digest("capsule"),
        fencing_generation: 7,
        writer_trust_domain: cache_identity.trust_domain.clone(),
        identity: cache_identity,
        expected_head,
        expected_tree_manifest_digest: Some(snapshot.manifest_digest.clone()),
        max_total_bytes,
        issued_at_unix_seconds: TICKET_NOW,
        expires_at_unix_seconds: TICKET_NOW + 60,
    }
}

fn commit_ticket_snapshot(
    store: &CacheStore,
    ticket: &CacheWriteTicket,
    snapshot: &TreeSnapshot,
) -> Result<CacheEntry, CacheError> {
    store.commit_ticketed_snapshot(&CacheSnapshotCommitRequest {
        ticket,
        active_tenant_id: "tenant",
        active_repository_id: "repository",
        active_job_id: "build",
        active_step_id: "compile",
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        active_writer_trust_domain: &ticket.writer_trust_domain,
        now_unix_seconds: TICKET_NOW + 1,
        snapshot,
        producer: producer(),
    })
}

fn test_store() -> (tempfile::TempDir, CacheStore) {
    let directory = tempdir().unwrap();
    let cas = FsCas::open(directory.path().join("cas"), CasLimits::default()).unwrap();
    let store = CacheStore::open(
        directory.path().join("metadata"),
        cas,
        CacheLimits::default(),
    )
    .unwrap();
    (directory, store)
}

fn source_tree(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let source = root.join(name);
    fs::create_dir(&source).unwrap();
    fs::write(source.join("output"), bytes).unwrap();
    source
}

fn object_path(cas: &FsCas, digest: &ContentDigest) -> PathBuf {
    let encoded = digest.as_str().strip_prefix("sha256:").unwrap();
    cas.root()
        .join("objects/sha256")
        .join(&encoded[..2])
        .join(&encoded[2..])
}

mod access;
mod commit;
mod corruption;
mod key;
mod promotion;
mod restore;
mod secure_io;
mod ticket;
