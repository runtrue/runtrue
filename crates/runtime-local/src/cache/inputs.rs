use super::{
    canonical_workspace, resolve_existing_exact, LocalCacheConfig, LOCAL_CACHE_FORMAT_VERSION,
};
use crate::secure_io::{file_is_executable, open_regular_nofollow};
use runtrue_cache::{
    cache_definition_digest, CacheIdentity, CacheKeyMaterial, CachePlatform, CacheStore,
    TrustDomain,
};
use runtrue_model::{normalize_relative_path, ContentDigest};
use runtrue_storage::{CasLimits, FsCas};
use runtrue_workflow_ir::{
    Architecture, CacheDeclaration, CacheMode, CacheRead, CacheWrite, ExecutionCapsule,
    OperatingSystem,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

#[derive(Debug, Clone)]
pub(crate) struct PreparedCapsule {
    pub(crate) capsule_digest: ContentDigest,
    pub(crate) known_steps: BTreeSet<(String, String)>,
    pub(crate) cache_steps: BTreeMap<(String, String), PreparedCacheStep>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedCacheStep {
    pub(crate) job_id: String,
    pub(crate) step_id: String,
    pub(crate) platform: CachePlatform,
    pub(crate) declaration: CacheDeclaration,
    pub(crate) definition_digest: ContentDigest,
    pub(crate) toolchain_digest: Option<ContentDigest>,
    pub(crate) max_size_bytes: u64,
    pub(crate) read: bool,
    pub(crate) write: bool,
}

pub(crate) fn open_store(config: &LocalCacheConfig) -> Result<CacheStore, String> {
    if config.policy_epoch == 0 {
        return Err("policy epoch must be greater than zero".to_owned());
    }
    if config.default_max_entry_bytes == 0 {
        return Err("default cache entry limit must be greater than zero".to_owned());
    }
    let cas = FsCas::open(config.cache_root.join("cas"), config.cas_limits)
        .map_err(|error| error.to_string())?;
    CacheStore::open(config.cache_root.join("metadata"), cas, config.cache_limits)
        .map_err(|error| error.to_string())
}

pub(crate) fn prepare_capsule(
    capsule: &ExecutionCapsule,
    config: &LocalCacheConfig,
) -> Result<PreparedCapsule, String> {
    let capsule_digest = capsule.digest().map_err(|error| error.to_string())?;
    let mut known_steps = BTreeSet::new();
    let mut cache_steps = BTreeMap::new();

    for job in &capsule.jobs {
        let platform = CachePlatform {
            os: os_name(job.runner.os).to_owned(),
            architecture: architecture_name(job.runner.arch).to_owned(),
        };
        for step in &job.steps {
            let key = (job.id.clone(), step.id.clone());
            if !known_steps.insert(key.clone()) {
                return Err(format!("duplicate execution step {}.{}", job.id, step.id));
            }
            let Some(declaration) = &step.cache else {
                continue;
            };
            let declaration = validate_declaration(declaration)?;
            let (read, write) = mode_operations(declaration.mode);
            if declaration.outputs.is_empty() {
                return Err(format!(
                    "step {}.{} declares a cache without any exact output path",
                    job.id, step.id
                ));
            }
            if read && step.capabilities.cache_read != CacheRead::Run {
                return Err(format!(
                    "step {}.{} requires cache.read: run for RunPrivate restore",
                    job.id, step.id
                ));
            }
            if write && step.capabilities.cache_write == CacheWrite::Deny {
                return Err(format!(
                    "step {}.{} requests cache write mode without cache write capability",
                    job.id, step.id
                ));
            }

            let max_size_bytes = declaration
                .max_size_bytes
                .unwrap_or(config.default_max_entry_bytes);
            if max_size_bytes == 0 || max_size_bytes > config.cas_limits.max_tree_total_bytes {
                return Err(format!(
                    "step {}.{} cache max-size must be within 1..={} bytes",
                    job.id, step.id, config.cas_limits.max_tree_total_bytes
                ));
            }
            let definition_digest = definition_digest(
                &job.id,
                &step.id,
                &declaration,
                &step.action,
                &job.runner.image,
                isolation_name(job.runner.isolation),
            )?;
            let prepared = PreparedCacheStep {
                job_id: job.id.clone(),
                step_id: step.id.clone(),
                platform: platform.clone(),
                declaration,
                definition_digest,
                toolchain_digest: capsule.context.lockfile_digest.clone(),
                max_size_bytes,
                read,
                write,
            };

            build_identity(
                config,
                &capsule_digest,
                &prepared,
                ContentDigest::sha256(b"preflight-input-placeholder"),
            )
            .digest(config.cache_limits)
            .map_err(|error| error.to_string())?;
            cache_steps.insert(key, prepared);
        }
    }

    Ok(PreparedCapsule {
        capsule_digest,
        known_steps,
        cache_steps,
    })
}

pub(crate) fn validate_declaration(
    declaration: &CacheDeclaration,
) -> Result<CacheDeclaration, String> {
    let mut inputs = declaration
        .inputs
        .iter()
        .map(|path| validate_exact_path(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut outputs = declaration
        .outputs
        .iter()
        .map(|path| validate_exact_path(path))
        .collect::<Result<Vec<_>, _>>()?;
    inputs.sort();
    inputs.dedup();
    outputs.sort();
    outputs.dedup();
    for (index, path) in outputs.iter().enumerate() {
        if outputs
            .iter()
            .skip(index + 1)
            .any(|other| paths_overlap(path, other))
        {
            return Err(format!("cache output paths overlap at {path}"));
        }
    }
    Ok(CacheDeclaration {
        inputs,
        outputs,
        mode: declaration.mode,
        max_size_bytes: declaration.max_size_bytes,
    })
}

pub(crate) fn validate_exact_path(path: &str) -> Result<String, String> {
    if path
        .chars()
        .any(|character| matches!(character, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Err(format!(
            "cache path {path} uses glob syntax; only exact paths are supported"
        ));
    }
    let normalized = normalize_relative_path(path).map_err(|error| error.to_string())?;
    if normalized != path {
        return Err(format!(
            "cache path {path} is not in canonical repository-relative form"
        ));
    }
    if normalized.split('/').next() == Some(".runtrue") {
        return Err("cache paths cannot address Runtrue private state".to_owned());
    }
    Ok(normalized)
}

pub(crate) fn paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(crate) const fn mode_operations(mode: CacheMode) -> (bool, bool) {
    match mode {
        CacheMode::ReadOnly => (true, false),
        CacheMode::ReadWrite => (true, true),
        CacheMode::WriteOnly => (false, true),
    }
}

#[derive(Serialize)]
pub(crate) struct DefinitionMaterial<'a> {
    version: u32,
    job_id: &'a str,
    step_id: &'a str,
    declaration: &'a CacheDeclaration,
    action: &'a runtrue_workflow_ir::StepAction,
    runner_image: &'a Option<String>,
    isolation: &'a str,
}

pub(crate) fn definition_digest(
    job_id: &str,
    step_id: &str,
    declaration: &CacheDeclaration,
    action: &runtrue_workflow_ir::StepAction,
    runner_image: &Option<String>,
    isolation: &str,
) -> Result<ContentDigest, String> {
    cache_definition_digest(&DefinitionMaterial {
        version: LOCAL_CACHE_FORMAT_VERSION,
        job_id,
        step_id,
        declaration,
        action,
        runner_image,
        isolation,
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn build_identity(
    config: &LocalCacheConfig,
    capsule_digest: &ContentDigest,
    step: &PreparedCacheStep,
    input_digest: ContentDigest,
) -> CacheIdentity {
    let run_id = format!(
        "{}:{}:{}",
        capsule_digest, step.platform.os, step.platform.architecture
    );
    build_key_material(config, step, input_digest).with_trust_domain(TrustDomain::RunPrivate {
        installation_id: config.installation_id.clone(),
        tenant_id: config.tenant_id.clone(),
        repository_id: config.repository_id.clone(),
        run_id,
    })
}

pub(crate) fn build_key_material(
    config: &LocalCacheConfig,
    step: &PreparedCacheStep,
    input_digest: ContentDigest,
) -> CacheKeyMaterial {
    CacheKeyMaterial {
        tenant_id: config.tenant_id.clone(),
        repository_id: config.repository_id.clone(),
        purpose: format!("{}.{}", step.job_id, step.step_id),
        platform: step.platform.clone(),
        toolchain: step.toolchain_digest.clone(),
        definition: step.definition_digest.clone(),
        declared_inputs: input_digest,
        policy_epoch: config.policy_epoch,
        user_suffix: None,
    }
}

pub(crate) const fn os_name(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Macos => "macos",
    }
}

pub(crate) const fn architecture_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}

pub(crate) const fn isolation_name(isolation: runtrue_workflow_ir::Isolation) -> &'static str {
    match isolation {
        runtrue_workflow_ir::Isolation::Wasm => "wasm",
        runtrue_workflow_ir::Isolation::Oci => "oci",
        runtrue_workflow_ir::Isolation::Microvm => "microvm",
        runtrue_workflow_ir::Isolation::Native => "native",
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct InputRecord {
    path: String,
    kind: InputRecordKind,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum InputRecordKind {
    Missing,
    Directory,
    File {
        digest: ContentDigest,
        size_bytes: u64,
        executable: bool,
    },
}

#[derive(Debug)]
pub(crate) struct WalkBudget {
    entries: usize,
    bytes: u64,
    limits: CasLimits,
}

pub(crate) fn declared_input_digest(
    workspace: &Path,
    inputs: &[String],
    limits: CasLimits,
) -> Result<ContentDigest, String> {
    let workspace = canonical_workspace(workspace)?;
    let mut records = Vec::new();
    let mut budget = WalkBudget {
        entries: 0,
        bytes: 0,
        limits,
    };
    for relative in inputs {
        match resolve_existing_exact(&workspace, relative)? {
            Some(path) => {
                walk_input(&workspace, &path, relative, 0, &mut budget, &mut records)?;
            }
            None => records.push(InputRecord {
                path: relative.clone(),
                kind: InputRecordKind::Missing,
            }),
        }
    }
    let bytes = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
    Ok(ContentDigest::sha256(bytes))
}

pub(crate) fn walk_input(
    workspace: &Path,
    path: &Path,
    relative: &str,
    depth: usize,
    budget: &mut WalkBudget,
    records: &mut Vec<InputRecord>,
) -> Result<(), String> {
    if depth > budget.limits.max_tree_depth {
        return Err(format!("input {relative} exceeds cache tree depth limit"));
    }
    budget.entries = budget
        .entries
        .checked_add(1)
        .ok_or("input entry count overflow")?;
    if budget.entries > budget.limits.max_tree_entries {
        return Err("declared inputs exceed cache tree entry limit".to_owned());
    }
    if relative.len() > budget.limits.max_relative_path_bytes {
        return Err(format!("input path {relative} exceeds cache path limit"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!("input {relative} is a symlink"));
    }
    if metadata.is_file() {
        let (digest, size_bytes) = hash_regular_file(path, budget)?;
        records.push(InputRecord {
            path: relative.to_owned(),
            kind: InputRecordKind::File {
                digest,
                size_bytes,
                executable: file_is_executable(&metadata),
            },
        });
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(format!(
            "input {relative} is not a regular file or directory"
        ));
    }
    records.push(InputRecord {
        path: relative.to_owned(),
        kind: InputRecordKind::Directory,
    });
    let mut entries = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("input directory {relative} contains a non-UTF-8 name"))?;
        let child_relative = format!("{relative}/{name}");
        let child = entry.path();
        if !child.starts_with(workspace) {
            return Err(format!("input {child_relative} escapes the workspace"));
        }
        walk_input(
            workspace,
            &child,
            &child_relative,
            depth + 1,
            budget,
            records,
        )?;
    }
    Ok(())
}

pub(crate) fn hash_regular_file(
    path: &Path,
    budget: &mut WalkBudget,
) -> Result<(ContentDigest, u64), String> {
    let mut file = open_regular_nofollow(path)?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err(format!("input {} is not a regular file", path.display()));
    }
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or("input size overflow")?;
        budget.bytes = budget
            .bytes
            .checked_add(read as u64)
            .ok_or("declared input size overflow")?;
        if budget.bytes > budget.limits.max_tree_total_bytes {
            return Err("declared inputs exceed local hashing limit".to_owned());
        }
        hasher.update(&buffer[..read]);
    }
    let digest = ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| error.to_string())?;
    Ok((digest, size))
}
