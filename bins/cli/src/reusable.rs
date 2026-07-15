use runtrue_compiler::{
    ReusableSourceBundleError, ReusableWorkflowSource, ReusableWorkflowSources,
    MAX_REUSABLE_BUNDLE_BYTES, MAX_REUSABLE_SOURCES, MAX_REUSABLE_SOURCE_BYTES,
};
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read as _},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[cfg(target_os = "linux")]
use {
    rustix::fs::{fstat, openat2, Mode, OFlags, RawDir, ResolveFlags, ABS},
    std::{fs::File, mem::MaybeUninit, os::unix::fs::MetadataExt as _},
};

const STORE_RELATIVE_PATH: &str = ".runtrue/reusable-workflows/sha256";

#[derive(Debug)]
pub(super) struct HydratedReusableWorkflows {
    pub(super) compiler: ReusableWorkflowSources,
    pub(super) transport: Vec<TransportReusableWorkflow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransportReusableWorkflow {
    pub(super) reference: String,
    pub(super) commit: String,
    pub(super) source_hex: String,
}

pub(super) fn hydrate_workspace_sources(
    workspace: &Path,
    lockfile: Option<&LockFile>,
) -> Result<HydratedReusableWorkflows, ReusableHydrationError> {
    #[cfg(target_os = "linux")]
    {
        hydrate_linux(workspace, lockfile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = workspace;
        if lockfile.is_none_or(|lockfile| lockfile.workflows().is_empty()) {
            Ok(HydratedReusableWorkflows {
                compiler: ReusableWorkflowSources::default(),
                transport: Vec::new(),
            })
        } else {
            Err(ReusableHydrationError::UnsupportedPlatform)
        }
    }
}

#[cfg(target_os = "linux")]
fn hydrate_linux(
    workspace: &Path,
    lockfile: Option<&LockFile>,
) -> Result<HydratedReusableWorkflows, ReusableHydrationError> {
    let locked = lockfile.map_or(&[][..], LockFile::workflows);
    if locked.len() > MAX_REUSABLE_SOURCES {
        return Err(ReusableHydrationError::TooManyLockedSources {
            limit: MAX_REUSABLE_SOURCES,
            actual: locked.len(),
        });
    }
    let expected = locked
        .iter()
        .map(|entry| {
            let digest = entry
                .digest()
                .as_str()
                .strip_prefix("sha256:")
                .expect("ContentDigest always has a SHA-256 prefix");
            (format!("{digest}.yaml"), entry)
        })
        .collect::<BTreeMap<_, _>>();
    let store = workspace.join(STORE_RELATIVE_PATH);
    let directory = match openat2(
        ABS,
        &store,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(directory) => directory,
        Err(error) if error == rustix::io::Errno::NOENT && expected.is_empty() => {
            return Ok(HydratedReusableWorkflows {
                compiler: ReusableWorkflowSources::default(),
                transport: Vec::new(),
            });
        }
        Err(error) => {
            return Err(ReusableHydrationError::UnsafeStore {
                path: store,
                source: error.into(),
            });
        }
    };
    let directory_stat =
        fstat(&directory).map_err(|source| ReusableHydrationError::UnsafeStore {
            path: store.clone(),
            source: source.into(),
        })?;
    if directory_stat.st_mode & 0o022 != 0 {
        return Err(ReusableHydrationError::InsecureMode { path: store });
    }

    let names = read_directory_names(&directory, &store)?;
    if let Some(extra) = names.iter().find(|name| !expected.contains_key(*name)) {
        return Err(ReusableHydrationError::UnexpectedEntry {
            path: store.join(extra),
        });
    }
    if let Some(missing) = expected.keys().find(|name| !names.contains(*name)) {
        return Err(ReusableHydrationError::MissingSource {
            path: store.join(missing),
        });
    }

    let mut compiler_entries = BTreeMap::new();
    let mut transport = Vec::with_capacity(expected.len());
    let mut total = 0usize;
    for (file_name, entry) in expected {
        let descriptor = openat2(
            &directory,
            file_name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|source| ReusableHydrationError::UnsafeSource {
            path: store.join(&file_name),
            source: source.into(),
        })?;
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|source| ReusableHydrationError::UnsafeSource {
                path: store.join(&file_name),
                source,
            })?;
        if !metadata.file_type().is_file() || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1
        {
            return Err(ReusableHydrationError::InsecureSource {
                path: store.join(&file_name),
            });
        }
        let mut bytes = Vec::new();
        file.take(
            u64::try_from(MAX_REUSABLE_SOURCE_BYTES).expect("reusable source limit fits u64") + 1,
        )
        .read_to_end(&mut bytes)
        .map_err(|source| ReusableHydrationError::UnsafeSource {
            path: store.join(&file_name),
            source,
        })?;
        if bytes.len() > MAX_REUSABLE_SOURCE_BYTES {
            return Err(ReusableHydrationError::SourceTooLarge {
                path: store.join(&file_name),
                limit: MAX_REUSABLE_SOURCE_BYTES,
            });
        }
        total = total.saturating_add(bytes.len());
        if total > MAX_REUSABLE_BUNDLE_BYTES {
            return Err(ReusableHydrationError::BundleTooLarge {
                limit: MAX_REUSABLE_BUNDLE_BYTES,
            });
        }
        let actual = ContentDigest::sha256(&bytes);
        if &actual != entry.digest() {
            return Err(ReusableHydrationError::DigestMismatch {
                path: store.join(&file_name),
                expected: entry.digest().clone(),
                actual,
            });
        }
        let source = ReusableWorkflowSource::new(entry.commit(), bytes.clone())?;
        compiler_entries.insert(entry.source().to_owned(), source);
        transport.push(TransportReusableWorkflow {
            reference: entry.source().to_owned(),
            commit: entry.commit().to_owned(),
            source_hex: encode_hex(&bytes),
        });
    }
    Ok(HydratedReusableWorkflows {
        compiler: ReusableWorkflowSources::new(compiler_entries)?,
        transport,
    })
}

#[cfg(target_os = "linux")]
fn read_directory_names(
    directory: &impl rustix::fd::AsFd,
    path: &Path,
) -> Result<BTreeSet<String>, ReusableHydrationError> {
    let duplicate = rustix::io::dup(directory.as_fd()).map_err(|source| {
        ReusableHydrationError::UnsafeStore {
            path: path.to_owned(),
            source: source.into(),
        }
    })?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 64 * 1024];
    let mut entries = RawDir::new(duplicate, &mut buffer);
    let mut names = BTreeSet::new();
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|source| ReusableHydrationError::UnsafeStore {
            path: path.to_owned(),
            source: source.into(),
        })?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if names.len() >= MAX_REUSABLE_SOURCES {
            return Err(ReusableHydrationError::TooManyStoreEntries {
                path: path.to_owned(),
                limit: MAX_REUSABLE_SOURCES,
            });
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| ReusableHydrationError::UnexpectedEntry {
                path: path.join("[non-UTF8-entry]"),
            })?
            .to_owned();
        if !names.insert(name.clone()) {
            return Err(ReusableHydrationError::UnexpectedEntry {
                path: path.join(name),
            });
        }
    }
    Ok(names)
}

fn encode_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        encoded.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Debug, Error)]
pub(super) enum ReusableHydrationError {
    #[cfg(not(target_os = "linux"))]
    #[error("reusable workflow hydration requires Linux openat2")]
    UnsupportedPlatform,
    #[error("reusable workflow lock contains {actual} entries; limit is {limit}")]
    TooManyLockedSources { limit: usize, actual: usize },
    #[error("reusable workflow store {} cannot be opened securely: {source}", path.display())]
    UnsafeStore { path: PathBuf, source: io::Error },
    #[error("reusable workflow store or source {} is group/world writable", path.display())]
    InsecureMode { path: PathBuf },
    #[error("reusable workflow store {} contains more than {limit} entries", path.display())]
    TooManyStoreEntries { path: PathBuf, limit: usize },
    #[error("unexpected reusable workflow store entry {}", path.display())]
    UnexpectedEntry { path: PathBuf },
    #[error("missing locked reusable workflow source {}", path.display())]
    MissingSource { path: PathBuf },
    #[error("reusable workflow source {} cannot be opened securely: {source}", path.display())]
    UnsafeSource { path: PathBuf, source: io::Error },
    #[error("reusable workflow source {} is not a private regular single-link file", path.display())]
    InsecureSource { path: PathBuf },
    #[error("reusable workflow source {} exceeds the {limit}-byte limit", path.display())]
    SourceTooLarge { path: PathBuf, limit: usize },
    #[error("reusable workflow sources exceed the {limit}-byte bundle limit")]
    BundleTooLarge { limit: usize },
    #[error("reusable workflow source {} digest mismatch: expected {expected}, got {actual}", path.display())]
    DigestMismatch {
        path: PathBuf,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error(transparent)]
    Bundle(#[from] ReusableSourceBundleError),
}

#[cfg(test)]
mod tests {
    use super::encode_hex;

    #[test]
    fn transport_hex_is_exact_and_lowercase() {
        assert_eq!(encode_hex(&[0, 1, 15, 16, 254, 255]), "00010f10feff");
    }
}
