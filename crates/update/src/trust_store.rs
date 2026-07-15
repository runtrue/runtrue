use crate::secure_fs::{open_absolute_nofollow, openat_confined};
use crate::{TrustedState, UpdateError, UpdateSigningKey, MAX_TRUST_STATE_BYTES};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

/// A retained-directory-handle trust store. The parent must already exist,
/// belong to the effective user, and have no group/world permissions.
pub struct TrustStore {
    path: PathBuf,
    parent: File,
    leaf: OsString,
}

/// An exclusive update-state transaction. The retained lock descriptor keeps
/// cooperating processes serialized from their state read through verification
/// and the final durable compare-and-swap.
pub struct TrustStoreTransaction<'a> {
    store: &'a TrustStore,
    _lock: File,
}

impl TrustStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, UpdateError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(UpdateError::UnsafeTrustStore(
                "trust state path must be absolute".to_owned(),
            ));
        }
        let leaf = path
            .file_name()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| UpdateError::UnsafeTrustStore("missing state filename".to_owned()))?
            .to_owned();
        let parent_path = path
            .parent()
            .ok_or_else(|| UpdateError::UnsafeTrustStore("missing state parent".to_owned()))?;
        let parent = open_absolute_nofollow(parent_path, directory_flags(), Mode::empty())?;
        let metadata = parent
            .metadata()
            .map_err(|source| trust_io("inspect parent", source))?;
        let effective_uid = nix::unistd::geteuid().as_raw();
        if !metadata.is_dir()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(UpdateError::UnsafeTrustStore(
                "state parent must be a private directory owned by the effective user".to_owned(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            parent,
            leaf,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<TrustedState>, UpdateError> {
        let file = match openat_confined(&self.parent, &self.leaf, read_flags(), Mode::empty()) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(trust_io("open state", source)),
        };
        let before = secure_file_metadata(&file)?;
        if before.len() == 0 || before.len() > MAX_TRUST_STATE_BYTES as u64 {
            return Err(UpdateError::UnsafeTrustStore(
                "state file size is invalid".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&file)
            .take((MAX_TRUST_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| trust_io("read state", source))?;
        let retained_after = secure_file_metadata(&file)?;
        if bytes.len() > MAX_TRUST_STATE_BYTES
            || bytes.len() as u64 != before.len()
            || !same_file_snapshot(&before, &retained_after)
        {
            return Err(UpdateError::UnsafeTrustStore(
                "state file changed while it was read".to_owned(),
            ));
        }
        let reopened = openat_confined(&self.parent, &self.leaf, read_flags(), Mode::empty())
            .map_err(|source| trust_io("reopen state", source))?;
        let reopened = secure_file_metadata(&reopened)?;
        if !same_file_snapshot(&before, &reopened) {
            return Err(UpdateError::UnsafeTrustStore(
                "state file changed while it was read".to_owned(),
            ));
        }
        TrustedState::decode(&bytes).map(Some)
    }

    pub fn transaction(&self) -> Result<TrustStoreTransaction<'_>, UpdateError> {
        let lock = openat_confined(
            &self.parent,
            OsStr::new(".runtrue-update.lock"),
            lock_flags(),
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|source| trust_io("open state lock", source))?;
        secure_file_metadata(&lock)?;
        rustix::fs::flock(&lock, FlockOperation::LockExclusive)
            .map_err(|source| trust_io("lock state", source.into()))?;
        // Recheck after blocking: a hostile replacement while waiting must not
        // turn the retained descriptor into authority over a different inode.
        let retained = secure_file_metadata(&lock)?;
        let reopened = openat_confined(
            &self.parent,
            OsStr::new(".runtrue-update.lock"),
            read_write_flags(),
            Mode::empty(),
        )
        .map_err(|source| trust_io("reopen state lock", source))?;
        let reopened = secure_file_metadata(&reopened)?;
        if retained.dev() != reopened.dev() || retained.ino() != reopened.ino() {
            return Err(UpdateError::UnsafeTrustStore(
                "state lock changed while lock acquisition was pending".to_owned(),
            ));
        }
        self.parent
            .sync_all()
            .map_err(|source| trust_io("sync state-lock parent", source))?;
        Ok(TrustStoreTransaction {
            store: self,
            _lock: lock,
        })
    }

    fn commit_inner(&self, state: &TrustedState, create_only: bool) -> Result<(), UpdateError> {
        let bytes = state.canonical_bytes()?;
        if bytes.len() > MAX_TRUST_STATE_BYTES {
            return Err(UpdateError::MetadataTooLarge);
        }
        match openat_confined(&self.parent, &self.leaf, read_flags(), Mode::empty()) {
            Ok(existing) => {
                secure_file_metadata(&existing)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(trust_io("inspect existing state", source)),
        }
        let (temporary, mut file) = self.reserve_temporary()?;
        let result = (|| {
            file.write_all(&bytes)
                .map_err(|source| trust_io("write temporary state", source))?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| trust_io("set temporary state mode", source))?;
            file.sync_all()
                .map_err(|source| trust_io("sync temporary state", source))?;
            if create_only {
                rustix::fs::renameat_with(
                    &self.parent,
                    &temporary,
                    &self.parent,
                    &self.leaf,
                    RenameFlags::NOREPLACE,
                )
                .map_err(|source| trust_io("create state", source.into()))?;
            } else {
                rustix::fs::renameat(&self.parent, &temporary, &self.parent, &self.leaf)
                    .map_err(|source| trust_io("replace state", source.into()))?;
            }
            self.parent
                .sync_all()
                .map_err(|source| trust_io("sync state parent", source))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.parent, &temporary, AtFlags::empty());
        }
        result
    }

    pub fn write_new_signing_key(
        path: impl AsRef<Path>,
        key: &UpdateSigningKey,
    ) -> Result<(), UpdateError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(UpdateError::UnsafeTrustStore(
                "private key path must be absolute".to_owned(),
            ));
        }
        let parent_path = path
            .parent()
            .ok_or_else(|| UpdateError::UnsafeTrustStore("missing key parent".to_owned()))?;
        let leaf = path
            .file_name()
            .ok_or_else(|| UpdateError::UnsafeTrustStore("missing key filename".to_owned()))?;
        let parent = open_absolute_nofollow(parent_path, directory_flags(), Mode::empty())?;
        let metadata = parent
            .metadata()
            .map_err(|source| trust_io("inspect key parent", source))?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(UpdateError::UnsafeTrustStore(
                "private key parent is not private".to_owned(),
            ));
        }
        let mut file = openat_confined(
            &parent,
            leaf,
            create_flags(),
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|source| trust_io("create private key", source))?;
        let mut encoded = hex::encode(key.seed()).into_bytes();
        encoded.push(b'\n');
        let result = file
            .write_all(&encoded)
            .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o600)))
            .and_then(|()| file.sync_all());
        encoded.zeroize();
        if let Err(source) = result {
            let _ = rustix::fs::unlinkat(&parent, leaf, AtFlags::empty());
            let _ = parent.sync_all();
            return Err(trust_io("write private key", source));
        }
        parent
            .sync_all()
            .map_err(|source| trust_io("sync private key parent", source))
    }

    fn reserve_temporary(&self) -> Result<(OsString, File), UpdateError> {
        for _ in 0..32 {
            let mut random = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| UpdateError::RandomnessUnavailable)?;
            let name = OsString::from(format!(".runtrue-update-{}.tmp", hex::encode(random)));
            random.zeroize();
            match openat_confined(
                &self.parent,
                &name,
                create_flags(),
                Mode::from_bits_truncate(0o600),
            ) {
                Ok(file) => return Ok((name, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(trust_io("create temporary state", source)),
            }
        }
        Err(UpdateError::RandomnessUnavailable)
    }
}

impl TrustStoreTransaction<'_> {
    pub fn load(&self) -> Result<Option<TrustedState>, UpdateError> {
        self.store.load()
    }

    /// Atomically create the first trusted state. The final rename itself is
    /// no-replace, so a non-cooperating concurrent creator also fails closed.
    pub fn initialize(&self, state: &TrustedState) -> Result<(), UpdateError> {
        if self.store.load()?.is_some() {
            return Err(UpdateError::TrustStateAlreadyInitialized);
        }
        self.store.commit_inner(state, true).map_err(|error| {
            if matches!(
                &error,
                UpdateError::TrustStoreIo { source, .. }
                    if source.kind() == io::ErrorKind::AlreadyExists
            ) {
                UpdateError::TrustStateAlreadyInitialized
            } else {
                error
            }
        })
    }

    /// Replace trusted state only if its current canonical digest is exactly
    /// the state the caller verified. This prevents stale apply operations from
    /// overwriting a newer monotonic state.
    pub fn replace(&self, expected: &TrustedState, next: &TrustedState) -> Result<(), UpdateError> {
        let expected_digest = state_digest(expected)?;
        let current = self
            .store
            .load()?
            .ok_or(UpdateError::ConcurrentTrustStateChange)?;
        if state_digest(&current)? != expected_digest {
            return Err(UpdateError::ConcurrentTrustStateChange);
        }
        self.store.commit_inner(next, false)
    }
}

fn state_digest(state: &TrustedState) -> Result<ContentDigest, UpdateError> {
    Ok(ContentDigest::sha256(state.canonical_bytes()?))
}

fn secure_file_metadata(file: &File) -> Result<fs::Metadata, UpdateError> {
    let metadata = file
        .metadata()
        .map_err(|source| trust_io("inspect state", source))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(UpdateError::UnsafeTrustStore(
            "state must be a single-link mode-0600 regular file owned by the effective user"
                .to_owned(),
        ));
    }
    Ok(metadata)
}

fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn create_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn lock_flags() -> OFlags {
    OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn read_write_flags() -> OFlags {
    OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn trust_io(operation: &'static str, source: io::Error) -> UpdateError {
    UpdateError::TrustStoreIo { operation, source }
}
