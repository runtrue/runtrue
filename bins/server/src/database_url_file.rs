use std::fs::{self, OpenOptions};
use std::io::{self, Read as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MAX_DATABASE_URL_BYTES: u64 = 8192;

#[derive(Debug, Error)]
pub enum DatabaseUrlFileError {
    #[error("PostgreSQL URL path `{0}` must be a normalized regular file without symbolic-link components")]
    UnsafePath(PathBuf),
    #[error("PostgreSQL URL file `{0}` must be owned by the current user, have exactly one link, and use mode 0600")]
    InsecureMetadata(PathBuf),
    #[error("PostgreSQL URL file `{0}` is empty or exceeds 8192 bytes")]
    InvalidSize(PathBuf),
    #[error("PostgreSQL URL file `{0}` must contain exactly one UTF-8 URL without whitespace")]
    InvalidContents(PathBuf),
    #[error("could not read PostgreSQL URL file `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Read a PostgreSQL credential without following links or retaining an
/// unprotected copy. The file identity is checked before and after opening to
/// close replacement races.
pub fn read_database_url_file(path: &Path) -> Result<Zeroizing<String>, DatabaseUrlFileError> {
    reject_unsafe_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_metadata(path, &metadata)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened = file.metadata().map_err(|source| io_error(path, source))?;
    validate_metadata(path, &opened)?;
    #[cfg(unix)]
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(DatabaseUrlFileError::UnsafePath(path.to_owned()));
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| DatabaseUrlFileError::InvalidSize(path.to_owned()))?,
    ));
    file.take(MAX_DATABASE_URL_BYTES + 1)
        .read_to_end(bytes.as_mut())
        .map_err(|source| io_error(path, source))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_DATABASE_URL_BYTES {
        return Err(DatabaseUrlFileError::InvalidSize(path.to_owned()));
    }
    std::str::from_utf8(bytes.as_slice())
        .map_err(|_| DatabaseUrlFileError::InvalidContents(path.to_owned()))?;
    let value = Zeroizing::new(
        String::from_utf8(std::mem::take(bytes.as_mut()))
            .expect("database URL bytes were validated as UTF-8"),
    );
    if value.chars().any(char::is_whitespace) {
        return Err(DatabaseUrlFileError::InvalidContents(path.to_owned()));
    }
    Ok(value)
}

fn reject_unsafe_components(path: &Path) -> Result<(), DatabaseUrlFileError> {
    if path.as_os_str().is_empty() {
        return Err(DatabaseUrlFileError::UnsafePath(path.to_owned()));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {
                current.push(component.as_os_str());
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata =
                    fs::symlink_metadata(&current).map_err(|source| io_error(path, source))?;
                if metadata.file_type().is_symlink() {
                    return Err(DatabaseUrlFileError::UnsafePath(path.to_owned()));
                }
            }
            Component::ParentDir => {
                return Err(DatabaseUrlFileError::UnsafePath(path.to_owned()));
            }
        }
    }
    Ok(())
}

fn validate_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), DatabaseUrlFileError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DatabaseUrlFileError::UnsafePath(path.to_owned()));
    }
    if metadata.len() == 0 || metadata.len() > MAX_DATABASE_URL_BYTES {
        return Err(DatabaseUrlFileError::InvalidSize(path.to_owned()));
    }
    #[cfg(unix)]
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(DatabaseUrlFileError::InsecureMetadata(path.to_owned()));
    }
    Ok(())
}

fn io_error(path: &Path, source: io::Error) -> DatabaseUrlFileError {
    DatabaseUrlFileError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn credential(contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("postgres.url");
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (directory, path)
    }

    #[test]
    fn accepts_one_exact_private_url() {
        let (_directory, path) =
            credential(b"postgresql://user:pass@localhost/runtrue?sslmode=disable");
        assert_eq!(
            read_database_url_file(&path).unwrap().as_str(),
            "postgresql://user:pass@localhost/runtrue?sslmode=disable"
        );
    }

    #[test]
    fn rejects_whitespace_empty_and_oversized_contents() {
        for contents in [
            b"".as_slice(),
            b" postgresql://localhost/db",
            b"postgresql://localhost/db\n",
        ] {
            let (_directory, path) = credential(contents);
            assert!(matches!(
                read_database_url_file(&path),
                Err(DatabaseUrlFileError::InvalidSize(_) | DatabaseUrlFileError::InvalidContents(_))
            ));
        }
        let (_directory, path) = credential(&vec![b'x'; MAX_DATABASE_URL_BYTES as usize + 1]);
        assert!(matches!(
            read_database_url_file(&path),
            Err(DatabaseUrlFileError::InvalidSize(_))
        ));
    }

    #[test]
    fn rejects_permissions_symbolic_links_and_hard_links() {
        let (directory, path) = credential(b"postgresql://localhost/db");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_database_url_file(&path),
            Err(DatabaseUrlFileError::InsecureMetadata(_))
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let symbolic = directory.path().join("symbolic.url");
        symlink(&path, &symbolic).unwrap();
        assert!(matches!(
            read_database_url_file(&symbolic),
            Err(DatabaseUrlFileError::UnsafePath(_))
        ));

        let hard = directory.path().join("hard.url");
        fs::hard_link(&path, &hard).unwrap();
        assert!(matches!(
            read_database_url_file(&path),
            Err(DatabaseUrlFileError::InsecureMetadata(_))
        ));
    }

    #[test]
    fn rejects_symbolic_linked_parent_directories() {
        let (directory, path) = credential(b"postgresql://localhost/db");
        let root = tempfile::tempdir().unwrap();
        let linked_parent = root.path().join("linked");
        symlink(directory.path(), &linked_parent).unwrap();
        assert!(matches!(
            read_database_url_file(&linked_parent.join(path.file_name().unwrap())),
            Err(DatabaseUrlFileError::UnsafePath(_))
        ));
    }
}
