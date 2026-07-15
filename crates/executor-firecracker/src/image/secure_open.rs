use crate::{artifact_io, FirecrackerError};
#[cfg(unix)]
use nix::{
    fcntl::{open, openat, OFlag},
    sys::stat::Mode,
    unistd::close,
};
use std::path::{Component, Path};
pub(super) struct RawDescriptor(i32);

#[cfg(unix)]
impl RawDescriptor {
    pub(super) const fn raw(&self) -> i32 {
        self.0
    }
}

#[cfg(unix)]
impl Drop for RawDescriptor {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

#[cfg(unix)]
pub(super) fn open_without_symlinks(path: &Path) -> Result<RawDescriptor, FirecrackerError> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(FirecrackerError::UnsafeArtifact {
            path: path.to_owned(),
            reason: "path must be absolute".to_owned(),
        });
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(FirecrackerError::UnsafeArtifact {
                path: path.to_owned(),
                reason: "path contains a non-normal component".to_owned(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (file_name, directories) =
        names
            .split_last()
            .ok_or_else(|| FirecrackerError::UnsafeArtifact {
                path: path.to_owned(),
                reason: "artifact path cannot be the filesystem root".to_owned(),
            })?;
    let mut directory = RawDescriptor(
        open(
            Path::new("/"),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| artifact_io(path, nix_io(error)))?,
    );
    for name in directories {
        let next = RawDescriptor(
            openat(
                directory.raw(),
                *name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| artifact_io(path, nix_io(error)))?,
        );
        directory = next;
    }
    let file = openat(
        directory.raw(),
        *file_name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| artifact_io(path, nix_io(error)))?;
    Ok(RawDescriptor(file))
}

#[cfg(unix)]
pub(super) fn nix_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}
