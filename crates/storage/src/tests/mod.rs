use crate::secure_io::*;
use crate::*;
use runtrue_model::ContentDigest;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs,
    io::{Cursor, Read},
    path::PathBuf,
    sync::Arc,
    thread,
};
use tempfile::tempdir;

fn test_cas() -> (tempfile::TempDir, FsCas) {
    let directory = tempdir().unwrap();
    let cas = FsCas::open(directory.path().join("cas"), CasLimits::default()).unwrap();
    (directory, cas)
}

fn object_path(cas: &FsCas, digest: &ContentDigest) -> PathBuf {
    cas.object_path(digest).unwrap()
}

mod blob;
mod capture;
mod corruption;
mod materialize;
mod symlink;
mod traversal;
