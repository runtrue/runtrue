use super::*;
use runtrue_lock::LockFile;

const SUPPORTED: &str = include_str!("../../tests/fixtures/supported.yml");
const UNSAFE: &str = include_str!("../../tests/fixtures/unsafe.yml");
const DUPLICATE: &str = include_str!("../../tests/fixtures/duplicate.yml");
const GITHUB_ONLY: &str = include_str!("../../tests/fixtures/github_only.yml");

mod frontend;
mod lockfile;
mod repository_action;
mod security;
mod supported;
mod unsupported;
