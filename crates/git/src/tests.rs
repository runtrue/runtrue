use crate::*;
use runtrue_model::ContentDigest;
use std::process::Command;
use std::{fs, path::Path};
use tempfile::TempDir;

struct Fixture {
    directory: TempDir,
    base: String,
    source: String,
}

impl Fixture {
    fn create() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        git(directory.path(), &["init", "--quiet"]);
        git(
            directory.path(),
            &["config", "user.email", "test@runtrue.invalid"],
        );
        git(directory.path(), &["config", "user.name", "Runtrue Test"]);
        fs::create_dir_all(directory.path().join(".runtrue/workflows"))
            .expect("workflow directory");
        fs::write(
            directory.path().join(".runtrue/workflows/ci.yaml"),
            b"version: 1\nname: trusted-base\n",
        )
        .expect("base workflow");
        fs::create_dir_all(directory.path().join("src")).expect("src");
        fs::write(directory.path().join("src/z.txt"), b"base\n").expect("base file");
        git(directory.path(), &["add", "."]);
        git(directory.path(), &["commit", "--quiet", "-m", "base"]);
        let base = git_output(directory.path(), &["rev-parse", "HEAD"]);

        fs::write(
            directory.path().join(".runtrue/workflows/ci.yaml"),
            b"version: 1\nname: proposed-untrusted\n",
        )
        .expect("proposed workflow");
        fs::write(directory.path().join("src/a.txt"), b"added\n").expect("added");
        fs::write(directory.path().join("large.bin"), vec![b'x'; 4096]).expect("large");
        #[cfg(unix)]
        std::os::unix::fs::symlink("src/a.txt", directory.path().join("linked")).expect("symlink");
        git(directory.path(), &["add", "."]);
        git(directory.path(), &["commit", "--quiet", "-m", "source"]);
        let source = git_output(directory.path(), &["rev-parse", "HEAD"]);
        Self {
            directory,
            base,
            source,
        }
    }

    fn repository(&self) -> GitRepository {
        GitRepository::open(self.directory.path(), GitLimits::default()).expect("repository")
    }
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

fn git_output(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git command");
    assert!(output.status.success(), "git {arguments:?}");
    String::from_utf8(output.stdout)
        .expect("UTF-8")
        .trim()
        .to_owned()
}

fn create_submodule_repository(origin: &str, contents: &[u8]) -> (TempDir, String) {
    let directory = tempfile::tempdir().expect("submodule tempdir");
    git(directory.path(), &["init", "--quiet"]);
    git(
        directory.path(),
        &["config", "user.email", "submodule@runtrue.invalid"],
    );
    git(
        directory.path(),
        &["config", "user.name", "Runtrue Submodule Test"],
    );
    git(directory.path(), &["remote", "add", "origin", origin]);
    fs::write(directory.path().join("nested.txt"), contents).expect("nested source");
    git(directory.path(), &["add", "nested.txt"]);
    git(
        directory.path(),
        &["commit", "--quiet", "-m", "nested source"],
    );
    let commit = git_output(directory.path(), &["rev-parse", "HEAD"]);
    (directory, commit)
}

fn add_gitlink(root: &Path, path: &str, origin: &str, commit: &str) -> String {
    fs::write(
        root.join(".gitmodules"),
        format!("[submodule \"locked\"]\n\tpath = {path}\n\turl = {origin}\n"),
    )
    .expect("gitmodules");
    git(root, &["add", ".gitmodules"]);
    let cache_info = format!("160000,{commit},{path}");
    git(root, &["update-index", "--add", "--cacheinfo", &cache_info]);
    git(root, &["commit", "--quiet", "-m", "locked submodule"]);
    git_output(root, &["rev-parse", "HEAD"])
}

fn normalized_origin(value: &str) -> NormalizedOrigin {
    OriginPolicy::new(["git.example.com".to_owned()])
        .expect("origin policy")
        .normalize(value)
        .expect("normalized origin")
}

mod repository;
mod snapshot;
mod submodules;
