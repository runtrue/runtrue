//! Strict parsing, canonicalization, and admission for `.runtrue.lock`.
//!
//! Lock input is bounded and decoded with duplicate-key and unknown-field
//! rejection. Parsed entries are validated, sorted, and immutable; consumers
//! bind the digest of canonical JSON bytes rather than the original TOML text.

mod diff;
mod error;
mod model;
mod parse;
mod raw;
mod requirements;
mod resolution;
mod validation;

pub use diff::{LockChange, LockChangeKind};
pub use error::LockError;
pub use model::{
    ComponentEntry, EntryKind, ImageEntry, LockFile, WorkflowEntry, LOCK_VERSION,
    MAX_LOCKFILE_BYTES,
};
pub use requirements::{ImageRequirement, LockRequirements};
pub use resolution::{ResolvedLock, ResolvedWorkflow};

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn component(source: &str, digest: &str) -> String {
        format!(
            r#"[[component]]
source = "{source}"
resolved = "sha256:{digest}"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"
"#
        )
    }

    fn image(source: &str, digest: &str) -> String {
        format!(
            r#"[[image]]
source = "{source}"
resolved = "registry.example/team/image@sha256:{digest}"
platform = "linux/amd64"
"#
        )
    }

    #[test]
    fn reordered_entries_have_identical_canonical_bytes_and_digest() {
        let first = format!(
            "lock_version = 1\n{}{}",
            component("wasm://registry.example/action@v1", A),
            image("registry.example/team/image:v1", B)
        );
        let second = format!(
            "lock_version = 1\n{}{}",
            image("registry.example/team/image:v1", B),
            component("wasm://registry.example/action@v1", A)
        );
        let first = LockFile::parse(first.as_bytes()).unwrap();
        let second = LockFile::parse(second.as_bytes()).unwrap();
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn duplicate_and_unknown_toml_fields_fail_closed() {
        for source in [
            "lock_version = 1\nlock_version = 1\n",
            "lock_version = 1\nunknown = true\n",
            &format!(
                "lock_version = 1\n{}{}",
                component("wasm://registry.example/action@v1", A),
                component("wasm://registry.example/action@v1", B)
            ),
            &format!(
                "lock_version = 1\n{}{}",
                component("wasm://registry.example/action-one@v1", A),
                component("wasm://registry.example/action-two@v1", A)
            ),
        ] {
            assert!(LockFile::parse(source.as_bytes()).is_err(), "{source}");
        }
    }

    #[test]
    fn parser_enforces_the_byte_bound_before_toml_decoding() {
        let oversized = vec![b'x'; MAX_LOCKFILE_BYTES + 1];
        assert!(matches!(
            LockFile::parse(&oversized),
            Err(LockError::TooLarge { .. })
        ));
    }

    #[test]
    fn mutable_or_truncated_resolutions_are_rejected() {
        for resolved in [
            "registry.example/team/image:latest",
            "registry.example/team/image@sha256:abcd",
            "registry.example/team/image@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let source = format!(
                r#"lock_version = 1
[[image]]
source = "registry.example/team/image:v1"
resolved = "{resolved}"
platform = "linux/amd64"
"#
            );
            assert!(LockFile::parse(source.as_bytes()).is_err(), "{resolved}");
        }
        let truncated_component = r#"lock_version = 1
[[component]]
source = "wasm://registry.example/action@v1"
resolved = "sha256:abcd"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0"
"#;
        assert!(LockFile::parse(truncated_component.as_bytes()).is_err());
    }

    #[test]
    fn resolution_requires_exact_capsule_match_and_rejects_unused_entries() {
        let source = format!(
            "lock_version = 1\n{}{}",
            component("wasm://registry.example/action@v1", A),
            image("registry.example/team/image:v1", B)
        );
        let lock = LockFile::parse(source.as_bytes()).unwrap();

        let mut missing = LockRequirements::default();
        missing.require_component("wasm://registry.example/other@v1");
        assert!(matches!(
            lock.resolve(&missing),
            Err(LockError::MissingEntry { .. })
        ));

        let mut unused = LockRequirements::default();
        unused.require_component("wasm://registry.example/action@v1");
        assert!(matches!(
            lock.resolve(&unused),
            Err(LockError::UnusedImageEntry { .. })
        ));

        let mut exact = LockRequirements::default();
        exact.require_component("wasm://registry.example/action@v1");
        exact.require_image("registry.example/team/image:v1", "linux/amd64");
        let resolved = lock.resolve(&exact).unwrap();
        assert_eq!(
            resolved.component("wasm://registry.example/action@v1"),
            Some(format!("wasm://registry.example/action@sha256:{A}").as_str())
        );
    }

    #[test]
    fn signature_wit_platform_and_workflow_metadata_are_strict() {
        let bad_identity = component("wasm://registry.example/action@v1", A)
            .replace("release@runtrue.example", "not-an-identity");
        let bad_wit = component("wasm://registry.example/action@v1", A)
            .replace("runtrue:action/run@1.0.0", "action/run@v1");
        let bad_platform =
            image("registry.example/team/image:v1", B).replace("linux/amd64", "linux/x86_64");
        for entry in [bad_identity, bad_wit, bad_platform] {
            let source = format!("lock_version = 1\n{entry}");
            assert!(LockFile::parse(source.as_bytes()).is_err());
        }

        let workflow = format!(
            r#"lock_version = 1
[[workflow]]
source = "git+https://example/reusable.git//build.yaml@v3"
commit = "{}"
digest = "sha256:{A}"
"#,
            "c".repeat(40)
        );
        let workflow_lock = LockFile::parse(workflow.as_bytes()).unwrap();
        let mut requirements = LockRequirements::default();
        requirements.require_workflow("git+https://example/reusable.git//build.yaml@v3");
        let resolved = workflow_lock.resolve(&requirements).unwrap();
        assert_eq!(
            resolved
                .workflow("git+https://example/reusable.git//build.yaml@v3")
                .unwrap()
                .commit,
            "c".repeat(40)
        );
        assert!(LockFile::parse(workflow.replace(&"c".repeat(40), "abcd").as_bytes()).is_err());
    }

    #[test]
    fn security_diff_classifies_resolution_and_metadata_changes() {
        let base = LockFile::parse(
            format!(
                "lock_version = 1\n{}",
                component("wasm://registry.example/action@v1", A)
            )
            .as_bytes(),
        )
        .unwrap();
        let resolution = LockFile::parse(
            format!(
                "lock_version = 1\n{}",
                component("wasm://registry.example/action@v1", B)
            )
            .as_bytes(),
        )
        .unwrap();
        let metadata = LockFile::parse(
            format!(
                "lock_version = 1\n{}",
                component("wasm://registry.example/action@v1", A)
                    .replace("release@runtrue.example", "security@runtrue.example")
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            base.security_changes(&resolution)[0].change,
            LockChangeKind::ResolutionChanged
        );
        assert_eq!(
            base.security_changes(&metadata)[0].change,
            LockChangeKind::MetadataChanged
        );
        assert!(base
            .security_changes(&metadata)
            .iter()
            .all(|change| change.security_sensitive));
    }
}
