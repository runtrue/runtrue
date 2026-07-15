//! Canonical, security-conscious primitives shared by Runtrue crates.

mod byte_size;
mod content_digest;
mod duration;
mod error;
mod path;
mod secret_reference;

pub use byte_size::ByteSize;
pub use content_digest::{ContentDigest, DIGEST_ALGORITHM};
pub use duration::DurationMillis;
pub use error::ModelError;
pub use path::normalize_relative_path;
pub use secret_reference::SecretReference;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_qualified_and_validated() {
        let digest = ContentDigest::sha256(b"runtrue");
        assert_eq!(digest.as_str().len(), 71);
        assert_eq!(ContentDigest::parse(digest.to_string()).unwrap(), digest);
        assert!(ContentDigest::parse("sha256:ABC").is_err());
    }

    #[test]
    fn durations_are_normalized() {
        assert_eq!(
            DurationMillis::parse("2m").unwrap(),
            DurationMillis(120_000)
        );
        assert!(DurationMillis::parse("0s").is_err());
        assert!(DurationMillis::parse("forever").is_err());
    }

    #[test]
    fn paths_cannot_escape_the_workspace() {
        assert_eq!(
            normalize_relative_path("./target/report.xml").unwrap(),
            "target/report.xml"
        );
        assert!(normalize_relative_path("../secret").is_err());
        assert!(normalize_relative_path("/etc/passwd").is_err());
        assert!(normalize_relative_path("windows\\escape").is_err());
    }
}
