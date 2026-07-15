use super::fixtures::{backend, capsule, output, ScriptedExecutor};
use crate::{observe_backend, BisimError, SecretCanary};
use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use std::collections::VecDeque;

#[test]
fn plain_hex_and_base64_secret_canaries_are_detected() {
    let canary = SecretCanary::new(b"high-entropy-secret-canary".to_vec()).unwrap();
    for leaked in [
        String::from_utf8(canary.as_bytes().to_vec()).unwrap(),
        hex::encode(canary.as_bytes()),
        Base64::encode_string(canary.as_bytes()),
        Base64UrlUnpadded::encode_string(canary.as_bytes()),
    ] {
        assert!(matches!(
            observe_backend(
                &capsule(),
                backend(),
                ScriptedExecutor {
                    outputs: VecDeque::from([output(&leaked, 0)]),
                },
                &[SecretCanary::new(b"high-entropy-secret-canary".to_vec()).unwrap()],
            ),
            Err(BisimError::SecretCanaryLeak { .. })
        ));
    }
    assert_eq!(format!("{canary:?}"), "SecretCanary(<redacted>)");
}
