//! Deterministic execution-capsule representation.
//!
//! The v0.x contract uses compact, recursively key-sorted JSON for hashing and
//! signing. Compatibility is scoped to the declared compiler and engine
//! generation; it is not yet a frozen cross-language transport encoding.

mod artifacts;
mod capabilities;
mod capsule;
mod context;
mod error;
mod jobs;
mod matrix;
mod outputs;
mod permissions;
mod steps;

pub use artifacts::*;
pub use capabilities::*;
pub use capsule::*;
pub use context::*;
pub use error::*;
pub use jobs::*;
pub use matrix::*;
pub use outputs::*;
pub use permissions::*;
pub use steps::*;

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_model::ContentDigest;
    use std::collections::BTreeMap;

    #[test]
    fn recursive_canonicalization_sorts_keys() {
        let value = serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}});
        let encoded = serde_json::to_string(&canonicalize_value(value)).unwrap();
        assert_eq!(encoded, r#"{"a":{"b":3,"y":2},"z":1}"#);
    }

    #[test]
    fn scalar_display_is_stable() {
        assert_eq!(ScalarValue::Boolean(true).to_string(), "true");
        assert_eq!(ScalarValue::Integer(7).to_string(), "7");
    }

    #[test]
    fn scalar_decoder_rejects_inexact_overflow_integers() {
        for value in ["9223372036854775808", "9223372036854775809"] {
            let error = serde_json::from_str::<ScalarValue>(value)
                .unwrap_err()
                .to_string();
            assert!(error.contains("signed 64-bit range"), "{error}");
        }
    }

    #[test]
    fn runtime_context_trust_classification_is_explicit() {
        let event = ValueBinding::Context(ContextBinding {
            from: "event.payload".to_owned(),
        });
        let matrix = ValueBinding::Context(ContextBinding {
            from: "matrix.mode".to_owned(),
        });
        assert!(event.is_untrusted_runtime_context());
        assert!(!matrix.is_untrusted_runtime_context());
    }

    #[test]
    fn historical_signing_fields_decode_and_reencode_as_default_deny() {
        let historical_step = serde_json::json!({
            "fs_read": [], "fs_write": [], "network": {"mode": "deny"},
            "secrets": [], "checks": "deny", "artifacts": "deny",
            "cache_read": "deny", "cache_write": "deny", "oidc_audiences": []
        });
        let capabilities: StepCapabilitySet =
            serde_json::from_value(historical_step.clone()).unwrap();
        assert!(capabilities.signing.is_empty());
        assert_eq!(
            serde_json::to_value(&capabilities).unwrap(),
            historical_step
        );

        let historical_job_capability = serde_json::json!({
            "purpose": "release-artifact", "operation": "sign-digest"
        });
        let capability: SigningCapability =
            serde_json::from_value(historical_job_capability.clone()).unwrap();
        assert!(capability.key_policy.is_empty());
        assert_eq!(
            serde_json::to_value(&capability).unwrap(),
            historical_job_capability
        );
        assert!(!capabilities.allows_signing(&capability));
    }

    #[test]
    fn signing_authorization_is_an_exact_three_part_identity() {
        let allowed = SigningCapability {
            purpose: "release-artifact".to_owned(),
            operation: SigningOperation::SignDigest,
            key_policy: "production-release-v1".to_owned(),
        };
        let capabilities = StepCapabilitySet {
            signing: vec![allowed.clone()],
            ..StepCapabilitySet::default()
        };
        assert!(capabilities.allows_signing(&allowed));
        for denied in [
            SigningCapability {
                purpose: "release-attestation".to_owned(),
                ..allowed.clone()
            },
            SigningCapability {
                operation: SigningOperation::SignAttestation,
                ..allowed.clone()
            },
            SigningCapability {
                key_policy: "another-policy".to_owned(),
                ..allowed.clone()
            },
        ] {
            assert!(!capabilities.allows_signing(&denied));
        }
    }

    #[test]
    fn source_trust_is_fail_closed_for_legacy_contexts_and_always_serialized() {
        let context: CapsuleContext = serde_json::from_value(serde_json::json!({
            "source_commit": "abc",
            "normalized_event_digest": ContentDigest::sha256(b"event"),
            "event_context": {}, "policy_version_ids": []
        }))
        .unwrap();
        assert_eq!(context.source_trust, SourceTrust::Untrusted);
        assert_eq!(
            serde_json::to_value(&context).unwrap()["source_trust"],
            "untrusted"
        );
    }

    #[test]
    fn source_trust_satisfies_only_equal_or_lower_job_floors() {
        assert!(SourceTrust::Untrusted.satisfies(Trust::UntrustedOk));
        assert!(!SourceTrust::Untrusted.satisfies(Trust::TrustedOnly));
        assert!(SourceTrust::Trusted.satisfies(Trust::TrustedOnly));
        assert!(!SourceTrust::Trusted.satisfies(Trust::ProtectedBranchOnly));
        assert!(SourceTrust::ProtectedBranch.satisfies(Trust::ProtectedBranchOnly));
    }

    #[test]
    fn shared_matrix_expansion_is_canonical_bounded_and_order_independent() {
        let left = BTreeMap::from([
            (
                "mode".to_owned(),
                vec![
                    ScalarValue::String("release".to_owned()),
                    ScalarValue::String("debug".to_owned()),
                    ScalarValue::String("debug".to_owned()),
                ],
            ),
            (
                "arch".to_owned(),
                vec![ScalarValue::String("amd64".to_owned())],
            ),
        ]);
        let right = BTreeMap::from([
            (
                "arch".to_owned(),
                vec![ScalarValue::String("amd64".to_owned())],
            ),
            (
                "mode".to_owned(),
                vec![
                    ScalarValue::String("debug".to_owned()),
                    ScalarValue::String("release".to_owned()),
                ],
            ),
        ]);
        let left = expand_matrix_values("build", &left, 2).unwrap();
        let right = expand_matrix_values("build", &right, 2).unwrap();
        assert_eq!(left, right);
        assert_eq!(left[0].0, "build[0]");
        assert!(matches!(
            expand_matrix_values(
                "build",
                &BTreeMap::from([(
                    "axis".to_owned(),
                    vec![ScalarValue::Integer(1), ScalarValue::Integer(2)]
                )]),
                1
            ),
            Err(MatrixExpansionError::LimitExceeded(1))
        ));
    }

    #[test]
    fn dynamic_matrix_rejects_non_scalar_and_changed_input_changes_identity() {
        let template = DynamicJobTemplate {
            id: "build".to_owned(),
            source: DynamicMatrixSource {
                producer_job_id: "generate".to_owned(),
                output_name: "matrix".to_owned(),
                maximum_jobs: 4,
            },
            template: test_job("build"),
        };
        let capsule_digest = ContentDigest::sha256(b"capsule");
        let first = expand_dynamic_job_set(
            capsule_digest.clone(),
            &template,
            &serde_json::json!({"mode": ["debug", "release"]}),
            7,
        )
        .unwrap();
        let changed = expand_dynamic_job_set(
            capsule_digest,
            &template,
            &serde_json::json!({"mode": ["release", "debug"]}),
            7,
        )
        .unwrap();
        assert_ne!(first.matrix_input_digest, changed.matrix_input_digest);
        let replay = expand_dynamic_job_set(
            ContentDigest::sha256(b"capsule"),
            &template,
            &serde_json::json!({"mode": ["debug", "release"]}),
            7,
        )
        .unwrap();
        assert_eq!(
            first.canonical_bytes().unwrap(),
            replay.canonical_bytes().unwrap()
        );
        assert_eq!(first.generated_job_ids, ["build[0]", "build[1]"]);
        assert!(first
            .jobs
            .iter()
            .all(|job| job.permissions == template.template.permissions
                && job.runner == template.template.runner
                && job.needs == template.template.needs
                && job.steps == template.template.steps
                && job.finalizers == template.template.finalizers));
        assert!(matches!(
            expand_dynamic_job_set(
                ContentDigest::sha256(b"capsule"),
                &template,
                &serde_json::json!({"mode": [{"nested": true}]}),
                7
            ),
            Err(MatrixExpansionError::InvalidScalar)
        ));
        assert!(matches!(
            expand_dynamic_job_set(
                ContentDigest::sha256(b"capsule"),
                &template,
                &serde_json::json!({"mode": [u64::MAX]}),
                7
            ),
            Err(MatrixExpansionError::InvalidScalar)
        ));
        let mut preexpanded = template.clone();
        preexpanded
            .template
            .matrix
            .insert("injected".to_owned(), ScalarValue::Boolean(true));
        assert!(matches!(
            expand_dynamic_job_set(
                ContentDigest::sha256(b"capsule"),
                &preexpanded,
                &serde_json::json!({"mode": ["debug"]}),
                7
            ),
            Err(MatrixExpansionError::TemplateMatrixNotEmpty)
        ));
        let mut detached = template;
        detached.template.needs.clear();
        assert!(matches!(
            expand_dynamic_job_set(
                ContentDigest::sha256(b"capsule"),
                &detached,
                &serde_json::json!({"mode": ["debug"]}),
                7
            ),
            Err(MatrixExpansionError::ProducerDependencyMissing)
        ));
    }

    fn test_job(id: &str) -> PlannedJob {
        PlannedJob {
            id: id.to_owned(),
            base_id: id.to_owned(),
            name: id.to_owned(),
            needs: vec!["generate".to_owned()],
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::UntrustedOk,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Wasm,
                image: None,
                cpu: 1,
                memory_bytes: 1,
                storage_bytes: None,
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 1,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
            finalizers: Vec::new(),
            finalizer_timeout_ms: 1,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }
    }
}
