use super::super::*;

#[test]
fn reusable_source_bundle_remains_bounded() {
    let oversized = vec![0_u8; MAX_REUSABLE_SOURCE_BYTES + 1];
    assert!(matches!(
        ReusableWorkflowSource::new("0123456789abcdef", oversized),
        Err(ReusableSourceBundleError::SourceTooLarge { .. })
    ));
}
