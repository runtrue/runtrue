use super::super::*;

#[test]
fn semantic_risk_diff_remains_part_of_the_public_api() {
    let _diff: fn(
        &runtrue_workflow_ir::ExecutionCapsule,
        &runtrue_workflow_ir::ExecutionCapsule,
    ) -> RiskReport = semantic_risk_diff;
}
