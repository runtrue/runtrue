//! Static dependency graph validation.

use crate::EngineError;
use runtrue_workflow_ir::ExecutionCapsule;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate_acyclic(capsule: &ExecutionCapsule) -> Result<(), EngineError> {
    let mut indegree = capsule
        .jobs
        .iter()
        .map(|job| (job.id.as_str(), job.needs.len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect::<BTreeSet<_>>();
    let mut visited = 0_usize;

    while let Some(id) = ready.pop_first() {
        visited += 1;
        for job in &capsule.jobs {
            if !job.needs.iter().any(|dependency| dependency == id) {
                continue;
            }
            let degree = indegree
                .get_mut(job.id.as_str())
                .expect("all validated jobs have an indegree entry");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(job.id.as_str());
            }
        }
    }

    if visited == capsule.jobs.len() {
        Ok(())
    } else {
        Err(EngineError::DependencyCycle)
    }
}
