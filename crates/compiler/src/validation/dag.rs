pub(crate) fn validate_dag(workflow: &ast::Workflow) -> Result<(), CompileError> {
    for (job_id, job) in &workflow.jobs {
        let mut unique = BTreeSet::new();
        for dependency in &job.needs {
            if !workflow.jobs.contains_key(dependency) {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.needs"),
                    format!("unknown dependency `{dependency}`"),
                ));
            }
            if dependency == job_id {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.needs"),
                    "job cannot depend on itself",
                ));
            }
            if !unique.insert(dependency) {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.needs"),
                    format!("duplicate dependency `{dependency}`"),
                ));
            }
        }
    }

    fn visit(
        id: &str,
        workflow: &ast::Workflow,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), CompileError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(CompileError::semantic(
                format!("jobs.{id}.needs"),
                format!("dependency cycle includes `{id}`"),
            ));
        }
        for dependency in &workflow.jobs[id].needs {
            visit(dependency, workflow, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id.to_owned());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in workflow.jobs.keys() {
        visit(id, workflow, &mut visiting, &mut visited)?;
    }
    Ok(())
}
use crate::{ast, BTreeSet, CompileError};
