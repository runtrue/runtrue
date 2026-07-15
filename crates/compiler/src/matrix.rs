pub(crate) struct MatrixExpansion {
    pub(crate) id: String,
    pub(crate) values: BTreeMap<String, ir::ScalarValue>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExpandedReusableWorkflows {
    pub(crate) workflow: ast::Workflow,
    pub(crate) identities: Vec<ReusableWorkflowIdentity>,
    pub(crate) references: BTreeSet<String>,
    pub(crate) selection_aliases: BTreeMap<String, Vec<String>>,
    pub(crate) reusable_digests: Vec<String>,
}

pub(crate) fn expand_all_matrices(
    workflow: &ast::Workflow,
    limit: usize,
) -> Result<BTreeMap<String, Vec<MatrixExpansion>>, CompileError> {
    let mut total = 0usize;
    let mut result = BTreeMap::new();
    for (job_id, job) in &workflow.jobs {
        let expanded = expand_matrix(job_id, &job.matrix, limit)?;
        total = total.saturating_add(expanded.len());
        if total > MAX_WORKFLOW_JOBS {
            return Err(CompileError::semantic(
                "jobs",
                format!("expanded workflow exceeds the {MAX_WORKFLOW_JOBS} job limit"),
            ));
        }
        result.insert(job_id.clone(), expanded);
    }
    Ok(result)
}

pub(crate) fn expand_matrix(
    job_id: &str,
    matrix: &BTreeMap<String, Vec<ast::Scalar>>,
    limit: usize,
) -> Result<Vec<MatrixExpansion>, CompileError> {
    let mut axes = BTreeMap::new();
    for (axis, values) in matrix {
        validate_identifier(axis, &format!("jobs.{job_id}.matrix.{axis}"))?;
        let normalized_values = values
            .iter()
            .map(|value| convert_scalar(value, &format!("jobs.{job_id}.matrix.{axis}")))
            .collect::<Result<Vec<_>, CompileError>>()?;
        axes.insert(axis.clone(), normalized_values);
    }
    ir::expand_matrix_values(job_id, &axes, limit)
        .map(|expanded| {
            expanded
                .into_iter()
                .map(|(id, values)| MatrixExpansion { id, values })
                .collect()
        })
        .map_err(|error| CompileError::semantic(format!("jobs.{job_id}.matrix"), error.to_string()))
}
use super::{
    ast, convert_scalar, ir, validate_identifier, BTreeMap, BTreeSet, CompileError,
    ReusableWorkflowIdentity, MAX_WORKFLOW_JOBS,
};
