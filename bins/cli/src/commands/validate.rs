use super::{
    super::{
        absolute, discover_workflows, display_path, print_json, read_event, CliError, ValidateArgs,
        EXIT_OK,
    },
    compile_path,
};
use serde::Serialize;
use std::path::Path;

pub(crate) fn validate(workspace: &Path, args: ValidateArgs) -> Result<u8, CliError> {
    let workflows = if let Some(workflow) = args.workflow {
        vec![absolute(workspace, workflow)]
    } else {
        discover_workflows(workspace)?
    };
    let event = read_event(args.event.as_deref(), workspace)?;
    let mut validated = Vec::new();
    for workflow in workflows {
        let compilation = compile_path(
            workspace,
            &workflow,
            event.clone(),
            args.source_commit.clone(),
            args.base_commit.clone(),
            None,
        )?;
        validated.push(ValidatedWorkflow {
            path: display_path(workspace, &workflow),
            capsule_digest: compilation.capsule_digest.to_string(),
            approval_subject_digest: compilation.approval_subject_digest.to_string(),
            jobs: compilation.capsule.jobs.len(),
            risk_score: compilation.risk_report.score,
        });
    }

    if args.json {
        print_json(&ValidationReport {
            valid: true,
            workflows: validated,
        })?;
    } else {
        for result in &validated {
            println!(
                "valid  {}  {}  jobs={} risk={}",
                result.capsule_digest, result.path, result.jobs, result.risk_score
            );
        }
    }
    Ok(EXIT_OK)
}

#[derive(Debug, Serialize)]
struct ValidationReport {
    valid: bool,
    workflows: Vec<ValidatedWorkflow>,
}

#[derive(Debug, Serialize)]
struct ValidatedWorkflow {
    path: String,
    capsule_digest: String,
    approval_subject_digest: String,
    jobs: usize,
    risk_score: u32,
}
