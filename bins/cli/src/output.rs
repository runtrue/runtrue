use super::CliError;
use runtrue_compiler::Compilation;
use runtrue_engine::ExecutionResult;
use runtrue_runtime_local::LocalArtifactCapture;
use serde::Serialize;
use std::io::{self, Write as _};

pub(super) fn print_human_capsule(compilation: &Compilation) {
    println!("Capsule:             {}", compilation.capsule_digest);
    println!("Approval subject: {}", compilation.approval_subject_digest);
    println!("Workflow:         {}", compilation.capsule.workflow.name);
    println!(
        "Expected parity:  {:?}",
        compilation.capsule.expected_parity
    );
    println!(
        "Risk:             {} ({:?})",
        compilation.risk_report.score, compilation.risk_report.highest_severity
    );
    println!("Jobs:");
    for job in &compilation.capsule.jobs {
        println!(
            "  {:<24} isolation={:?} steps={} needs={}",
            job.id,
            job.runner.isolation,
            job.steps.len(),
            if job.needs.is_empty() {
                "-".to_owned()
            } else {
                job.needs.join(",")
            }
        );
    }
    for finding in &compilation.risk_report.findings {
        println!(
            "{:?} {} {}: {}",
            finding.severity, finding.code, finding.path, finding.message
        );
    }
}

pub(super) fn print_human_run(
    compilation: &Compilation,
    result: &ExecutionResult,
    artifacts: &[LocalArtifactCapture],
) -> Result<(), CliError> {
    println!("Capsule: {}", compilation.capsule_digest);
    print_execution_result(result)?;
    print_human_artifacts(artifacts);
    Ok(())
}

pub(super) fn print_human_artifacts(artifacts: &[LocalArtifactCapture]) {
    for artifact in artifacts {
        println!(
            "artifact {}.{}: {}  {}",
            artifact.job_id, artifact.output_name, artifact.artifact_id, artifact.source_path
        );
    }
}

pub(super) fn print_execution_result(result: &ExecutionResult) -> Result<(), CliError> {
    for job in result.jobs.values() {
        for attempt in &job.attempts {
            for step in &attempt.steps {
                if let Some(output) = &step.output {
                    print!("{}", output.stdout);
                    io::stdout().flush().map_err(CliError::Output)?;
                    eprint!("{}", output.stderr);
                }
            }
        }
        println!("job {}: {:?}", job.id, job.state);
    }
    println!("run: {:?}", result.state);
    Ok(())
}

pub(super) fn print_json(value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer_pretty(io::stdout().lock(), value)?;
    println!();
    Ok(())
}
