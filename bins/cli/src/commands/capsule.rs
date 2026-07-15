use super::{
    super::{
        absolute, print_human_capsule, print_json, read_event, resolve_one_workflow,
        write_atomic_output, CapsuleArgs, CliError, EXIT_OK,
    },
    compile_path,
};
use std::path::Path;

pub(crate) fn capsule(workspace: &Path, args: CapsuleArgs) -> Result<u8, CliError> {
    let path = resolve_one_workflow(workspace, args.context.workflow)?;
    let event = read_event(args.context.event.as_deref(), workspace)?;
    let compilation = compile_path(
        workspace,
        &path,
        event,
        args.context.source_commit,
        args.context.base_commit,
        args.job,
    )?;

    if let Some(output) = args.output {
        let output = absolute(workspace, output);
        let bytes = compilation
            .capsule
            .canonical_bytes()
            .map_err(runtrue_compiler::CompileError::from)?;
        write_atomic_output(&output, &bytes)?;
    }
    if args.json {
        print_json(&compilation)?;
    } else {
        print_human_capsule(&compilation);
    }
    Ok(EXIT_OK)
}
