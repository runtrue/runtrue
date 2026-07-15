pub(crate) fn bind_reusable_inputs(
    definitions: &BTreeMap<String, ast::InputDefinition>,
    provided: &BTreeMap<String, ast::Scalar>,
) -> Result<BTreeMap<String, ast::Scalar>, CompileError> {
    if let Some(unknown) = provided
        .keys()
        .find(|name| !definitions.contains_key(*name))
    {
        return Err(CompileError::semantic(
            format!("with.{unknown}"),
            format!("reusable workflow does not declare input `{unknown}`"),
        ));
    }
    let mut bound = BTreeMap::new();
    for (name, definition) in definitions {
        let value = provided.get(name).or(definition.default.as_ref());
        let Some(value) = value else {
            if definition.required {
                return Err(CompileError::semantic(
                    format!("with.{name}"),
                    format!("required reusable workflow input `{name}` is missing"),
                ));
            }
            continue;
        };
        if !scalar_matches_input(value, definition.kind) {
            return Err(CompileError::semantic(
                format!("with.{name}"),
                format!("value for `{name}` does not match its declared input type"),
            ));
        }
        if definition.kind == ast::InputType::Choice && !definition.options.contains(value) {
            return Err(CompileError::semantic(
                format!("with.{name}"),
                format!("value for choice input `{name}` is not an allowed option"),
            ));
        }
        bound.insert(name.clone(), value.clone());
    }
    Ok(bound)
}

pub(crate) struct ReusableContextMappings {
    pub(crate) jobs: BTreeMap<String, Option<String>>,
    pub(crate) outputs: BTreeMap<(String, String), ReusableOutputTarget>,
}

pub(crate) fn context_mappings(
    pieces: &BTreeMap<String, ReusableFragment>,
) -> ReusableContextMappings {
    let mut jobs = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for (source_id, piece) in pieces {
        let concrete = if !piece.call_boundary
            && piece.jobs.len() == 1
            && piece
                .public_outputs
                .values()
                .all(|output| piece.jobs.contains_key(&output.job))
        {
            piece.jobs.keys().next().cloned()
        } else {
            None
        };
        jobs.insert(source_id.clone(), concrete);
        for (name, target) in &piece.public_outputs {
            outputs.insert((source_id.clone(), name.clone()), target.clone());
        }
    }
    ReusableContextMappings { jobs, outputs }
}
use crate::{
    ast, scalar_matches_input, BTreeMap, CompileError, ReusableFragment, ReusableOutputTarget,
};
