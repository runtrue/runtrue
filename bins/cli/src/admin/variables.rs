use super::{
    secure_fs::{
        ensure_runtrue_directory, print_json, read_regular_file, secure_file_exists, validate_name,
        validate_variable_value, write_private_atomic,
    },
    AdminError, VarDeleteArgs, VarGetArgs, VarSetArgs, MAX_VARIABLE_STATE_BYTES,
    VARIABLE_STATE_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) fn var_set(workspace: &Path, args: VarSetArgs) -> Result<(), AdminError> {
    validate_name(&args.name)?;
    validate_variable_value(&args.value)?;
    let (mut state, path) = load_variable_state(workspace, true)?;
    let (operation, version) = match state.variables.get(&args.name) {
        Some(existing) => (
            "updated",
            existing
                .version
                .checked_add(1)
                .ok_or(AdminError::VariableVersionOverflow)?,
        ),
        None => ("created", 1),
    };
    state.variables.insert(
        args.name.clone(),
        VariableRecord {
            value: args.value.clone(),
            version,
        },
    );
    persist_variable_state(&path, &state)?;
    print_variable_result(operation, &args.name, version, Some(&args.value), args.json)
}

pub(super) fn var_get(workspace: &Path, args: VarGetArgs) -> Result<(), AdminError> {
    validate_name(&args.name)?;
    let (state, _) = load_variable_state(workspace, false)?;
    let record = state
        .variables
        .get(&args.name)
        .ok_or_else(|| AdminError::VariableNotFound(args.name.clone()))?;
    print_variable_result(
        "read",
        &args.name,
        record.version,
        Some(&record.value),
        args.json,
    )
}

pub(super) fn var_delete(workspace: &Path, args: VarDeleteArgs) -> Result<(), AdminError> {
    validate_name(&args.name)?;
    let (mut state, path) = load_variable_state(workspace, false)?;
    let removed = state
        .variables
        .remove(&args.name)
        .ok_or_else(|| AdminError::VariableNotFound(args.name.clone()))?;
    persist_variable_state(&path, &state)?;
    print_variable_result("deleted", &args.name, removed.version, None, args.json)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariableState {
    state_version: u32,
    variables: BTreeMap<String, VariableRecord>,
}

impl Default for VariableState {
    fn default() -> Self {
        Self {
            state_version: VARIABLE_STATE_VERSION,
            variables: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariableRecord {
    value: String,
    version: u64,
}

fn load_variable_state(
    workspace: &Path,
    allow_missing: bool,
) -> Result<(VariableState, PathBuf), AdminError> {
    let directory = ensure_runtrue_directory(workspace, allow_missing)?;
    let path = directory.join("vars.json");
    if !secure_file_exists(&path, "variable state")? {
        return if allow_missing {
            Ok((VariableState::default(), path))
        } else {
            Err(AdminError::StateMissing("variable state"))
        };
    }
    let bytes = read_regular_file(&path, MAX_VARIABLE_STATE_BYTES, "variable state", true)?;
    let state: VariableState =
        serde_json::from_slice(&bytes).map_err(|source| AdminError::InvalidState {
            kind: "variable",
            source,
        })?;
    validate_variable_state(&state)?;
    Ok((state, path))
}

fn validate_variable_state(state: &VariableState) -> Result<(), AdminError> {
    if state.state_version != VARIABLE_STATE_VERSION {
        return Err(AdminError::UnsupportedStateVersion {
            kind: "variable",
            version: state.state_version,
        });
    }
    for (name, record) in &state.variables {
        validate_name(name)?;
        validate_variable_value(&record.value)?;
        if record.version == 0 {
            return Err(AdminError::InvalidVariableVersion(name.clone()));
        }
    }
    Ok(())
}

fn persist_variable_state(path: &Path, state: &VariableState) -> Result<(), AdminError> {
    let bytes = serde_json::to_vec(state).map_err(AdminError::SerializeState)?;
    if bytes.len() as u64 > MAX_VARIABLE_STATE_BYTES {
        return Err(AdminError::StateTooLarge {
            kind: "variable",
            limit: MAX_VARIABLE_STATE_BYTES,
            actual: bytes.len() as u64,
        });
    }
    let directory = path.parent().ok_or_else(|| AdminError::UnsafePath {
        path: path.to_owned(),
        reason: "state path has no parent",
    })?;
    write_private_atomic(directory, path, &bytes)
}

#[derive(Debug, Serialize)]
struct VariableResult<'a> {
    operation: &'static str,
    metadata: VariableMetadata<'a>,
    value: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct VariableMetadata<'a> {
    name: &'a str,
    version: u64,
}

fn print_variable_result(
    operation: &'static str,
    name: &str,
    version: u64,
    value: Option<&str>,
    json: bool,
) -> Result<(), AdminError> {
    if json {
        print_json(&VariableResult {
            operation,
            metadata: VariableMetadata { name, version },
            value,
        })
    } else if operation == "read" {
        println!("{}", value.unwrap_or_default());
        Ok(())
    } else {
        println!("variable {name}: {operation} (version={version})");
        Ok(())
    }
}
