use crate::{strict_yaml::StrictYamlValue, validation::safe_relative_path, ImportError};
use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

const MAX_ACTION_METADATA_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryActionMetadata {
    pub digest: ContentDigest,
    pub dockerfile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionMetadata {
    name: String,
    description: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    inputs: BTreeMap<String, ActionInput>,
    #[serde(default)]
    outputs: BTreeMap<String, ActionOutput>,
    runs: ActionRuns,
    #[serde(default)]
    branding: Option<ActionBranding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ActionInput {
    description: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    default: Option<YamlValue>,
    #[serde(default)]
    deprecation_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionOutput {
    description: String,
    #[serde(default)]
    value: Option<YamlValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRuns {
    using: String,
    image: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionBranding {
    icon: String,
    color: String,
}

pub fn parse_repository_action_metadata(
    bytes: &[u8],
) -> Result<RepositoryActionMetadata, ImportError> {
    if bytes.len() > MAX_ACTION_METADATA_BYTES {
        return Err(ImportError::RepositoryActionMetadata(
            "action metadata exceeds the 256 KiB limit".to_owned(),
        ));
    }
    let source = std::str::from_utf8(bytes).map_err(|_| {
        ImportError::RepositoryActionMetadata("action metadata is not UTF-8".to_owned())
    })?;
    let _: StrictYamlValue = serde_yaml::from_str(source)?;
    let metadata: ActionMetadata = serde_yaml::from_str(source)?;
    validate_text("name", &metadata.name)?;
    validate_text("description", &metadata.description)?;
    if let Some(author) = &metadata.author {
        validate_text("author", author)?;
    }
    for (name, input) in &metadata.inputs {
        validate_identifier("input", name)?;
        validate_text("input description", &input.description)?;
        let _ = (input.required, &input.default, &input.deprecation_message);
    }
    for (name, output) in &metadata.outputs {
        validate_identifier("output", name)?;
        validate_text("output description", &output.description)?;
        let _ = &output.value;
    }
    if let Some(branding) = &metadata.branding {
        validate_text("branding icon", &branding.icon)?;
        validate_text("branding color", &branding.color)?;
    }
    if metadata.runs.using != "docker" {
        return Err(ImportError::RepositoryActionMetadata(
            "only runs.using: docker repository actions are supported".to_owned(),
        ));
    }
    if !safe_relative_path(&metadata.runs.image, false)
        || metadata.runs.image.starts_with("docker://")
        || !metadata.runs.image.rsplit('/').next().is_some_and(|name| {
            name.eq_ignore_ascii_case("Dockerfile") || name.ends_with(".Dockerfile")
        })
    {
        return Err(ImportError::RepositoryActionMetadata(
            "runs.image must name a repository-relative Dockerfile".to_owned(),
        ));
    }
    Ok(RepositoryActionMetadata {
        digest: ContentDigest::sha256(bytes),
        dockerfile: metadata.runs.image,
    })
}

fn validate_text(field: &str, value: &str) -> Result<(), ImportError> {
    if value.is_empty() || value.len() > 8 * 1024 || value.chars().any(char::is_control) {
        return Err(ImportError::RepositoryActionMetadata(format!(
            "{field} is empty or invalid"
        )));
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), ImportError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ImportError::RepositoryActionMetadata(format!(
            "{field} name is invalid"
        )));
    }
    Ok(())
}
