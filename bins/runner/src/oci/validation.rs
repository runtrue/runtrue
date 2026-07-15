pub(super) fn load_runtime_environment(
    path: &Path,
) -> Result<BTreeMap<String, String>, RunnerError> {
    let bytes = read_bounded_private_file(path, MAX_RUNTIME_ENVIRONMENT_BYTES)?;
    strict_json(&bytes).map_err(|error| {
        RunnerError::OciConfiguration(format!("invalid OCI runtime environment: {error}"))
    })
}

pub(super) fn sorted_directory_files(directory: &Path) -> Result<Vec<PathBuf>, RunnerError> {
    let mut paths = fs::read_dir(directory)
        .map_err(|error| RunnerError::OciConfiguration(error.to_string()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| RunnerError::OciConfiguration(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    Ok(paths)
}

pub(super) fn validate_private_directory(path: &Path, kind: &str) -> Result<PathBuf, RunnerError> {
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::OciConfiguration(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunnerError::OciConfiguration(format!(
            "{kind} is not a real directory"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(RunnerError::OciConfiguration(format!(
            "{kind} must have mode 0700"
        )));
    }
    path.canonicalize()
        .map_err(|error| RunnerError::OciConfiguration(error.to_string()))
}

pub(super) fn validate_private_regular_file(path: &Path) -> Result<PathBuf, RunnerError> {
    // Reuse the bounded private-file loader for no-follow, mode, and race checks.
    let _ = read_bounded_private_file(path, MAX_MANIFEST_BYTES)?;
    path.canonicalize()
        .map_err(|error| RunnerError::OciConfiguration(error.to_string()))
}

pub(super) fn validate_podman(path: &Path) -> Result<PathBuf, RunnerError> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("podman") {
        return Err(RunnerError::OciConfiguration(
            "OCI runtime must be an absolute local podman path".to_owned(),
        ));
    }
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::OciConfiguration(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunnerError::OciConfiguration(
            "podman path is not a real regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(RunnerError::OciConfiguration(
            "podman must be executable and not group/world writable".to_owned(),
        ));
    }
    path.canonicalize()
        .map_err(|error| RunnerError::OciConfiguration(error.to_string()))
}

pub(super) fn decode_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    (text.len() == 64)
        .then(|| hex::decode(text).ok())
        .flatten()
        .and_then(|decoded| <[u8; 32]>::try_from(decoded.as_slice()).ok())
}

pub(super) fn now_unix_ms() -> Result<u64, RunnerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(RunnerError::ClockRange)
}

pub(crate) fn strict_json<T>(bytes: &[u8]) -> Result<T, serde_json::Error>
where
    T: for<'de> Deserialize<'de>,
{
    let unique: UniqueJson = serde_json::from_slice(bytes)?;
    serde_json::from_value(unique.0)
}

struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(UniqueJson)
                    .ok_or_else(|| E::custom("JSON number must be finite"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(serde_json::Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(serde_json::Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueJson(values.into()))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some((name, value)) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(name.clone(), value.0).is_some() {
                        return Err(A::Error::custom(format!(
                            "duplicate JSON object key `{name}`"
                        )));
                    }
                }
                Ok(UniqueJson(values.into()))
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}
use super::{
    fmt, fs, read_bounded_private_file, validate_no_symlink_components, BTreeMap, Deserialize,
    Deserializer, MapAccess, Path, PathBuf, RunnerError, SeqAccess, SystemTime, Visitor,
    MAX_MANIFEST_BYTES, MAX_RUNTIME_ENVIRONMENT_BYTES, UNIX_EPOCH,
};
use serde::de::Error as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
