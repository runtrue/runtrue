use crate::model::{MAX_ENTRIES_PER_KIND, MAX_METADATA_BYTES, MAX_SOURCE_BYTES};
use crate::{
    ComponentEntry, EntryKind, ImageEntry, LockError, LockFile, WorkflowEntry, LOCK_VERSION,
};
use runtrue_model::ContentDigest;
use std::collections::BTreeSet;

impl LockFile {
    pub(crate) fn normalize_and_validate(&mut self) -> Result<(), LockError> {
        if self.lock_version != LOCK_VERSION {
            return Err(LockError::UnsupportedVersion(self.lock_version));
        }
        for (kind, count) in [
            (EntryKind::Component, self.components.len()),
            (EntryKind::Image, self.images.len()),
            (EntryKind::Workflow, self.workflows.len()),
        ] {
            if count > MAX_ENTRIES_PER_KIND {
                return Err(LockError::TooManyEntries {
                    kind,
                    limit: MAX_ENTRIES_PER_KIND,
                    actual: count,
                });
            }
        }
        for entry in &self.components {
            entry.validate()?;
        }
        for entry in &self.images {
            entry.validate()?;
        }
        for entry in &self.workflows {
            entry.validate()?;
        }
        self.components.sort();
        self.images.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then_with(|| left.platform.cmp(&right.platform))
                .then_with(|| left.resolved.cmp(&right.resolved))
        });
        self.workflows.sort();
        validate_uniqueness(self)?;
        Ok(())
    }
}

impl ComponentEntry {
    fn validate(&self) -> Result<(), LockError> {
        validate_source(EntryKind::Component, &self.source)?;
        validate_signature_identity(&self.signature_identity)?;
        validate_wit_world(&self.wit_world)?;
        if let Some((_, selector)) = self.source.rsplit_once('@') {
            if selector.starts_with("sha256:") && selector != self.resolved.as_str() {
                return Err(LockError::ResolutionMismatch {
                    kind: EntryKind::Component,
                    logical_source: self.source.clone(),
                });
            }
        }
        Ok(())
    }
}

impl ImageEntry {
    fn validate(&self) -> Result<(), LockError> {
        validate_source(EntryKind::Image, &self.source)?;
        validate_immutable_image(&self.resolved)?;
        validate_platform(&self.platform)?;
        if self.source.contains("@sha256:") && self.source != self.resolved {
            return Err(LockError::ResolutionMismatch {
                kind: EntryKind::Image,
                logical_source: self.source.clone(),
            });
        }
        Ok(())
    }
}

impl WorkflowEntry {
    fn validate(&self) -> Result<(), LockError> {
        validate_source(EntryKind::Workflow, &self.source)?;
        validate_commit(&self.commit)?;
        let (_, selector) =
            self.source
                .rsplit_once('@')
                .ok_or_else(|| LockError::InvalidField {
                    path: "workflow.source".to_owned(),
                    reason: "reusable workflow source must include an @selector".to_owned(),
                })?;
        if is_full_commit(selector) && selector != self.commit {
            return Err(LockError::ResolutionMismatch {
                kind: EntryKind::Workflow,
                logical_source: self.source.clone(),
            });
        }
        Ok(())
    }
}

fn validate_uniqueness(lock: &LockFile) -> Result<(), LockError> {
    ensure_unique(
        EntryKind::Component,
        lock.components.iter().map(|entry| entry.source.clone()),
        true,
    )?;
    ensure_unique(
        EntryKind::Component,
        lock.components
            .iter()
            .map(|entry| entry.resolved.to_string()),
        false,
    )?;
    ensure_unique(
        EntryKind::Image,
        lock.images
            .iter()
            .map(|entry| format!("{}\0{}", entry.source, entry.platform)),
        true,
    )?;
    ensure_unique(
        EntryKind::Image,
        lock.images
            .iter()
            .map(|entry| format!("{}\0{}", entry.resolved, entry.platform)),
        false,
    )?;
    ensure_unique(
        EntryKind::Workflow,
        lock.workflows.iter().map(|entry| entry.source.clone()),
        true,
    )?;
    ensure_unique(
        EntryKind::Workflow,
        lock.workflows
            .iter()
            .map(|entry| format!("{}\0{}", entry.commit, entry.digest)),
        false,
    )
}

fn ensure_unique(
    kind: EntryKind,
    values: impl IntoIterator<Item = String>,
    source: bool,
) -> Result<(), LockError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(if source {
                LockError::DuplicateSource { kind, value }
            } else {
                LockError::DuplicateResolution { kind, value }
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_source(kind: EntryKind, source: &str) -> Result<(), LockError> {
    validate_text(&format!("{kind}.source"), source, MAX_SOURCE_BYTES)?;
    match kind {
        EntryKind::Component => {
            let locator = source
                .strip_prefix("wasm://")
                .or_else(|| source.strip_prefix("oci://"));
            let Some(locator) = locator else {
                return invalid(
                    "component.source",
                    "component sources must use wasm:// or oci://",
                );
            };
            let (location, selector) = locator
                .rsplit_once('@')
                .map_or((locator, None), |(location, selector)| {
                    (location, Some(selector))
                });
            if location.is_empty() || selector.is_some_and(str::is_empty) {
                return invalid(
                    "component.source",
                    "component source locator and optional selector must be non-empty",
                );
            }
            validate_embedded_digest("component.source", source)?;
        }
        EntryKind::Image => validate_embedded_digest("image.source", source)?,
        EntryKind::Workflow => {
            if !(source.starts_with("git+https://") || source.starts_with("git+ssh://")) {
                return invalid(
                    "workflow.source",
                    "workflow sources must use git+https:// or git+ssh://",
                );
            }
            let without_scheme = source
                .strip_prefix("git+https://")
                .or_else(|| source.strip_prefix("git+ssh://"))
                .expect("prefix checked");
            let (location, selector) =
                without_scheme
                    .rsplit_once('@')
                    .ok_or_else(|| LockError::InvalidField {
                        path: "workflow.source".to_owned(),
                        reason: "reusable workflow source must include an @selector".to_owned(),
                    })?;
            if selector.is_empty() {
                return invalid(
                    "workflow.source",
                    "reusable workflow selector must be non-empty",
                );
            }
            let (repository, workflow_path) =
                location
                    .rsplit_once("//")
                    .ok_or_else(|| LockError::InvalidField {
                        path: "workflow.source".to_owned(),
                        reason: "reusable workflow source must include //path".to_owned(),
                    })?;
            if repository.is_empty()
                || workflow_path.is_empty()
                || workflow_path.contains('\\')
                || workflow_path
                    .split('/')
                    .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
                || !matches!(
                    workflow_path
                        .rsplit_once('.')
                        .map(|(_, extension)| extension),
                    Some("yaml" | "yml")
                )
            {
                return invalid(
                    "workflow.source",
                    "reusable workflow path must be normalized and non-empty",
                );
            }
        }
    }
    Ok(())
}

fn validate_embedded_digest(path: &str, source: &str) -> Result<(), LockError> {
    if let Some((_, digest)) = source.rsplit_once('@') {
        if digest.eq_ignore_ascii_case("sha256")
            || digest
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sha256:"))
        {
            ContentDigest::parse(digest.to_owned()).map_err(|_| LockError::InvalidField {
                path: path.to_owned(),
                reason: "embedded digest must be a full lowercase SHA-256 pin".to_owned(),
            })?;
        }
    }
    Ok(())
}

fn validate_immutable_image(resolved: &str) -> Result<(), LockError> {
    validate_text("image.resolved", resolved, MAX_SOURCE_BYTES)?;
    let (repository, digest) =
        resolved
            .rsplit_once('@')
            .ok_or_else(|| LockError::InvalidField {
                path: "image.resolved".to_owned(),
                reason: "resolved image must use name@sha256:<64 lowercase hex>".to_owned(),
            })?;
    if repository.is_empty() || repository.contains('@') {
        return invalid(
            "image.resolved",
            "resolved image repository must be non-empty and unambiguous",
        );
    }
    ContentDigest::parse(digest.to_owned()).map_err(|_| LockError::InvalidField {
        path: "image.resolved".to_owned(),
        reason: "resolved image must contain a full lowercase SHA-256 pin".to_owned(),
    })?;
    Ok(())
}

pub(crate) fn validate_platform(platform: &str) -> Result<(), LockError> {
    validate_text("image.platform", platform, MAX_METADATA_BYTES)?;
    let mut parts = platform.split('/');
    let os = parts.next().unwrap_or_default();
    let architecture = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !matches!(os, "linux" | "windows")
        || !matches!(architecture, "amd64" | "arm64")
    {
        return invalid(
            "image.platform",
            "platform must be linux/amd64, linux/arm64, windows/amd64, or windows/arm64",
        );
    }
    Ok(())
}

fn validate_signature_identity(identity: &str) -> Result<(), LockError> {
    validate_text("component.signature_identity", identity, MAX_METADATA_BYTES)?;
    if identity.starts_with("https://")
        || identity.starts_with("spiffe://")
        || identity.starts_with("urn:")
    {
        let valid = if let Some(rest) = identity.strip_prefix("https://") {
            let authority = rest.split('/').next().unwrap_or_default();
            !authority.is_empty() && authority.contains('.')
        } else if let Some(rest) = identity.strip_prefix("spiffe://") {
            let (trust_domain, path) = rest.split_once('/').unwrap_or((rest, ""));
            !trust_domain.is_empty() && trust_domain.contains('.') && !path.is_empty()
        } else {
            identity.strip_prefix("urn:").is_some_and(|rest| {
                rest.split_once(':')
                    .is_some_and(|(namespace, value)| !namespace.is_empty() && !value.is_empty())
            })
        };
        if valid {
            return Ok(());
        }
        return invalid(
            "component.signature_identity",
            "signature URI identity is malformed",
        );
    }
    let Some((local, domain)) = identity.split_once('@') else {
        return invalid(
            "component.signature_identity",
            "signature identity must be an email, HTTPS URI, SPIFFE URI, or URN",
        );
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        || !valid_dns_name(domain)
    {
        return invalid(
            "component.signature_identity",
            "signature email identity is malformed",
        );
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_wit_world(world: &str) -> Result<(), LockError> {
    validate_text("component.wit_world", world, MAX_METADATA_BYTES)?;
    let (name, version) = world
        .rsplit_once('@')
        .ok_or_else(|| LockError::InvalidField {
            path: "component.wit_world".to_owned(),
            reason: "WIT world must include @major.minor.patch".to_owned(),
        })?;
    let (namespace, package_world) =
        name.split_once(':')
            .ok_or_else(|| LockError::InvalidField {
                path: "component.wit_world".to_owned(),
                reason: "WIT world must use namespace:package/world".to_owned(),
            })?;
    let (package, world_name) =
        package_world
            .split_once('/')
            .ok_or_else(|| LockError::InvalidField {
                path: "component.wit_world".to_owned(),
                reason: "WIT world must use namespace:package/world".to_owned(),
            })?;
    if ![namespace, package, world_name]
        .iter()
        .all(|value| valid_wit_identifier(value))
    {
        return invalid(
            "component.wit_world",
            "WIT namespace, package, and world names are malformed",
        );
    }
    let versions = version.split('.').collect::<Vec<_>>();
    if versions.len() != 3
        || versions.iter().any(|value| {
            value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || value.parse::<u64>().is_err()
        })
    {
        return invalid(
            "component.wit_world",
            "WIT world version must be major.minor.patch",
        );
    }
    Ok(())
}

fn valid_wit_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
        && !value.contains("--")
}

fn validate_commit(commit: &str) -> Result<(), LockError> {
    if !is_full_commit(commit) {
        return invalid(
            "workflow.commit",
            "commit must be a full 40- or 64-character lowercase hexadecimal object ID",
        );
    }
    Ok(())
}

fn is_full_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_text(path: &str, value: &str, max_bytes: usize) -> Result<(), LockError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return invalid(
            path,
            "value must be non-empty, bounded, and contain no whitespace or control characters",
        );
    }
    Ok(())
}

fn invalid<T>(path: &str, reason: &str) -> Result<T, LockError> {
    Err(LockError::InvalidField {
        path: path.to_owned(),
        reason: reason.to_owned(),
    })
}
