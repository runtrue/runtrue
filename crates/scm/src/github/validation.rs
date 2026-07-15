use super::{
    installation::{GitHubPermission, GitHubPermissionLevel, InstallationTokenRequest},
    GitHubError, GITHUB_API_VERSION, MAX_APP_SLUG_BYTES, MAX_INSTALL_STATE_BYTES, MAX_REPOSITORIES,
    MAX_REQUEST_BYTES, MAX_TOKEN_BYTES, MIN_INSTALL_STATE_BYTES,
};
use crate::ScmError;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use zeroize::Zeroizing;
pub(super) fn valid_app_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_APP_SLUG_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn valid_install_state(value: &str) -> bool {
    (MIN_INSTALL_STATE_BYTES..=MAX_INSTALL_STATE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn validate_secret_token(value: &str) -> Result<(), GitHubError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(GitHubError::InvalidConfiguration);
    }
    Ok(())
}

pub(super) fn validate_web_origin(value: &str) -> Result<(String, u16), GitHubError> {
    let (authority, path) = validate_https_url_shape(value)?;
    if !path.is_empty() {
        return Err(GitHubError::InvalidConfiguration);
    }
    parse_dns_authority(authority)
}

pub(super) fn validate_api_origin(value: &str) -> Result<(), GitHubError> {
    let (authority, path) = validate_https_url_shape(value)?;
    parse_dns_authority(authority)?;
    if value == "https://api.github.com" || path == "/api/v3" {
        Ok(())
    } else {
        Err(GitHubError::InvalidConfiguration)
    }
}

pub(super) fn validate_https_url_shape(value: &str) -> Result<(&str, &str), GitHubError> {
    let Some(authority_and_path) = value.strip_prefix("https://") else {
        return Err(GitHubError::InvalidConfiguration);
    };
    if value.ends_with('/')
        || authority_and_path.is_empty()
        || authority_and_path.contains(['?', '#', '@'])
        || authority_and_path
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(GitHubError::InvalidConfiguration);
    }
    let authority = authority_and_path
        .split_once('/')
        .map_or(authority_and_path, |(authority, _)| authority);
    if authority.is_empty() || authority == "." || authority == ".." {
        return Err(GitHubError::InvalidConfiguration);
    }
    let path = authority_and_path
        .strip_prefix(authority)
        .unwrap_or_default();
    if path.split('/').skip(1).any(|segment| {
        segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~')
            })
    }) {
        return Err(GitHubError::InvalidConfiguration);
    }
    Ok((authority, path))
}

pub(super) fn parse_dns_authority(authority: &str) -> Result<(String, u16), GitHubError> {
    if authority.starts_with('[') || authority.contains(']') || authority.matches(':').count() > 1 {
        return Err(GitHubError::InvalidConfiguration);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(GitHubError::InvalidConfiguration);
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| GitHubError::InvalidConfiguration)?;
            if port == 0 || port == 443 {
                return Err(GitHubError::InvalidConfiguration);
            }
            (host, port)
        }
        None => (authority, 443),
    };
    if host.parse::<IpAddr>().is_ok()
        || host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(GitHubError::InvalidConfiguration);
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || host == "localhost"
        || host.ends_with(".localhost")
    {
        return Err(GitHubError::InvalidConfiguration);
    }
    Ok((host.to_owned(), port))
}

pub(super) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            is_public_ipv6(address)
        }
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

pub(super) fn validate_token_request(
    request: &InstallationTokenRequest,
) -> Result<(), GitHubError> {
    if request.installation_id == 0
        || request.repository_ids.is_empty()
        || request.repository_ids.len() > MAX_REPOSITORIES
        || request.repository_ids.contains(&0)
        || !request
            .repository_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || request.permissions.is_empty()
        || request.permissions.get(&GitHubPermission::Metadata)
            != Some(&GitHubPermissionLevel::Read)
    {
        return Err(GitHubError::InvalidTokenScope);
    }
    for (permission, level) in &request.permissions {
        let allowed = match permission {
            GitHubPermission::Metadata => *level == GitHubPermissionLevel::Read,
            GitHubPermission::Actions | GitHubPermission::MergeQueues => {
                *level == GitHubPermissionLevel::Read
            }
            GitHubPermission::Contents
            | GitHubPermission::PullRequests
            | GitHubPermission::Checks
            | GitHubPermission::Statuses
            | GitHubPermission::Issues => true,
        };
        if !allowed {
            return Err(GitHubError::InvalidTokenScope);
        }
    }
    Ok(())
}

pub(super) fn headers(api_origin: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::from([
        (
            "accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        ),
        ("content-type".to_owned(), "application/json".to_owned()),
        ("user-agent".to_owned(), "Project-Runtrue/0.1".to_owned()),
    ]);
    // GitHub Enterprise Server API versions vary with the appliance release.
    // Omitting the header selects that instance's default version instead of
    // sending a dotcom version the appliance may not implement.
    if api_origin == "https://api.github.com" {
        headers.insert(
            "x-github-api-version".to_owned(),
            GITHUB_API_VERSION.to_owned(),
        );
    }
    headers
}

pub(super) fn serialize_body(value: &Value) -> Result<Zeroizing<Vec<u8>>, GitHubError> {
    let body = serde_json::to_vec(value).map_err(|_| GitHubError::InvalidConfiguration)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(GitHubError::RequestTooLarge);
    }
    Ok(Zeroizing::new(body))
}

use serde::{
    de::{Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictJsonVisitor;

        impl<'de> Visitor<'de> for StrictJsonVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with unique object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictJsonValue)
                    .ok_or_else(|| E::custom("JSON numbers must be finite"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
                    values.push(value.0);
                }
                Ok(StrictJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = mapping.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(A::Error::custom(format!(
                            "duplicate JSON object key `{key}`"
                        )));
                    }
                    let value = mapping.next_value::<StrictJsonValue>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictJsonValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

pub(crate) fn parse_strict_json(source: &[u8]) -> Result<Value, ScmError> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| ScmError::InvalidJson(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| ScmError::InvalidJson(error.to_string()))?;
    Ok(value)
}
