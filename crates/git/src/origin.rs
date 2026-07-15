use crate::GitError;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

const MAX_ORIGIN_BYTES: usize = 4096;

/// Administrative network policy for production Git origins. Hosts are exact
/// lowercase DNS names; wildcard and suffix matching are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPolicy {
    allowed_hosts: BTreeSet<String>,
    allowed_nonstandard_ports: BTreeSet<(String, u16)>,
}

impl OriginPolicy {
    pub fn new(hosts: impl IntoIterator<Item = String>) -> Result<Self, GitError> {
        let mut allowed_hosts = BTreeSet::new();
        for host in hosts {
            let normalized =
                normalize_dns_host(&host).map_err(|_| GitError::InvalidOriginPolicy)?;
            if normalized != host {
                return Err(GitError::InvalidOriginPolicy);
            }
            allowed_hosts.insert(normalized);
        }
        if allowed_hosts.is_empty() {
            return Err(GitError::InvalidOriginPolicy);
        }
        Ok(Self {
            allowed_hosts,
            allowed_nonstandard_ports: BTreeSet::new(),
        })
    }

    pub fn allow_nonstandard_port(
        &mut self,
        host: impl Into<String>,
        port: u16,
    ) -> Result<(), GitError> {
        let host = host.into();
        let normalized = normalize_dns_host(&host).map_err(|_| GitError::InvalidOriginPolicy)?;
        if normalized != host || !self.allowed_hosts.contains(&host) || port == 0 || port == 443 {
            return Err(GitError::InvalidOriginPolicy);
        }
        self.allowed_nonstandard_ports.insert((host, port));
        Ok(())
    }

    pub fn normalize(&self, origin: &str) -> Result<NormalizedOrigin, GitError> {
        if origin.is_empty()
            || origin.len() > MAX_ORIGIN_BYTES
            || origin
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || origin.contains(['?', '#', '@', '\\', '%'])
        {
            return Err(GitError::UnsafeOrigin);
        }
        let remainder = origin
            .strip_prefix("https://")
            .ok_or(GitError::UnsafeOrigin)?;
        let (authority, raw_path) = remainder.split_once('/').ok_or(GitError::UnsafeOrigin)?;
        if authority.is_empty() || raw_path.is_empty() {
            return Err(GitError::UnsafeOrigin);
        }
        let (host, port) = parse_authority(authority)?;
        if !self.allowed_hosts.contains(&host) {
            return Err(GitError::OriginHostDenied(host));
        }
        if port != 443
            && !self
                .allowed_nonstandard_ports
                .contains(&(host.clone(), port))
        {
            return Err(GitError::OriginPortDenied(port));
        }
        let path = normalize_origin_path(raw_path)?;
        let canonical = if port == 443 {
            format!("https://{host}/{path}")
        } else {
            format!("https://{host}:{port}/{path}")
        };
        Ok(NormalizedOrigin {
            canonical,
            host,
            port,
            path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedOrigin {
    canonical: String,
    host: String,
    port: u16,
    path: String,
}

impl NormalizedOrigin {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16), GitError> {
    if authority.starts_with('[') || authority.contains(']') || authority.matches(':').count() > 1 {
        return Err(GitError::UnsafeOrigin);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(GitError::UnsafeOrigin);
            }
            let port = port.parse::<u16>().map_err(|_| GitError::UnsafeOrigin)?;
            if port == 0 {
                return Err(GitError::UnsafeOrigin);
            }
            (host, port)
        }
        None => (authority, 443),
    };
    if host.parse::<IpAddr>().is_ok() {
        // Reject every literal, which strictly includes loopback, private,
        // link-local, documentation, and other special-purpose ranges.
        return Err(GitError::OriginIpLiteralDenied);
    }
    let host = normalize_dns_host(host)?;
    Ok((host, port))
}

fn normalize_dns_host(host: &str) -> Result<String, GitError> {
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(GitError::UnsafeOrigin);
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
        return Err(GitError::UnsafeOrigin);
    }
    Ok(host.to_owned())
}

fn normalize_origin_path(path: &str) -> Result<String, GitError> {
    if path.is_empty()
        || path.len() > 2048
        || path.starts_with('/')
        || path.ends_with('/')
        || path.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || segment.len() > 255
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                })
        })
    {
        return Err(GitError::UnsafeOrigin);
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_https_origin_is_normalized_and_allowlisted() {
        let policy = OriginPolicy::new(["github.com".to_owned()]).unwrap();
        let origin = policy
            .normalize("https://github.com/openai/runtrue.git")
            .unwrap();
        assert_eq!(origin.host(), "github.com");
        assert_eq!(origin.port(), 443);
        assert_eq!(origin.as_str(), "https://github.com/openai/runtrue.git");
    }

    #[test]
    fn protocols_ambiguous_urls_ips_and_dot_segments_are_denied() {
        let policy = OriginPolicy::new(["github.com".to_owned()]).unwrap();
        for origin in [
            "http://github.com/o/r.git",
            "ssh://github.com/o/r.git",
            "git@github.com:o/r.git",
            "https://user@github.com/o/r.git",
            "https://github.com/o/../r.git",
            "https://github.com/o/%2e%2e/r.git",
            "https://127.0.0.1/o/r.git",
            "https://[::1]/o/r.git",
            "file:///tmp/repo",
            "ext::command",
        ] {
            assert!(policy.normalize(origin).is_err(), "accepted {origin}");
        }
    }

    #[test]
    fn nonstandard_port_requires_exact_administrative_exception() {
        let mut policy = OriginPolicy::new(["git.example.com".to_owned()]).unwrap();
        assert!(matches!(
            policy.normalize("https://git.example.com:8443/o/r.git"),
            Err(GitError::OriginPortDenied(8443))
        ));
        policy
            .allow_nonstandard_port("git.example.com", 8443)
            .unwrap();
        assert!(policy
            .normalize("https://git.example.com:8443/o/r.git")
            .is_ok());
    }
}
