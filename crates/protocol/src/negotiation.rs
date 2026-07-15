use std::cmp::{max, min};
use thiserror::Error;

/// Oldest runner protocol generation accepted by this control plane.
pub const PROTOCOL_MIN: u32 = 1;

/// Newest runner protocol generation accepted by this control plane.
pub const PROTOCOL_MAX: u32 = 2;

/// Select the newest protocol generation shared with a peer.
pub fn negotiate_protocol_version(
    peer_min: u32,
    peer_max: u32,
) -> Result<u32, ProtocolVersionError> {
    negotiate_protocol_version_with_supported(peer_min, peer_max, PROTOCOL_MIN, PROTOCOL_MAX)
}

/// Select the newest generation shared by explicit peer and local ranges.
pub fn negotiate_protocol_version_with_supported(
    peer_min: u32,
    peer_max: u32,
    supported_min: u32,
    supported_max: u32,
) -> Result<u32, ProtocolVersionError> {
    if peer_min == 0 || peer_max == 0 || peer_min > peer_max {
        return Err(ProtocolVersionError::InvalidPeerRange {
            min: peer_min,
            max: peer_max,
        });
    }
    if supported_min == 0 || supported_max == 0 || supported_min > supported_max {
        return Err(ProtocolVersionError::InvalidSupportedRange {
            min: supported_min,
            max: supported_max,
        });
    }
    let shared_min = max(supported_min, peer_min);
    let shared_max = min(supported_max, peer_max);
    if shared_min > shared_max {
        return Err(ProtocolVersionError::NoCompatibleVersion {
            peer_min,
            peer_max,
            supported_min,
            supported_max,
        });
    }
    Ok(shared_max)
}

/// Decode an additive advertised range with the generation-one zero fallback.
pub fn advertised_protocol_range(
    advertised_min: u32,
    advertised_max: u32,
    legacy_singleton: u32,
) -> Result<(u32, u32), ProtocolVersionError> {
    match (advertised_min, advertised_max) {
        (0, 0) if legacy_singleton != 0 => Ok((legacy_singleton, legacy_singleton)),
        (0, 0) => Err(ProtocolVersionError::InvalidPeerRange { min: 0, max: 0 }),
        (0, maximum) => Err(ProtocolVersionError::InvalidPeerRange {
            min: 0,
            max: maximum,
        }),
        (minimum, 0) => Err(ProtocolVersionError::InvalidPeerRange {
            min: minimum,
            max: 0,
        }),
        (minimum, maximum) if minimum > maximum => Err(ProtocolVersionError::InvalidPeerRange {
            min: minimum,
            max: maximum,
        }),
        range => Ok(range),
    }
}

/// Validate a server-owned selection, with a legacy response fallback.
pub fn resolve_selected_protocol_version(
    advertised_min: u32,
    advertised_max: u32,
    legacy_singleton: u32,
    selected: u32,
) -> Result<u32, ProtocolVersionError> {
    let (peer_min, peer_max) =
        advertised_protocol_range(advertised_min, advertised_max, legacy_singleton)?;
    let expected = negotiate_protocol_version(peer_min, peer_max)?;
    if selected == 0 || selected == expected {
        return Ok(expected);
    }
    Err(ProtocolVersionError::UnexpectedSelection { selected, expected })
}

/// Whether one advertised peer version is accepted by this implementation.
#[must_use]
pub const fn supports_protocol_version(version: u32) -> bool {
    matches!(version, PROTOCOL_MIN..=PROTOCOL_MAX)
}

/// Failure to validate or negotiate a peer protocol range.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolVersionError {
    #[error("invalid peer protocol range {min}..={max}")]
    InvalidPeerRange { min: u32, max: u32 },
    #[error("invalid supported protocol range {min}..={max}")]
    InvalidSupportedRange { min: u32, max: u32 },
    #[error("peer protocol range {peer_min}..={peer_max} does not overlap supported range {supported_min}..={supported_max}")]
    NoCompatibleVersion {
        peer_min: u32,
        peer_max: u32,
        supported_min: u32,
        supported_max: u32,
    },
    #[error("peer selected protocol generation {selected}; expected newest common generation {expected}")]
    UnexpectedSelection { selected: u32, expected: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_negotiation_uses_the_newest_shared_generation() {
        assert_eq!(negotiate_protocol_version(1, 1), Ok(1));
        assert_eq!(negotiate_protocol_version(1, 2), Ok(2));
        assert_eq!(negotiate_protocol_version(2, 2), Ok(2));
        assert!(supports_protocol_version(1));
        assert!(!supports_protocol_version(0));
        assert!(supports_protocol_version(2));
    }

    #[test]
    fn malformed_and_disjoint_protocol_ranges_are_distinct() {
        assert_eq!(
            negotiate_protocol_version(2, 1),
            Err(ProtocolVersionError::InvalidPeerRange { min: 2, max: 1 })
        );
        assert_eq!(negotiate_protocol_version(2, 3), Ok(2));
        assert!(matches!(
            negotiate_protocol_version(3, 3),
            Err(ProtocolVersionError::NoCompatibleVersion { .. })
        ));
    }

    #[test]
    fn legacy_zero_range_is_only_a_complete_singleton_fallback() {
        assert_eq!(advertised_protocol_range(0, 0, 1), Ok((1, 1)));
        assert_eq!(advertised_protocol_range(1, 2, 1), Ok((1, 2)));
        for (minimum, maximum, singleton) in [(0, 2, 1), (1, 0, 1), (2, 1, 1), (0, 0, 0)] {
            assert!(matches!(
                advertised_protocol_range(minimum, maximum, singleton),
                Err(ProtocolVersionError::InvalidPeerRange { .. })
            ));
        }
    }

    #[test]
    fn server_selection_is_newest_common_and_legacy_absence_is_derived() {
        assert_eq!(resolve_selected_protocol_version(1, 2, 1, 2), Ok(2));
        assert_eq!(resolve_selected_protocol_version(1, 1, 1, 0), Ok(1));
        assert_eq!(resolve_selected_protocol_version(0, 0, 1, 0), Ok(1));
        assert_eq!(
            resolve_selected_protocol_version(1, 2, 1, 1),
            Err(ProtocolVersionError::UnexpectedSelection {
                selected: 1,
                expected: 2,
            })
        );
    }

    #[test]
    fn configured_security_minimum_disables_generation_one() {
        assert_eq!(negotiate_protocol_version_with_supported(1, 2, 2, 2), Ok(2));
        assert!(matches!(
            negotiate_protocol_version_with_supported(1, 1, 2, 2),
            Err(ProtocolVersionError::NoCompatibleVersion { .. })
        ));
        assert_eq!(
            negotiate_protocol_version_with_supported(1, 2, 2, 1),
            Err(ProtocolVersionError::InvalidSupportedRange { min: 2, max: 1 })
        );
    }
}
