use crate::v1;
use runtrue_model::{ContentDigest, DIGEST_ALGORITHM};
use thiserror::Error;

/// Failure to convert between the canonical model digest and its wire form.
#[derive(Debug, Error, PartialEq)]
pub enum DigestConversionError {
    #[error("unsupported digest algorithm `{0}`; expected `{DIGEST_ALGORITHM}`")]
    UnsupportedAlgorithm(String),
    #[error("invalid {algorithm} digest length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        algorithm: String,
        expected: usize,
        actual: usize,
    },
    #[error("invalid hexadecimal digest payload: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid canonical content digest: {0}")]
    InvalidContentDigest(#[from] runtrue_model::ModelError),
}

impl TryFrom<&ContentDigest> for v1::Digest {
    type Error = DigestConversionError;

    fn try_from(value: &ContentDigest) -> Result<Self, Self::Error> {
        let (algorithm, encoded) = value.as_str().split_once(':').ok_or_else(|| {
            DigestConversionError::UnsupportedAlgorithm(value.as_str().to_owned())
        })?;
        if algorithm != DIGEST_ALGORITHM {
            return Err(DigestConversionError::UnsupportedAlgorithm(
                algorithm.to_owned(),
            ));
        }
        let bytes = hex::decode(encoded)?;
        validate_digest_length(algorithm, &bytes)?;
        Ok(Self {
            algorithm: algorithm.to_owned(),
            value: bytes,
        })
    }
}

impl TryFrom<ContentDigest> for v1::Digest {
    type Error = DigestConversionError;
    fn try_from(value: ContentDigest) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&v1::Digest> for ContentDigest {
    type Error = DigestConversionError;
    fn try_from(value: &v1::Digest) -> Result<Self, Self::Error> {
        if value.algorithm != DIGEST_ALGORITHM {
            return Err(DigestConversionError::UnsupportedAlgorithm(
                value.algorithm.clone(),
            ));
        }
        validate_digest_length(&value.algorithm, &value.value)?;
        ContentDigest::parse(format!("{}:{}", value.algorithm, hex::encode(&value.value)))
            .map_err(DigestConversionError::from)
    }
}

impl TryFrom<v1::Digest> for ContentDigest {
    type Error = DigestConversionError;
    fn try_from(value: v1::Digest) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

fn validate_digest_length(algorithm: &str, value: &[u8]) -> Result<(), DigestConversionError> {
    const SHA256_BYTES: usize = 32;
    if value.len() != SHA256_BYTES {
        return Err(DigestConversionError::InvalidLength {
            algorithm: algorithm.to_owned(),
            expected: SHA256_BYTES,
            actual: value.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_digest_round_trips_through_wire_bytes() {
        let model = ContentDigest::sha256(b"runtrue runner protocol");
        let wire = v1::Digest::try_from(&model).unwrap();
        assert_eq!(wire.algorithm, DIGEST_ALGORITHM);
        assert_eq!(wire.value.len(), 32);
        assert_eq!(ContentDigest::try_from(wire).unwrap(), model);
    }

    #[test]
    fn wire_digest_rejects_algorithm_and_length_confusion() {
        let wrong_algorithm = v1::Digest {
            algorithm: "sha512".to_owned(),
            value: vec![0; 64],
        };
        assert!(matches!(
            ContentDigest::try_from(wrong_algorithm),
            Err(DigestConversionError::UnsupportedAlgorithm(_))
        ));
        let wrong_length = v1::Digest {
            algorithm: DIGEST_ALGORITHM.to_owned(),
            value: vec![0; 31],
        };
        assert!(matches!(
            ContentDigest::try_from(wrong_length),
            Err(DigestConversionError::InvalidLength {
                expected: 32,
                actual: 31,
                ..
            })
        ));
    }
}
