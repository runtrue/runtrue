use crate::ModelError;
use serde::{Deserialize, Serialize};

/// A normalized byte size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        const SUFFIXES: [(&str, u64); 8] = [
            ("KiB", 1 << 10),
            ("MiB", 1 << 20),
            ("GiB", 1 << 30),
            ("TiB", 1 << 40),
            ("KB", 1_000),
            ("MB", 1_000_000),
            ("GB", 1_000_000_000),
            ("B", 1),
        ];

        for (suffix, multiplier) in SUFFIXES {
            if let Some(digits) = value.strip_suffix(suffix) {
                let amount = digits
                    .parse::<u64>()
                    .map_err(|_| ModelError::InvalidSize(value.to_owned()))?;
                return amount
                    .checked_mul(multiplier)
                    .map(Self)
                    .ok_or_else(|| ModelError::InvalidSize(value.to_owned()));
            }
        }
        Err(ModelError::InvalidSize(value.to_owned()))
    }
}
