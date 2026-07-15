use crate::ModelError;
use serde::{Deserialize, Serialize};

/// A normalized duration represented in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DurationMillis(pub u64);

impl DurationMillis {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let (digits, multiplier) = if let Some(value) = value.strip_suffix("ms") {
            (value, 1)
        } else if let Some(value) = value.strip_suffix('s') {
            (value, 1_000)
        } else if let Some(value) = value.strip_suffix('m') {
            (value, 60_000)
        } else if let Some(value) = value.strip_suffix('h') {
            (value, 3_600_000)
        } else {
            return Err(ModelError::InvalidDuration(value.to_owned()));
        };

        let amount = digits
            .parse::<u64>()
            .map_err(|_| ModelError::InvalidDuration(value.to_owned()))?;
        if amount == 0 {
            return Err(ModelError::InvalidDuration(value.to_owned()));
        }
        amount
            .checked_mul(multiplier)
            .map(Self)
            .ok_or_else(|| ModelError::InvalidDuration(value.to_owned()))
    }
}
