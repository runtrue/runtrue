use super::MAX_SCM_SNAPSHOT_BYTES;
use crate::error::DecodeError;
use runtrue_auth::TokenDigest;
use runtrue_model::ContentDigest;
use rusqlite::Row;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::error::Error as StdError;

pub(super) fn to_i64(value: u64) -> Result<i64, crate::ControlPlaneError> {
    i64::try_from(value).map_err(|_| crate::ControlPlaneError::IntegerRange { field: "u64" })
}

pub(super) fn from_i64(field: &'static str, value: i64) -> Result<u64, crate::ControlPlaneError> {
    u64::try_from(value).map_err(|_| crate::ControlPlaneError::IntegerRange { field })
}

pub(super) fn u64_column(
    row: &Row<'_>,
    index: usize,
    field: &'static str,
) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value)
        .map_err(|error| conversion(index, DecodeError(format!("{field}: {error}"))))
}

pub(super) fn optional_u64_column(
    row: &Row<'_>,
    index: usize,
    field: &'static str,
) -> rusqlite::Result<Option<u64>> {
    let value: Option<i64> = row.get(index)?;
    value
        .map(|value| {
            u64::try_from(value)
                .map_err(|error| conversion(index, DecodeError(format!("{field}: {error}"))))
        })
        .transpose()
}

pub(super) fn digest_column(row: &Row<'_>, index: usize) -> rusqlite::Result<ContentDigest> {
    let value: String = row.get(index)?;
    ContentDigest::parse(value).map_err(|error| conversion(index, error))
}

pub(super) fn optional_digest_column(
    row: &Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<ContentDigest>> {
    let value: Option<String> = row.get(index)?;
    value
        .map(ContentDigest::parse)
        .transpose()
        .map_err(|error| conversion(index, error))
}

pub(super) fn token_digest_column(row: &Row<'_>, index: usize) -> rusqlite::Result<TokenDigest> {
    let value: String = row.get(index)?;
    serde_json::from_value(Value::String(value)).map_err(|error| conversion(index, error))
}

pub(super) fn json_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> rusqlite::Result<T> {
    let value: String = row.get(index)?;
    serde_json::from_str(&value).map_err(|error| conversion(index, error))
}

pub(super) fn json_blob_column<T: DeserializeOwned>(
    row: &Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let value: Vec<u8> = row.get(index)?;
    if value.len() > MAX_SCM_SNAPSHOT_BYTES {
        return Err(conversion(
            index,
            DecodeError("SCM durable JSON exceeds its bound".to_owned()),
        ));
    }
    serde_json::from_slice(&value).map_err(|error| conversion(index, error))
}

pub(super) fn bounded_json_blob_column<T: DeserializeOwned>(
    row: &Row<'_>,
    index: usize,
    maximum: usize,
    field: &'static str,
) -> rusqlite::Result<T> {
    let value: Vec<u8> = row.get(index)?;
    if value.len() > maximum {
        return Err(conversion(
            index,
            DecodeError(format!("{field} exceeds its durable bound")),
        ));
    }
    serde_json::from_slice(&value).map_err(|error| conversion(index, error))
}

pub(super) fn conversion(
    index: usize,
    error: impl StdError + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(error))
}
