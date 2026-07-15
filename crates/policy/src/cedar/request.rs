use super::{model::CedarRequestContext, validation::bounded, CedarAuthorizationError};
use cedar_policy::{EntityId, EntityTypeName, EntityUid};
use serde_json::{json, Map, Value};
use std::str::FromStr as _;

pub(super) fn entity_uid(
    entity_type: &str,
    id: &str,
) -> Result<EntityUid, CedarAuthorizationError> {
    let entity_type = EntityTypeName::from_str(entity_type)
        .map_err(|error| CedarAuthorizationError::Request(bounded(error)))?;
    Ok(EntityUid::from_type_name_and_id(
        entity_type,
        EntityId::new(id),
    ))
}
pub(super) fn context_json(
    context: &CedarRequestContext,
) -> Result<Value, CedarAuthorizationError> {
    let mut value = Map::from_iter([("break_glass".to_owned(), json!(context.break_glass))]);
    if let Some(age) = context.mfa_age_seconds {
        value.insert(
            "mfa_age_seconds".to_owned(),
            json!(i64::try_from(age).map_err(|_| CedarAuthorizationError::InvalidContextAge)?),
        );
    }
    if let Some(age) = context.reauthentication_age_seconds {
        value.insert(
            "reauthentication_age_seconds".to_owned(),
            json!(i64::try_from(age).map_err(|_| CedarAuthorizationError::InvalidContextAge)?),
        );
    }
    Ok(Value::Object(value))
}
