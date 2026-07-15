use super::model::{CedarAction, CedarResourceKind};
use serde_json::{json, Map, Value};
pub(super) fn runtrue_schema() -> Value {
    let context = json!({
        "type": "Record",
        "attributes": {
            "mfa_age_seconds": {"type": "Long", "required": false},
            "reauthentication_age_seconds": {"type": "Long", "required": false},
            "break_glass": {"type": "Boolean"}
        }
    });
    let resource_types = CedarResourceKind::ALL
        .into_iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    let actions = CedarAction::ALL
        .into_iter()
        .map(|action| {
            (
                action.as_str().to_owned(),
                json!({
                    "appliesTo": {
                        "principalTypes": ["User", "ServiceAccount"],
                        "resourceTypes": resource_types,
                        "context": context,
                    }
                }),
            )
        })
        .collect::<Map<_, _>>();
    let principal_shape = json!({"type": "Record", "attributes": {
        "id": {"type": "String"},
        "tenant_id": {"type": "String"}
    }});
    let resource_shape = json!({"type": "Record", "attributes": {
        "kind": {"type": "String"},
        "tenant_id": {"type": "String"},
        "repository_id": {"type": "String", "required": false},
        "author_id": {"type": "String", "required": false},
        "risk_score": {"type": "Long"},
        "privileged": {"type": "Boolean"},
        "untrusted": {"type": "Boolean"}
    }});
    let mut entity_types = Map::from_iter([
        (
            "User".to_owned(),
            json!({"memberOfTypes": ["Team"], "shape": principal_shape}),
        ),
        (
            "ServiceAccount".to_owned(),
            json!({"memberOfTypes": ["Team"], "shape": principal_shape}),
        ),
        ("Team".to_owned(), json!({"memberOfTypes": []})),
    ]);
    entity_types.extend(CedarResourceKind::ALL.into_iter().map(|kind| {
        (
            kind.as_str().to_owned(),
            json!({"memberOfTypes": [], "shape": resource_shape}),
        )
    }));
    json!({
        "": {
            "entityTypes": entity_types,
            "actions": actions
        }
    })
}
