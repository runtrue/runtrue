use super::model::CedarAuthorizationRequest;
use serde_json::{json, Map, Value};
pub(super) fn entities_json(request: &CedarAuthorizationRequest) -> Value {
    let parents = request
        .principal
        .groups
        .iter()
        .map(|group| json!({"type": "Team", "id": group}))
        .collect::<Vec<_>>();
    let mut entities = vec![json!({
        "uid": {
            "type": request.principal.kind.entity_type(),
            "id": request.principal.id,
        },
        "attrs": {
            "id": request.principal.id,
            "tenant_id": request.principal.tenant_id,
        },
        "parents": parents,
    })];
    entities.extend(request.principal.groups.iter().map(|group| {
        json!({
            "uid": {"type": "Team", "id": group},
            "attrs": {},
            "parents": [],
        })
    }));
    let mut attributes = Map::from_iter([
        ("kind".to_owned(), json!(request.resource.kind.as_str())),
        ("tenant_id".to_owned(), json!(request.resource.tenant_id)),
        ("risk_score".to_owned(), json!(request.resource.risk_score)),
        ("privileged".to_owned(), json!(request.resource.privileged)),
        ("untrusted".to_owned(), json!(request.resource.untrusted)),
    ]);
    if let Some(repository) = &request.resource.repository_id {
        attributes.insert("repository_id".to_owned(), json!(repository));
    }
    if let Some(author) = &request.resource.author_id {
        attributes.insert("author_id".to_owned(), json!(author));
    }
    entities.push(json!({
        "uid": {"type": request.resource.kind.as_str(), "id": request.resource.id},
        "attrs": attributes,
        "parents": [],
    }));
    Value::Array(entities)
}
