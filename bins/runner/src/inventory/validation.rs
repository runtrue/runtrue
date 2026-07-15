pub fn apply_authoritative_posture(
    inventory: &mut VerifiedInventory,
    digest: &ContentDigest,
) -> Result<(), InventoryError> {
    inventory.profile.posture_digest = digest.clone();
    let capability = inventory
        .wire
        .capabilities
        .iter_mut()
        .find(|capability| capability.key == "runtrue.posture.digest")
        .ok_or(InventoryError::MissingPostureCapability)?;
    capability.json_value =
        serde_json::to_string(digest.as_str()).map_err(InventoryError::PostureEncoding)?;
    capability.evidence_source = "enrollment-authoritative".to_owned();
    inventory.profile.validate()?;
    Ok(())
}

#[cfg(unix)]
use super::{InventoryError, VerifiedInventory};
use runtrue_model::ContentDigest;
