use crate::error::ImageCliError;
use runtrue_attest::SignedImageManifest;
pub(crate) fn authorize_if_required(
    signed: &SignedImageManifest,
    required: bool,
) -> Result<(), ImageCliError> {
    if required {
        signed.manifest.authorize_warm_snapshot_publication()?;
    }
    Ok(())
}
