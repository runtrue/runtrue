use super::{
    AdmittedImage, Arc, AssignmentRecord, BTreeMap, ContentDigest, ImageAdmissionError,
    ImageAdmissionProvider, ImageVerifyingKey, LockedImage,
};

#[derive(Debug, Clone)]
pub(super) struct SelectedManifestAdmission {
    pub(super) keys: Arc<BTreeMap<ContentDigest, ImageVerifyingKey>>,
    pub(super) records: BTreeMap<String, AssignmentRecord>,
}

impl ImageAdmissionProvider for SelectedManifestAdmission {
    fn admit(&self, image: &LockedImage) -> Result<AdmittedImage, ImageAdmissionError> {
        let record = self.records.get(image.reference()).ok_or_else(|| {
            ImageAdmissionError::Denied("image has no selected signed assignment".to_owned())
        })?;
        self.keys
            .get(&record.signed.key_id)
            .ok_or_else(|| ImageAdmissionError::Denied("image key is not trusted".to_owned()))?
            .verify_manifest(&record.signed)
            .map_err(|error| ImageAdmissionError::Denied(error.to_string()))?;
        if record.locked != *image {
            return Err(ImageAdmissionError::Denied(
                "locked image differs from selected assignment".to_owned(),
            ));
        }
        AdmittedImage::verified(
            image.reference(),
            image.signature_identity(),
            image.platform(),
        )
        .map_err(|error| ImageAdmissionError::Denied(error.to_string()))
    }
}
