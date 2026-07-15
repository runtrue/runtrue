pub trait ImageAdmissionProvider: Send + Sync {
    fn admit(&self, image: &LockedImage) -> Result<AdmittedImage, ImageAdmissionError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ImageAdmissionError {
    #[error("image admission denied: {0}")]
    Denied(String),
    #[error("image verification provider unavailable: {0}")]
    Unavailable(String),
}
use crate::{AdmittedImage, LockedImage};
use thiserror::Error;
