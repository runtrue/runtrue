mod error;
mod load;
mod model;
mod publish;
mod rotation;
mod secure_fs;
#[cfg(test)]
mod tests;
mod validation;

pub use error::CredentialError;
pub use model::{
    LoadedRunnerCredentials, NewRunnerCredentials, PendingRotationResponse, PendingRunnerRotation,
    RunnerCredentialStore,
};

const GENERATIONS_DIRECTORY: &str = "generations";
const CURRENT_FILE: &str = "current";
const PRIVATE_KEY_FILE: &str = "client-key.pem";
const CERTIFICATE_FILE: &str = "client-certificate.pem";
const METADATA_FILE: &str = "metadata.json";
const PROTOCOL_VERSION_FILE: &str = "protocol-version";
const PENDING_ROTATION_DIRECTORY: &str = "pending-rotation";
const PENDING_ROTATION_PREFIX: &str = ".pending-rotation-";
const ROTATION_RESPONSE_TEMP_PREFIX: &str = ".rotation-response-";
const ROTATION_CSR_FILE: &str = "request.der";
const ROTATION_RESPONSE_FILE: &str = "response.json";
const ROTATION_LOCK_FILE: &str = "rotation.lock";
const CREDENTIAL_FORMAT_VERSION: u32 = 1;
const ROTATION_FORMAT_VERSION: u32 = 1;
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024;
const MAX_RETAINED_GENERATIONS: usize = 2;

use model::{CredentialMetadata, PendingRotationMetadata};
use validation::certificate_fingerprint;
