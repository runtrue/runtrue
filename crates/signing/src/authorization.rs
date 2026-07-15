use crate::{SigningApproval, SigningError, SigningGrant, SigningRequest};

pub trait SigningAuthorizer {
    fn authorize(
        &self,
        request: &SigningRequest,
        now_unix_seconds: u64,
    ) -> Result<(SigningGrant, SigningApproval), SigningError>;
}
