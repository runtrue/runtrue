pub(crate) fn signing_capability(request: &ast::SigningRequest) -> ir::SigningCapability {
    ir::SigningCapability {
        purpose: request.purpose.clone(),
        operation: match request.operation {
            ast::SigningOperation::SignDigest => ir::SigningOperation::SignDigest,
            ast::SigningOperation::SignAttestation => ir::SigningOperation::SignAttestation,
        },
        key_policy: request.key_policy.clone(),
    }
}

pub(crate) fn validate_signing_requests(
    requests: &[ast::SigningRequest],
    path: &str,
) -> Result<(), CompileError> {
    if requests.len() > MAX_SIGNING_CAPABILITIES {
        return Err(CompileError::semantic(
            path,
            format!("signing capabilities exceed the {MAX_SIGNING_CAPABILITIES} entry limit"),
        ));
    }
    let mut exact = BTreeSet::new();
    for (index, request) in requests.iter().enumerate() {
        validate_signing_identifier(&request.purpose, &format!("{path}[{index}].purpose"))?;
        validate_signing_identifier(&request.key_policy, &format!("{path}[{index}].key-policy"))?;
        if !exact.insert((&request.purpose, request.operation, &request.key_policy)) {
            return Err(CompileError::semantic(
                path,
                "signing capabilities must be exact and unique",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_signing_identifier(value: &str, path: &str) -> Result<(), CompileError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_SIGNING_IDENTIFIER_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(CompileError::semantic(
            path,
            format!(
                "signing identifier must be 1..={MAX_SIGNING_IDENTIFIER_BYTES} ASCII letters, digits, '.', '_' or '-', starting with a letter or digit"
            ),
        ))
    }
}
use crate::{
    ast, ir, BTreeSet, CompileError, MAX_SIGNING_CAPABILITIES, MAX_SIGNING_IDENTIFIER_BYTES,
};
