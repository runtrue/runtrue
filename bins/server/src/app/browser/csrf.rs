use crate::app::{
    authentication_tag, invalid_object_problem, problem_response, HmacSha256, RequestId,
    AUTH_DOMAIN, MAX_RETURN_TO_BYTES,
};
use axum::{
    body::Bytes,
    extract::rejection::BytesRejection,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use hmac::Mac as _;
use zeroize::Zeroizing;

pub(in crate::app) fn browser_csrf_input(
    request_id: &RequestId,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Zeroizing<String>, Box<Response>> {
    let header = match headers.get("x-csrf-token") {
        Some(value) => Some(
            value
                .to_str()
                .map_err(|_| invalid_object_problem(request_id, "invalid CSRF header"))?
                .to_owned(),
        ),
        None => None,
    };
    let body = body.map_err(|_| invalid_object_problem(request_id, "invalid CSRF body"))?;
    let form = if body.is_empty() {
        None
    } else {
        form_value(&body, "csrf_token")
            .map_err(|_| invalid_object_problem(request_id, "invalid CSRF body"))?
    };
    let selected = match (header, form) {
        (Some(header), Some(form)) if !constant_time_text_equal(&header, &form) => {
            return Err(invalid_object_problem(request_id, "conflicting CSRF credentials").into());
        }
        (Some(header), _) => header,
        (_, Some(form)) => form,
        (None, None) => {
            return Err(problem_response(
                request_id,
                StatusCode::FORBIDDEN,
                "CSRF validation failed",
                "a bound CSRF token is required",
            )
            .into());
        }
    };
    if selected.is_empty()
        || selected.len() > 1024
        || selected.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_object_problem(request_id, "invalid CSRF token").into());
    }
    Ok(Zeroizing::new(selected))
}
pub(in crate::app) fn form_value(body: &[u8], name: &str) -> Result<Option<String>, ()> {
    let body = std::str::from_utf8(body).map_err(|_| ())?;
    let mut found = None;
    for pair in body.split('&') {
        let (candidate, value) = pair.split_once('=').ok_or(())?;
        if percent_decode(candidate)? == name && found.replace(percent_decode(value)?).is_some() {
            return Err(());
        }
    }
    Ok(found)
}

pub(in crate::app) fn percent_decode(value: &str) -> Result<String, ()> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_nibble(bytes[index + 1]).ok_or(())?;
                let low = hex_nibble(bytes[index + 2]).ok_or(())?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err(()),
            byte if byte.is_ascii() => {
                decoded.push(byte);
                index += 1;
            }
            _ => return Err(()),
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

pub(in crate::app) const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(in crate::app) fn constant_time_text_equal(left: &str, right: &str) -> bool {
    let key = [0x5a_u8; 32];
    let expected = authentication_tag(&key, left.as_bytes());
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts 32-byte keys");
    mac.update(AUTH_DOMAIN);
    mac.update(right.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

pub(in crate::app) fn valid_return_to(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= MAX_RETURN_TO_BYTES
        && !value.contains('\\')
        && !value.contains('#')
        && !value.bytes().any(|byte| byte.is_ascii_control())
}
