use serde_yaml::Value as YamlValue;

pub(crate) fn has_secret_expression(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    let mut remaining = lowercase.as_str();
    while let Some(start) = remaining.find("${{") {
        let expression_start = start + 3;
        remaining = &remaining[expression_start..];
        let (expression, rest) = remaining.find("}}").map_or((remaining, ""), |end| {
            (&remaining[..end], &remaining[end + 2..])
        });
        let compact = expression
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        if contains_identifier(expression, "secrets")
            || contains_identifier(expression, "github_token")
            || compact.contains("github.token")
            || compact.contains("github['token']")
            || compact.contains("github[\"token\"]")
        {
            return true;
        }
        remaining = rest;
    }
    false
}

pub(crate) fn is_github_token_expression(value: &str) -> bool {
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        compact.as_str(),
        "${{github.token}}" | "${{github['token']}}" | "${{github[\"token\"]}}"
    )
}

pub(crate) fn contains_identifier(value: &str, identifier: &str) -> bool {
    value.match_indices(identifier).any(|(index, _)| {
        let before = value[..index].chars().next_back();
        let after = value[index + identifier.len()..].chars().next();
        before.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
            && after.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

pub(crate) fn contains_github_runtime(value: &str) -> bool {
    [
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_WORKSPACE",
        "GITHUB_ACTION",
        "GITHUB_EVENT",
        "RUNNER_",
        "::set-output",
        "::add-mask",
        "::error",
        "::warning",
        "::group",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

pub(crate) fn has_privileged_or_host_feature(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    [
        "--privileged",
        "--network=host",
        "--network host",
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/dev/",
        "nsenter",
        "mount -t",
        "sudo ",
        "hostpath",
        "pid: host",
        "ipc: host",
    ]
    .iter()
    .any(|needle| lowercase.contains(needle))
}

pub(crate) fn looks_like_secret_name(name: &str) -> bool {
    let uppercase = name.to_ascii_uppercase();
    [
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "PRIVATE_KEY",
        "API_KEY",
        "ACCESS_KEY",
        "CLIENT_SECRET",
        "CREDENTIAL",
    ]
    .iter()
    .any(|needle| uppercase.contains(needle))
}

pub(crate) fn is_empty_scalar(value: &YamlValue) -> bool {
    value.is_null() || value.as_str() == Some("")
}
