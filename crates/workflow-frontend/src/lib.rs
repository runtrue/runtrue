//! Domain-neutral source-language boundary for workflow integrations.
//!
//! A frontend can live in a separate repository and deployment artifact. It
//! produces native Runtrue workflow YAML plus integrity-bound diagnostics; it
//! never receives authority to admit or execute the translated Program.

#![forbid(unsafe_code)]

use runtrue_model::ContentDigest;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

const MAX_FRONTEND_ID_BYTES: usize = 128;
const MAX_FRONTENDS: usize = 16;
const MAX_DISCOVERY_ROOTS: usize = 64;
const MAX_WORKFLOW_PATH_BYTES: usize = 1024;
const MAX_FRONTEND_OPTION_COUNT: usize = 64;
const MAX_FRONTEND_OPTION_NAME_BYTES: usize = 128;
const MAX_FRONTEND_OPTION_VALUE_BYTES: usize = 4096;
const MAX_FRONTEND_OPTION_BYTES: usize = 64 * 1024;
const MAX_RESOLVED_ACTIONS: usize = 256;
const MAX_RESOLVED_ACTION_REFERENCE_BYTES: usize = 1024;
const MAX_RESOLVED_ACTION_INPUTS: usize = 256;
const MAX_RESOLVED_ACTION_INPUT_NAME_BYTES: usize = 128;
const MAX_RESOLVED_ACTION_INPUT_DEFAULT_BYTES: usize = 4096;
const MAX_RESOLVED_ACTION_NETWORK_DESTINATIONS: usize = 64;
const MAX_RESOLVED_ACTION_SECRETS: usize = 64;
const MAX_RESOLVED_ACTION_HOST_BYTES: usize = 253;
const MAX_RESOLVED_PROGRAM_FIELD_BYTES: usize = 4096;
const MAX_RESOLVED_PROGRAM_ARGUMENTS: usize = 128;
const MAX_RESOLVED_ACTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTION_DESCRIPTOR_CANDIDATES: usize = 8;
const MAX_ACTION_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const MAX_ACTION_DESCRIPTORS_BYTES: usize = 2 * 1024 * 1024;
const MAX_FRONTEND_ERROR_CODE_BYTES: usize = 128;
const MAX_FRONTEND_ERROR_DETAIL_BYTES: usize = 4096;
pub const MAX_REPORT_MEDIA_TYPE_BYTES: usize = 255;
pub const MAX_NATIVE_WORKFLOW_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_GENERATED_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FRONTEND_REPORT_BYTES: usize = 1024 * 1024;

/// Generation of the repository-independent frontend contract itself.
///
/// This is separate from `frontend_generation`, which versions one adapter's
/// translation semantics. A contract generation change requires both sides of
/// the repository boundary to opt in explicitly.
pub const WORKFLOW_FRONTEND_CONTRACT_GENERATION: u32 = 3;

const OPTIONS_DIGEST_DOMAIN: &[u8] = b"runtrue.workflow-frontend.options.v3\0";
const RESOLVED_ACTIONS_ENCODING_DOMAIN: &[u8] = b"resolved-source-actions.v2\0";

/// Inputs that affect source translation and therefore its emitted digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkflowFrontendOptions {
    values: BTreeMap<String, String>,
    encoded_bytes: usize,
    resolved_actions: BTreeMap<String, ResolvedSourceAction>,
    resolved_action_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowFrontendOptionsError {
    TooManyOptions,
    InvalidOptionName,
    OptionValueTooLarge,
    OptionsTooLarge,
    TooManyResolvedActions,
    InvalidResolvedActionReference,
    DuplicateResolvedAction,
    ResolvedActionsTooLarge,
}

impl fmt::Display for WorkflowFrontendOptionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyOptions => "workflow frontend option count exceeds its bound",
            Self::InvalidOptionName => "workflow frontend option name is invalid",
            Self::OptionValueTooLarge => "workflow frontend option value exceeds its bound",
            Self::OptionsTooLarge => "workflow frontend options exceed their total bound",
            Self::TooManyResolvedActions => "resolved source action count exceeds its bound",
            Self::InvalidResolvedActionReference => "resolved source action reference is invalid",
            Self::DuplicateResolvedAction => "resolved source action reference is duplicated",
            Self::ResolvedActionsTooLarge => "resolved source actions exceed their total bound",
        })
    }
}

impl Error for WorkflowFrontendOptionsError {}

impl WorkflowFrontendOptions {
    /// Set a namespaced adapter option. Names and values are bounded before
    /// they can enter the deterministic configuration digest.
    pub fn set(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), WorkflowFrontendOptionsError> {
        let name = name.into();
        let value = value.into();
        if name.is_empty()
            || name.len() > MAX_FRONTEND_OPTION_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(WorkflowFrontendOptionsError::InvalidOptionName);
        }
        if value.len() > MAX_FRONTEND_OPTION_VALUE_BYTES {
            return Err(WorkflowFrontendOptionsError::OptionValueTooLarge);
        }
        if !self.values.contains_key(&name) && self.values.len() >= MAX_FRONTEND_OPTION_COUNT {
            return Err(WorkflowFrontendOptionsError::TooManyOptions);
        }

        let replaced_bytes = self
            .values
            .get(&name)
            .map_or(0, |existing| name.len() + existing.len());
        let encoded_bytes = self
            .encoded_bytes
            .saturating_sub(replaced_bytes)
            .saturating_add(name.len())
            .saturating_add(value.len());
        if encoded_bytes > MAX_FRONTEND_OPTION_BYTES {
            return Err(WorkflowFrontendOptionsError::OptionsTooLarge);
        }
        self.values.insert(name, value);
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }

    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Add one exact source-language reference resolved by trusted SCM code.
    /// Duplicate references fail closed rather than silently replacing a
    /// previously authenticated resolution.
    pub fn insert_resolved_action(
        &mut self,
        reference: impl Into<String>,
        action: ResolvedSourceAction,
    ) -> Result<(), WorkflowFrontendOptionsError> {
        let reference = reference.into();
        if !valid_bounded_text(&reference, MAX_RESOLVED_ACTION_REFERENCE_BYTES) {
            return Err(WorkflowFrontendOptionsError::InvalidResolvedActionReference);
        }
        if self.resolved_actions.contains_key(&reference) {
            return Err(WorkflowFrontendOptionsError::DuplicateResolvedAction);
        }
        if self.resolved_actions.len() >= MAX_RESOLVED_ACTIONS {
            return Err(WorkflowFrontendOptionsError::TooManyResolvedActions);
        }
        let encoded_bytes = self
            .resolved_action_bytes
            .saturating_add(4 + reference.len())
            .saturating_add(action.encoded_len());
        if encoded_bytes > MAX_RESOLVED_ACTION_BYTES {
            return Err(WorkflowFrontendOptionsError::ResolvedActionsTooLarge);
        }
        self.resolved_actions.insert(reference, action);
        self.resolved_action_bytes = encoded_bytes;
        Ok(())
    }

    /// Return only an exact authenticated resolution. A frontend cannot add,
    /// replace, or derive an executable identity through this view.
    #[must_use]
    pub fn resolved_action(&self, reference: &str) -> Option<&ResolvedSourceAction> {
        self.resolved_actions.get(reference)
    }

    pub fn resolved_actions(&self) -> impl ExactSizeIterator<Item = (&str, &ResolvedSourceAction)> {
        self.resolved_actions
            .iter()
            .map(|(reference, action)| (reference.as_str(), action))
    }

    /// Digest a canonical length-prefixed encoding in sorted option-name
    /// order. The domain includes the contract generation.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut canonical = Vec::with_capacity(
            OPTIONS_DIGEST_DOMAIN.len() + self.encoded_bytes + self.values.len() * 8 + 4,
        );
        canonical.extend_from_slice(OPTIONS_DIGEST_DOMAIN);
        canonical.extend_from_slice(&(self.values.len() as u32).to_be_bytes());
        for (name, value) in &self.values {
            canonical.extend_from_slice(&(name.len() as u32).to_be_bytes());
            canonical.extend_from_slice(name.as_bytes());
            canonical.extend_from_slice(&(value.len() as u32).to_be_bytes());
            canonical.extend_from_slice(value.as_bytes());
        }
        // Keep the generation-2 encoding of ordinary options byte-for-byte
        // stable. This additive, explicitly versioned section exists only when
        // trusted SCM supplied resolutions. An incompatible representation
        // requires a new contract generation and options digest domain.
        if !self.resolved_actions.is_empty() {
            canonical.extend_from_slice(RESOLVED_ACTIONS_ENCODING_DOMAIN);
            canonical.extend_from_slice(&(self.resolved_actions.len() as u32).to_be_bytes());
            for (reference, action) in &self.resolved_actions {
                encode_bytes(&mut canonical, reference.as_bytes());
                action.encode(&mut canonical);
            }
        }
        ContentDigest::sha256(canonical)
    }
}

/// A provider-neutral source action resolved against the authenticated source
/// snapshot before translation. All fields are private so only bounded,
/// canonical values can cross the frontend boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSourceAction {
    program: ResolvedProgram,
    inputs: BTreeMap<String, ResolvedActionInput>,
    requirements: ResolvedActionRequirements,
    encoded_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedActionError {
    InvalidProgramField,
    ProgramFieldTooLarge,
    TooManyArguments,
    InvalidInputName,
    InputDefaultTooLarge,
    TooManyInputs,
    DuplicateInput,
    InvalidNetworkDestination,
    TooManyNetworkDestinations,
    DuplicateNetworkDestination,
    InvalidSecret,
    TooManySecrets,
    DuplicateSecret,
    ActionTooLarge,
}

impl fmt::Display for ResolvedActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProgramField => "resolved program field is invalid",
            Self::ProgramFieldTooLarge => "resolved program field exceeds its bound",
            Self::TooManyArguments => "resolved program argument count exceeds its bound",
            Self::InvalidInputName => "resolved action input name is invalid",
            Self::InputDefaultTooLarge => "resolved action input default exceeds its bound",
            Self::TooManyInputs => "resolved action input count exceeds its bound",
            Self::DuplicateInput => "resolved action input name is duplicated",
            Self::InvalidNetworkDestination => "resolved action network destination is invalid",
            Self::TooManyNetworkDestinations => {
                "resolved action network destination count exceeds its bound"
            }
            Self::DuplicateNetworkDestination => {
                "resolved action network destination is duplicated"
            }
            Self::InvalidSecret => "resolved action secret declaration is invalid",
            Self::TooManySecrets => "resolved action secret count exceeds its bound",
            Self::DuplicateSecret => "resolved action secret declaration is duplicated",
            Self::ActionTooLarge => "resolved action exceeds its total bound",
        })
    }
}

impl Error for ResolvedActionError {}

impl ResolvedSourceAction {
    #[must_use]
    pub fn new(program: ResolvedProgram) -> Self {
        let requirements = ResolvedActionRequirements::default();
        let encoded_bytes = program.encoded_len() + requirements.encoded_len();
        Self {
            program,
            inputs: BTreeMap::new(),
            requirements,
            encoded_bytes,
        }
    }

    pub fn insert_input(
        &mut self,
        name: impl Into<String>,
        input: ResolvedActionInput,
    ) -> Result<(), ResolvedActionError> {
        let name = name.into();
        if !valid_identifier(&name, MAX_RESOLVED_ACTION_INPUT_NAME_BYTES) {
            return Err(ResolvedActionError::InvalidInputName);
        }
        if self.inputs.contains_key(&name) {
            return Err(ResolvedActionError::DuplicateInput);
        }
        if self.inputs.len() >= MAX_RESOLVED_ACTION_INPUTS {
            return Err(ResolvedActionError::TooManyInputs);
        }
        let encoded_bytes = self
            .encoded_bytes
            .saturating_add(4 + name.len())
            .saturating_add(input.encoded_len());
        if encoded_bytes > MAX_RESOLVED_ACTION_BYTES {
            return Err(ResolvedActionError::ActionTooLarge);
        }
        self.inputs.insert(name, input);
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }

    #[must_use]
    pub fn program(&self) -> ResolvedProgramRef<'_> {
        self.program.as_ref()
    }

    #[must_use]
    pub fn input(&self, name: &str) -> Option<&ResolvedActionInput> {
        self.inputs.get(name)
    }

    pub fn inputs(&self) -> impl ExactSizeIterator<Item = (&str, &ResolvedActionInput)> {
        self.inputs
            .iter()
            .map(|(name, input)| (name.as_str(), input))
    }

    pub fn insert_network_destination(
        &mut self,
        destination: ResolvedActionNetworkDestination,
    ) -> Result<(), ResolvedActionError> {
        self.requirements.insert_network_destination(destination)?;
        self.refresh_encoded_bytes()
    }

    pub fn insert_secret(
        &mut self,
        secret: ResolvedActionSecret,
    ) -> Result<(), ResolvedActionError> {
        self.requirements.insert_secret(secret)?;
        self.refresh_encoded_bytes()
    }

    #[must_use]
    pub const fn deny_private_networks(&self) -> bool {
        self.requirements.deny_private_networks
    }

    pub fn network_destinations(
        &self,
    ) -> impl ExactSizeIterator<Item = &ResolvedActionNetworkDestination> {
        self.requirements.network_destinations.iter()
    }

    pub fn secrets(&self) -> impl ExactSizeIterator<Item = &ResolvedActionSecret> {
        self.requirements.secrets.iter()
    }

    fn refresh_encoded_bytes(&mut self) -> Result<(), ResolvedActionError> {
        let encoded_bytes = self
            .program
            .encoded_len()
            .saturating_add(
                self.inputs
                    .iter()
                    .map(|(name, input)| 4 + name.len() + input.encoded_len())
                    .sum::<usize>(),
            )
            .saturating_add(self.requirements.encoded_len());
        if encoded_bytes > MAX_RESOLVED_ACTION_BYTES {
            return Err(ResolvedActionError::ActionTooLarge);
        }
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.encoded_bytes + 4
    }

    fn encode(&self, canonical: &mut Vec<u8>) {
        self.program.encode(canonical);
        canonical.extend_from_slice(&(self.inputs.len() as u32).to_be_bytes());
        for (name, input) in &self.inputs {
            encode_bytes(canonical, name.as_bytes());
            input.encode(canonical);
        }
        self.requirements.encode(canonical);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResolvedActionRequirements {
    deny_private_networks: bool,
    network_destinations: BTreeSet<ResolvedActionNetworkDestination>,
    secrets: BTreeSet<ResolvedActionSecret>,
}

impl ResolvedActionRequirements {
    fn insert_network_destination(
        &mut self,
        destination: ResolvedActionNetworkDestination,
    ) -> Result<(), ResolvedActionError> {
        if self.network_destinations.len() >= MAX_RESOLVED_ACTION_NETWORK_DESTINATIONS {
            return Err(ResolvedActionError::TooManyNetworkDestinations);
        }
        if !self.network_destinations.insert(destination) {
            return Err(ResolvedActionError::DuplicateNetworkDestination);
        }
        self.deny_private_networks = true;
        Ok(())
    }

    fn insert_secret(&mut self, secret: ResolvedActionSecret) -> Result<(), ResolvedActionError> {
        if self.secrets.len() >= MAX_RESOLVED_ACTION_SECRETS {
            return Err(ResolvedActionError::TooManySecrets);
        }
        if self
            .secrets
            .iter()
            .any(|existing| existing.name == secret.name || existing.file_env == secret.file_env)
        {
            return Err(ResolvedActionError::DuplicateSecret);
        }
        self.secrets.insert(secret);
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        1 + 4
            + self
                .network_destinations
                .iter()
                .map(ResolvedActionNetworkDestination::encoded_len)
                .sum::<usize>()
            + 4
            + self
                .secrets
                .iter()
                .map(ResolvedActionSecret::encoded_len)
                .sum::<usize>()
    }

    fn encode(&self, canonical: &mut Vec<u8>) {
        canonical.push(u8::from(self.deny_private_networks));
        canonical.extend_from_slice(&(self.network_destinations.len() as u32).to_be_bytes());
        for destination in &self.network_destinations {
            destination.encode(canonical);
        }
        canonical.extend_from_slice(&(self.secrets.len() as u32).to_be_bytes());
        for secret in &self.secrets {
            secret.encode(canonical);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedActionNetworkDestination {
    host: String,
    port: u16,
}

impl ResolvedActionNetworkDestination {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ResolvedActionError> {
        let host = host.into();
        if port == 0
            || host.is_empty()
            || host.len() > MAX_RESOLVED_ACTION_HOST_BYTES
            || host != host.to_ascii_lowercase()
            || host.contains(['/', '@', ':'])
            || host.chars().any(char::is_whitespace)
        {
            return Err(ResolvedActionError::InvalidNetworkDestination);
        }
        Ok(Self { host, port })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    fn encoded_len(&self) -> usize {
        4 + self.host.len() + 2
    }

    fn encode(&self, canonical: &mut Vec<u8>) {
        encode_bytes(canonical, self.host.as_bytes());
        canonical.extend_from_slice(&self.port.to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedActionSecret {
    name: String,
    purpose: String,
    file_env: String,
}

impl ResolvedActionSecret {
    pub fn new(
        name: impl Into<String>,
        purpose: impl Into<String>,
        file_env: impl Into<String>,
    ) -> Result<Self, ResolvedActionError> {
        let name = name.into();
        let purpose = purpose.into();
        let file_env = file_env.into();
        if !valid_identifier(&name, MAX_RESOLVED_ACTION_INPUT_NAME_BYTES)
            || !valid_identifier(&purpose, MAX_RESOLVED_ACTION_INPUT_NAME_BYTES)
            || !valid_environment_name(&file_env)
        {
            return Err(ResolvedActionError::InvalidSecret);
        }
        Ok(Self {
            name,
            purpose,
            file_env,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn file_env(&self) -> &str {
        &self.file_env
    }

    fn encoded_len(&self) -> usize {
        12 + self.name.len() + self.purpose.len() + self.file_env.len()
    }

    fn encode(&self, canonical: &mut Vec<u8>) {
        for value in [&self.name, &self.purpose, &self.file_env] {
            encode_bytes(canonical, value.as_bytes());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProgram {
    kind: ResolvedProgramKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedProgramKind {
    Container {
        image: String,
        entrypoint: Option<String>,
        arguments: Option<Vec<String>>,
    },
    Component {
        reference: String,
        api_url: String,
        signature_identity: String,
        interface: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedProgramRef<'a> {
    Container {
        image: &'a str,
        entrypoint: Option<&'a str>,
        /// `None` preserves the image command; `Some` replaces it exactly.
        arguments: Option<&'a [String]>,
    },
    Component {
        reference: &'a str,
        api_url: &'a str,
        signature_identity: &'a str,
        interface: &'a str,
    },
}

impl ResolvedProgram {
    pub fn container(
        image: impl Into<String>,
        entrypoint: Option<String>,
        arguments: Option<Vec<String>>,
    ) -> Result<Self, ResolvedActionError> {
        let image = image.into();
        validate_program_field(&image)?;
        validate_immutable_reference(&image)?;
        if let Some(value) = &entrypoint {
            validate_program_field(value)?;
        }
        if let Some(values) = &arguments {
            if values.len() > MAX_RESOLVED_PROGRAM_ARGUMENTS {
                return Err(ResolvedActionError::TooManyArguments);
            }
            for value in values {
                validate_program_field(value)?;
            }
        }
        Ok(Self {
            kind: ResolvedProgramKind::Container {
                image,
                entrypoint,
                arguments,
            },
        })
    }

    pub fn component(
        reference: impl Into<String>,
        api_url: impl Into<String>,
        signature_identity: impl Into<String>,
        interface: impl Into<String>,
    ) -> Result<Self, ResolvedActionError> {
        let reference = reference.into();
        let api_url = api_url.into();
        let signature_identity = signature_identity.into();
        let interface = interface.into();
        for value in [&reference, &api_url, &signature_identity, &interface] {
            validate_program_field(value)?;
        }
        validate_immutable_reference(&reference)?;
        Ok(Self {
            kind: ResolvedProgramKind::Component {
                reference,
                api_url,
                signature_identity,
                interface,
            },
        })
    }

    #[must_use]
    pub fn as_ref(&self) -> ResolvedProgramRef<'_> {
        match &self.kind {
            ResolvedProgramKind::Container {
                image,
                entrypoint,
                arguments,
            } => ResolvedProgramRef::Container {
                image,
                entrypoint: entrypoint.as_deref(),
                arguments: arguments.as_deref(),
            },
            ResolvedProgramKind::Component {
                reference,
                api_url,
                signature_identity,
                interface,
            } => ResolvedProgramRef::Component {
                reference,
                api_url,
                signature_identity,
                interface,
            },
        }
    }

    fn encoded_len(&self) -> usize {
        match &self.kind {
            ResolvedProgramKind::Container {
                image,
                entrypoint,
                arguments,
            } => {
                1 + encoded_optional_text_len(entrypoint.as_deref())
                    + 4
                    + image.len()
                    + encoded_optional_list_len(arguments.as_deref())
            }
            ResolvedProgramKind::Component {
                reference,
                api_url,
                signature_identity,
                interface,
            } => {
                1 + 16
                    + reference.len()
                    + api_url.len()
                    + signature_identity.len()
                    + interface.len()
            }
        }
    }

    fn encode(&self, canonical: &mut Vec<u8>) {
        match &self.kind {
            ResolvedProgramKind::Container {
                image,
                entrypoint,
                arguments,
            } => {
                canonical.push(1);
                encode_bytes(canonical, image.as_bytes());
                encode_optional_text(canonical, entrypoint.as_deref());
                encode_optional_list(canonical, arguments.as_deref());
            }
            ResolvedProgramKind::Component {
                reference,
                api_url,
                signature_identity,
                interface,
            } => {
                canonical.push(2);
                for value in [reference, api_url, signature_identity, interface] {
                    encode_bytes(canonical, value.as_bytes());
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedActionInput {
    required: bool,
    default: Option<String>,
}

impl ResolvedActionInput {
    pub fn new(required: bool, default: Option<String>) -> Result<Self, ResolvedActionError> {
        if default
            .as_ref()
            .is_some_and(|value| value.len() > MAX_RESOLVED_ACTION_INPUT_DEFAULT_BYTES)
        {
            return Err(ResolvedActionError::InputDefaultTooLarge);
        }
        if default.as_ref().is_some_and(|value| value.contains('\0')) {
            return Err(ResolvedActionError::InvalidProgramField);
        }
        Ok(Self { required, default })
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub fn default_value(&self) -> Option<&str> {
        self.default.as_deref()
    }

    fn encoded_len(&self) -> usize {
        1 + encoded_optional_text_len(self.default.as_deref())
    }

    fn encode(&self, canonical: &mut Vec<u8>) {
        canonical.push(u8::from(self.required));
        encode_optional_text(canonical, self.default.as_deref());
    }
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    valid_bounded_text(value, maximum)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= MAX_RESOLVED_ACTION_INPUT_NAME_BYTES
}

fn validate_program_field(value: &str) -> Result<(), ResolvedActionError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err(ResolvedActionError::InvalidProgramField)
    } else if value.len() > MAX_RESOLVED_PROGRAM_FIELD_BYTES {
        Err(ResolvedActionError::ProgramFieldTooLarge)
    } else {
        Ok(())
    }
}

fn validate_immutable_reference(value: &str) -> Result<(), ResolvedActionError> {
    let Some((_, digest)) = value.rsplit_once("@sha256:") else {
        return Err(ResolvedActionError::InvalidProgramField);
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ResolvedActionError::InvalidProgramField)
    }
}

fn encode_bytes(canonical: &mut Vec<u8>, value: &[u8]) {
    canonical.extend_from_slice(&(value.len() as u32).to_be_bytes());
    canonical.extend_from_slice(value);
}

fn encoded_optional_text_len(value: Option<&str>) -> usize {
    1 + value.map_or(0, |value| 4 + value.len())
}

fn encode_optional_text(canonical: &mut Vec<u8>, value: Option<&str>) {
    canonical.push(u8::from(value.is_some()));
    if let Some(value) = value {
        encode_bytes(canonical, value.as_bytes());
    }
}

fn encoded_optional_list_len(value: Option<&[String]>) -> usize {
    1 + value.map_or(0, |values| {
        4 + values.iter().map(|value| 4 + value.len()).sum::<usize>()
    })
}

fn encode_optional_list(canonical: &mut Vec<u8>, value: Option<&[String]>) {
    canonical.push(u8::from(value.is_some()));
    if let Some(values) = value {
        canonical.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            encode_bytes(canonical, value.as_bytes());
        }
    }
}

/// Bounded provider-neutral request for trusted SCM to resolve repository
/// content. The adapter interprets source syntax; trusted SCM authenticates
/// the locator and fetches every descriptor from the exact revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceActionResolutionRequest {
    source_reference: String,
    repository: String,
    revision: String,
    subpath: String,
    descriptor_candidates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceActionResolutionError {
    InvalidReference,
    InvalidRepository,
    InvalidRevision,
    InvalidPath,
    TooManyDescriptorCandidates,
    DuplicateDescriptorCandidate,
    TooManyRequests,
    DuplicateRequest,
    UnexpectedDescriptor,
    DescriptorTooLarge,
    DescriptorsTooLarge,
}

impl fmt::Display for SourceActionResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidReference => "source action reference is invalid",
            Self::InvalidRepository => "source action repository locator is invalid",
            Self::InvalidRevision => "source action revision is invalid",
            Self::InvalidPath => "source action path is invalid",
            Self::TooManyDescriptorCandidates => {
                "action descriptor candidate count exceeds its bound"
            }
            Self::DuplicateDescriptorCandidate => "action descriptor candidate is duplicated",
            Self::TooManyRequests => "source action resolution request count exceeds its bound",
            Self::DuplicateRequest => "source action resolution request is duplicated",
            Self::UnexpectedDescriptor => "action descriptor was not requested",
            Self::DescriptorTooLarge => "action descriptor exceeds its byte bound",
            Self::DescriptorsTooLarge => "action descriptors exceed their aggregate byte bound",
        })
    }
}

impl Error for SourceActionResolutionError {}

impl SourceActionResolutionRequest {
    pub fn new(
        source_reference: impl Into<String>,
        repository: impl Into<String>,
        revision: impl Into<String>,
        subpath: impl Into<String>,
        descriptor_candidates: impl IntoIterator<Item = String>,
    ) -> Result<Self, SourceActionResolutionError> {
        let source_reference = source_reference.into();
        let repository = repository.into();
        let revision = revision.into();
        let subpath = subpath.into();
        if !valid_bounded_text(&source_reference, MAX_RESOLVED_ACTION_REFERENCE_BYTES) {
            return Err(SourceActionResolutionError::InvalidReference);
        }
        if !valid_bounded_text(&repository, MAX_WORKFLOW_PATH_BYTES) {
            return Err(SourceActionResolutionError::InvalidRepository);
        }
        if !valid_bounded_text(&revision, MAX_FRONTEND_OPTION_NAME_BYTES) {
            return Err(SourceActionResolutionError::InvalidRevision);
        }
        if !subpath.is_empty() && !valid_relative_path(&subpath) {
            return Err(SourceActionResolutionError::InvalidPath);
        }
        let mut candidates = Vec::new();
        let mut unique = BTreeSet::new();
        for candidate in descriptor_candidates {
            if !valid_relative_path(&candidate) {
                return Err(SourceActionResolutionError::InvalidPath);
            }
            if !unique.insert(candidate.clone()) {
                return Err(SourceActionResolutionError::DuplicateDescriptorCandidate);
            }
            if candidates.len() >= MAX_ACTION_DESCRIPTOR_CANDIDATES {
                return Err(SourceActionResolutionError::TooManyDescriptorCandidates);
            }
            candidates.push(candidate);
        }
        if candidates.is_empty() {
            return Err(SourceActionResolutionError::InvalidPath);
        }
        Ok(Self {
            source_reference,
            repository,
            revision,
            subpath,
            descriptor_candidates: candidates,
        })
    }

    #[must_use]
    pub fn source_reference(&self) -> &str {
        &self.source_reference
    }
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
    #[must_use]
    pub fn subpath(&self) -> &str {
        &self.subpath
    }
    #[must_use]
    pub fn descriptor_candidates(&self) -> &[String] {
        &self.descriptor_candidates
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceActionResolutionRequests {
    requests: BTreeMap<String, SourceActionResolutionRequest>,
}

impl SourceActionResolutionRequests {
    pub fn insert(
        &mut self,
        request: SourceActionResolutionRequest,
    ) -> Result<(), SourceActionResolutionError> {
        if self.requests.contains_key(request.source_reference()) {
            return Err(SourceActionResolutionError::DuplicateRequest);
        }
        if self.requests.len() >= MAX_RESOLVED_ACTIONS {
            return Err(SourceActionResolutionError::TooManyRequests);
        }
        self.requests
            .insert(request.source_reference.clone(), request);
        Ok(())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &SourceActionResolutionRequest> {
        self.requests.values()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}

/// Descriptor bytes fetched by trusted SCM. Only candidate paths named by the
/// request can be inserted, and absence remains distinguishable from an empty
/// descriptor so the adapter can reject ambiguous candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceActionDescriptors {
    allowed: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    encoded_bytes: usize,
}

impl SourceActionDescriptors {
    #[must_use]
    pub fn for_request(request: &SourceActionResolutionRequest) -> Self {
        Self {
            allowed: request.descriptor_candidates.iter().cloned().collect(),
            files: BTreeMap::new(),
            encoded_bytes: 0,
        }
    }

    pub fn insert(
        &mut self,
        path: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<(), SourceActionResolutionError> {
        let path = path.into();
        if !self.allowed.contains(&path) {
            return Err(SourceActionResolutionError::UnexpectedDescriptor);
        }
        if self.files.contains_key(&path) {
            return Err(SourceActionResolutionError::DuplicateDescriptorCandidate);
        }
        if bytes.len() > MAX_ACTION_DESCRIPTOR_BYTES {
            return Err(SourceActionResolutionError::DescriptorTooLarge);
        }
        let encoded_bytes = self.encoded_bytes.saturating_add(path.len() + bytes.len());
        if encoded_bytes > MAX_ACTION_DESCRIPTORS_BYTES {
            return Err(SourceActionResolutionError::DescriptorsTooLarge);
        }
        self.files.insert(path, bytes);
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }

    #[must_use]
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// Return the exact descriptor selected by the adapter. This mechanically
    /// rejects a fabricated or absent selection before trusted SCM hashes it.
    pub fn selected_descriptor(
        &self,
        declaration: &SourceActionDeclaration,
    ) -> Result<&[u8], SourceActionResolutionError> {
        self.get(declaration.descriptor_path())
            .ok_or(SourceActionResolutionError::UnexpectedDescriptor)
    }
}

/// Adapter-parsed, non-executable declaration. Trusted SCM must verify/build
/// this declaration and construct the final immutable `ResolvedSourceAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceActionDeclaration {
    source_reference: String,
    descriptor_path: String,
    program: SourceActionProgramDeclaration,
    inputs: BTreeMap<String, ResolvedActionInput>,
    requirements: ResolvedActionRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceActionProgramDeclaration {
    /// Repository-relative build recipe. It is not an image identity; trusted
    /// SCM/build infrastructure must produce an immutable image reference.
    ContainerBuild {
        build_file: String,
        entrypoint: Option<String>,
        arguments: Option<Vec<String>>,
    },
    /// Claims read from the exact authenticated descriptor. This deliberately
    /// has no API origin and is not executable: downstream admission must
    /// independently verify the immutable digest, signature identity, and
    /// interface before constructing `ResolvedProgram::component`.
    Component {
        reference: String,
        signature_identity: String,
        interface: String,
    },
}

impl SourceActionDeclaration {
    pub fn new(
        source_reference: impl Into<String>,
        descriptor_path: impl Into<String>,
        program: SourceActionProgramDeclaration,
    ) -> Result<Self, ResolvedActionError> {
        let source_reference = source_reference.into();
        let descriptor_path = descriptor_path.into();
        if !valid_bounded_text(&source_reference, MAX_RESOLVED_ACTION_REFERENCE_BYTES) {
            return Err(ResolvedActionError::InvalidProgramField);
        }
        if !valid_relative_path(&descriptor_path) {
            return Err(ResolvedActionError::InvalidProgramField);
        }
        program.validate()?;
        Ok(Self {
            source_reference,
            descriptor_path,
            program,
            inputs: BTreeMap::new(),
            requirements: ResolvedActionRequirements::default(),
        })
    }

    pub fn insert_input(
        &mut self,
        name: impl Into<String>,
        input: ResolvedActionInput,
    ) -> Result<(), ResolvedActionError> {
        let name = name.into();
        if !valid_identifier(&name, MAX_RESOLVED_ACTION_INPUT_NAME_BYTES) {
            return Err(ResolvedActionError::InvalidInputName);
        }
        if self.inputs.contains_key(&name) {
            return Err(ResolvedActionError::DuplicateInput);
        }
        if self.inputs.len() >= MAX_RESOLVED_ACTION_INPUTS {
            return Err(ResolvedActionError::TooManyInputs);
        }
        self.inputs.insert(name, input);
        Ok(())
    }

    #[must_use]
    pub fn source_reference(&self) -> &str {
        &self.source_reference
    }
    #[must_use]
    pub fn descriptor_path(&self) -> &str {
        &self.descriptor_path
    }
    #[must_use]
    pub const fn program(&self) -> &SourceActionProgramDeclaration {
        &self.program
    }
    pub fn inputs(&self) -> impl ExactSizeIterator<Item = (&str, &ResolvedActionInput)> {
        self.inputs
            .iter()
            .map(|(name, input)| (name.as_str(), input))
    }

    pub fn insert_network_destination(
        &mut self,
        destination: ResolvedActionNetworkDestination,
    ) -> Result<(), ResolvedActionError> {
        self.requirements.insert_network_destination(destination)
    }

    pub fn insert_secret(
        &mut self,
        secret: ResolvedActionSecret,
    ) -> Result<(), ResolvedActionError> {
        self.requirements.insert_secret(secret)
    }

    #[must_use]
    pub const fn deny_private_networks(&self) -> bool {
        self.requirements.deny_private_networks
    }

    pub fn network_destinations(
        &self,
    ) -> impl ExactSizeIterator<Item = &ResolvedActionNetworkDestination> {
        self.requirements.network_destinations.iter()
    }

    pub fn secrets(&self) -> impl ExactSizeIterator<Item = &ResolvedActionSecret> {
        self.requirements.secrets.iter()
    }
}

impl SourceActionProgramDeclaration {
    fn validate(&self) -> Result<(), ResolvedActionError> {
        match self {
            Self::ContainerBuild {
                build_file,
                entrypoint,
                arguments,
            } => {
                if !valid_relative_path(build_file) {
                    return Err(ResolvedActionError::InvalidProgramField);
                }
                if let Some(value) = entrypoint {
                    validate_program_field(value)?;
                }
                if let Some(values) = arguments {
                    if values.len() > MAX_RESOLVED_PROGRAM_ARGUMENTS {
                        return Err(ResolvedActionError::TooManyArguments);
                    }
                    for value in values {
                        validate_program_field(value)?;
                    }
                }
            }
            Self::Component {
                reference,
                signature_identity,
                interface,
            } => {
                for value in [reference, signature_identity, interface] {
                    validate_program_field(value)?;
                }
            }
        }
        Ok(())
    }
}

/// Adapter-specific diagnostic bytes with a generic, integrity-bound envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowFrontendReport {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// Adapter-produced data required to compile a translated workflow.
///
/// Identity and all integrity digests are deliberately absent: the trusted
/// planner derives those values from the registered frontend and exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkflowSource {
    pub native_yaml: String,
    pub generated_lockfile_toml: Option<String>,
    pub report: Option<WorkflowFrontendReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowFrontendErrorKind {
    InvalidSource,
    IncompatibleSource,
    Internal,
}

/// Bounded, structured failure returned across the frontend boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowFrontendError {
    kind: WorkflowFrontendErrorKind,
    code: &'static str,
    detail: String,
}

impl WorkflowFrontendError {
    #[must_use]
    pub fn new(
        kind: WorkflowFrontendErrorKind,
        code: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        let code = if code.is_empty()
            || code.len() > MAX_FRONTEND_ERROR_CODE_BYTES
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            "frontend.error"
        } else {
            code
        };
        let mut detail = detail.into();
        if detail.len() > MAX_FRONTEND_ERROR_DETAIL_BYTES {
            let mut boundary = MAX_FRONTEND_ERROR_DETAIL_BYTES;
            while !detail.is_char_boundary(boundary) {
                boundary -= 1;
            }
            detail.truncate(boundary);
        }
        Self { kind, code, detail }
    }

    #[must_use]
    pub const fn kind(&self) -> WorkflowFrontendErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for WorkflowFrontendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            formatter.write_str(self.code)
        } else {
            write!(formatter, "{}: {}", self.code, self.detail)
        }
    }
}

impl Error for WorkflowFrontendError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowFrontendRegistryError {
    TooManyFrontends,
    TooManyDiscoveryRoots,
    InvalidFrontendIdentity,
    InvalidFrontendGeneration,
    DuplicateFrontendIdentity,
    InvalidDiscoveryRoot,
    InvalidWorkflowPath,
    AmbiguousFrontend,
}

impl fmt::Display for WorkflowFrontendRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyFrontends => "workflow frontend registry exceeds its frontend bound",
            Self::TooManyDiscoveryRoots => {
                "workflow frontend registry exceeds its discovery-root bound"
            }
            Self::InvalidFrontendIdentity => "workflow frontend identity is invalid",
            Self::InvalidFrontendGeneration => {
                "workflow frontend generation must be greater than zero"
            }
            Self::DuplicateFrontendIdentity => "workflow frontend identity is duplicated",
            Self::InvalidDiscoveryRoot => "workflow frontend discovery root is invalid",
            Self::InvalidWorkflowPath => "workflow frontend path is invalid",
            Self::AmbiguousFrontend => "multiple workflow frontends claim the same path",
        })
    }
}

impl Error for WorkflowFrontendRegistryError {}

/// Validated collection of source-language frontends supplied by the binary's
/// composition root. Discovery metadata lives with each adapter so the trusted
/// server and planner do not acquire source-language-specific paths.
pub struct WorkflowFrontendRegistry<'a> {
    frontends: Vec<&'a dyn WorkflowSourceFrontend>,
    discovery_roots: Vec<&'static str>,
}

impl<'a> WorkflowFrontendRegistry<'a> {
    pub fn new(
        frontends: &[&'a dyn WorkflowSourceFrontend],
    ) -> Result<Self, WorkflowFrontendRegistryError> {
        if frontends.len() > MAX_FRONTENDS {
            return Err(WorkflowFrontendRegistryError::TooManyFrontends);
        }
        let mut frontend_ids = BTreeSet::new();
        let mut discovery_roots = BTreeSet::new();
        for frontend in frontends {
            let frontend_id = frontend.frontend_id();
            if frontend_id.is_empty()
                || frontend_id.len() > MAX_FRONTEND_ID_BYTES
                || !frontend_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                return Err(WorkflowFrontendRegistryError::InvalidFrontendIdentity);
            }
            if frontend.frontend_generation() == 0 {
                return Err(WorkflowFrontendRegistryError::InvalidFrontendGeneration);
            }
            if !frontend_ids.insert(frontend_id) {
                return Err(WorkflowFrontendRegistryError::DuplicateFrontendIdentity);
            }
            for root in frontend.discovery_roots() {
                if !valid_relative_path(root) {
                    return Err(WorkflowFrontendRegistryError::InvalidDiscoveryRoot);
                }
                discovery_roots.insert(*root);
                if discovery_roots.len() > MAX_DISCOVERY_ROOTS {
                    return Err(WorkflowFrontendRegistryError::TooManyDiscoveryRoots);
                }
            }
        }
        Ok(Self {
            frontends: frontends.to_vec(),
            discovery_roots: discovery_roots.into_iter().collect(),
        })
    }

    #[must_use]
    pub fn discovery_roots(&self) -> &[&'static str] {
        &self.discovery_roots
    }

    pub fn frontend_for(
        &self,
        workflow_path: &str,
    ) -> Result<Option<&'a dyn WorkflowSourceFrontend>, WorkflowFrontendRegistryError> {
        if !valid_relative_path(workflow_path) {
            return Err(WorkflowFrontendRegistryError::InvalidWorkflowPath);
        }
        let mut matches = self
            .frontends
            .iter()
            .copied()
            .filter(|frontend| frontend.supports(workflow_path));
        let selected = matches.next();
        if matches.next().is_some() {
            return Err(WorkflowFrontendRegistryError::AmbiguousFrontend);
        }
        Ok(selected)
    }
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_WORKFLOW_PATH_BYTES
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path
            .chars()
            .any(|character| matches!(character, '\\' | '\0'))
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

/// A replaceable source adapter injected by the composition root.
pub trait WorkflowSourceFrontend: Send + Sync {
    /// Stable adapter identity used in signed provenance.
    fn frontend_id(&self) -> &'static str;

    /// Adapter translation generation used in signed provenance.
    fn frontend_generation(&self) -> u32;

    /// Repository directories inspected for workflows owned by this adapter.
    /// Every returned path is validated by `WorkflowFrontendRegistry`.
    fn discovery_roots(&self) -> &'static [&'static str];

    fn supports(&self, workflow_path: &str) -> bool;

    /// Discover adapter-owned references without giving trusted SCM knowledge
    /// of source-language syntax. The default preserves native-only and
    /// frontends that do not resolve repository-backed actions.
    fn action_resolution_requests(
        &self,
        _source: &str,
        _workflow_path: &str,
    ) -> Result<SourceActionResolutionRequests, WorkflowFrontendError> {
        Ok(SourceActionResolutionRequests::default())
    }

    /// Parse exact descriptor bytes fetched by trusted SCM into a bounded,
    /// non-executable build declaration. Trusted SCM remains responsible for
    /// policy, building, and immutable program resolution.
    fn parse_action_descriptor(
        &self,
        _request: &SourceActionResolutionRequest,
        _descriptors: &SourceActionDescriptors,
    ) -> Result<SourceActionDeclaration, WorkflowFrontendError> {
        Err(WorkflowFrontendError::new(
            WorkflowFrontendErrorKind::Internal,
            "frontend.action-descriptor-unsupported",
            "this frontend does not parse source action descriptors",
        ))
    }

    fn prepare(
        &self,
        source: &str,
        workflow_path: &str,
        options: &WorkflowFrontendOptions,
    ) -> Result<PreparedWorkflowSource, WorkflowFrontendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_A: &str = "registry.invalid/tool@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IMAGE_B: &str = "registry.invalid/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const COMPONENT_A: &str =
        "component://tool@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct TestFrontend {
        id: &'static str,
        generation: u32,
        roots: &'static [&'static str],
        suffix: &'static str,
    }

    impl WorkflowSourceFrontend for TestFrontend {
        fn frontend_id(&self) -> &'static str {
            self.id
        }

        fn frontend_generation(&self) -> u32 {
            self.generation
        }

        fn discovery_roots(&self) -> &'static [&'static str] {
            self.roots
        }

        fn supports(&self, workflow_path: &str) -> bool {
            workflow_path.ends_with(self.suffix)
        }

        fn prepare(
            &self,
            _source: &str,
            _workflow_path: &str,
            _options: &WorkflowFrontendOptions,
        ) -> Result<PreparedWorkflowSource, WorkflowFrontendError> {
            Err(WorkflowFrontendError::new(
                WorkflowFrontendErrorKind::Internal,
                "test.unused",
                "not used by registry tests",
            ))
        }
    }

    #[test]
    fn options_are_bounded_namespaced_and_order_independent() {
        let mut first = WorkflowFrontendOptions::default();
        first.set("runtrue.test.second", "two").unwrap();
        first.set("runtrue.test.first", "one").unwrap();

        let mut second = WorkflowFrontendOptions::default();
        second.set("runtrue.test.first", "one").unwrap();
        second.set("runtrue.test.second", "two").unwrap();

        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.value("runtrue.test.first"), Some("one"));
        assert_eq!(
            first.set("invalid option", "value"),
            Err(WorkflowFrontendOptionsError::InvalidOptionName)
        );
        assert_eq!(
            first.set(
                "runtrue.test.large",
                "x".repeat(MAX_FRONTEND_OPTION_VALUE_BYTES + 1)
            ),
            Err(WorkflowFrontendOptionsError::OptionValueTooLarge)
        );
    }

    fn container_action(image: &str) -> ResolvedSourceAction {
        ResolvedSourceAction::new(
            ResolvedProgram::container(
                image,
                Some("/entrypoint".to_owned()),
                Some(vec!["--exact".to_owned()]),
            )
            .unwrap(),
        )
    }

    #[test]
    fn resolved_actions_are_canonical_digest_covered_and_read_only() {
        let mut first_action = container_action(IMAGE_A);
        first_action
            .insert_input(
                "token",
                ResolvedActionInput::new(true, Some("default".to_owned())).unwrap(),
            )
            .unwrap();
        first_action
            .insert_network_destination(
                ResolvedActionNetworkDestination::new("api.example.test", 443).unwrap(),
            )
            .unwrap();
        first_action
            .insert_secret(
                ResolvedActionSecret::new("API_KEY", "inference", "INPUT_API_KEY_FILE").unwrap(),
            )
            .unwrap();
        let second_action = ResolvedSourceAction::new(
            ResolvedProgram::component(
                COMPONENT_A,
                "https://scm.invalid/api",
                "issuer.invalid/subject",
                "run",
            )
            .unwrap(),
        );

        let mut first = WorkflowFrontendOptions::default();
        first
            .insert_resolved_action("owner/first@revision", first_action.clone())
            .unwrap();
        first
            .insert_resolved_action("owner/second@revision", second_action.clone())
            .unwrap();

        let mut second = WorkflowFrontendOptions::default();
        second
            .insert_resolved_action("owner/second@revision", second_action)
            .unwrap();
        second
            .insert_resolved_action("owner/first@revision", first_action)
            .unwrap();

        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.resolved_actions().len(), 2);
        let resolved = first.resolved_action("owner/first@revision").unwrap();
        assert!(matches!(
            resolved.program(),
            ResolvedProgramRef::Container {
                image: IMAGE_A,
                entrypoint: Some("/entrypoint"),
                arguments: Some(_),
            }
        ));
        assert!(resolved.input("token").unwrap().required());
        assert!(resolved.deny_private_networks());
        assert_eq!(
            resolved
                .network_destinations()
                .next()
                .map(ResolvedActionNetworkDestination::host),
            Some("api.example.test")
        );
        assert_eq!(
            resolved
                .secrets()
                .next()
                .map(ResolvedActionSecret::file_env),
            Some("INPUT_API_KEY_FILE")
        );

        let mut changed = WorkflowFrontendOptions::default();
        changed
            .insert_resolved_action("owner/first@revision", container_action(IMAGE_B))
            .unwrap();
        assert_ne!(first.digest(), changed.digest());
    }

    #[test]
    fn resolved_actions_reject_duplicate_malicious_and_oversize_data() {
        assert_eq!(
            ResolvedProgram::container("", None, None),
            Err(ResolvedActionError::InvalidProgramField)
        );
        assert_eq!(
            ResolvedProgram::container("image\0injection", None, None),
            Err(ResolvedActionError::InvalidProgramField)
        );
        assert_eq!(
            ResolvedProgram::container("registry.invalid/tool:latest", None, None),
            Err(ResolvedActionError::InvalidProgramField)
        );
        assert_eq!(
            ResolvedProgram::container(
                IMAGE_A,
                None,
                Some(vec![
                    "argument".to_owned();
                    MAX_RESOLVED_PROGRAM_ARGUMENTS + 1
                ]),
            ),
            Err(ResolvedActionError::TooManyArguments)
        );
        assert_eq!(
            ResolvedActionInput::new(
                false,
                Some("x".repeat(MAX_RESOLVED_ACTION_INPUT_DEFAULT_BYTES + 1)),
            ),
            Err(ResolvedActionError::InputDefaultTooLarge)
        );
        assert_eq!(
            ResolvedActionNetworkDestination::new("https://invalid.example", 443),
            Err(ResolvedActionError::InvalidNetworkDestination)
        );
        assert_eq!(
            ResolvedActionSecret::new("API_KEY", "inference", "bad-env"),
            Err(ResolvedActionError::InvalidSecret)
        );

        let mut action = container_action(IMAGE_A);
        action
            .insert_input("input", ResolvedActionInput::new(false, None).unwrap())
            .unwrap();
        assert_eq!(
            action.insert_input("input", ResolvedActionInput::new(true, None).unwrap()),
            Err(ResolvedActionError::DuplicateInput)
        );

        let mut options = WorkflowFrontendOptions::default();
        options
            .insert_resolved_action("owner/action@revision", action.clone())
            .unwrap();
        assert_eq!(
            options.insert_resolved_action("owner/action@revision", action.clone()),
            Err(WorkflowFrontendOptionsError::DuplicateResolvedAction)
        );
        assert_eq!(
            options.insert_resolved_action("bad\0reference", action),
            Err(WorkflowFrontendOptionsError::InvalidResolvedActionReference)
        );
    }

    #[test]
    fn resolved_action_collection_enforces_count_bound() {
        let mut options = WorkflowFrontendOptions::default();
        for index in 0..MAX_RESOLVED_ACTIONS {
            options
                .insert_resolved_action(format!("source/action-{index}"), container_action(IMAGE_A))
                .unwrap();
        }
        assert_eq!(
            options.insert_resolved_action("source/one-too-many", container_action(IMAGE_A),),
            Err(WorkflowFrontendOptionsError::TooManyResolvedActions)
        );
    }

    #[test]
    fn action_preflight_is_bounded_and_keeps_declarations_non_executable() {
        let request = SourceActionResolutionRequest::new(
            "owner/action@revision",
            "owner/action",
            "revision",
            "subdirectory",
            vec!["action.yml".to_owned(), "action.yaml".to_owned()],
        )
        .unwrap();
        let mut requests = SourceActionResolutionRequests::default();
        requests.insert(request.clone()).unwrap();
        assert_eq!(requests.iter().len(), 1);
        assert_eq!(request.repository(), "owner/action");

        let mut descriptors = SourceActionDescriptors::for_request(&request);
        descriptors
            .insert("action.yml", b"runs: container".to_vec())
            .unwrap();
        assert_eq!(descriptors.get("action.yml"), Some(&b"runs: container"[..]));
        assert_eq!(
            descriptors.insert("unrequested.yml", Vec::new()),
            Err(SourceActionResolutionError::UnexpectedDescriptor)
        );

        let declaration = SourceActionDeclaration::new(
            request.source_reference(),
            "action.yml",
            SourceActionProgramDeclaration::ContainerBuild {
                build_file: "Dockerfile".to_owned(),
                entrypoint: None,
                arguments: None,
            },
        )
        .unwrap();
        assert_eq!(
            descriptors.selected_descriptor(&declaration).unwrap(),
            b"runs: container"
        );
        assert!(matches!(
            declaration.program(),
            SourceActionProgramDeclaration::ContainerBuild { build_file, .. }
                if build_file == "Dockerfile"
        ));
    }

    #[test]
    fn action_preflight_rejects_duplicate_candidates_requests_and_unsafe_paths() {
        assert_eq!(
            SourceActionResolutionRequest::new(
                "reference",
                "repository",
                "revision",
                "../escape",
                vec!["action.yml".to_owned()],
            ),
            Err(SourceActionResolutionError::InvalidPath)
        );
        assert_eq!(
            SourceActionResolutionRequest::new(
                "reference",
                "repository",
                "revision",
                "",
                vec!["action.yml".to_owned(), "action.yml".to_owned()],
            ),
            Err(SourceActionResolutionError::DuplicateDescriptorCandidate)
        );

        let request = SourceActionResolutionRequest::new(
            "reference",
            "repository",
            "revision",
            "",
            vec!["action.yml".to_owned()],
        )
        .unwrap();
        let mut requests = SourceActionResolutionRequests::default();
        requests.insert(request.clone()).unwrap();
        assert_eq!(
            requests.insert(request),
            Err(SourceActionResolutionError::DuplicateRequest)
        );
        let descriptor_request = requests.iter().next().unwrap();
        let mut descriptors = SourceActionDescriptors::for_request(descriptor_request);
        assert_eq!(
            descriptors.insert("action.yml", vec![0; MAX_ACTION_DESCRIPTOR_BYTES + 1],),
            Err(SourceActionResolutionError::DescriptorTooLarge)
        );
        assert_eq!(
            SourceActionDeclaration::new(
                "reference",
                "action.yml",
                SourceActionProgramDeclaration::ContainerBuild {
                    build_file: "../Dockerfile".to_owned(),
                    entrypoint: None,
                    arguments: None,
                },
            ),
            Err(ResolvedActionError::InvalidProgramField)
        );
    }

    #[test]
    fn frontend_errors_have_typed_kinds_stable_codes_and_bounded_details() {
        let error = WorkflowFrontendError::new(
            WorkflowFrontendErrorKind::InvalidSource,
            "test.invalid-source",
            "é".repeat(MAX_FRONTEND_ERROR_DETAIL_BYTES),
        );
        assert_eq!(error.kind(), WorkflowFrontendErrorKind::InvalidSource);
        assert_eq!(error.code(), "test.invalid-source");
        assert!(error.detail().len() <= MAX_FRONTEND_ERROR_DETAIL_BYTES);
        assert!(error.detail().is_char_boundary(error.detail().len()));

        let invalid_code = WorkflowFrontendError::new(
            WorkflowFrontendErrorKind::Internal,
            "invalid code",
            "detail",
        );
        assert_eq!(invalid_code.code(), "frontend.error");
    }

    #[test]
    fn registry_owns_deduplicated_discovery_and_exact_selection() {
        let yaml = TestFrontend {
            id: "runtrue.test-yaml",
            generation: 1,
            roots: &[".foreign/workflows"],
            suffix: ".yaml",
        };
        let yml = TestFrontend {
            id: "runtrue.test-yml",
            generation: 1,
            roots: &[".foreign/workflows"],
            suffix: ".yml",
        };
        let registry = WorkflowFrontendRegistry::new(&[&yaml, &yml]).unwrap();
        assert_eq!(registry.discovery_roots(), &[".foreign/workflows"]);
        assert!(registry
            .frontend_for(".foreign/workflows/ci.yaml")
            .unwrap()
            .is_some());
        assert!(registry
            .frontend_for(".runtrue/workflows/ci.json")
            .unwrap()
            .is_none());
    }

    #[test]
    fn registry_rejects_unsafe_roots_paths_and_ambiguous_ownership() {
        let unsafe_frontend = TestFrontend {
            id: "runtrue.test-unsafe",
            generation: 1,
            roots: &["../workflows"],
            suffix: ".yaml",
        };
        assert!(matches!(
            WorkflowFrontendRegistry::new(&[&unsafe_frontend]),
            Err(WorkflowFrontendRegistryError::InvalidDiscoveryRoot)
        ));

        let first = TestFrontend {
            id: "runtrue.test-first",
            generation: 1,
            roots: &["workflows"],
            suffix: ".yaml",
        };
        let second = TestFrontend {
            id: "runtrue.test-second",
            generation: 1,
            roots: &["other"],
            suffix: ".yaml",
        };
        let registry = WorkflowFrontendRegistry::new(&[&first, &second]).unwrap();
        assert!(matches!(
            registry.frontend_for("workflows/ci.yaml"),
            Err(WorkflowFrontendRegistryError::AmbiguousFrontend)
        ));
        assert!(matches!(
            registry.frontend_for("workflows/../ci.yaml"),
            Err(WorkflowFrontendRegistryError::InvalidWorkflowPath)
        ));
    }

    #[test]
    fn registry_rejects_invalid_or_duplicate_frontend_metadata() {
        let invalid_id = TestFrontend {
            id: "invalid identity",
            generation: 1,
            roots: &["workflows"],
            suffix: ".yaml",
        };
        assert!(matches!(
            WorkflowFrontendRegistry::new(&[&invalid_id]),
            Err(WorkflowFrontendRegistryError::InvalidFrontendIdentity)
        ));

        let invalid_generation = TestFrontend {
            id: "runtrue.test",
            generation: 0,
            roots: &["workflows"],
            suffix: ".yaml",
        };
        assert!(matches!(
            WorkflowFrontendRegistry::new(&[&invalid_generation]),
            Err(WorkflowFrontendRegistryError::InvalidFrontendGeneration)
        ));

        let duplicate_a = TestFrontend {
            id: "runtrue.test",
            generation: 1,
            roots: &["workflows"],
            suffix: ".yaml",
        };
        let duplicate_b = TestFrontend {
            id: "runtrue.test",
            generation: 2,
            roots: &["other"],
            suffix: ".yml",
        };
        assert!(matches!(
            WorkflowFrontendRegistry::new(&[&duplicate_a, &duplicate_b]),
            Err(WorkflowFrontendRegistryError::DuplicateFrontendIdentity)
        ));
    }
}
