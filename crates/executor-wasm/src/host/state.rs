use super::{
    bindings::{invoke_adapter, REDACTION_MARKER},
    filesystem::normalize_guest_path,
    AggregateStoreLimits, CapabilityAdapters, CapabilityCallContext, DirectoryGrant,
    FilesystemAccess, HostLimits, HostOutput,
};
use crate::runtrue::action::host::{
    DirectoryAccess as WitDirectoryAccess, DirectoryHandle as WitDirectoryHandle, Host,
    OidcHandle as WitOidcHandle, SecretHandle as WitSecretHandle,
};
use runtrue_model::SecretReference;
use runtrue_workflow_ir::NetworkPermission;
use serde_json::Value;
use std::collections::BTreeMap;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use zeroize::{Zeroize as _, Zeroizing};
pub(crate) struct HostState {
    input: Zeroizing<Vec<u8>>,
    output: Option<Zeroizing<Vec<u8>>>,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    limits: HostLimits,
    call_context: CapabilityCallContext,
    adapters: CapabilityAdapters,
    pub(super) directories: BTreeMap<u64, DirectoryGrant>,
    pub(super) networks: BTreeMap<u64, NetworkPermission>,
    pub(super) secrets: BTreeMap<u64, SecretReference>,
    pub(super) oidc_audiences: BTreeMap<u64, String>,
    sensitive_log_values: Vec<Zeroizing<Vec<u8>>>,
    pub store_limits: AggregateStoreLimits,
    wasi_ctx: WasiCtx,
    wasi_resources: ResourceTable,
}

pub(crate) struct HostInvocation {
    pub input: Vec<u8>,
    pub limits: HostLimits,
    pub call_context: CapabilityCallContext,
    pub adapters: CapabilityAdapters,
    pub directories: BTreeMap<u64, DirectoryGrant>,
    pub networks: BTreeMap<u64, NetworkPermission>,
    pub secrets: BTreeMap<u64, SecretReference>,
    pub oidc_audiences: BTreeMap<u64, String>,
    pub store_limits: AggregateStoreLimits,
}
impl HostState {
    pub(crate) fn new(invocation: HostInvocation) -> Self {
        let mut wasi = WasiCtx::builder();
        wasi.allow_tcp(false).allow_udp(false);
        Self {
            input: Zeroizing::new(invocation.input),
            output: None,
            stdout: Zeroizing::new(Vec::new()),
            stderr: Zeroizing::new(Vec::new()),
            stdout_truncated: false,
            stderr_truncated: false,
            limits: invocation.limits,
            call_context: invocation.call_context,
            adapters: invocation.adapters,
            directories: invocation.directories,
            networks: invocation.networks,
            secrets: invocation.secrets,
            oidc_audiences: invocation.oidc_audiences,
            sensitive_log_values: Vec::new(),
            store_limits: invocation.store_limits,
            wasi_ctx: wasi.build(),
            wasi_resources: ResourceTable::new(),
        }
    }

    pub(crate) fn output(&self) -> HostOutput {
        HostOutput {
            output: self.output.as_ref().map(|value| value.to_vec()),
            stdout: String::from_utf8_lossy(&self.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.stderr).into_owned(),
            stdout_truncated: self.stdout_truncated,
            stderr_truncated: self.stderr_truncated,
        }
    }

    fn append_log(&mut self, stream: &str, message: &str) -> Result<(), String> {
        if message.len() > self.limits.max_log_entry_bytes {
            return Err("log entry exceeds the configured byte limit".to_owned());
        }
        let message = self.redact_log_message(message.as_bytes());
        let (buffer, truncated) = match stream {
            "stdout" => (&mut self.stdout, &mut self.stdout_truncated),
            "stderr" => (&mut self.stderr, &mut self.stderr_truncated),
            _ => return Err("log stream must be `stdout` or `stderr`".to_owned()),
        };
        let separator = usize::from(!buffer.is_empty());
        let required = separator.saturating_add(message.len());
        let available = self.limits.max_log_bytes.saturating_sub(buffer.len());
        if required > available {
            *truncated = true;
            return Err("log stream exceeds the configured byte limit".to_owned());
        }
        if separator != 0 {
            buffer.push(b'\n');
        }
        buffer.extend_from_slice(&message);
        Ok(())
    }

    fn register_sensitive_log_value(&mut self, value: &[u8]) {
        if value.is_empty()
            || value.len() > self.limits.max_log_entry_bytes
            || self
                .sensitive_log_values
                .iter()
                .any(|known| known.as_slice() == value)
        {
            return;
        }
        self.sensitive_log_values
            .push(Zeroizing::new(value.to_vec()));
        self.sensitive_log_values
            .sort_by_key(|value| std::cmp::Reverse(value.len()));
    }

    fn redact_log_message(&self, message: &[u8]) -> Zeroizing<Vec<u8>> {
        if self.sensitive_log_values.is_empty() {
            return Zeroizing::new(message.to_vec());
        }
        let mut redacted = Zeroizing::new(Vec::with_capacity(message.len()));
        let mut index = 0_usize;
        while index < message.len() {
            if let Some(value) = self
                .sensitive_log_values
                .iter()
                .find(|value| message[index..].starts_with(value.as_slice()))
            {
                redacted.extend_from_slice(REDACTION_MARKER);
                index = index.saturating_add(value.len());
            } else {
                redacted.push(message[index]);
                index = index.saturating_add(1);
            }
        }
        redacted
    }

    fn bounded_adapter_response(&self, value: Vec<u8>) -> Result<Vec<u8>, String> {
        if value.len() > self.limits.max_adapter_response_bytes {
            return Err("capability response exceeds the configured byte limit".to_owned());
        }
        Ok(value)
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.wasi_resources,
        }
    }
}

impl Drop for HostState {
    fn drop(&mut self) {
        if let Some(output) = &mut self.output {
            output.zeroize();
        }
    }
}

impl Host for HostState {
    fn get_input(&mut self) -> Vec<u8> {
        self.input.to_vec()
    }

    fn set_output(&mut self, value: Vec<u8>) -> Result<(), String> {
        let value = Zeroizing::new(value);
        if value.len() > self.limits.max_output_bytes {
            return Err("component output exceeds the configured byte limit".to_owned());
        }
        let parsed: Value = match serde_json::from_slice(&value) {
            Ok(value) => value,
            Err(_) => return Err("component output must be valid JSON".to_owned()),
        };
        if !parsed.is_object() {
            return Err("component output must be a JSON object".to_owned());
        }
        let canonical = match serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(parsed)) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return Err("component output could not be canonicalized".to_owned()),
        };
        if canonical.as_slice() != value.as_slice() {
            return Err("component output must use duplicate-free canonical JSON bytes".to_owned());
        }
        if self.sensitive_log_values.iter().any(|sensitive| {
            canonical
                .windows(sensitive.len())
                .any(|window| window == sensitive.as_slice())
        }) {
            return Err("component output contains sensitive capability material".to_owned());
        }
        self.output = Some(canonical);
        Ok(())
    }

    fn log(&mut self, stream: String, message: String) -> Result<(), String> {
        self.append_log(&stream, &message)
    }

    fn directory_handles(&mut self) -> Vec<WitDirectoryHandle> {
        self.directories
            .iter()
            .map(|(id, grant)| WitDirectoryHandle {
                id: *id,
                scope: grant.scope.clone(),
                access: match grant.access {
                    FilesystemAccess::Read => WitDirectoryAccess::Read,
                    FilesystemAccess::Write => WitDirectoryAccess::Write,
                    FilesystemAccess::ReadWrite => WitDirectoryAccess::ReadWrite,
                },
            })
            .collect()
    }

    fn read_file(&mut self, handle: u64, path: String) -> Result<Vec<u8>, String> {
        let path = match normalize_guest_path(&path) {
            Ok(path) => path,
            Err(_) => return Err("file path is not a safe relative path".to_owned()),
        };
        let Some(grant) = self.directories.get(&handle) else {
            return Err("invalid directory handle".to_owned());
        };
        if !grant.access.permits_read() {
            return Err("directory handle does not permit reads".to_owned());
        }
        let Some(adapter) = self.adapters.filesystem.clone() else {
            return Err("filesystem capability adapter is unavailable".to_owned());
        };
        let grant = grant.clone();
        let response = match invoke_adapter(&self.call_context, move |context| {
            adapter.read_file(&context, &grant, &path)
        }) {
            Ok(value) => value,
            Err(error) => return Err(error.guest_code().to_owned()),
        };
        self.bounded_adapter_response(response)
    }

    fn write_file(&mut self, handle: u64, path: String, value: Vec<u8>) -> Result<(), String> {
        if value.len() > self.limits.max_adapter_request_bytes {
            return Err("capability request exceeds the configured byte limit".to_owned());
        }
        let path = match normalize_guest_path(&path) {
            Ok(path) => path,
            Err(_) => return Err("file path is not a safe relative path".to_owned()),
        };
        let Some(grant) = self.directories.get(&handle) else {
            return Err("invalid directory handle".to_owned());
        };
        if !grant.access.permits_write() {
            return Err("directory handle does not permit writes".to_owned());
        }
        let Some(adapter) = self.adapters.filesystem.clone() else {
            return Err("filesystem capability adapter is unavailable".to_owned());
        };
        let grant = grant.clone();
        invoke_adapter(&self.call_context, move |context| {
            adapter.write_file(&context, &grant, &path, &value)
        })
        .map_err(|error| error.guest_code().to_owned())
    }

    fn network_handles(&mut self) -> Vec<u64> {
        self.networks.keys().copied().collect()
    }

    fn http_request(&mut self, handle: u64, request: Vec<u8>) -> Result<Vec<u8>, String> {
        if request.len() > self.limits.max_adapter_request_bytes {
            return Err("capability request exceeds the configured byte limit".to_owned());
        }
        let Some(grant) = self.networks.get(&handle) else {
            return Err("invalid network handle".to_owned());
        };
        let Some(adapter) = self.adapters.network.clone() else {
            return Err("network capability adapter is unavailable".to_owned());
        };
        let grant = grant.clone();
        let response = match invoke_adapter(&self.call_context, move |context| {
            adapter.http_request(&context, &grant, &request)
        }) {
            Ok(value) => value,
            Err(error) => return Err(error.guest_code().to_owned()),
        };
        self.bounded_adapter_response(response)
    }

    fn secret_handles(&mut self) -> Vec<WitSecretHandle> {
        self.secrets
            .iter()
            .map(|(id, grant)| WitSecretHandle {
                id: *id,
                name: grant.name.clone(),
                purpose: grant.purpose.clone(),
            })
            .collect()
    }

    fn read_secret(&mut self, handle: u64) -> Result<Vec<u8>, String> {
        let Some(grant) = self.secrets.get(&handle) else {
            return Err("invalid secret handle".to_owned());
        };
        let Some(adapter) = self.adapters.secrets.clone() else {
            return Err("secret capability adapter is unavailable".to_owned());
        };
        let grant = grant.clone();
        let response = match invoke_adapter(&self.call_context, move |context| {
            adapter.read_secret(&context, &grant)
        }) {
            Ok(value) => value,
            Err(error) => return Err(error.guest_code().to_owned()),
        };
        if response.as_bytes().len() > self.limits.max_secret_bytes {
            return Err("secret exceeds the configured byte limit".to_owned());
        }
        let value = response.as_bytes().to_vec();
        self.register_sensitive_log_value(&value);
        Ok(value)
    }

    fn oidc_handles(&mut self) -> Vec<WitOidcHandle> {
        self.oidc_audiences
            .iter()
            .map(|(id, audience)| WitOidcHandle {
                id: *id,
                audience: audience.clone(),
            })
            .collect()
    }

    fn mint_oidc_token(&mut self, handle: u64) -> Result<Vec<u8>, String> {
        let Some(audience) = self.oidc_audiences.get(&handle) else {
            return Err("invalid OIDC audience handle".to_owned());
        };
        let Some(adapter) = self.adapters.oidc.clone() else {
            return Err("OIDC capability adapter is unavailable".to_owned());
        };
        let audience = audience.clone();
        let response = match invoke_adapter(&self.call_context, move |context| {
            adapter.mint_token(&context, &audience)
        }) {
            Ok(value) => value,
            Err(error) => return Err(error.guest_code().to_owned()),
        };
        if response.as_bytes().len() > self.limits.max_oidc_token_bytes {
            return Err("OIDC token exceeds the configured byte limit".to_owned());
        }
        let value = response.as_bytes().to_vec();
        self.register_sensitive_log_value(&value);
        Ok(value)
    }
}
