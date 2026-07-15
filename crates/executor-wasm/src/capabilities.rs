use crate::DirectoryGrant;
use runtrue_model::SecretReference;
use runtrue_workflow_ir::NetworkPermission;
use std::collections::BTreeMap;
#[derive(Debug)]
pub(crate) struct InvocationGrants {
    pub(crate) directories: BTreeMap<u64, DirectoryGrant>,
    pub(crate) networks: BTreeMap<u64, NetworkPermission>,
    pub(crate) secrets: BTreeMap<u64, SecretReference>,
    pub(crate) oidc_audiences: BTreeMap<u64, String>,
}
