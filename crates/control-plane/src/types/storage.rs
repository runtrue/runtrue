use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;

/// Installation policy for authoritative bytes retained for one tenant.
/// Reservations are charged before a data-plane ticket is issued so
/// concurrent issuers cannot exceed either bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantStorageQuota {
    pub tenant_id: String,
    pub maximum_stored_bytes: u64,
    pub maximum_object_count: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageReservationState {
    Reserved,
    Committed,
    Released,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantStorageReservation {
    pub id: String,
    pub tenant_id: String,
    pub ticket_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<ContentDigest>,
    pub reserved_bytes: u64,
    pub reserved_objects: u64,
    pub state: StorageReservationState,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageTicketBindingState {
    Issued,
    Committed,
    Accounted,
    Released,
}

/// Durable join between an atomic quota reservation and the only data-plane
/// ticket authorized to consume it. Unbound filesystem tickets are not
/// authorities and must be rejected by commit handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageTicketBinding {
    pub reservation_id: String,
    pub tenant_id: String,
    pub ticket_kind: String,
    pub ticket_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_objects: Option<u64>,
    pub state: StorageTicketBindingState,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantStorageObject {
    pub tenant_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub billed_bytes: u64,
    pub billed_objects: u64,
    pub active: bool,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantStorageUsage {
    pub tenant_id: String,
    pub active_bytes: u64,
    pub active_objects: u64,
    pub reserved_bytes: u64,
    pub reserved_objects: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPinRecord {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub root_kind: String,
    pub root_id: String,
    pub object_digest: ContentDigest,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_unix_ms: Option<u64>,
}
