use serde::Serialize;

/// A server operation that still lacks a PostgreSQL-safe runtime path.
///
/// This inventory is intentionally separate from the migration-boundary
/// inventory: schema/domain parity alone does not prove that every server
/// worker is using the backend-neutral contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PostgresServerRuntimeGap {
    pub domain: &'static str,
    pub owning_contract: &'static str,
    pub operations: &'static [&'static str],
}

const POSTGRES_SERVER_RUNTIME_GAPS: &[PostgresServerRuntimeGap] = &[];

#[must_use]
pub const fn postgres_server_runtime_inventory() -> &'static [PostgresServerRuntimeGap] {
    POSTGRES_SERVER_RUNTIME_GAPS
}

#[must_use]
pub fn postgres_server_runtime_ready() -> bool {
    POSTGRES_SERVER_RUNTIME_GAPS.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn postgres_server_selection_opens_only_with_zero_runtime_gaps() {
        assert!(postgres_server_runtime_ready());
        assert!(postgres_server_runtime_inventory().is_empty());
    }

    #[test]
    fn runtime_inventory_is_machine_readable_and_has_unique_operations() {
        let encoded = serde_json::to_value(postgres_server_runtime_inventory()).unwrap();
        assert!(encoded.is_array());

        let mut operations = BTreeSet::new();
        for gap in postgres_server_runtime_inventory() {
            assert!(!gap.domain.is_empty());
            assert!(!gap.owning_contract.is_empty());
            assert!(!gap.operations.is_empty());
            for operation in gap.operations {
                assert!(operations.insert(*operation), "duplicate {operation}");
            }
        }
    }
}
