use wasmtime::ResourceLimiter;
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostLimits {
    pub max_output_bytes: usize,
    pub max_log_bytes: usize,
    pub max_log_entry_bytes: usize,
    pub max_adapter_request_bytes: usize,
    pub max_adapter_response_bytes: usize,
    pub max_secret_bytes: usize,
    pub max_oidc_token_bytes: usize,
}
pub(crate) struct AggregateStoreLimits {
    max_memory_bytes: usize,
    allocated_memory_bytes: usize,
    max_table_elements: u64,
    allocated_table_elements: u64,
    max_instances: usize,
    max_tables: usize,
    max_memories: usize,
}

impl AggregateStoreLimits {
    pub(crate) const fn new(
        max_memory_bytes: usize,
        max_table_elements: u32,
        max_instances: usize,
        max_tables: usize,
        max_memories: usize,
    ) -> Self {
        Self {
            max_memory_bytes,
            allocated_memory_bytes: 0,
            max_table_elements: max_table_elements as u64,
            allocated_table_elements: 0,
            max_instances,
            max_tables,
            max_memories,
        }
    }
}

impl ResourceLimiter for AggregateStoreLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let Some(growth) = desired.checked_sub(current) else {
            return Ok(false);
        };
        let Some(total) = self.allocated_memory_bytes.checked_add(growth) else {
            return Ok(false);
        };
        if maximum.is_some_and(|maximum| desired > maximum) || total > self.max_memory_bytes {
            return Ok(false);
        }
        self.allocated_memory_bytes = total;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let Some(growth) = desired
            .checked_sub(current)
            .and_then(|growth| u64::try_from(growth).ok())
        else {
            return Ok(false);
        };
        let Some(total) = self.allocated_table_elements.checked_add(growth) else {
            return Ok(false);
        };
        if maximum.is_some_and(|maximum| desired > maximum) || total > self.max_table_elements {
            return Ok(false);
        }
        self.allocated_table_elements = total;
        Ok(true)
    }

    fn instances(&self) -> usize {
        self.max_instances
    }

    fn tables(&self) -> usize {
        self.max_tables
    }

    fn memories(&self) -> usize {
        self.max_memories
    }
}
