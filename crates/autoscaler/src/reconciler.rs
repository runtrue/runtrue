use crate::{
    AutoscalerError, Clock, ControlPlaneClient, FleetRequest, FleetView, OwnershipLease,
    PoolTemplate, Provider, ProviderInstance, SystemClock, GENERIC_RUNTIME_COMPATIBILITY_DIGEST,
};
use futures_util::future::join_all;
use std::{cmp, collections::BTreeMap};

const LEASE_DURATION_MS: u64 = 45_000;
const TARGET_UTILIZATION_PERCENT: u64 = 75;

pub struct Reconciler<C, P, K = SystemClock> {
    control_plane: C,
    provider: P,
    pool_id: String,
    owner_id: String,
    clock: K,
}

impl<C, P> Reconciler<C, P, SystemClock> {
    pub fn new(control_plane: C, provider: P, pool_id: String, owner_id: String) -> Self {
        Self {
            control_plane,
            provider,
            pool_id,
            owner_id,
            clock: SystemClock,
        }
    }
}

impl<C, P, K> Reconciler<C, P, K> {
    pub fn with_clock(
        control_plane: C,
        provider: P,
        pool_id: String,
        owner_id: String,
        clock: K,
    ) -> Self {
        Self {
            control_plane,
            provider,
            pool_id,
            owner_id,
            clock,
        }
    }
}

impl<C, P, K> Reconciler<C, P, K>
where
    C: ControlPlaneClient,
    P: Provider,
    K: Clock,
{
    pub async fn reconcile(&self) -> Result<(), AutoscalerError> {
        let lease = self
            .control_plane
            .acquire_lease(&self.pool_id, &self.owner_id, LEASE_DURATION_MS)
            .await
            .map_err(|error| reconcile("acquire autoscaler lease", error))?;
        let view = self
            .control_plane
            .fleet(&self.pool_id)
            .await
            .map_err(|error| reconcile("read fleet", error))?;
        if !view.policy.enabled {
            return Ok(());
        }
        self.reconcile_stale_bootstraps(&lease, &view).await?;
        self.reconcile_stale_offline_instances(&lease, &view)
            .await?;
        for request in &view.requests {
            if matches!(
                request.state.as_str(),
                "enrolled" | "online" | "failed" | "quarantined" | "terminated"
            ) {
                self.provider.cleanup_claim(request).await?;
            }
        }
        for replacement in &view.replacements {
            if replacement.state == "probationary" {
                self.control_plane
                    .activate_replacement(&self.pool_id, &replacement.id, lease.fencing_generation)
                    .await
                    .map_err(|error| {
                        reconcile(&format!("activate replacement {}", replacement.id), error)
                    })?;
            }
        }
        let planned = self
            .control_plane
            .plan_replacement(&self.pool_id, lease.fencing_generation)
            .await
            .map_err(|error| reconcile("plan immutable replacement", error))?;
        if let Some(replacement) = planned.as_ref() {
            self.provision_existing(&lease, &replacement.fleet_request)
                .await?;
        }
        for request in &view.requests {
            if matches!(request.state.as_str(), "requested" | "provisioning") {
                self.provision_existing(&lease, request)
                    .await
                    .map_err(|error| {
                        reconcile(
                            &format!("resume requested fleet instance {}", request.id),
                            error,
                        )
                    })?;
            }
        }

        let templates = view
            .templates
            .iter()
            .map(|template| (template.runtime_compatibility_digest.as_str(), template))
            .collect::<BTreeMap<_, _>>();
        let mut current = view
            .requests
            .iter()
            .filter(|request| {
                matches!(request.state.as_str(), "online" | "draining")
                    && matches!(request.runner_status.as_str(), "online" | "draining")
            })
            .count() as u64;
        if planned.is_some() {
            current = current.saturating_add(1);
        }
        current = current.saturating_add(
            view.requests
                .iter()
                .filter(|request| pending(&request.state))
                .count() as u64,
        );
        let mut remaining_batch = u64::from(view.policy.scale_up_batch);
        let mut scale_up = Vec::<PoolTemplate>::new();
        let now = view.observed_unix_ms;
        let mut recent_offline = 0_u64;
        let mut recent_offline_by_digest = BTreeMap::<&str, u64>::new();
        for request in &view.requests {
            if request.state == "online"
                && request.runner_status == "offline"
                && request.runner_last_heartbeat_unix_ms > 0
                && now
                    < request
                        .runner_last_heartbeat_unix_ms
                        .saturating_add(view.policy.offline_grace_ms)
            {
                recent_offline = recent_offline.saturating_add(1);
                let count = recent_offline_by_digest
                    .entry(request.runtime_compatibility_digest.as_str())
                    .or_default();
                *count = count.saturating_add(1);
            }
        }
        current = current.saturating_add(recent_offline);
        let cooldown = view.requests.iter().any(|request| {
            now < request
                .updated_unix_ms
                .saturating_add(view.policy.cooldown_ms)
        });

        if cooldown {
            return Ok(());
        }
        let mut provider_capacity = self
            .provider
            .available_capacity()
            .await
            .map_err(|error| reconcile("read provider capacity", error))?;

        if !view.policy.baseline_runtime_compatibility_digest.is_empty() {
            let baseline = view.policy.baseline_runtime_compatibility_digest.as_str();
            let mut baseline_total = 0_u64;
            let mut baseline_idle = 0_u64;
            for request in &view.requests {
                if request.runtime_compatibility_digest != baseline {
                    continue;
                }
                let serving = matches!(request.state.as_str(), "online" | "draining")
                    && matches!(request.runner_status.as_str(), "online" | "draining");
                let grace = request.runner_status == "offline"
                    && request.runner_last_heartbeat_unix_ms > 0
                    && now
                        < request
                            .runner_last_heartbeat_unix_ms
                            .saturating_add(view.policy.offline_grace_ms);
                if pending(&request.state) || serving || grace {
                    baseline_total = baseline_total.saturating_add(1);
                }
                if request.state == "online"
                    && request.runner_status == "online"
                    && request.runner_active_jobs == 0
                {
                    baseline_idle = baseline_idle.saturating_add(1);
                }
            }
            let need = cmp::max(
                u64::from(view.policy.minimum_workers).saturating_sub(baseline_total),
                u64::from(view.policy.minimum_idle_workers).saturating_sub(baseline_idle),
            );
            let count = minimum3(
                need,
                u64::from(view.policy.maximum_workers).saturating_sub(current),
                remaining_batch,
            )
            .min(provider_capacity);
            if count > 0 {
                let template = templates.get(baseline).ok_or_else(|| {
                    AutoscalerError::Reconcile(format!("no exact baseline template for {baseline}"))
                })?;
                for _ in 0..count {
                    scale_up.push((*template).clone());
                    current = current.saturating_add(1);
                    remaining_batch = remaining_batch.saturating_sub(1);
                    provider_capacity = provider_capacity.saturating_sub(1);
                }
            }
        }
        for demand in &view.demand {
            let recent = recent_offline_by_digest
                .get(demand.runtime_compatibility_digest.as_str())
                .copied()
                .unwrap_or_default();
            let slots_per_worker = demand.slots_per_worker.max(1);
            let required_capacity = demand
                .active_slots
                .saturating_add(demand.queued_jobs)
                .saturating_mul(100)
                .saturating_add(TARGET_UTILIZATION_PERCENT - 1)
                / TARGET_UTILIZATION_PERCENT;
            let supplied = demand
                .active_slots
                .saturating_add(demand.available_slots)
                .saturating_add(demand.pending_slots)
                .saturating_add(recent.saturating_mul(slots_per_worker));
            let missing_slots = required_capacity.saturating_sub(supplied);
            let workers_needed =
                missing_slots.saturating_add(slots_per_worker - 1) / slots_per_worker;
            let count = minimum3(
                workers_needed,
                u64::from(view.policy.maximum_workers).saturating_sub(current),
                remaining_batch,
            )
            .min(provider_capacity);
            if count == 0 {
                continue;
            }
            let template = templates
                .get(demand.runtime_compatibility_digest.as_str())
                .copied()
                .or_else(|| templates.get(GENERIC_RUNTIME_COMPATIBILITY_DIGEST).copied())
                .ok_or_else(|| {
                    AutoscalerError::Reconcile(format!(
                        "no exact or generic template for demand {}",
                        demand.runtime_compatibility_digest
                    ))
                })?;
            let mut bound_template = template.clone();
            bound_template.runtime_compatibility_digest =
                demand.runtime_compatibility_digest.clone();
            if template.runtime_compatibility_digest == GENERIC_RUNTIME_COMPATIBILITY_DIGEST {
                let suffix = demand
                    .runtime_compatibility_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&demand.runtime_compatibility_digest);
                bound_template.provider_template_id = format!(
                    "{}--{}",
                    template.provider_template_id,
                    &suffix[..suffix.len().min(16)]
                );
            }
            for _ in 0..count {
                scale_up.push(bound_template.clone());
                current = current.saturating_add(1);
                remaining_batch = remaining_batch.saturating_sub(1);
                provider_capacity = provider_capacity.saturating_sub(1);
            }
        }
        self.provision_batch(&lease, &scale_up).await?;
        self.reconcile_scale_down(&lease, &view).await
    }

    async fn reconcile_stale_bootstraps(
        &self,
        lease: &OwnershipLease,
        view: &FleetView,
    ) -> Result<(), AutoscalerError> {
        for request in &view.requests {
            if request.state != "bootstrapping"
                || request.provider_instance_id.is_empty()
                || view.observed_unix_ms
                    < request
                        .updated_unix_ms
                        .saturating_add(view.policy.offline_grace_ms)
            {
                continue;
            }
            let quarantined = self
                .control_plane
                .transition(
                    request,
                    "quarantined",
                    lease.fencing_generation,
                    "bootstrap_timeout",
                )
                .await
                .map_err(|error| {
                    reconcile(&format!("quarantine stale bootstrap {}", request.id), error)
                })?;
            let terminating = self
                .control_plane
                .transition(&quarantined, "terminating", lease.fencing_generation, "")
                .await
                .map_err(|error| {
                    reconcile(&format!("terminate stale bootstrap {}", request.id), error)
                })?;
            self.provider
                .destroy(&ProviderInstance {
                    id: request.provider_instance_id.clone(),
                    fleet_request_id: request.id.clone(),
                    ..ProviderInstance::default()
                })
                .await
                .map_err(|error| {
                    reconcile(&format!("destroy stale bootstrap {}", request.id), error)
                })?;
            self.control_plane
                .transition(&terminating, "terminated", lease.fencing_generation, "")
                .await
                .map_err(|error| {
                    reconcile(&format!("finish stale bootstrap {}", request.id), error)
                })?;
            self.provider.cleanup_claim(request).await?;
        }
        Ok(())
    }

    async fn reconcile_stale_offline_instances(
        &self,
        lease: &OwnershipLease,
        view: &FleetView,
    ) -> Result<(), AutoscalerError> {
        for request in &view.requests {
            if request.state != "online"
                || request.runner_status != "offline"
                || request.runner_active_jobs != 0
                || request.runner_last_heartbeat_unix_ms == 0
                || request.provider_instance_id.is_empty()
                || view.observed_unix_ms
                    < request
                        .runner_last_heartbeat_unix_ms
                        .saturating_add(view.policy.offline_grace_ms)
            {
                continue;
            }
            let quarantined = self
                .control_plane
                .transition(
                    request,
                    "quarantined",
                    lease.fencing_generation,
                    "offline_timeout",
                )
                .await
                .map_err(|error| {
                    reconcile(
                        &format!("quarantine stale offline instance {}", request.id),
                        error,
                    )
                })?;
            let terminating = self
                .control_plane
                .transition(&quarantined, "terminating", lease.fencing_generation, "")
                .await
                .map_err(|error| {
                    reconcile(
                        &format!("terminate stale offline instance {}", request.id),
                        error,
                    )
                })?;
            let instance = ProviderInstance {
                id: request.provider_instance_id.clone(),
                fleet_request_id: request.id.clone(),
                ..ProviderInstance::default()
            };
            if let Err(error) = self.provider.destroy(&instance).await {
                return Err(reconcile(
                    &format!("destroy stale offline instance {}", request.id),
                    error,
                ));
            }
            self.control_plane
                .transition(&terminating, "terminated", lease.fencing_generation, "")
                .await
                .map_err(|error| {
                    reconcile(
                        &format!("finish stale offline instance {}", request.id),
                        error,
                    )
                })?;
            self.provider.cleanup_claim(request).await?;
        }
        Ok(())
    }

    async fn provision(
        &self,
        lease: &OwnershipLease,
        template: &PoolTemplate,
    ) -> Result<(), AutoscalerError> {
        let request = self
            .control_plane
            .create_request(&self.pool_id, lease.fencing_generation, template)
            .await
            .map_err(|error| reconcile("create fleet request", error))?;
        self.provision_existing(lease, &request).await
    }

    async fn provision_batch(
        &self,
        lease: &OwnershipLease,
        templates: &[PoolTemplate],
    ) -> Result<(), AutoscalerError> {
        let results = join_all(
            templates
                .iter()
                .map(|template| self.provision(lease, template)),
        )
        .await;
        let mut first_error = None;
        for result in results {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn provision_existing(
        &self,
        lease: &OwnershipLease,
        request: &FleetRequest,
    ) -> Result<(), AutoscalerError> {
        let prepared = match self.provider.prepare(request).await {
            Ok(value) => value,
            Err(error) => {
                let _ = self
                    .control_plane
                    .transition(
                        request,
                        "failed",
                        lease.fencing_generation,
                        "prepare_failed",
                    )
                    .await;
                return Err(reconcile("prepare provider instance", error));
            }
        };
        let provisioning = if request.state == "requested" {
            self.control_plane
                .transition(
                    request,
                    "provisioning",
                    lease.fencing_generation,
                    &prepared.provider_request_id,
                )
                .await
                .map_err(|error| reconcile("fence provisioning transition", error))?
        } else if request.state == "provisioning" {
            request.clone()
        } else {
            return Err(AutoscalerError::Reconcile(format!(
                "cannot provision fleet request {} from state {}",
                request.id, request.state
            )));
        };
        let instance = match self.provider.create(&provisioning, &prepared).await {
            Ok(value) => value,
            Err(error) => {
                let _ = self
                    .control_plane
                    .transition(
                        &provisioning,
                        "quarantined",
                        lease.fencing_generation,
                        "ambiguous_create",
                    )
                    .await;
                return Err(reconcile("create provider instance", error));
            }
        };
        let claim = match self
            .control_plane
            .create_launch_claim(&provisioning, lease.fencing_generation, &instance.identity)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                let _ = self.provider.destroy(&instance).await;
                return Err(reconcile("create launch claim", error));
            }
        };
        if let Err(error) = self
            .provider
            .publish_claim(&instance, &prepared, &claim)
            .await
        {
            let _ = self.provider.destroy(&instance).await;
            return Err(reconcile("publish launch claim", error));
        }
        if let Err(error) = self.provider.start(&instance).await {
            let _ = self.provider.destroy(&instance).await;
            return Err(reconcile("start provider instance", error));
        }
        Ok(())
    }

    async fn reconcile_scale_down(
        &self,
        lease: &OwnershipLease,
        view: &FleetView,
    ) -> Result<(), AutoscalerError> {
        // A request that was drained during an earlier reconciliation must
        // finish terminating even though it no longer contributes to the
        // online-worker excess calculated below.
        for request in &view.requests {
            if request.state != "draining"
                || request.runner_active_jobs != 0
                || request.provider_instance_id.is_empty()
            {
                continue;
            }
            let terminating = self
                .control_plane
                .transition(request, "terminating", lease.fencing_generation, "")
                .await
                .map_err(|error| {
                    reconcile(&format!("fence termination for {}", request.id), error)
                })?;
            let instance = ProviderInstance {
                id: terminating.provider_instance_id.clone(),
                fleet_request_id: request.id.clone(),
                ..ProviderInstance::default()
            };
            if let Err(error) = self.provider.destroy(&instance).await {
                let _ = self
                    .control_plane
                    .transition(
                        &terminating,
                        "quarantined",
                        lease.fencing_generation,
                        "ambiguous_delete",
                    )
                    .await;
                return Err(reconcile(
                    &format!("destroy provider instance {}", instance.id),
                    error,
                ));
            }
            self.control_plane
                .transition(&terminating, "terminated", lease.fencing_generation, "")
                .await
                .map_err(|error| {
                    reconcile(&format!("record termination for {}", request.id), error)
                })?;
        }

        let minimum = cmp::max(
            u64::from(view.policy.minimum_workers),
            u64::from(view.policy.minimum_idle_workers),
        );
        let managed_online = view
            .requests
            .iter()
            .filter(|request| request.state == "online" && request.runner_status == "online")
            .count() as u64;
        let mut excess = managed_online.saturating_sub(minimum);
        if excess == 0 {
            return Ok(());
        }
        let now = self.clock.now_unix_ms()?;
        for request in &view.requests {
            if excess == 0 {
                break;
            }
            if request.state != "online"
                || request.runner_id.is_empty()
                || request.runner_active_jobs != 0
                || now
                    < request
                        .updated_unix_ms
                        .saturating_add(view.policy.idle_timeout_ms)
            {
                continue;
            }
            self.control_plane
                .transition(request, "draining", lease.fencing_generation, "")
                .await
                .map_err(|error| reconcile(&format!("record drain for {}", request.id), error))?;
            excess = excess.saturating_sub(1);
        }
        Ok(())
    }
}

fn pending(state: &str) -> bool {
    matches!(
        state,
        "requested" | "provisioning" | "bootstrapping" | "enrolled"
    )
}

fn minimum3(first: u64, second: u64, third: u64) -> u64 {
    cmp::min(first, cmp::min(second, third))
}

fn reconcile(context: &str, error: AutoscalerError) -> AutoscalerError {
    AutoscalerError::Reconcile(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DemandGroup, LaunchClaim, OwnershipLease, PlannedReplacement, PreparedInstance,
        ProviderIdentity, Replacement, ScalingPolicy,
    };
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_unix_ms(&self) -> Result<u64, AutoscalerError> {
            Ok(self.0)
        }
    }

    #[derive(Default)]
    struct FakeControl {
        view: Mutex<FleetView>,
        created: AtomicUsize,
        created_digests: Mutex<Vec<String>>,
        created_template_ids: Mutex<Vec<String>>,
        transitions: Mutex<Vec<String>>,
        activated: AtomicUsize,
        planned: Mutex<Option<PlannedReplacement>>,
    }

    #[async_trait]
    impl ControlPlaneClient for FakeControl {
        async fn acquire_lease(
            &self,
            pool: &str,
            owner: &str,
            _expires_in_ms: u64,
        ) -> Result<OwnershipLease, AutoscalerError> {
            Ok(OwnershipLease {
                pool_id: pool.into(),
                owner_id: owner.into(),
                fencing_generation: 7,
                expires_unix_ms: u64::MAX,
            })
        }

        async fn fleet(&self, _pool: &str) -> Result<FleetView, AutoscalerError> {
            Ok(self.view.lock().unwrap().clone())
        }

        async fn create_request(
            &self,
            pool: &str,
            _generation: u64,
            template: &PoolTemplate,
        ) -> Result<FleetRequest, AutoscalerError> {
            let number = self.created.fetch_add(1, Ordering::Relaxed) + 1;
            self.created_digests
                .lock()
                .unwrap()
                .push(template.runtime_compatibility_digest.clone());
            self.created_template_ids
                .lock()
                .unwrap()
                .push(template.provider_template_id.clone());
            Ok(FleetRequest {
                id: format!("request-{number}"),
                pool_id: pool.into(),
                runtime_compatibility_digest: template.runtime_compatibility_digest.clone(),
                provider: template.provider.clone(),
                state: "requested".into(),
                ..FleetRequest::default()
            })
        }

        async fn transition(
            &self,
            request: &FleetRequest,
            next: &str,
            _generation: u64,
            _detail: &str,
        ) -> Result<FleetRequest, AutoscalerError> {
            self.transitions
                .lock()
                .unwrap()
                .push(format!("{}->{next}", request.state));
            let mut changed = request.clone();
            changed.state = next.into();
            changed.provider_instance_id = "instance".into();
            Ok(changed)
        }

        async fn create_launch_claim(
            &self,
            _request: &FleetRequest,
            _generation: u64,
            _identity: &ProviderIdentity,
        ) -> Result<LaunchClaim, AutoscalerError> {
            Ok(LaunchClaim {
                version: 1,
                ..LaunchClaim::default()
            })
        }

        async fn plan_replacement(
            &self,
            _pool: &str,
            _generation: u64,
        ) -> Result<Option<PlannedReplacement>, AutoscalerError> {
            Ok(self.planned.lock().unwrap().take())
        }

        async fn activate_replacement(
            &self,
            _pool: &str,
            _replacement: &str,
            _generation: u64,
        ) -> Result<(), AutoscalerError> {
            self.activated.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FakeProvider {
        created: AtomicUsize,
        started: AtomicUsize,
        destroyed: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        capacity: usize,
    }

    impl Default for FakeProvider {
        fn default() -> Self {
            Self {
                created: AtomicUsize::new(0),
                started: AtomicUsize::new(0),
                destroyed: AtomicUsize::new(0),
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                capacity: usize::MAX,
            }
        }
    }

    #[async_trait]
    impl Provider for FakeProvider {
        async fn available_capacity(&self) -> Result<u64, AutoscalerError> {
            Ok(self.capacity as u64)
        }

        async fn prepare(
            &self,
            _request: &FleetRequest,
        ) -> Result<PreparedInstance, AutoscalerError> {
            Ok(PreparedInstance {
                provider_request_id: "provider-request".into(),
                ..PreparedInstance::default()
            })
        }

        async fn create(
            &self,
            request: &FleetRequest,
            _prepared: &PreparedInstance,
        ) -> Result<ProviderInstance, AutoscalerError> {
            self.created.fetch_add(1, Ordering::Relaxed);
            let in_flight = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_in_flight.fetch_max(in_flight, Ordering::Relaxed);
            tokio::task::yield_now().await;
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            Ok(ProviderInstance {
                id: "instance".into(),
                fleet_request_id: request.id.clone(),
                identity: ProviderIdentity {
                    provider: "fake".into(),
                    ..ProviderIdentity::default()
                },
            })
        }

        async fn publish_claim(
            &self,
            _instance: &ProviderInstance,
            _prepared: &PreparedInstance,
            _claim: &LaunchClaim,
        ) -> Result<(), AutoscalerError> {
            Ok(())
        }

        async fn start(&self, _instance: &ProviderInstance) -> Result<(), AutoscalerError> {
            self.started.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn destroy(&self, _instance: &ProviderInstance) -> Result<(), AutoscalerError> {
            self.destroyed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn cleanup_claim(&self, _request: &FleetRequest) -> Result<(), AutoscalerError> {
            Ok(())
        }
    }

    fn template(digest: &str) -> PoolTemplate {
        PoolTemplate {
            runtime_compatibility_digest: digest.into(),
            provider: "fake".into(),
            ..PoolTemplate::default()
        }
    }

    #[tokio::test]
    async fn exact_demand_scales_only_registered_template() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 5,
                    scale_up_batch: 2,
                    ..ScalingPolicy::default()
                },
                demand: vec![DemandGroup {
                    runtime_compatibility_digest: "sha256:exact".into(),
                    queued_jobs: 3,
                    ..DemandGroup::default()
                }],
                templates: vec![template("sha256:exact")],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        let reconciler = Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        );
        reconciler.reconcile().await.unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 2);
        assert_eq!(provider.created.load(Ordering::Relaxed), 2);
        assert_eq!(provider.max_in_flight.load(Ordering::Relaxed), 2);
        assert_eq!(provider.started.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn generic_template_is_bound_to_the_exact_demand_digest() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    scale_up_batch: 1,
                    ..ScalingPolicy::default()
                },
                demand: vec![DemandGroup {
                    runtime_compatibility_digest: "sha256:job-specific".into(),
                    queued_jobs: 1,
                    ..DemandGroup::default()
                }],
                templates: vec![template(GENERIC_RUNTIME_COMPATIBILITY_DIGEST)],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 1);
        assert_eq!(
            control.created_digests.lock().unwrap().as_slice(),
            &["sha256:job-specific"]
        );
        assert_eq!(
            control.created_template_ids.lock().unwrap().as_slice(),
            &["--job-specific"]
        );
    }

    #[tokio::test]
    async fn fixed_pool_workers_do_not_consume_the_managed_worker_limit() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    scale_up_batch: 1,
                    ..ScalingPolicy::default()
                },
                demand: vec![DemandGroup {
                    runtime_compatibility_digest: "sha256:exact".into(),
                    queued_jobs: 1,
                    ..DemandGroup::default()
                }],
                templates: vec![template("sha256:exact")],
                online_workers: 2,
                draining_workers: 3,
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn wasm_slot_pressure_rounds_missing_capacity_to_whole_workers() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 5,
                    scale_up_batch: 5,
                    ..ScalingPolicy::default()
                },
                demand: vec![DemandGroup {
                    runtime_compatibility_digest: "sha256:wasm".into(),
                    queued_jobs: 2,
                    active_slots: 6,
                    available_slots: 2,
                    pending_slots: 0,
                    slots_per_worker: 8,
                }],
                templates: vec![template("sha256:wasm")],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cold_pool_creates_exact_baseline_capacity() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    minimum_workers: 2,
                    maximum_workers: 4,
                    scale_up_batch: 3,
                    baseline_runtime_compatibility_digest: "sha256:baseline".into(),
                    ..ScalingPolicy::default()
                },
                templates: vec![template("sha256:baseline")],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn maximum_and_batch_are_global_across_demand_classes() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 3,
                    scale_up_batch: 2,
                    ..ScalingPolicy::default()
                },
                requests: vec![FleetRequest {
                    id: "pending".into(),
                    state: "bootstrapping".into(),
                    ..FleetRequest::default()
                }],
                demand: vec![
                    DemandGroup {
                        runtime_compatibility_digest: "a".into(),
                        queued_jobs: 3,
                        ..DemandGroup::default()
                    },
                    DemandGroup {
                        runtime_compatibility_digest: "b".into(),
                        queued_jobs: 3,
                        ..DemandGroup::default()
                    },
                ],
                templates: vec![template("a"), template("b")],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(100_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn provider_capacity_caps_scale_up_without_creating_failed_requests() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 8,
                    scale_up_batch: 8,
                    ..ScalingPolicy::default()
                },
                demand: vec![DemandGroup {
                    runtime_compatibility_digest: "a".into(),
                    queued_jobs: 8,
                    ..DemandGroup::default()
                }],
                templates: vec![template("a")],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider {
            capacity: 2,
            ..FakeProvider::default()
        };
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(100_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 2);
        assert_eq!(provider.created.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn scale_down_drains_before_destroy() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                observed_unix_ms: 10_000,
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 5,
                    idle_timeout_ms: 1,
                    ..ScalingPolicy::default()
                },
                online_workers: 1,
                requests: vec![FleetRequest {
                    id: "one".into(),
                    pool_id: "pool".into(),
                    state: "online".into(),
                    runner_id: "runner".into(),
                    runner_status: "online".into(),
                    updated_unix_ms: 1,
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.transitions.lock().unwrap()[0], "online->draining");
        assert_eq!(provider.destroyed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn previously_drained_request_is_terminated_without_online_excess() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                observed_unix_ms: 10_000,
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    ..ScalingPolicy::default()
                },
                requests: vec![FleetRequest {
                    id: "one".into(),
                    pool_id: "pool".into(),
                    state: "draining".into(),
                    runner_id: "runner".into(),
                    runner_status: "draining".into(),
                    provider_instance_id: "instance".into(),
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(
            *control.transitions.lock().unwrap(),
            ["draining->terminating", "terminating->terminated"]
        );
        assert_eq!(provider.destroyed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn offline_grace_and_cooldown_prevent_premature_replacement() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                observed_unix_ms: 50_000,
                policy: ScalingPolicy {
                    enabled: true,
                    minimum_workers: 1,
                    maximum_workers: 2,
                    scale_up_batch: 1,
                    baseline_runtime_compatibility_digest: "sha256:baseline".into(),
                    offline_grace_ms: 20_000,
                    cooldown_ms: 1_000,
                    ..ScalingPolicy::default()
                },
                templates: vec![template("sha256:baseline")],
                requests: vec![FleetRequest {
                    id: "old".into(),
                    runtime_compatibility_digest: "sha256:baseline".into(),
                    state: "online".into(),
                    runner_status: "offline".into(),
                    runner_last_heartbeat_unix_ms: 40_000,
                    updated_unix_ms: 40_000,
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        let reconciler = Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(70_000),
        );
        reconciler.reconcile().await.unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 0);
        {
            let mut view = control.view.lock().unwrap();
            view.observed_unix_ms = 70_000;
            view.requests[0].updated_unix_ms = 69_500;
        }
        reconciler.reconcile().await.unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 0);
        control.view.lock().unwrap().requests[0].updated_unix_ms = 60_000;
        reconciler.reconcile().await.unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn offline_instance_past_grace_is_destroyed_and_terminated() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                observed_unix_ms: 100_000,
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    scale_up_batch: 1,
                    offline_grace_ms: 10_000,
                    ..ScalingPolicy::default()
                },
                requests: vec![FleetRequest {
                    id: "stopped".into(),
                    pool_id: "pool".into(),
                    state: "online".into(),
                    runner_id: "runner".into(),
                    runner_status: "offline".into(),
                    runner_last_heartbeat_unix_ms: 80_000,
                    provider_instance_id: "instance".into(),
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(100_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(provider.destroyed.load(Ordering::Relaxed), 1);
        assert_eq!(
            control.transitions.lock().unwrap().as_slice(),
            [
                "online->quarantined",
                "quarantined->terminating",
                "terminating->terminated"
            ]
        );
    }

    #[tokio::test]
    async fn stale_bootstrap_is_quarantined_destroyed_and_terminated() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                observed_unix_ms: 100_000,
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    scale_up_batch: 1,
                    offline_grace_ms: 10_000,
                    ..ScalingPolicy::default()
                },
                requests: vec![FleetRequest {
                    id: "ambiguous".into(),
                    pool_id: "pool".into(),
                    state: "bootstrapping".into(),
                    provider_instance_id: "instance".into(),
                    updated_unix_ms: 1,
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(100_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(provider.destroyed.load(Ordering::Relaxed), 1);
        assert_eq!(
            control.transitions.lock().unwrap().as_slice(),
            [
                "bootstrapping->quarantined",
                "quarantined->terminating",
                "terminating->terminated"
            ]
        );
    }

    #[tokio::test]
    async fn replacement_is_planned_provisioned_and_probationary_is_activated() {
        let replacement_request = FleetRequest {
            id: "replacement-request".into(),
            pool_id: "pool".into(),
            state: "requested".into(),
            provider: "fake".into(),
            ..FleetRequest::default()
        };
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 2,
                    ..ScalingPolicy::default()
                },
                replacements: vec![Replacement {
                    id: "ready".into(),
                    pool_id: "pool".into(),
                    state: "probationary".into(),
                    ..Replacement::default()
                }],
                ..FleetView::default()
            }),
            planned: Mutex::new(Some(PlannedReplacement {
                replacement: Replacement {
                    id: "planned".into(),
                    pool_id: "pool".into(),
                    state: "requested".into(),
                    ..Replacement::default()
                },
                fleet_request: replacement_request,
            })),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.activated.load(Ordering::Relaxed), 1);
        assert_eq!(provider.created.load(Ordering::Relaxed), 1);
        assert_eq!(provider.started.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn requested_instances_resume_after_restart() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    ..ScalingPolicy::default()
                },
                requests: vec![FleetRequest {
                    id: "resume".into(),
                    pool_id: "pool".into(),
                    state: "requested".into(),
                    provider: "fake".into(),
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(control.created.load(Ordering::Relaxed), 0);
        assert_eq!(provider.created.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn provisioning_instances_resume_without_repeating_transition() {
        let control = FakeControl {
            view: Mutex::new(FleetView {
                policy: ScalingPolicy {
                    enabled: true,
                    maximum_workers: 1,
                    ..ScalingPolicy::default()
                },
                requests: vec![FleetRequest {
                    id: "resume-provisioning".into(),
                    pool_id: "pool".into(),
                    state: "provisioning".into(),
                    provider: "fake".into(),
                    ..FleetRequest::default()
                }],
                ..FleetView::default()
            }),
            ..FakeControl::default()
        };
        let provider = FakeProvider::default();
        Reconciler::with_clock(
            &control,
            &provider,
            "pool".into(),
            "owner".into(),
            FixedClock(10_000),
        )
        .reconcile()
        .await
        .unwrap();
        assert_eq!(provider.created.load(Ordering::Relaxed), 1);
        assert!(control.transitions.lock().unwrap().is_empty());
    }
}
