-- Request rows bind stable run/job/approval keys and the authoritative
-- migration-0010 artifact catalog used by atomic reservation and transition
-- checks in the PostgreSQL persistence boundary.

CREATE UNIQUE INDEX IF NOT EXISTS leases_tenant_id ON leases(tenant_id,id);

CREATE TABLE tenant_provider_configurations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    capability TEXT NOT NULL CHECK (capability IN ('external-secret', 'signing')),
    provider_kind TEXT NOT NULL,
    endpoint_origin TEXT NOT NULL,
    credential_reference TEXT NOT NULL,
    trust_bundle_digest TEXT NOT NULL,
    public_key_digest TEXT,
    configuration_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'retired')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, capability, configuration_digest)
);

CREATE INDEX tenant_provider_configurations_status
    ON tenant_provider_configurations(tenant_id, capability, status, id);

CREATE TABLE tenant_provider_configuration_versions (
    tenant_id TEXT NOT NULL,
    provider_configuration_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    snapshot_digest TEXT NOT NULL,
    snapshot_json BYTEA NOT NULL CHECK (octet_length(snapshot_json) <= 262144),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (tenant_id, provider_configuration_id, version),
    UNIQUE (tenant_id, provider_configuration_id, snapshot_digest),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_provider_configurations(tenant_id, id)
);

CREATE TABLE signer_policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    provider_configuration_id TEXT NOT NULL,
    provider_configuration_digest TEXT NOT NULL,
    provider_configuration_version BIGINT NOT NULL CHECK (provider_configuration_version >= 1),
    backend_key_reference TEXT NOT NULL,
    purpose TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('sign-digest', 'sign-attestation')),
    public_key_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'retired')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, policy_digest),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_provider_configurations(tenant_id, id),
    FOREIGN KEY (tenant_id, provider_configuration_id, provider_configuration_version)
        REFERENCES tenant_provider_configuration_versions
            (tenant_id, provider_configuration_id, version)
);

CREATE INDEX signer_policies_status
    ON signer_policies(tenant_id, status, purpose, operation, id);

CREATE TABLE signer_policy_versions (
    tenant_id TEXT NOT NULL,
    signer_policy_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    snapshot_digest TEXT NOT NULL,
    snapshot_json BYTEA NOT NULL CHECK (octet_length(snapshot_json) <= 262144),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (tenant_id, signer_policy_id, version),
    UNIQUE (tenant_id, signer_policy_id, snapshot_digest),
    FOREIGN KEY (tenant_id, signer_policy_id) REFERENCES signer_policies(tenant_id, id)
);

CREATE TABLE environments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL,
    name TEXT NOT NULL,
    deployment_target_reference TEXT NOT NULL,
    deployment_target_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    protection_rules_json BYTEA NOT NULL CHECK (octet_length(protection_rules_json) <= 1048576),
    protection_rules_digest TEXT NOT NULL,
    wait_timer_ms BIGINT NOT NULL CHECK (wait_timer_ms BETWEEN 0 AND 604800000),
    concurrency_limit BIGINT NOT NULL CHECK (concurrency_limit BETWEEN 1 AND 128),
    secret_provider_configuration_id TEXT,
    signing_provider_configuration_id TEXT,
    required_policy_epoch BIGINT NOT NULL CHECK (required_policy_epoch >= 1),
    last_concurrency_fence BIGINT NOT NULL DEFAULT 0 CHECK (last_concurrency_fence >= 0),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, repository_id, name),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    FOREIGN KEY (tenant_id, secret_provider_configuration_id)
        REFERENCES tenant_provider_configurations(tenant_id, id),
    FOREIGN KEY (tenant_id, signing_provider_configuration_id)
        REFERENCES tenant_provider_configurations(tenant_id, id)
);

CREATE INDEX environments_tenant_repository
    ON environments(tenant_id, repository_id, status, id);

CREATE TABLE environment_versions (
    tenant_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    snapshot_digest TEXT NOT NULL,
    snapshot_json BYTEA NOT NULL CHECK (octet_length(snapshot_json) <= 1048576),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (tenant_id, environment_id, version),
    UNIQUE (tenant_id, environment_id, snapshot_digest),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments(tenant_id, id)
);

CREATE TABLE deployment_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    environment_id TEXT NOT NULL,
    environment_version BIGINT NOT NULL CHECK (environment_version >= 1),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 1),
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL,
    job_attempt BIGINT NOT NULL CHECK (job_attempt >= 1),
    artifact_id TEXT NOT NULL,
    promoted_artifact_id TEXT,
    artifact_source_run_id TEXT NOT NULL REFERENCES runs(id),
    artifact_source_job_id TEXT NOT NULL,
    artifact_source_job_attempt BIGINT NOT NULL CHECK (artifact_source_job_attempt >= 1),
    artifact_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    provenance_digest TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    deployment_capsule_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    approval_subject_digest TEXT NOT NULL,
    approval_request_id TEXT UNIQUE REFERENCES approval_requests(id),
    rollback_of_deployment_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('waiting-timer','awaiting-approval','awaiting-concurrency','ready','leased','in-progress','succeeded','failed','canceled')),
    wait_until_unix_ms BIGINT NOT NULL,
    concurrency_fence BIGINT CHECK (concurrency_fence >= 1),
    execution_lease_id TEXT,
    lease_fencing_generation BIGINT CHECK (lease_fencing_generation >= 1),
    installation_fencing_epoch BIGINT CHECK (installation_fencing_epoch >= 1),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    completed_unix_ms BIGINT,
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id,id), UNIQUE (tenant_id,request_digest), UNIQUE (tenant_id,job_id,job_attempt),
    FOREIGN KEY (tenant_id,environment_id) REFERENCES environments(tenant_id,id),
    FOREIGN KEY (tenant_id,environment_id,environment_version) REFERENCES environment_versions(tenant_id,environment_id,version),
    FOREIGN KEY (tenant_id,repository_id) REFERENCES repositories(tenant_id,id),
    FOREIGN KEY (job_id,job_attempt) REFERENCES jobs(id,attempt),
    FOREIGN KEY (artifact_source_job_id,artifact_source_job_attempt) REFERENCES jobs(id,attempt),
    FOREIGN KEY (artifact_id) REFERENCES artifacts_catalog(artifact_id),
    FOREIGN KEY (tenant_id,execution_lease_id) REFERENCES leases(tenant_id,id),
    CHECK ((execution_lease_id IS NULL)=(lease_fencing_generation IS NULL)),
    CHECK ((concurrency_fence IS NULL)=(installation_fencing_epoch IS NULL)),
    CHECK (wait_until_unix_ms>=created_unix_ms),
    CHECK (completed_unix_ms IS NULL OR completed_unix_ms>=created_unix_ms)
);
CREATE INDEX deployment_requests_gate_queue ON deployment_requests(tenant_id,environment_id,status,wait_until_unix_ms,id);
CREATE INDEX deployment_requests_run_job ON deployment_requests(tenant_id,run_id,job_id,job_attempt,id);

CREATE TABLE deployment_request_events (
    deployment_request_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    version BIGINT NOT NULL CHECK(version>=1),
    status TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    occurred_unix_ms BIGINT NOT NULL CHECK(occurred_unix_ms>=0),
    PRIMARY KEY(deployment_request_id,version),
    UNIQUE(tenant_id,deployment_request_id,version),
    FOREIGN KEY(tenant_id,deployment_request_id) REFERENCES deployment_requests(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE environment_concurrency_leases (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    deployment_request_id TEXT NOT NULL,
    concurrency_fence BIGINT NOT NULL CHECK(concurrency_fence>=1),
    execution_lease_id TEXT,
    lease_fencing_generation BIGINT CHECK(lease_fencing_generation>=1),
    installation_fencing_epoch BIGINT NOT NULL CHECK(installation_fencing_epoch>=1),
    state TEXT NOT NULL CHECK(state IN('active','released','expired')),
    acquired_unix_ms BIGINT NOT NULL CHECK(acquired_unix_ms>=0),
    expires_unix_ms BIGINT NOT NULL CHECK(expires_unix_ms>acquired_unix_ms),
    released_unix_ms BIGINT,
    UNIQUE(tenant_id,environment_id,concurrency_fence),
    FOREIGN KEY(tenant_id,environment_id) REFERENCES environments(tenant_id,id),
    FOREIGN KEY(tenant_id,deployment_request_id) REFERENCES deployment_requests(tenant_id,id),
    FOREIGN KEY(tenant_id,execution_lease_id) REFERENCES leases(tenant_id,id),
    CHECK(released_unix_ms IS NULL OR released_unix_ms>=acquired_unix_ms),
    CHECK((state='active')=(released_unix_ms IS NULL)),
    CHECK((execution_lease_id IS NULL)=(lease_fencing_generation IS NULL))
);
CREATE INDEX environment_concurrency_leases_active ON environment_concurrency_leases(tenant_id,environment_id,state,expires_unix_ms,id);
CREATE UNIQUE INDEX environment_concurrency_leases_one_active_request ON environment_concurrency_leases(tenant_id,deployment_request_id) WHERE state='active';

CREATE TABLE external_secret_release_journal (
    release_id TEXT PRIMARY KEY,
    release_subject_digest TEXT NOT NULL,
    provider_configuration_id TEXT NOT NULL,
    provider_configuration_digest TEXT NOT NULL,
    provider_configuration_version BIGINT NOT NULL CHECK (provider_configuration_version >= 1),
    provider_reference_digest TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs(id),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    execution_lease_id TEXT NOT NULL,
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch BIGINT NOT NULL CHECK (installation_fencing_epoch >= 1),
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    secret_metadata_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    reservation_json BYTEA NOT NULL CHECK (octet_length(reservation_json) <= 262144),
    state TEXT NOT NULL CHECK (state IN
        ('reserved', 'delivered', 'revoking', 'revoked', 'indeterminate')),
    provider_metadata_json BYTEA CHECK (
        provider_metadata_json IS NULL OR octet_length(provider_metadata_json) <= 262144
    ),
    provider_metadata_digest TEXT,
    transition_attempts INTEGER NOT NULL DEFAULT 0 CHECK (transition_attempts BETWEEN 0 AND 8),
    expires_unix_ms BIGINT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    revoked_unix_ms BIGINT,
    reservation_digest TEXT NOT NULL,
    UNIQUE (tenant_id, release_id),
    UNIQUE (tenant_id, release_subject_digest),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_provider_configurations(tenant_id, id),
    FOREIGN KEY (tenant_id, provider_configuration_id, provider_configuration_version)
        REFERENCES tenant_provider_configuration_versions
            (tenant_id, provider_configuration_id, version),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    FOREIGN KEY (tenant_id, execution_lease_id) REFERENCES leases(tenant_id, id),
    FOREIGN KEY (tenant_id, secret_metadata_id) REFERENCES secret_metadata(tenant_id, id),
    FOREIGN KEY (job_id, job_attempt) REFERENCES jobs(id, attempt),
    CHECK (expires_unix_ms > created_unix_ms),
    CHECK ((provider_metadata_json IS NULL) = (provider_metadata_digest IS NULL)),
    CHECK (revoked_unix_ms IS NULL OR revoked_unix_ms >= created_unix_ms)
);

CREATE INDEX external_secret_release_reconcile
    ON external_secret_release_journal(tenant_id,state,expires_unix_ms,updated_unix_ms,release_id);

CREATE FUNCTION protect_external_secret_release() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'external secret release journal is append-preserving';
    END IF;
    IF NEW.release_id IS DISTINCT FROM OLD.release_id
       OR NEW.release_subject_digest IS DISTINCT FROM OLD.release_subject_digest
       OR NEW.provider_configuration_id IS DISTINCT FROM OLD.provider_configuration_id
       OR NEW.provider_configuration_digest IS DISTINCT FROM OLD.provider_configuration_digest
       OR NEW.provider_configuration_version IS DISTINCT FROM OLD.provider_configuration_version
       OR NEW.provider_reference_digest IS DISTINCT FROM OLD.provider_reference_digest
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
       OR NEW.execution_lease_id IS DISTINCT FROM OLD.execution_lease_id
       OR NEW.fencing_generation IS DISTINCT FROM OLD.fencing_generation
       OR NEW.installation_fencing_epoch IS DISTINCT FROM OLD.installation_fencing_epoch
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.job_attempt IS DISTINCT FROM OLD.job_attempt
       OR NEW.step_id IS DISTINCT FROM OLD.step_id
       OR NEW.secret_metadata_id IS DISTINCT FROM OLD.secret_metadata_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.reservation_json IS DISTINCT FROM OLD.reservation_json
       OR NEW.expires_unix_ms IS DISTINCT FROM OLD.expires_unix_ms
       OR NEW.created_unix_ms IS DISTINCT FROM OLD.created_unix_ms
       OR NEW.reservation_digest IS DISTINCT FROM OLD.reservation_digest THEN
        RAISE EXCEPTION 'external secret release reservation binding changed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER external_secret_release_update_guard
BEFORE UPDATE ON external_secret_release_journal
FOR EACH ROW EXECUTE FUNCTION protect_external_secret_release();
CREATE TRIGGER external_secret_release_delete_guard
BEFORE DELETE ON external_secret_release_journal
FOR EACH ROW EXECUTE FUNCTION protect_external_secret_release();

-- Deployment results retain the exact artifact, provenance, capsule, signing,
-- and environment bindings validated in the same transaction as insertion.
CREATE TABLE deployments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    environment_id TEXT NOT NULL,
    deployment_request_id TEXT NOT NULL UNIQUE,
    rollback_of_deployment_id TEXT,
    artifact_id TEXT NOT NULL,
    promoted_artifact_id TEXT,
    artifact_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    provenance_digest TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    deployment_capsule_digest TEXT NOT NULL,
    signing_request_id TEXT,
    signing_result_digest TEXT,
    signer_key_id TEXT,
    signing_algorithm TEXT,
    signature_digest TEXT,
    certificate_digest TEXT,
    attestation_digest TEXT,
    external_reference TEXT,
    status TEXT NOT NULL CHECK(status IN('succeeded','failed','rolled-back')),
    result_digest TEXT NOT NULL,
    metadata_json BYTEA NOT NULL CHECK(octet_length(metadata_json)<=1048576),
    metadata_digest TEXT NOT NULL,
    started_unix_ms BIGINT NOT NULL CHECK(started_unix_ms>=0),
    completed_unix_ms BIGINT NOT NULL CHECK(completed_unix_ms>=started_unix_ms),
    UNIQUE(tenant_id,id),
    FOREIGN KEY(tenant_id,environment_id) REFERENCES environments(tenant_id,id),
    FOREIGN KEY(tenant_id,deployment_request_id) REFERENCES deployment_requests(tenant_id,id),
    FOREIGN KEY(tenant_id,rollback_of_deployment_id) REFERENCES deployments(tenant_id,id),
    FOREIGN KEY(artifact_id) REFERENCES artifacts_catalog(artifact_id),
    CHECK((signing_request_id IS NULL)=(signing_result_digest IS NULL)),
    CHECK((signing_request_id IS NULL)=(signer_key_id IS NULL)),
    CHECK((signing_request_id IS NULL)=(signing_algorithm IS NULL)),
    CHECK((signing_request_id IS NULL)=(signature_digest IS NULL))
);
CREATE INDEX deployments_environment_history
    ON deployments(tenant_id,environment_id,started_unix_ms,id);

CREATE TABLE signing_result_journal (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    provider_configuration_id TEXT NOT NULL,
    provider_configuration_digest TEXT NOT NULL,
    provider_configuration_version BIGINT NOT NULL CHECK(provider_configuration_version>=1),
    environment_id TEXT NOT NULL,
    deployment_request_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL,
    job_attempt BIGINT NOT NULL CHECK(job_attempt>=1),
    step_id TEXT NOT NULL,
    execution_lease_id TEXT NOT NULL,
    fencing_generation BIGINT NOT NULL CHECK(fencing_generation>=1),
    installation_fencing_epoch BIGINT NOT NULL CHECK(installation_fencing_epoch>=1),
    policy_epoch BIGINT NOT NULL CHECK(policy_epoch>=1),
    environment_version BIGINT NOT NULL CHECK(environment_version>=1),
    approval_request_id TEXT NOT NULL REFERENCES approval_requests(id),
    approval_subject_digest TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    provenance_digest TEXT NOT NULL,
    purpose TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN('sign-digest','sign-attestation')),
    signer_policy_id TEXT NOT NULL,
    signer_policy_digest TEXT NOT NULL,
    signer_policy_version BIGINT NOT NULL CHECK(signer_policy_version>=1),
    request_digest TEXT NOT NULL,
    reservation_json BYTEA NOT NULL CHECK(octet_length(reservation_json)<=1048576),
    state TEXT NOT NULL CHECK(state IN('reserved','signed','complete','aborted')),
    result_json BYTEA CHECK(result_json IS NULL OR octet_length(result_json)<=1048576),
    result_digest TEXT,
    retry_attempts BIGINT NOT NULL DEFAULT 0 CHECK(retry_attempts BETWEEN 0 AND 8),
    requested_unix_ms BIGINT NOT NULL CHECK(requested_unix_ms>=0),
    expires_unix_ms BIGINT NOT NULL CHECK(expires_unix_ms>requested_unix_ms),
    updated_unix_ms BIGINT NOT NULL CHECK(updated_unix_ms>=requested_unix_ms),
    completed_unix_ms BIGINT,
    UNIQUE(tenant_id,request_id),
    UNIQUE(tenant_id,request_digest),
    FOREIGN KEY(tenant_id,provider_configuration_id)
        REFERENCES tenant_provider_configurations(tenant_id,id),
    FOREIGN KEY(tenant_id,provider_configuration_id,provider_configuration_version)
        REFERENCES tenant_provider_configuration_versions(tenant_id,provider_configuration_id,version),
    FOREIGN KEY(tenant_id,signer_policy_id) REFERENCES signer_policies(tenant_id,id),
    FOREIGN KEY(tenant_id,signer_policy_id,signer_policy_version)
        REFERENCES signer_policy_versions(tenant_id,signer_policy_id,version),
    FOREIGN KEY(tenant_id,environment_id) REFERENCES environments(tenant_id,id),
    FOREIGN KEY(tenant_id,deployment_request_id) REFERENCES deployment_requests(tenant_id,id),
    FOREIGN KEY(tenant_id,repository_id) REFERENCES repositories(tenant_id,id),
    FOREIGN KEY(tenant_id,execution_lease_id) REFERENCES leases(tenant_id,id),
    FOREIGN KEY(job_id,job_attempt) REFERENCES jobs(id,attempt),
    CHECK((result_json IS NULL)=(result_digest IS NULL)),
    CHECK(completed_unix_ms IS NULL OR completed_unix_ms>=requested_unix_ms),
    CHECK((state IN('signed','complete'))=(result_json IS NOT NULL)),
    CHECK((state='complete')=(completed_unix_ms IS NOT NULL))
);
CREATE INDEX signing_result_reconcile
    ON signing_result_journal(tenant_id,state,expires_unix_ms,updated_unix_ms,request_id);

CREATE FUNCTION reject_deployment_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER tenant_provider_configuration_versions_append_only
BEFORE UPDATE OR DELETE ON tenant_provider_configuration_versions
FOR EACH ROW EXECUTE FUNCTION reject_deployment_history_mutation();

CREATE TRIGGER signer_policy_versions_append_only
BEFORE UPDATE OR DELETE ON signer_policy_versions
FOR EACH ROW EXECUTE FUNCTION reject_deployment_history_mutation();

CREATE TRIGGER environment_versions_append_only
BEFORE UPDATE OR DELETE ON environment_versions
FOR EACH ROW EXECUTE FUNCTION reject_deployment_history_mutation();

CREATE TRIGGER deployment_request_events_append_only
BEFORE UPDATE OR DELETE ON deployment_request_events
FOR EACH ROW EXECUTE FUNCTION reject_deployment_history_mutation();

CREATE FUNCTION protect_signing_result_journal() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.request_id IS DISTINCT FROM NEW.request_id
       OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.provider_configuration_id IS DISTINCT FROM NEW.provider_configuration_id
       OR OLD.provider_configuration_digest IS DISTINCT FROM NEW.provider_configuration_digest
       OR OLD.provider_configuration_version IS DISTINCT FROM NEW.provider_configuration_version
       OR OLD.environment_id IS DISTINCT FROM NEW.environment_id
       OR OLD.deployment_request_id IS DISTINCT FROM NEW.deployment_request_id
       OR OLD.repository_id IS DISTINCT FROM NEW.repository_id
       OR OLD.run_id IS DISTINCT FROM NEW.run_id
       OR OLD.job_id IS DISTINCT FROM NEW.job_id
       OR OLD.job_attempt IS DISTINCT FROM NEW.job_attempt
       OR OLD.step_id IS DISTINCT FROM NEW.step_id
       OR OLD.execution_lease_id IS DISTINCT FROM NEW.execution_lease_id
       OR OLD.fencing_generation IS DISTINCT FROM NEW.fencing_generation
       OR OLD.installation_fencing_epoch IS DISTINCT FROM NEW.installation_fencing_epoch
       OR OLD.policy_epoch IS DISTINCT FROM NEW.policy_epoch
       OR OLD.environment_version IS DISTINCT FROM NEW.environment_version
       OR OLD.approval_request_id IS DISTINCT FROM NEW.approval_request_id
       OR OLD.approval_subject_digest IS DISTINCT FROM NEW.approval_subject_digest
       OR OLD.artifact_digest IS DISTINCT FROM NEW.artifact_digest
       OR OLD.provenance_digest IS DISTINCT FROM NEW.provenance_digest
       OR OLD.purpose IS DISTINCT FROM NEW.purpose
       OR OLD.operation IS DISTINCT FROM NEW.operation
       OR OLD.signer_policy_id IS DISTINCT FROM NEW.signer_policy_id
       OR OLD.signer_policy_digest IS DISTINCT FROM NEW.signer_policy_digest
       OR OLD.signer_policy_version IS DISTINCT FROM NEW.signer_policy_version
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.reservation_json IS DISTINCT FROM NEW.reservation_json
       OR (OLD.result_json IS NOT NULL AND
           (OLD.result_json IS DISTINCT FROM NEW.result_json OR OLD.result_digest IS DISTINCT FROM NEW.result_digest))
       OR NOT ((OLD.state='reserved' AND NEW.state IN('signed','aborted'))
               OR (OLD.state='signed' AND NEW.state='complete'))
    THEN
        RAISE EXCEPTION 'signing result durable binding or transition changed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER signing_result_journal_guard
BEFORE UPDATE ON signing_result_journal
FOR EACH ROW EXECUTE FUNCTION protect_signing_result_journal();

CREATE TRIGGER signing_result_journal_no_delete
BEFORE DELETE ON signing_result_journal
FOR EACH ROW EXECUTE FUNCTION reject_deployment_history_mutation();

CREATE FUNCTION protect_deployment_result() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT (OLD.status='succeeded' AND NEW.status='rolled-back')
       OR (to_jsonb(OLD)-'status') IS DISTINCT FROM (to_jsonb(NEW)-'status')
    THEN
        RAISE EXCEPTION 'deployment result durable binding changed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deployments_result_guard
BEFORE UPDATE ON deployments
FOR EACH ROW EXECUTE FUNCTION protect_deployment_result();

CREATE TRIGGER deployments_no_delete
BEFORE DELETE ON deployments
FOR EACH ROW EXECUTE FUNCTION reject_deployment_history_mutation();
