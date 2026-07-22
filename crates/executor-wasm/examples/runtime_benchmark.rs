use runtrue_attest::{ImageKind, ImageManifest, ImageSigningKey};
use runtrue_engine::{CancellationToken, PreparedAction, StepExecutionRequest};
use runtrue_executor_wasm::{
    AotAuthenticationKey, AotCacheConfig, CapabilityAdapters, HandleAuthenticationKey,
    WasmComponentArtifact, WasmExecutor, WasmExecutorConfig, WasmLimits, WasmTarget,
    COMPONENT_MEDIA_TYPE, WASI_VERSION, WASMTIME_VERSION, WIT_SOURCE, WIT_WORLD,
};
use runtrue_model::ContentDigest;
use runtrue_runtime_metrics::{
    BenchmarkEnvironment, BenchmarkReport, BenchmarkSample, PhaseTiming, PreparationState,
    ResourceSample, RuntimePhase,
};
use runtrue_workflow_ir::{Isolation, RunnerRequirements, StepCapabilitySet};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    time::Instant,
};

const SUITE_VERSION: &str = "wasm-executor-v1";

#[derive(Clone, Copy)]
enum Scenario {
    Cold,
    Aot,
    Warmish,
    Hot,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, IoError> {
        match value {
            "cold" => Ok(Self::Cold),
            "aot" => Ok(Self::Aot),
            "warmish" => Ok(Self::Warmish),
            "hot" => Ok(Self::Hot),
            _ => Err(invalid_input(
                "--state must be one of: cold, aot, warmish, hot",
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Cold => "process-cold-cache-cold",
            Self::Aot => "process-cold-cache-hit",
            Self::Warmish => "process-warm-aot-prepared",
            Self::Hot => "process-warm-package-hot",
        }
    }

    const fn expected(self) -> PreparationState {
        match self {
            Self::Cold => PreparationState::ProcessColdCacheCold,
            Self::Aot => PreparationState::ProcessColdCacheHit,
            Self::Warmish => PreparationState::ProcessWarmAotPrepared,
            Self::Hot => PreparationState::ProcessWarmPackageHot,
        }
    }
}

struct Arguments {
    scenario: Scenario,
    iterations: u32,
    warmup_iterations: u32,
    output: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments()?;
    let bytes = noop_component()?;
    let samples = run_scenario(&arguments, &bytes)?;
    let target = WasmTarget::host_baseline()?;
    let compatibility = expected_compatibility(&target);
    let report = BenchmarkReport::from_samples(
        SUITE_VERSION,
        arguments.scenario.name(),
        BenchmarkEnvironment {
            harness_commit: option_env!("RUNTRUE_HARNESS_COMMIT")
                .unwrap_or("working-tree")
                .to_owned(),
            fixture_digest: ContentDigest::sha256(&bytes).to_string(),
            runtime_family: "wasm".to_owned(),
            runtime_compatibility_digest: ContentDigest::sha256(serde_json::to_vec(
                &compatibility,
            )?)
            .to_string(),
            runtime_version: WASMTIME_VERSION.to_owned(),
            host_os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            logical_cpus: std::thread::available_parallelism()
                .map_or(1, |count| u32::try_from(count.get()).unwrap_or(u32::MAX)),
            memory_bytes: host_memory_bytes().unwrap_or(1),
            attributes: BTreeMap::from([
                ("profile".to_owned(), "release".to_owned()),
                ("fixture".to_owned(), "noop-component".to_owned()),
            ]),
        },
        samples,
    )?;
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(path) = arguments.output {
        fs::write(path, encoded)?;
    } else {
        println!("{}", String::from_utf8(encoded)?);
    }
    Ok(())
}

fn parse_arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut scenario = Scenario::Hot;
    let mut iterations = 100_u32;
    let mut warmup_iterations = 10_u32;
    let mut output = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--state" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| invalid_input("--state requires a value"))?;
                scenario = Scenario::parse(&value)?;
            }
            "--iterations" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| invalid_input("--iterations requires a value"))?;
                iterations = value.parse()?;
            }
            "--warmup" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| invalid_input("--warmup requires a value"))?;
                warmup_iterations = value.parse()?;
            }
            "--output" => {
                output = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| invalid_input("--output requires a value"))?,
                ));
            }
            _ => return Err(invalid_input(format!("unknown argument `{argument}`")).into()),
        }
    }
    if iterations == 0 || iterations > 100_000 || warmup_iterations > 10_000 {
        return Err(invalid_input("iteration counts are outside the allowed bounds").into());
    }
    Ok(Arguments {
        scenario,
        iterations,
        warmup_iterations,
        output,
    })
}

fn run_scenario(
    arguments: &Arguments,
    bytes: &[u8],
) -> Result<Vec<BenchmarkSample>, Box<dyn Error>> {
    match arguments.scenario {
        Scenario::Hot => run_hot(arguments, bytes),
        Scenario::Warmish => run_warmish(arguments, bytes),
        Scenario::Cold | Scenario::Aot => {
            for _ in 0..arguments.warmup_iterations {
                let _ = run_isolated(arguments.scenario, bytes, 1)?;
            }
            (1..=arguments.iterations)
                .map(|iteration| run_isolated(arguments.scenario, bytes, iteration))
                .collect()
        }
    }
}

fn run_warmish(
    arguments: &Arguments,
    bytes: &[u8],
) -> Result<Vec<BenchmarkSample>, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let eviction = eviction_component()?;
    let executor = create_executor_with_components(
        &temporary.path().join("cache"),
        &[bytes, &eviction],
        Some(runtrue_executor_wasm::WasmPackageCacheConfig {
            max_warm_components: 1,
            max_warmish_entries: 2,
            max_warmish_bytes: 16 * 1024 * 1024,
        }),
    )?;
    let target_request = request(bytes)?;
    let eviction_request = request(&eviction)?;
    executor.execute_request(&target_request)?;
    for _ in 0..arguments.warmup_iterations {
        executor.execute_request(&eviction_request)?;
        executor.execute_request(&target_request)?;
    }
    (1..=arguments.iterations)
        .map(|iteration| {
            executor.execute_request(&eviction_request)?;
            let started = Instant::now();
            let mut output = executor.execute_request(&target_request)?;
            output.measurement.phases.push(PhaseTiming::new(
                RuntimePhase::EndToEnd,
                Some("harness".to_owned()),
                duration_ns(started),
            ));
            sample(iteration, arguments.scenario, output)
        })
        .collect()
}

fn run_hot(arguments: &Arguments, bytes: &[u8]) -> Result<Vec<BenchmarkSample>, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let executor = create_executor(&temporary.path().join("cache"), bytes)?;
    let request = request(bytes)?;
    executor.execute_request(&request)?;
    for _ in 0..arguments.warmup_iterations {
        executor.execute_request(&request)?;
    }
    (1..=arguments.iterations)
        .map(|iteration| {
            let started = Instant::now();
            let mut output = executor.execute_request(&request)?;
            output.measurement.phases.push(PhaseTiming::new(
                RuntimePhase::EndToEnd,
                Some("harness".to_owned()),
                duration_ns(started),
            ));
            sample(iteration, arguments.scenario, output)
        })
        .collect()
}

fn run_isolated(
    scenario: Scenario,
    bytes: &[u8],
    iteration: u32,
) -> Result<BenchmarkSample, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = temporary.path().join("cache");
    let request = request(bytes)?;
    if matches!(scenario, Scenario::Aot) {
        let seed = create_executor(&cache, bytes)?;
        seed.execute_request(&request)?;
        drop(seed);
    }
    let total_started = Instant::now();
    let construct_started = Instant::now();
    let executor = create_executor(&cache, bytes)?;
    let construct_ns = duration_ns(construct_started);
    let mut output = executor.execute_request(&request)?;
    output.measurement.phases.push(PhaseTiming::new(
        RuntimePhase::RuntimeAcquire,
        Some("executor_construct".to_owned()),
        construct_ns,
    ));
    output.measurement.phases.push(PhaseTiming::new(
        RuntimePhase::EndToEnd,
        Some("harness".to_owned()),
        duration_ns(total_started),
    ));
    sample(iteration, scenario, output)
}

fn sample(
    iteration: u32,
    scenario: Scenario,
    output: runtrue_executor_wasm::WasmExecutionOutput,
) -> Result<BenchmarkSample, Box<dyn Error>> {
    if output.measurement.preparation_state != scenario.expected() {
        return Err(invalid_input(format!(
            "expected preparation state {:?}, observed {:?}",
            scenario.expected(),
            output.measurement.preparation_state
        ))
        .into());
    }
    let succeeded = output.executor.succeeded();
    Ok(BenchmarkSample {
        iteration,
        measurement: output.measurement,
        succeeded,
        diagnostic_code: (!succeeded).then_some("execution_failed".to_owned()),
        resources: ResourceSample::default(),
        load: None,
    })
}

fn create_executor(cache: &Path, bytes: &[u8]) -> Result<WasmExecutor, Box<dyn Error>> {
    create_executor_with_components(cache, &[bytes], None)
}

fn create_executor_with_components(
    cache: &Path,
    components: &[&[u8]],
    package_cache: Option<runtrue_executor_wasm::WasmPackageCacheConfig>,
) -> Result<WasmExecutor, Box<dyn Error>> {
    let mut config = WasmExecutorConfig::new(
        WasmTarget::host_baseline()?,
        AotCacheConfig::new(cache, AotAuthenticationKey::new([7; 32])),
        HandleAuthenticationKey::new([8; 32]),
    );
    config.limits = WasmLimits::default();
    if let Some(package_cache) = package_cache {
        config.package_cache = package_cache;
    }
    for bytes in components {
        config.register_component(signed_artifact(bytes)?)?;
    }
    Ok(WasmExecutor::new(config, CapabilityAdapters::new())?)
}

fn signed_artifact(bytes: &[u8]) -> Result<WasmComponentArtifact, Box<dyn Error>> {
    let target = WasmTarget::host_baseline()?;
    let digest = ContentDigest::sha256(bytes);
    let reference = format!("wasm://registry.example/runtrue/benchmark@{digest}");
    let signing = ImageSigningKey::from_seed([41; 32]);
    let manifest = ImageManifest {
        manifest_version: 1,
        kind: ImageKind::WasmComponent,
        name: "runtrue-runtime-benchmark".to_owned(),
        payload_digest: digest,
        payload_size_bytes: u64::try_from(bytes.len())?,
        payload_media_type: COMPONENT_MEDIA_TYPE.to_owned(),
        operating_system: "wasm".to_owned(),
        architecture: manifest_architecture(&target).to_owned(),
        builder_id: "runtrue-runtime-benchmark-v1".to_owned(),
        build_provenance_digest: ContentDigest::sha256(b"benchmark-provenance-v1"),
        sbom_digest: ContentDigest::sha256(b"benchmark-sbom-v1"),
        created_unix_ms: 1,
        expires_unix_ms: None,
        snapshot_phase: None,
        components: BTreeMap::from([("wit".to_owned(), ContentDigest::sha256(WIT_SOURCE))]),
        compatibility: expected_compatibility(&target),
    };
    let signed = signing.sign_manifest(&manifest)?;
    Ok(WasmComponentArtifact::new(
        reference,
        bytes.to_vec(),
        signed,
        signing.verifying_key(),
    )?)
}

fn request(bytes: &[u8]) -> Result<StepExecutionRequest, Box<dyn Error>> {
    let target = WasmTarget::host_baseline()?;
    Ok(StepExecutionRequest {
        job_id: "benchmark-job".to_owned(),
        step_id: "benchmark-step".to_owned(),
        job_attempt: 1,
        runner: RunnerRequirements {
            os: target.operating_system(),
            arch: target.architecture(),
            isolation: Isolation::Wasm,
            image: None,
            cpu: 1,
            memory_bytes: 64 * 1024 * 1024,
            storage_bytes: None,
            region: None,
            capabilities: Vec::new(),
        },
        action: PreparedAction::Component {
            reference: format!(
                "wasm://registry.example/runtrue/benchmark@{}",
                ContentDigest::sha256(bytes)
            ),
            inputs: BTreeMap::new(),
        },
        environment: BTreeMap::new(),
        working_directory: None,
        capabilities: StepCapabilitySet::default(),
        timeout_ms: Some(60_000),
        cancellation: CancellationToken::default(),
    })
}

fn noop_component() -> Result<Vec<u8>, wat::Error> {
    wat::parse_str(
        r#"(component
                (core module $m
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    )
}

fn eviction_component() -> Result<Vec<u8>, wat::Error> {
    wat::parse_str(
        r#"(component
                (core module $m
                    (func (export "run") i32.const 1 drop))
                (core instance $i (instantiate $m))
                (func (export "run") (canon lift (core func $i "run"))))"#,
    )
}

fn expected_compatibility(target: &WasmTarget) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "cpu_feature_floor".to_owned(),
            target.cpu_feature_floor().to_owned(),
        ),
        (
            "target_triple".to_owned(),
            target.target_triple().to_owned(),
        ),
        ("wasi_version".to_owned(), WASI_VERSION.to_owned()),
        ("wasmtime_version".to_owned(), WASMTIME_VERSION.to_owned()),
        ("wit_world".to_owned(), WIT_WORLD.to_owned()),
    ])
}

fn manifest_architecture(target: &WasmTarget) -> &'static str {
    match target.architecture() {
        runtrue_workflow_ir::Architecture::Amd64 => "amd64",
        runtrue_workflow_ir::Architecture::Arm64 => "arm64",
    }
}

fn duration_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn host_memory_bytes() -> Option<u64> {
    let memory = fs::read_to_string("/proc/meminfo").ok()?;
    let kibibytes = memory
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

fn invalid_input(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message.into())
}
