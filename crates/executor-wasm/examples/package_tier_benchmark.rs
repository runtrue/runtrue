//! Compare package-specific cold, warmish, and warm Wasm startup states.

use hmac::{Hmac, Mac as _};
use serde::Serialize;
use sha2::Sha256;
use std::{
    error::Error,
    fs,
    hint::black_box,
    io::{Error as IoError, ErrorKind},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use wasmtime::{
    component::{Component, Linker},
    Config, Engine, OptLevel, Store,
};

const AUTHENTICATION_DOMAIN: &[u8] = b"runtrue.package-tier-benchmark.v1\0";
const AUTHENTICATION_KEY: &[u8] = b"benchmark-only-authentication-key";
const DEFAULT_MEMORY_BUDGETS: [u64; 2] = [256 * 1024 * 1024, 1024 * 1024 * 1024];

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
struct Fixture {
    name: &'static str,
    functions: usize,
    operations_per_function: usize,
    iterations: usize,
}

const FIXTURES: [Fixture; 3] = [
    Fixture {
        name: "tiny",
        functions: 1,
        operations_per_function: 2,
        iterations: 50,
    },
    Fixture {
        name: "medium",
        functions: 300,
        operations_per_function: 20,
        iterations: 30,
    },
    Fixture {
        name: "large",
        functions: 1_500,
        operations_per_function: 30,
        iterations: 20,
    },
];

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    runtime: &'static str,
    runtime_version: &'static str,
    target: &'static str,
    profile: &'static str,
    authentication: &'static str,
    warm_definition: &'static str,
    placement_objective: &'static str,
    fixtures: Vec<FixtureReport>,
}

#[derive(Serialize)]
struct FixtureReport {
    fixture: &'static str,
    source_bytes: usize,
    aot_bytes: usize,
    aot_to_source_ratio: f64,
    admission_authentication: TimingSummary,
    states: Vec<StateReport>,
    placement_thresholds: PlacementThresholds,
    warmish_capacity: Vec<CapacityReport>,
}

#[derive(Serialize)]
struct StateReport {
    state: &'static str,
    retained: &'static str,
    iterations: usize,
    startup: TimingSummary,
}

#[derive(Serialize)]
struct CapacityReport {
    memory_budget_bytes: u64,
    exact_aot_entries: u64,
}

#[derive(Serialize)]
struct PlacementThresholds {
    idle_warmish_beats_warm_after_extra_warm_queue_ns: u64,
    idle_cold_beats_warmish_after_extra_warmish_queue_ns: u64,
}

#[derive(Serialize)]
struct TimingSummary {
    p50_ns: u64,
    p95_ns: u64,
    min_ns: u64,
    max_ns: u64,
}

struct AuthenticatedAot {
    /// The allocation is immutable after admission. Keeping this as an
    /// `Arc<[u8]>` prevents callers from mutating bytes after authentication.
    bytes: Arc<[u8]>,
}

impl AuthenticatedAot {
    fn admit(bytes: Vec<u8>, tag: &[u8]) -> Result<Self, Box<dyn Error>> {
        authenticate(&bytes, tag)?;
        Ok(Self {
            bytes: bytes.into(),
        })
    }

    #[allow(unsafe_code)]
    fn deserialize(&self, engine: &Engine) -> wasmtime::Result<Component> {
        // SAFETY: the immutable bytes were emitted by this exact pinned
        // Wasmtime configuration, authenticated before admission, and cannot
        // be modified through this type. Production use would additionally
        // bind the authentication metadata to the engine compatibility key.
        unsafe { Component::deserialize(engine, &self.bytes) }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let output = parse_output_argument()?;
    let engine = exact_engine()?;
    let linker = Linker::<()>::new(&engine);
    let fixtures = FIXTURES
        .into_iter()
        .map(|fixture| benchmark_fixture(&engine, &linker, fixture))
        .collect::<Result<Vec<_>, _>>()?;
    let report = Report {
        schema_version: 1,
        runtime: "wasm",
        runtime_version: "46.0.1",
        target: host_target(),
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        authentication: "hmac-sha256-on-admission",
        warm_definition: "resident-component; instances-are-created-per-invocation",
        placement_objective: "minimum(queue_delay_ns + package_state_p95_startup_ns)",
        fixtures,
    };
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = output {
        fs::write(output, encoded)?;
    } else {
        println!("{}", String::from_utf8(encoded)?);
    }
    Ok(())
}

fn benchmark_fixture(
    engine: &Engine,
    linker: &Linker<()>,
    fixture: Fixture,
) -> Result<FixtureReport, Box<dyn Error>> {
    let source = wat::parse_str(component_wat(fixture))?;
    let aot = engine.precompile_component(&source)?;
    let tag = authentication_tag(&aot)?;
    let authenticated = AuthenticatedAot::admit(aot.clone(), &tag)?;
    let warm = Component::from_binary(engine, &source)?;

    // Fault the common execution path before collecting samples.
    invoke(engine, linker, &warm)?;
    invoke(engine, linker, &authenticated.deserialize(engine)?)?;

    let authentication_times = measure(fixture.iterations, || authenticate(&aot, &tag))?;
    let cold_times = measure(fixture.iterations, || {
        let component = Component::from_binary(engine, black_box(&source))?;
        Ok(invoke(engine, linker, &component)?)
    })?;
    let warmish_times = measure(fixture.iterations, || {
        let component = authenticated.deserialize(engine)?;
        Ok(invoke(engine, linker, &component)?)
    })?;
    let warm_times = measure(fixture.iterations, || Ok(invoke(engine, linker, &warm)?))?;
    let cold = summarize(cold_times);
    let warmish = summarize(warmish_times);
    let warm = summarize(warm_times);
    let placement_thresholds = PlacementThresholds {
        idle_warmish_beats_warm_after_extra_warm_queue_ns: warmish
            .p95_ns
            .saturating_sub(warm.p95_ns),
        idle_cold_beats_warmish_after_extra_warmish_queue_ns: cold
            .p95_ns
            .saturating_sub(warmish.p95_ns),
    };

    Ok(FixtureReport {
        fixture: fixture.name,
        source_bytes: source.len(),
        aot_bytes: aot.len(),
        aot_to_source_ratio: aot.len() as f64 / source.len() as f64,
        admission_authentication: summarize(authentication_times),
        states: vec![
            StateReport {
                state: "cold",
                retained: "source",
                iterations: fixture.iterations,
                startup: cold,
            },
            StateReport {
                state: "warmish",
                retained: "authenticated-immutable-aot-memory",
                iterations: fixture.iterations,
                startup: warmish,
            },
            StateReport {
                state: "warm",
                retained: "resident-component",
                iterations: fixture.iterations,
                startup: warm,
            },
        ],
        placement_thresholds,
        warmish_capacity: DEFAULT_MEMORY_BUDGETS
            .into_iter()
            .map(|memory_budget_bytes| CapacityReport {
                memory_budget_bytes,
                exact_aot_entries: memory_budget_bytes
                    / u64::try_from(aot.len()).unwrap_or(u64::MAX),
            })
            .collect(),
    })
}

fn invoke(engine: &Engine, linker: &Linker<()>, component: &Component) -> wasmtime::Result<()> {
    let mut store = Store::new(engine, ());
    store.set_fuel(100_000_000)?;
    store.set_epoch_deadline(1);
    let instance = linker.instantiate(&mut store, component)?;
    let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    run.call(&mut store, ())?;
    Ok(())
}

fn exact_engine() -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .wasm_component_model_async(true)
        .consume_fuel(true)
        .epoch_interruption(true)
        .max_wasm_stack(2 * 1024 * 1024)
        .wasm_relaxed_simd(false)
        .wasm_simd(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .cranelift_opt_level(OptLevel::SpeedAndSize)
        .cranelift_nan_canonicalization(true);
    config.target(host_target())?;
    Engine::new(&config)
}

fn measure<T>(
    iterations: usize,
    mut operation: impl FnMut() -> Result<T, Box<dyn Error>>,
) -> Result<Vec<Duration>, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        black_box(operation()?);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    Ok(samples)
}

fn summarize(samples: Vec<Duration>) -> TimingSummary {
    TimingSummary {
        p50_ns: duration_ns(percentile(&samples, 50)),
        p95_ns: duration_ns(percentile(&samples, 95)),
        min_ns: duration_ns(samples[0]),
        max_ns: duration_ns(samples[samples.len() - 1]),
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = ((samples.len() * percentile).div_ceil(100)).saturating_sub(1);
    samples[index]
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn authentication_tag(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut mac = HmacSha256::new_from_slice(AUTHENTICATION_KEY)?;
    mac.update(AUTHENTICATION_DOMAIN);
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn authenticate(bytes: &[u8], expected: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut mac = HmacSha256::new_from_slice(AUTHENTICATION_KEY)?;
    mac.update(AUTHENTICATION_DOMAIN);
    mac.update(bytes);
    mac.verify_slice(expected)?;
    Ok(())
}

fn parse_output_argument() -> Result<Option<PathBuf>, IoError> {
    let mut output = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument != "--output" || output.is_some() {
            return Err(invalid_input(
                "usage: package_tier_benchmark [--output PATH]",
            ));
        }
        output = Some(PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| invalid_input("--output requires a path"))?,
        ));
    }
    Ok(output)
}

fn invalid_input(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message.into())
}

fn component_wat(fixture: Fixture) -> String {
    let mut wat = String::from("(component (core module $m ");
    for function in 0..fixture.functions {
        wat.push_str(&format!(
            "(func $f{function} (param i64) (result i64) local.get 0 "
        ));
        for operation in 0..fixture.operations_per_function {
            wat.push_str(&format!("i64.const {} i64.add ", operation + 1));
        }
        wat.push_str(") ");
    }
    wat.push_str(&format!(
        "(func (export \"run\") i64.const 1 call $f{} drop)) \
         (core instance $i (instantiate $m)) \
         (func (export \"run\") (canon lift (core func $i \"run\"))))",
        fixture.functions - 1,
    ));
    wat
}

fn host_target() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    {
        "x86_64-unknown-linux-musl"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "musl"))]
    {
        "aarch64-unknown-linux-musl"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_rejects_modified_aot() {
        let tag = authentication_tag(b"original").unwrap();
        assert!(AuthenticatedAot::admit(b"modified".to_vec(), &tag).is_err());
    }

    #[test]
    fn admitted_aot_deserializes_with_exact_engine() {
        let engine = exact_engine().unwrap();
        let source = wat::parse_str(component_wat(FIXTURES[0])).unwrap();
        let bytes = engine.precompile_component(&source).unwrap();
        let tag = authentication_tag(&bytes).unwrap();
        let admitted = AuthenticatedAot::admit(bytes, &tag).unwrap();
        let component = admitted.deserialize(&engine).unwrap();
        invoke(&engine, &Linker::new(&engine), &component).unwrap();
    }
}
