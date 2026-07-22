//! Backend-neutral runtime phase measurements and reproducible benchmark
//! reports.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use thiserror::Error;

pub const RUNTIME_BENCHMARK_SCHEMA_VERSION: u32 = 1;

/// Portable execution phases shared by every runtime family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    RequestAdmission,
    QueueWait,
    Placement,
    LeaseDelivery,
    LeaseAcceptance,
    RuntimeAcquire,
    PackagePrepare,
    InvocationPrepare,
    Instantiate,
    GuestRun,
    OutputFinalize,
    Cleanup,
    CompletionPublish,
    EndToEnd,
}

/// Observed preparation state. This records what happened; it is not workload
/// authority and must never be used in place of runtime compatibility checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationState {
    NotObserved,
    ProcessColdCacheCold,
    ProcessColdCacheHit,
    ProcessWarmAotPrepared,
    ProcessWarmPackageHot,
    ProcessColdQuarantinedMiss,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseTiming {
    pub phase: RuntimePhase,
    /// Bounded backend-specific subdivision, such as `manifest_verify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub duration_ns: u64,
}

impl PhaseTiming {
    #[must_use]
    pub fn new(phase: RuntimePhase, detail: Option<String>, duration_ns: u64) -> Self {
        Self {
            phase,
            detail,
            duration_ns,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMeasurement {
    pub preparation_state: PreparationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<String>,
    pub phases: Vec<PhaseTiming>,
}

impl RuntimeMeasurement {
    pub fn validate(&self) -> Result<(), RuntimeMetricsError> {
        if self.phases.is_empty() {
            return Err(RuntimeMetricsError::EmptyMeasurement);
        }
        let mut names = BTreeSet::new();
        for timing in &self.phases {
            if let Some(detail) = &timing.detail {
                validate_label("phase detail", detail)?;
            }
            if !names.insert((timing.phase, timing.detail.clone())) {
                return Err(RuntimeMetricsError::DuplicatePhase);
            }
        }
        if let Some(status) = &self.cache_status {
            validate_label("cache status", status)?;
        }
        Ok(())
    }
}

/// Low-overhead monotonic recorder for one process-local operation.
pub struct PhaseRecorder {
    started: Instant,
    phases: Vec<PhaseTiming>,
}

impl Default for PhaseRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl PhaseRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            phases: Vec::new(),
        }
    }

    pub fn measure<T>(
        &mut self,
        phase: RuntimePhase,
        detail: Option<&str>,
        operation: impl FnOnce() -> T,
    ) -> T {
        let started = Instant::now();
        let result = operation();
        self.record_elapsed(phase, detail, started);
        result
    }

    pub fn record_elapsed(&mut self, phase: RuntimePhase, detail: Option<&str>, started: Instant) {
        self.phases.push(PhaseTiming::new(
            phase,
            detail.map(str::to_owned),
            duration_ns(started.elapsed()),
        ));
    }

    #[must_use]
    pub fn finish(
        mut self,
        preparation_state: PreparationState,
        cache_status: Option<String>,
    ) -> RuntimeMeasurement {
        self.phases.push(PhaseTiming::new(
            RuntimePhase::EndToEnd,
            Some("executor".to_owned()),
            duration_ns(self.started.elapsed()),
        ));
        RuntimeMeasurement {
            preparation_state,
            cache_status,
            phases: self.phases,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_time_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_read_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_write_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadTiming {
    pub intended_start_offset_ns: u64,
    pub actual_start_offset_ns: u64,
    pub completed_offset_ns: u64,
    pub queue_depth_at_submit: u64,
    pub active_workers: u32,
    pub active_executions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkSample {
    pub iteration: u32,
    pub measurement: RuntimeMeasurement,
    pub succeeded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
    #[serde(default)]
    pub resources: ResourceSample,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<LoadTiming>,
}

/// Intended request offsets for an open-loop test. A driver waits for these
/// offsets independently of prior completion so system slowdown is measured as
/// queueing instead of reducing the offered load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenLoopSchedule {
    pub rate_per_second: u32,
    pub duration_ms: u64,
    pub intended_start_offsets_ns: Vec<u64>,
}

impl OpenLoopSchedule {
    pub fn constant(rate_per_second: u32, duration_ms: u64) -> Result<Self, RuntimeMetricsError> {
        if rate_per_second == 0 || duration_ms == 0 {
            return Err(RuntimeMetricsError::InvalidSchedule);
        }
        let request_count =
            u128::from(rate_per_second).saturating_mul(u128::from(duration_ms)) / 1_000;
        let request_count =
            usize::try_from(request_count).map_err(|_| RuntimeMetricsError::TooManySamples)?;
        if request_count == 0 || request_count > 10_000_000 {
            return Err(RuntimeMetricsError::InvalidSchedule);
        }
        let interval_ns = 1_000_000_000_u64 / u64::from(rate_per_second);
        let intended_start_offsets_ns = (0..request_count)
            .map(|index| {
                u64::try_from(index)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(interval_ns)
            })
            .collect();
        Ok(Self {
            rate_per_second,
            duration_ms,
            intended_start_offsets_ns,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkEnvironment {
    pub harness_commit: String,
    pub fixture_digest: String,
    pub runtime_family: String,
    pub runtime_compatibility_digest: String,
    pub runtime_version: String,
    pub host_os: String,
    pub architecture: String,
    pub logical_cpus: u32,
    pub memory_bytes: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl BenchmarkEnvironment {
    pub fn validate(&self) -> Result<(), RuntimeMetricsError> {
        for (name, value) in [
            ("harness commit", self.harness_commit.as_str()),
            ("fixture digest", self.fixture_digest.as_str()),
            ("runtime family", self.runtime_family.as_str()),
            (
                "runtime compatibility digest",
                self.runtime_compatibility_digest.as_str(),
            ),
            ("runtime version", self.runtime_version.as_str()),
            ("host OS", self.host_os.as_str()),
            ("architecture", self.architecture.as_str()),
        ] {
            validate_label(name, value)?;
        }
        if self.logical_cpus == 0 || self.memory_bytes == 0 || self.attributes.len() > 64 {
            return Err(RuntimeMetricsError::InvalidEnvironment);
        }
        for (key, value) in &self.attributes {
            validate_label("environment attribute key", key)?;
            validate_label("environment attribute value", value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionSummary {
    pub count: u64,
    pub minimum_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub maximum_ns: u64,
    pub mean_ns: u64,
    pub standard_deviation_ns: u64,
}

impl DistributionSummary {
    fn from_values(values: &[u64]) -> Self {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let total = sorted
            .iter()
            .fold(0_u128, |sum, value| sum.saturating_add(u128::from(*value)));
        let count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
        let mean = total / u128::from(count);
        let variance = sorted.iter().fold(0_f64, |sum, value| {
            let delta = *value as f64 - mean as f64;
            sum + delta * delta
        }) / count as f64;
        Self {
            count,
            minimum_ns: sorted[0],
            p50_ns: percentile(&sorted, 50),
            p90_ns: percentile(&sorted, 90),
            p95_ns: percentile(&sorted, 95),
            p99_ns: percentile(&sorted, 99),
            maximum_ns: sorted[sorted.len() - 1],
            mean_ns: u64::try_from(mean).unwrap_or(u64::MAX),
            standard_deviation_ns: variance.sqrt().round() as u64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub suite_version: String,
    pub scenario: String,
    pub environment: BenchmarkEnvironment,
    pub samples: Vec<BenchmarkSample>,
    pub summary: BenchmarkSummary,
    /// Keys are `<phase>` or `<phase>:<detail>`.
    pub phase_summaries: BTreeMap<String, DistributionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkSummary {
    pub sample_count: u64,
    pub succeeded: u64,
    pub failed: u64,
    /// Thousandths of a completion per second when load timing is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_milli_per_second: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_queue_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_start_lag_ns: Option<u64>,
}

impl BenchmarkReport {
    pub fn from_samples(
        suite_version: impl Into<String>,
        scenario: impl Into<String>,
        environment: BenchmarkEnvironment,
        mut samples: Vec<BenchmarkSample>,
    ) -> Result<Self, RuntimeMetricsError> {
        let suite_version = suite_version.into();
        let scenario = scenario.into();
        validate_label("suite version", &suite_version)?;
        validate_label("scenario", &scenario)?;
        environment.validate()?;
        if samples.is_empty() {
            return Err(RuntimeMetricsError::EmptyReport);
        }
        samples.sort_by_key(|sample| sample.iteration);
        for (index, sample) in samples.iter().enumerate() {
            let expected =
                u32::try_from(index + 1).map_err(|_| RuntimeMetricsError::TooManySamples)?;
            if sample.iteration != expected {
                return Err(RuntimeMetricsError::NonContiguousIterations);
            }
            sample.measurement.validate()?;
            if let Some(code) = &sample.diagnostic_code {
                validate_label("diagnostic code", code)?;
            }
        }
        let mut values = BTreeMap::<String, Vec<u64>>::new();
        for sample in &samples {
            for timing in &sample.measurement.phases {
                values
                    .entry(phase_key(timing))
                    .or_default()
                    .push(timing.duration_ns);
            }
        }
        let phase_summaries = values
            .into_iter()
            .map(|(key, values)| (key, DistributionSummary::from_values(&values)))
            .collect();
        let sample_count = u64::try_from(samples.len()).unwrap_or(u64::MAX);
        let succeeded = u64::try_from(samples.iter().filter(|sample| sample.succeeded).count())
            .unwrap_or(u64::MAX);
        let load_samples = samples
            .iter()
            .filter_map(|sample| sample.load.as_ref())
            .collect::<Vec<_>>();
        let load_span = load_samples
            .iter()
            .map(|load| load.completed_offset_ns)
            .max();
        let throughput_milli_per_second = load_span.filter(|span| *span > 0).map(|span| {
            let completed = samples
                .iter()
                .filter(|sample| sample.succeeded && sample.load.is_some())
                .count();
            let scaled = u128::try_from(completed)
                .unwrap_or(u128::MAX)
                .saturating_mul(1_000_000_000_000);
            u64::try_from(scaled / u128::from(span)).unwrap_or(u64::MAX)
        });
        let maximum_queue_depth = load_samples
            .iter()
            .map(|load| load.queue_depth_at_submit)
            .max();
        let maximum_start_lag_ns = load_samples
            .iter()
            .map(|load| {
                load.actual_start_offset_ns
                    .saturating_sub(load.intended_start_offset_ns)
            })
            .max();
        let summary = BenchmarkSummary {
            sample_count,
            succeeded,
            failed: sample_count.saturating_sub(succeeded),
            throughput_milli_per_second,
            maximum_queue_depth,
            maximum_start_lag_ns,
        };
        Ok(Self {
            schema_version: RUNTIME_BENCHMARK_SCHEMA_VERSION,
            suite_version,
            scenario,
            environment,
            samples,
            summary,
            phase_summaries,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeMetricsError {
    #[error("runtime measurement contains no phase timings")]
    EmptyMeasurement,
    #[error("runtime measurement contains a duplicate phase/detail pair")]
    DuplicatePhase,
    #[error("benchmark report contains no samples")]
    EmptyReport,
    #[error("benchmark sample iterations are not contiguous and one-based")]
    NonContiguousIterations,
    #[error("benchmark report contains too many samples")]
    TooManySamples,
    #[error("benchmark environment is invalid")]
    InvalidEnvironment,
    #[error("open-loop schedule is invalid or outside its request bound")]
    InvalidSchedule,
    #[error("{0} is empty, too long, or contains a control character")]
    InvalidLabel(&'static str),
}

fn validate_label(name: &'static str, value: &str) -> Result<(), RuntimeMetricsError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(RuntimeMetricsError::InvalidLabel(name));
    }
    Ok(())
}

fn phase_key(timing: &PhaseTiming) -> String {
    let phase = match timing.phase {
        RuntimePhase::RequestAdmission => "request_admission",
        RuntimePhase::QueueWait => "queue_wait",
        RuntimePhase::Placement => "placement",
        RuntimePhase::LeaseDelivery => "lease_delivery",
        RuntimePhase::LeaseAcceptance => "lease_acceptance",
        RuntimePhase::RuntimeAcquire => "runtime_acquire",
        RuntimePhase::PackagePrepare => "package_prepare",
        RuntimePhase::InvocationPrepare => "invocation_prepare",
        RuntimePhase::Instantiate => "instantiate",
        RuntimePhase::GuestRun => "guest_run",
        RuntimePhase::OutputFinalize => "output_finalize",
        RuntimePhase::Cleanup => "cleanup",
        RuntimePhase::CompletionPublish => "completion_publish",
        RuntimePhase::EndToEnd => "end_to_end",
    };
    timing
        .detail
        .as_ref()
        .map_or_else(|| phase.to_owned(), |detail| format!("{phase}:{detail}"))
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len().saturating_sub(1))]
}

fn duration_ns(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> BenchmarkEnvironment {
        BenchmarkEnvironment {
            harness_commit: "abc123".to_owned(),
            fixture_digest: "sha256:fixture".to_owned(),
            runtime_family: "wasm".to_owned(),
            runtime_compatibility_digest: "sha256:runtime".to_owned(),
            runtime_version: "1".to_owned(),
            host_os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            logical_cpus: 2,
            memory_bytes: 1024,
            attributes: BTreeMap::new(),
        }
    }

    fn sample(iteration: u32, duration_ns: u64) -> BenchmarkSample {
        BenchmarkSample {
            iteration,
            measurement: RuntimeMeasurement {
                preparation_state: PreparationState::ProcessWarmPackageHot,
                cache_status: Some("memory_resident".to_owned()),
                phases: vec![PhaseTiming::new(RuntimePhase::GuestRun, None, duration_ns)],
            },
            succeeded: true,
            diagnostic_code: None,
            resources: ResourceSample::default(),
            load: None,
        }
    }

    #[test]
    fn report_sorts_samples_and_uses_nearest_rank_percentiles() {
        let report = BenchmarkReport::from_samples(
            "v1",
            "noop",
            environment(),
            vec![sample(4, 40), sample(1, 10), sample(3, 30), sample(2, 20)],
        )
        .unwrap();
        let summary = &report.phase_summaries["guest_run"];
        assert_eq!(summary.minimum_ns, 10);
        assert_eq!(summary.p50_ns, 20);
        assert_eq!(summary.p95_ns, 40);
        assert_eq!(summary.maximum_ns, 40);
        assert_eq!(report.samples[0].iteration, 1);
        assert_eq!(report.summary.succeeded, 4);
        assert_eq!(report.schema_version, RUNTIME_BENCHMARK_SCHEMA_VERSION);
    }

    #[test]
    fn open_loop_schedule_preserves_the_intended_arrival_rate() {
        let schedule = OpenLoopSchedule::constant(4, 1_000).unwrap();
        assert_eq!(
            schedule.intended_start_offsets_ns,
            vec![0, 250_000_000, 500_000_000, 750_000_000]
        );
    }

    #[test]
    fn load_summary_reports_throughput_queue_depth_and_start_lag() {
        let mut first = sample(1, 10);
        first.load = Some(LoadTiming {
            intended_start_offset_ns: 0,
            actual_start_offset_ns: 10,
            completed_offset_ns: 500_000_000,
            queue_depth_at_submit: 1,
            active_workers: 1,
            active_executions: 0,
        });
        let mut second = sample(2, 10);
        second.load = Some(LoadTiming {
            intended_start_offset_ns: 250_000_000,
            actual_start_offset_ns: 300_000_000,
            completed_offset_ns: 1_000_000_000,
            queue_depth_at_submit: 3,
            active_workers: 1,
            active_executions: 1,
        });
        let report =
            BenchmarkReport::from_samples("v1", "load", environment(), vec![first, second])
                .unwrap();
        assert_eq!(report.summary.throughput_milli_per_second, Some(2_000));
        assert_eq!(report.summary.maximum_queue_depth, Some(3));
        assert_eq!(report.summary.maximum_start_lag_ns, Some(50_000_000));
    }

    #[test]
    fn report_rejects_duplicate_phase_details() {
        let mut duplicate = sample(1, 10);
        duplicate
            .measurement
            .phases
            .push(PhaseTiming::new(RuntimePhase::GuestRun, None, 20));
        assert_eq!(
            BenchmarkReport::from_samples("v1", "noop", environment(), vec![duplicate]),
            Err(RuntimeMetricsError::DuplicatePhase)
        );
    }

    #[test]
    fn report_round_trips_without_unknown_fields() {
        let report =
            BenchmarkReport::from_samples("v1", "noop", environment(), vec![sample(1, 10)])
                .unwrap();
        let encoded = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<BenchmarkReport>(&encoded).unwrap(),
            report
        );
    }
}
