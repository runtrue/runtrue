use crate::GitError;
use serde::{Deserialize, Serialize};

/// Reproducible benchmark inputs. Values describe the fixture; they are never
/// presented as measurements by the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorBenchmarkInput {
    pub report_version: u32,
    pub fixture_name: String,
    pub iterations: u32,
    pub warmup_iterations: u32,
    pub repository_bytes: u64,
    pub ref_count: u64,
    pub object_count: u64,
    pub source_commit: String,
    pub base_commit: Option<String>,
}

impl MirrorBenchmarkInput {
    fn validate(&self) -> Result<(), GitError> {
        if self.report_version != 1
            || self.fixture_name.is_empty()
            || self.fixture_name.len() > 256
            || self
                .fixture_name
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || self.iterations == 0
            || self.iterations > 100_000
            || self.repository_bytes == 0
            || self.ref_count == 0
            || self.object_count == 0
        {
            return Err(GitError::InvalidConfiguration);
        }
        super::validate_object_id(&self.source_commit)?;
        if let Some(base) = &self.base_commit {
            super::validate_object_id(base)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorBenchmarkSample {
    pub iteration: u32,
    pub cold_fetch_millis: u64,
    pub warm_fetch_millis: u64,
    pub hydration_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorBenchmarkReport {
    pub input: MirrorBenchmarkInput,
    pub samples: Vec<MirrorBenchmarkSample>,
    pub cold_fetch_p50_millis: u64,
    pub cold_fetch_p95_millis: u64,
    pub warm_fetch_p50_millis: u64,
    pub warm_fetch_p95_millis: u64,
    pub hydration_p50_millis: u64,
    pub hydration_p95_millis: u64,
}

impl MirrorBenchmarkReport {
    pub fn from_samples(
        input: MirrorBenchmarkInput,
        mut samples: Vec<MirrorBenchmarkSample>,
    ) -> Result<Self, GitError> {
        input.validate()?;
        if samples.len() != usize::try_from(input.iterations).unwrap_or(usize::MAX) {
            return Err(GitError::InvalidConfiguration);
        }
        samples.sort_by_key(|sample| sample.iteration);
        if samples
            .iter()
            .enumerate()
            .any(|(index, sample)| sample.iteration != u32::try_from(index + 1).unwrap_or(u32::MAX))
        {
            return Err(GitError::InvalidConfiguration);
        }
        let cold = samples
            .iter()
            .map(|sample| sample.cold_fetch_millis)
            .collect::<Vec<_>>();
        let warm = samples
            .iter()
            .map(|sample| sample.warm_fetch_millis)
            .collect::<Vec<_>>();
        let hydration = samples
            .iter()
            .map(|sample| sample.hydration_millis)
            .collect::<Vec<_>>();
        Ok(Self {
            input,
            cold_fetch_p50_millis: percentile(&cold, 50),
            cold_fetch_p95_millis: percentile(&cold, 95),
            warm_fetch_p50_millis: percentile(&warm, 50),
            warm_fetch_p95_millis: percentile(&warm, 95),
            hydration_p50_millis: percentile(&hydration, 50),
            hydration_p95_millis: percentile(&hydration, 95),
            samples,
        })
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len().saturating_sub(1))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_uses_nearest_rank_without_claiming_fixture_numbers() {
        let input = MirrorBenchmarkInput {
            report_version: 1,
            fixture_name: "synthetic".to_owned(),
            iterations: 4,
            warmup_iterations: 1,
            repository_bytes: 1,
            ref_count: 1,
            object_count: 1,
            source_commit: "a".repeat(40),
            base_commit: None,
        };
        let report = MirrorBenchmarkReport::from_samples(
            input,
            vec![
                MirrorBenchmarkSample {
                    iteration: 4,
                    cold_fetch_millis: 40,
                    warm_fetch_millis: 4,
                    hydration_millis: 8,
                },
                MirrorBenchmarkSample {
                    iteration: 1,
                    cold_fetch_millis: 10,
                    warm_fetch_millis: 1,
                    hydration_millis: 5,
                },
                MirrorBenchmarkSample {
                    iteration: 2,
                    cold_fetch_millis: 20,
                    warm_fetch_millis: 2,
                    hydration_millis: 6,
                },
                MirrorBenchmarkSample {
                    iteration: 3,
                    cold_fetch_millis: 30,
                    warm_fetch_millis: 3,
                    hydration_millis: 7,
                },
            ],
        )
        .unwrap();
        assert_eq!(report.cold_fetch_p50_millis, 20);
        assert_eq!(report.cold_fetch_p95_millis, 40);
        assert_eq!(report.samples[0].iteration, 1);
    }
}
