use runtrue_reports::{ingest, ReportFormat, ReportLimits};
use std::io::{self, Read as _, Write as _};

const MAX_CONFIGURABLE_INPUT_BYTES: usize = 256 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("runtrue-report: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let format = arguments.next().ok_or_else(usage)?.parse::<CliFormat>()?.0;
    let mut limits = ReportLimits::default();
    while let Some(argument) = arguments.next() {
        if argument != "--max-bytes" {
            return Err(usage());
        }
        let value = arguments.next().ok_or_else(usage)?;
        limits.max_input_bytes = value
            .parse::<usize>()
            .map_err(|_| "--max-bytes must be a positive integer".to_owned())?;
        if limits.max_input_bytes == 0 || limits.max_input_bytes > MAX_CONFIGURABLE_INPUT_BYTES {
            return Err(format!(
                "--max-bytes must be between 1 and {MAX_CONFIGURABLE_INPUT_BYTES}"
            ));
        }
    }

    let read_limit = limits
        .max_input_bytes
        .checked_add(1)
        .ok_or_else(|| "input limit is too large".to_owned())?;
    let mut input = Vec::with_capacity(read_limit.min(1024 * 1024));
    io::stdin()
        .lock()
        .take(read_limit as u64)
        .read_to_end(&mut input)
        .map_err(|_| "failed to read report from standard input".to_owned())?;
    if input.len() > limits.max_input_bytes {
        return Err("report exceeds the configured byte limit".to_owned());
    }

    let report = ingest(format, &input, limits).map_err(|error| error.to_string())?;
    let output = report
        .canonical_bytes()
        .map_err(|error| error.to_string())?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&output)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| "failed to write normalized report".to_owned())
}

fn usage() -> String {
    "usage: runtrue-report <junit|sarif|coverage|custom> [--max-bytes N] < report".to_owned()
}

struct CliFormat(ReportFormat);

impl std::str::FromStr for CliFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let format = match value {
            "junit" => ReportFormat::JunitXml,
            "sarif" => ReportFormat::Sarif,
            "coverage" => ReportFormat::CoverageSummary,
            "custom" => ReportFormat::CustomEvents,
            _ => return Err(usage()),
        };
        Ok(Self(format))
    }
}
