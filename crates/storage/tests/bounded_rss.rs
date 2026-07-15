#![cfg(target_os = "linux")]

use runtrue_storage::{CasLimits, FsCas, PathSnapshot};
use std::{
    fs,
    io::{self, Read},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD_ENV: &str = "RUNTRUE_BOUNDED_RSS_CHILD";
const ROOT_ENV: &str = "RUNTRUE_BOUNDED_RSS_ROOT";
const STREAM_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RSS_GROWTH_BYTES: u64 = 32 * 1024 * 1024;

struct GeneratedReader {
    remaining: u64,
}

impl Read for GeneratedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap();
        buffer[..count].fill(0xa5);
        self.remaining -= count as u64;
        Ok(count)
    }
}

struct InterruptedReader {
    emitted: bool,
}

impl Read for InterruptedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.emitted {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "simulated canceled transfer",
            ));
        }
        self.emitted = true;
        let count = buffer.len().min(4096);
        buffer[..count].fill(0x5a);
        Ok(count)
    }
}

fn resident_bytes(pid: u32) -> io::Result<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .ok_or_else(|| io::Error::other("VmRSS is missing from process status"))?;
    let kib = line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("VmRSS has no value"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    Ok(kib * 1024)
}

fn child_workload(root: &std::path::Path) {
    let cas = FsCas::open(
        root.join("cas"),
        CasLimits {
            max_blob_bytes: STREAM_BYTES,
            ..CasLimits::default()
        },
    )
    .unwrap();
    fs::write(root.join("ready"), b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.join("go").exists() {
        assert!(Instant::now() < deadline, "parent never released workload");
        thread::sleep(Duration::from_millis(5));
    }

    let record = cas
        .put_reader(GeneratedReader {
            remaining: STREAM_BYTES,
        })
        .unwrap();
    assert_eq!(record.size_bytes, STREAM_BYTES);
    let materialized = root.join("materialized");
    cas.materialize_path(
        &PathSnapshot::File {
            digest: record.digest.clone(),
            size_bytes: STREAM_BYTES,
            executable: false,
        },
        &materialized,
    )
    .unwrap();
    assert_eq!(fs::metadata(&materialized).unwrap().len(), STREAM_BYTES);
    let mut verified = cas.verified_reader(&record.digest, STREAM_BYTES).unwrap();
    assert_eq!(
        io::copy(&mut verified, &mut io::sink()).unwrap(),
        STREAM_BYTES
    );
}

#[test]
fn cas_large_stream_uses_bounded_resident_memory() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let root = std::env::var_os(ROOT_ENV).expect("child CAS root");
        child_workload(std::path::Path::new(&root));
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cas_large_stream_uses_bounded_resident_memory",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(ROOT_ENV, directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let pid = child.id();
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    while !directory.path().join("ready").exists() {
        assert!(
            Instant::now() < startup_deadline,
            "bounded-RSS child did not become ready"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "bounded-RSS child exited"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let baseline = resident_bytes(pid).unwrap();
    let mut peak = baseline;
    fs::write(directory.path().join("go"), b"go").unwrap();
    let workload_deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < workload_deadline,
            "bounded-RSS workload exceeded its time bound"
        );
        if let Ok(current) = resident_bytes(pid) {
            peak = peak.max(current);
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success(), "bounded-RSS child failed: {status}");
    let growth = peak.saturating_sub(baseline);
    assert!(
        growth <= MAX_RSS_GROWTH_BYTES,
        "streaming and materializing {STREAM_BYTES} bytes grew RSS by {growth} bytes (baseline {baseline}, peak {peak})"
    );
}

#[test]
fn interrupted_stream_removes_private_staging_without_publication() {
    let directory = tempfile::tempdir().unwrap();
    let cas = FsCas::open(directory.path().join("cas"), CasLimits::default()).unwrap();
    let result = cas.put_reader(InterruptedReader { emitted: false });
    assert!(
        result.is_err(),
        "interrupted input must not be acknowledged"
    );
    let staging = fs::read_dir(cas.root().join("tmp"))
        .unwrap()
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    assert!(
        staging.is_empty(),
        "cancellation/error must remove private staging state"
    );
    assert_eq!(
        fs::read_dir(cas.root().join("objects/sha256"))
            .unwrap()
            .count(),
        0,
        "partial bytes must never become an immutable object"
    );
}
