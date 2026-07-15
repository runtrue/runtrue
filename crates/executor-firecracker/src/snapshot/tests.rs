use super::*;
use crate::{FirecrackerError, JobStatePaths, SnapshotStatePaths};
use runtrue_model::ContentDigest;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};
use tempfile::TempDir;

fn paths(directory: &TempDir, snapshot: bool) -> JobStatePaths {
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("run")).unwrap();
    JobStatePaths {
        directory: root.clone(),
        kernel: root.join("kernel"),
        rootfs: root.join("rootfs.ext4"),
        guest: root.join("runtrue-guest"),
        snapshot: snapshot.then(|| SnapshotStatePaths {
            state: root.join("snapshot.vmstate"),
            memory: root.join("snapshot.memory"),
            state_digest: ContentDigest::sha256(b"state"),
            state_size_bytes: 5,
            memory_digest: ContentDigest::sha256(b"memory"),
            memory_size_bytes: 6,
            compatibility: crate::SnapshotRuntimeCompatibility::new(
                crate::SnapshotRuntimeRequirements {
                    firecracker_version: "1.12.0".to_owned(),
                    firecracker_binary_digest: ContentDigest::sha256(b"firecracker"),
                    firecracker_binary_size_bytes: 11,
                    snapshot_format_version: "1.8.0".to_owned(),
                    cpu_template: "T2A".to_owned(),
                    cpu_feature_digest: ContentDigest::sha256(b"cpu"),
                    mitigation_profile_digest: ContentDigest::sha256(b"mitigations"),
                    vcpu_count: 2,
                    memory_bytes: 256 * 1024 * 1024,
                    guest_cid: 42,
                },
            )
            .unwrap(),
        }),
        boot_config: root.join("boot-config.img"),
        firecracker_config: root.join("firecracker.json"),
        api_socket: root.join("run/firecracker-api.sock"),
        vsock_socket: root.join("run/vsock.sock"),
        log_fifo: root.join("run/firecracker.log"),
        metrics_fifo: root.join("run/firecracker.metrics"),
    }
}

fn write_snapshot_files(paths: &JobStatePaths) {
    use std::os::unix::fs::PermissionsExt as _;
    let snapshot = paths.snapshot.as_ref().unwrap();
    fs::write(&snapshot.state, b"state").unwrap();
    fs::write(&snapshot.memory, b"memory").unwrap();
    fs::set_permissions(&snapshot.state, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&snapshot.memory, fs::Permissions::from_mode(0o400)).unwrap();
}

#[test]
fn launch_capsule_selects_exact_cold_config_or_snapshot_api() {
    let directory = TempDir::new().unwrap();
    let cold =
        FirecrackerLaunchPlan::build(&paths(&directory, false), 2, 256 * 1024 * 1024, 42, None)
            .unwrap();
    let cold_json = serde_json::to_value(cold.cold_config().unwrap()).unwrap();
    assert_eq!(cold_json["boot-source"]["kernel_image_path"], "/kernel");
    assert_eq!(cold_json["machine-config"]["vcpu_count"], 2);
    assert!(cold.snapshot_request().is_none());

    let snapshot =
        FirecrackerLaunchPlan::build(&paths(&directory, true), 2, 256 * 1024 * 1024, 42, None)
            .unwrap();
    let request = snapshot.snapshot_request().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&request.json_bytes().unwrap()).unwrap();
    assert_eq!(json["snapshot_path"], IN_JAIL_SNAPSHOT_STATE);
    assert_eq!(json["mem_backend"]["backend_path"], IN_JAIL_SNAPSHOT_MEMORY);
    assert_eq!(json["mem_backend"]["backend_type"], "File");
    assert_eq!(json["track_dirty_pages"], false);
    assert_eq!(json["resume_vm"], true);
    assert_eq!(json["vsock_override"]["uds_path"], IN_JAIL_VSOCK_SOCKET);
    assert!(json.get("mem_file_path").is_none());
    assert!(json.get("enable_diff_snapshots").is_none());
    assert!(snapshot.cold_config().is_none());
}

#[test]
fn snapshot_launch_rejects_tap_override() {
    let directory = TempDir::new().unwrap();
    assert!(FirecrackerLaunchPlan::build(
        &paths(&directory, true),
        2,
        256 * 1024 * 1024,
        42,
        Some("tap0")
    )
    .is_err());
}

#[test]
fn snapshot_launch_rejects_topology_substitution() {
    let directory = TempDir::new().unwrap();
    for (vcpus, memory_bytes, guest_cid) in [
        (3, 256 * 1024 * 1024, 42),
        (2, 512 * 1024 * 1024, 42),
        (2, 256 * 1024 * 1024, 43),
    ] {
        assert!(FirecrackerLaunchPlan::build(
            &paths(&directory, true),
            vcpus,
            memory_bytes,
            guest_cid,
            None,
        )
        .is_err());
    }
}

#[test]
fn snapshot_request_binds_installed_firecracker_binary() {
    let directory = TempDir::new().unwrap();
    let paths = paths(&directory, true);
    let request = SnapshotLoadRequest::build(&paths).unwrap();
    let binary = directory.path().join("firecracker");
    fs::write(&binary, b"firecracker").unwrap();
    request.verify_firecracker_binary(&binary).unwrap();
    fs::write(&binary, b"substitute!").unwrap();
    assert!(request.verify_firecracker_binary(&binary).is_err());
}

#[test]
fn launch_capsule_builds_snapshot_jailer_only_after_binary_verification() {
    let directory = TempDir::new().unwrap();
    let paths = paths(&directory, true);
    let launch = FirecrackerLaunchPlan::build(&paths, 2, 256 * 1024 * 1024, 42, None).unwrap();
    let firecracker = directory.path().join("firecracker");
    fs::write(&firecracker, b"firecracker").unwrap();
    let requirements = crate::HostRequirements {
        paths: crate::FirecrackerPaths {
            jailer: directory.path().join("jailer"),
            firecracker,
            reflink_copy: PathBuf::from("/bin/cp"),
            jail_root: directory.path().join("jailer-root"),
            cgroup_parent: PathBuf::from("runtrue"),
        },
        tap_device: None,
    };
    let invocation = crate::JailerInvocation::build_for_launch(
        &requirements,
        "job-deadbeef",
        1000,
        1000,
        &launch,
    )
    .unwrap();
    assert!(invocation
        .arguments
        .iter()
        .any(|value| value == "--api-sock"));
    assert!(!invocation
        .arguments
        .iter()
        .any(|value| value == "--config-file"));

    fs::write(&requirements.paths.firecracker, b"substitute!").unwrap();
    assert!(crate::JailerInvocation::build_for_launch(
        &requirements,
        "job-deadbeef",
        1000,
        1000,
        &launch,
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn client_sends_bounded_exact_snapshot_load_request() {
    let directory = TempDir::new().unwrap();
    let paths = paths(&directory, true);
    write_snapshot_files(&paths);
    let request = SnapshotLoadRequest::build(&paths).unwrap();
    let expected_body = request.json_bytes().unwrap();
    let listener = UnixListener::bind(&paths.api_socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (headers, body) = read_request(&mut stream);
        assert!(headers.starts_with(b"PUT /snapshot/load HTTP/1.1\r\n"));
        assert!(headers
            .windows(b"Content-Type: application/json".len())
            .any(|window| window == b"Content-Type: application/json"));
        assert_eq!(body, expected_body);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    UnixSnapshotApiClient::new(
        &paths.api_socket,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap()
    .load(&request)
    .unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn client_rejects_firecracker_api_failure() {
    let directory = TempDir::new().unwrap();
    let paths = paths(&directory, true);
    write_snapshot_files(&paths);
    let request = SnapshotLoadRequest::build(&paths).unwrap();
    let listener = UnixListener::bind(&paths.api_socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
    });
    let result = UnixSnapshotApiClient::new(
        &paths.api_socket,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap()
    .load(&request);
    assert!(matches!(result, Err(FirecrackerError::SnapshotApi(_))));
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn client_rechecks_staged_artifacts_before_snapshot_load() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TempDir::new().unwrap();
    let paths = paths(&directory, true);
    write_snapshot_files(&paths);
    let memory = &paths.snapshot.as_ref().unwrap().memory;
    fs::set_permissions(memory, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(memory, b"tamper").unwrap();
    fs::set_permissions(memory, fs::Permissions::from_mode(0o400)).unwrap();
    let request = SnapshotLoadRequest::build(&paths).unwrap();
    let result = UnixSnapshotApiClient::new(
        &paths.api_socket,
        Duration::from_millis(50),
        Duration::from_secs(1),
    )
    .unwrap()
    .load(&request);
    assert!(matches!(
        result,
        Err(FirecrackerError::ArtifactDigestMismatch { .. })
    ));
}

#[cfg(unix)]
fn read_request(stream: &mut UnixStream) -> (Vec<u8>, Vec<u8>) {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
        assert!(headers.len() < MAX_API_RESPONSE_HEADER_BYTES);
    }
    let header_text = std::str::from_utf8(&headers).unwrap();
    let length = header_text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).unwrap();
    (headers, body)
}
