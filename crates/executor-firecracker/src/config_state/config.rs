use super::{write_new_private, JobStatePaths};
use crate::FirecrackerError;
use serde::Serialize;
use std::path::Path;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirecrackerVmConfig {
    boot_source: BootSource,
    drives: Vec<Drive>,
    machine_config: MachineConfig,
    vsock: Vsock,
    network_interfaces: Vec<NetworkInterface>,
    logger: Logger,
    metrics: Metrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Drive {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MachineConfig {
    vcpu_count: u16,
    mem_size_mib: u64,
    smt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Vsock {
    guest_cid: u32,
    uds_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct NetworkInterface {
    iface_id: String,
    guest_mac: String,
    host_dev_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Logger {
    log_path: String,
    level: String,
    show_level: bool,
    show_log_origin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Metrics {
    metrics_path: String,
}

impl FirecrackerVmConfig {
    pub(crate) fn build_cold(
        paths: &JobStatePaths,
        vcpus: u16,
        memory_bytes: u64,
        guest_cid: u32,
        tap_device: Option<&str>,
    ) -> Result<Self, FirecrackerError> {
        if paths.snapshot.is_some() {
            return Err(FirecrackerError::InvalidConfiguration(
                "snapshot state must use FirecrackerLaunchPlan::Snapshot".to_owned(),
            ));
        }
        if vcpus == 0 || vcpus > 64 || guest_cid < 3 || tap_device.is_some_and(str::is_empty) {
            return Err(FirecrackerError::InvalidConfiguration(
                "invalid VM CPU, CID, or tap configuration".to_owned(),
            ));
        }
        const MIB: u64 = 1024 * 1024;
        if memory_bytes < 128 * MIB || !memory_bytes.is_multiple_of(MIB) {
            return Err(FirecrackerError::InvalidConfiguration(
                "VM memory must be MiB-aligned and at least 128 MiB".to_owned(),
            ));
        }
        let mac = format!(
            "06:00:{:02x}:{:02x}:{:02x}:{:02x}",
            (guest_cid >> 24) & 0xff,
            (guest_cid >> 16) & 0xff,
            (guest_cid >> 8) & 0xff,
            guest_cid & 0xff
        );
        Ok(Self {
            boot_source: BootSource {
                kernel_image_path: "/kernel".to_owned(),
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=off".to_owned(),
            },
            drives: vec![
                Drive {
                    drive_id: "rootfs".to_owned(),
                    path_on_host: "/rootfs.ext4".to_owned(),
                    is_root_device: true,
                    is_read_only: false,
                },
                Drive {
                    drive_id: "runtrue-boot".to_owned(),
                    path_on_host: "/boot-config.img".to_owned(),
                    is_root_device: false,
                    is_read_only: true,
                },
            ],
            machine_config: MachineConfig {
                vcpu_count: vcpus,
                mem_size_mib: memory_bytes / MIB,
                smt: false,
            },
            vsock: Vsock {
                guest_cid,
                uds_path: "/run/vsock.sock".to_owned(),
            },
            network_interfaces: tap_device
                .map(|tap_device| NetworkInterface {
                    iface_id: "eth0".to_owned(),
                    guest_mac: mac,
                    host_dev_name: tap_device.to_owned(),
                })
                .into_iter()
                .collect(),
            logger: Logger {
                log_path: "/run/firecracker.log".to_owned(),
                level: "Warning".to_owned(),
                show_level: true,
                show_log_origin: false,
            },
            metrics: Metrics {
                metrics_path: "/run/firecracker.metrics".to_owned(),
            },
        })
    }

    pub fn write_private(&self, path: &Path) -> Result<(), FirecrackerError> {
        let bytes = serde_json::to_vec(self)?;
        write_new_private(path, &bytes)
    }
}
