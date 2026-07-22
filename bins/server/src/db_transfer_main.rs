use clap::{Parser, Subcommand};
#[cfg(feature = "postgres")]
use runtrue_control_plane::{
    activate_verified_postgres_transfer, copy_sqlite_to_postgres,
    prepare_empty_postgres_destination, InstallationStateStore, PostgresDatabaseConfig,
    PostgresInstallationStore, SqliteTransferSource,
};
use runtrue_control_plane::{
    postgres_boundary_inventory, postgres_transfer_ready, PostgresBoundaryInventory,
    PostgresBoundaryStatus,
};
#[cfg(feature = "postgres")]
use runtrue_server::read_database_url_file;
use serde::Serialize;
#[cfg(feature = "postgres")]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

const REFUSED_EXIT: u8 = 10;

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-db-transfer",
    about = "Transfer an offline Runtrue SQLite control plane to PostgreSQL"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit the machine-readable PostgreSQL boundary inventory.
    Inventory,
    /// Initialize a fresh active PostgreSQL control plane with migration-owner credentials.
    Initialize {
        /// Secure file containing the destination PostgreSQL URL.
        #[arg(long, value_name = "PATH")]
        postgres_url_file: PathBuf,
        /// New or existing installation identity to bind exactly.
        #[arg(long)]
        installation_id: String,
    },
    /// Copy a safe-mode SQLite database into an empty PostgreSQL database.
    Transfer {
        /// Offline SQLite control-plane database to transfer.
        #[arg(long, value_name = "PATH")]
        sqlite: PathBuf,
        /// Mode-0600 file containing the destination PostgreSQL URL.
        #[arg(long, value_name = "PATH")]
        postgres_url_file: PathBuf,
    },
    /// Explicitly activate a verified PostgreSQL transfer at its exact fence.
    Activate {
        /// Mode-0600 file containing the destination PostgreSQL URL.
        #[arg(long, value_name = "PATH")]
        postgres_url_file: PathBuf,
        /// Exact installation identity printed by `transfer`.
        #[arg(long)]
        installation_id: String,
        /// Exact destination fencing epoch printed by `transfer`.
        #[arg(long)]
        expected_fencing_epoch: u64,
    },
}

#[derive(Debug, Serialize)]
struct InventoryReport<'a> {
    version: u32,
    operation: &'static str,
    activation_permitted: bool,
    transfer_ready: bool,
    boundaries: &'a [PostgresBoundaryInventory],
}

#[derive(Debug, Serialize)]
struct TransferRefusal<'a> {
    version: u32,
    operation: &'static str,
    status: &'static str,
    activation_permitted: bool,
    source_sqlite: String,
    postgres_url_file: String,
    blockers: Vec<&'static str>,
    boundaries: &'a [PostgresBoundaryInventory],
}

#[cfg(feature = "postgres")]
#[derive(Debug, Serialize)]
struct ActivationReport {
    version: u32,
    operation: &'static str,
    status: &'static str,
    installation_id: String,
    fencing_epoch: u64,
    safe_mode: bool,
}

#[cfg(feature = "postgres")]
#[derive(Debug, Serialize)]
struct InitializationReport {
    version: u32,
    operation: &'static str,
    status: &'static str,
    installation_id: String,
    fencing_epoch: u64,
    safe_mode: bool,
}

fn inventory_report() -> InventoryReport<'static> {
    InventoryReport {
        version: 1,
        operation: "sqlite_to_postgres_boundary_inventory",
        activation_permitted: false,
        transfer_ready: postgres_transfer_ready(),
        boundaries: postgres_boundary_inventory(),
    }
}

fn refusal_report(sqlite: &Path, postgres_url_file: &Path) -> TransferRefusal<'static> {
    let boundaries = postgres_boundary_inventory();
    let mut blockers = boundaries
        .iter()
        .filter(|boundary| boundary.status == PostgresBoundaryStatus::Unported)
        .map(|boundary| boundary.id)
        .collect::<Vec<_>>();
    #[cfg(not(feature = "postgres"))]
    blockers.push("binary_built_without_postgres_support");
    if blockers.is_empty() {
        blockers.push("transfer_precondition_failed");
    }
    TransferRefusal {
        version: 1,
        operation: "sqlite_to_postgres_transfer",
        status: "refused",
        activation_permitted: false,
        source_sqlite: sqlite.display().to_string(),
        postgres_url_file: postgres_url_file.display().to_string(),
        blockers,
        boundaries,
    }
}

fn write_json(value: &impl Serialize) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).map_err(io::Error::other)?;
    writeln!(stdout)
}

#[cfg(feature = "postgres")]
fn now_unix_ms() -> io::Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| io::Error::other("system time is outside the supported range"))
}

#[cfg(feature = "postgres")]
async fn transfer(
    sqlite: &Path,
    postgres_url_file: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !postgres_transfer_ready() {
        write_json(&refusal_report(sqlite, postgres_url_file))?;
        return Err(Box::new(TransferRefused));
    }
    let now = now_unix_ms()?;
    let source = SqliteTransferSource::open(sqlite)?;
    let installation_id = source.installation_id().to_owned();
    let database_url = read_database_url_file(postgres_url_file)?;
    let config = PostgresDatabaseConfig::parse(&database_url)?;
    let destination =
        PostgresInstallationStore::connect_for_transfer(config, &installation_id, now).await?;
    let destination_state = prepare_empty_postgres_destination(&destination, now).await?;

    let report = copy_sqlite_to_postgres(&source, &destination, now).await?;
    if report.destination_fencing_epoch <= destination_state.fencing_epoch {
        return Err("transfer did not advance the destination fence".into());
    }
    write_json(&report)?;
    destination.close().await;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn activate(
    postgres_url_file: &Path,
    installation_id: &str,
    expected_fencing_epoch: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !postgres_transfer_ready() {
        return Err("PostgreSQL parity is incomplete; activation remains disabled".into());
    }
    let now = now_unix_ms()?;
    let database_url = read_database_url_file(postgres_url_file)?;
    let config = PostgresDatabaseConfig::parse(&database_url)?;
    let destination = PostgresInstallationStore::connect_existing(config, installation_id).await?;
    let state =
        activate_verified_postgres_transfer(&destination, expected_fencing_epoch, now).await?;
    write_json(&ActivationReport {
        version: 1,
        operation: "activate_postgres_control_plane",
        status: "activated",
        installation_id: installation_id.to_owned(),
        fencing_epoch: state.fencing_epoch,
        safe_mode: state.safe_mode,
    })?;
    destination.close().await;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn initialize(
    postgres_url_file: &Path,
    installation_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !postgres_transfer_ready() {
        return Err("PostgreSQL parity is incomplete; initialization remains disabled".into());
    }
    let now = now_unix_ms()?;
    let database_url = read_database_url_file(postgres_url_file)?;
    let config = PostgresDatabaseConfig::parse(&database_url)?;
    let destination =
        PostgresInstallationStore::connect_and_migrate(config, installation_id, now).await?;
    let readiness = destination.load_database_readiness().await?;
    if readiness.recovery.safe_mode {
        return Err(
            "PostgreSQL installation is in restore safe mode and cannot be initialized".into(),
        );
    }
    write_json(&InitializationReport {
        version: 1,
        operation: "initialize_postgres_control_plane",
        status: "initialized",
        installation_id: readiness.installation_id,
        fencing_epoch: readiness.recovery.fencing_epoch,
        safe_mode: readiness.recovery.safe_mode,
    })?;
    destination.close().await;
    Ok(())
}

#[cfg(feature = "postgres")]
#[derive(Debug)]
struct TransferRefused;

#[cfg(feature = "postgres")]
impl std::fmt::Display for TransferRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PostgreSQL transfer remains gated by unported boundaries")
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for TransferRefused {}

#[tokio::main]
async fn main() -> ExitCode {
    match Args::parse().command {
        Command::Inventory => match write_json(&inventory_report()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failed(error),
        },
        Command::Transfer {
            sqlite,
            postgres_url_file,
        } => {
            #[cfg(feature = "postgres")]
            {
                match transfer(&sqlite, &postgres_url_file).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) if error.is::<TransferRefused>() => ExitCode::from(REFUSED_EXIT),
                    Err(error) => failed(error),
                }
            }
            #[cfg(not(feature = "postgres"))]
            {
                match write_json(&refusal_report(&sqlite, &postgres_url_file)) {
                    Ok(()) => ExitCode::from(REFUSED_EXIT),
                    Err(error) => failed(error),
                }
            }
        }
        Command::Initialize {
            postgres_url_file,
            installation_id,
        } => {
            #[cfg(feature = "postgres")]
            {
                match initialize(&postgres_url_file, &installation_id).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => failed(error),
                }
            }
            #[cfg(not(feature = "postgres"))]
            {
                let _ = (postgres_url_file, installation_id);
                failed("binary was built without PostgreSQL support")
            }
        }
        Command::Activate {
            postgres_url_file,
            installation_id,
            expected_fencing_epoch,
        } => {
            #[cfg(feature = "postgres")]
            {
                match activate(&postgres_url_file, &installation_id, expected_fencing_epoch).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => failed(error),
                }
            }
            #[cfg(not(feature = "postgres"))]
            {
                let _ = (postgres_url_file, installation_id, expected_fencing_epoch);
                failed("binary was built without PostgreSQL support")
            }
        }
    }
}

fn failed(error: impl std::fmt::Display) -> ExitCode {
    let _ = writeln!(io::stderr(), "runtrue-db-transfer: {error}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_refuses_every_unported_boundary_without_activation() {
        let report = refusal_report(Path::new("control-plane.sqlite"), Path::new("postgres-url"));
        assert_eq!(report.status, "refused");
        assert!(!report.activation_permitted);
        assert!(!report.blockers.is_empty());
    }

    #[test]
    fn inventory_is_machine_readable() {
        let encoded = serde_json::to_value(inventory_report()).expect("serialize inventory");
        assert_eq!(encoded["version"], 1);
        assert_eq!(encoded["activation_permitted"], false);
        assert!(encoded["boundaries"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()));
    }

    #[test]
    fn initialize_is_an_explicit_cli_operation() {
        let parsed = Args::try_parse_from([
            "runtrue-db-transfer",
            "initialize",
            "--postgres-url-file",
            "postgres.url",
            "--installation-id",
            "fresh-installation",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Initialize {
                postgres_url_file,
                installation_id,
            } if postgres_url_file == Path::new("postgres.url")
                && installation_id == "fresh-installation"
        ));
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn fresh_postgres_initialize_is_active_and_idempotent() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let suffix = format!(
            "{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let schema = format!("runtrue_initialize_cli_{suffix}");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let separator = if url.contains('?') { '&' } else { '?' };
        let url = format!("{url}{separator}options=-csearch_path%3D{schema}");
        let directory = tempfile::tempdir().unwrap();
        let url_file = directory.path().join("postgres.url");
        std::fs::write(&url_file, &url).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        initialize(&url_file, "fresh-cli-installation")
            .await
            .unwrap();
        initialize(&url_file, "fresh-cli-installation")
            .await
            .unwrap();

        let database_url = read_database_url_file(&url_file).unwrap();
        let store = PostgresInstallationStore::connect_existing(
            PostgresDatabaseConfig::parse(&database_url).unwrap(),
            "fresh-cli-installation",
        )
        .await
        .unwrap();
        let readiness = store.load_database_readiness().await.unwrap();
        assert!(!readiness.recovery.safe_mode);
        assert_eq!(readiness.installation_id, "fresh-cli-installation");
        store.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
