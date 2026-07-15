use super::SnapshotLoadRequest;
use crate::FirecrackerError;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[cfg(unix)]
use std::{os::unix::fs::FileTypeExt as _, os::unix::net::UnixStream, thread};
const MAX_API_REQUEST_BYTES: usize = 64 * 1024;
pub(super) const MAX_API_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const API_RETRY_INTERVAL: Duration = Duration::from_millis(10);
pub trait SnapshotApi: Send + Sync {
    fn load(&self, request: &SnapshotLoadRequest) -> Result<(), FirecrackerError>;
}

#[derive(Debug, Clone)]
pub struct UnixSnapshotApiClient {
    socket_path: PathBuf,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl UnixSnapshotApiClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, FirecrackerError> {
        let client = Self {
            socket_path: socket_path.into(),
            connect_timeout,
            io_timeout,
        };
        if !client.socket_path.is_absolute()
            || client.connect_timeout.is_zero()
            || client.io_timeout.is_zero()
        {
            return Err(FirecrackerError::InvalidConfiguration(
                "invalid Firecracker snapshot API client configuration".to_owned(),
            ));
        }
        Ok(client)
    }

    #[cfg(unix)]
    fn connect(&self) -> Result<UnixStream, FirecrackerError> {
        let deadline = Instant::now()
            .checked_add(self.connect_timeout)
            .ok_or_else(|| {
                FirecrackerError::InvalidConfiguration(
                    "snapshot API connect deadline overflows".to_owned(),
                )
            })?;
        loop {
            validate_socket_if_present(&self.socket_path)?;
            match UnixStream::connect(&self.socket_path) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(self.io_timeout))
                        .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
                        .map_err(|error| FirecrackerError::SnapshotApi(error.to_string()))?;
                    return Ok(stream);
                }
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(API_RETRY_INTERVAL);
                }
                Err(error) => {
                    return Err(FirecrackerError::SnapshotApi(format!(
                        "API socket connection timed out: {error}"
                    )));
                }
            }
        }
    }
}

impl SnapshotApi for UnixSnapshotApiClient {
    fn load(&self, request: &SnapshotLoadRequest) -> Result<(), FirecrackerError> {
        #[cfg(not(unix))]
        {
            let _ = request;
            return Err(FirecrackerError::SnapshotApi(
                "Firecracker API sockets require Unix".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            request.verify_staged_artifacts()?;
            let body = request.json_bytes()?;
            let mut stream = self.connect()?;
            let headers = format!(
                "PUT /snapshot/load HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if headers.len() + body.len() > MAX_API_REQUEST_BYTES {
                return Err(FirecrackerError::InvalidConfiguration(
                    "snapshot HTTP request exceeds its bound".to_owned(),
                ));
            }
            stream
                .write_all(headers.as_bytes())
                .and_then(|()| stream.write_all(&body))
                .and_then(|()| stream.flush())
                .map_err(|error| FirecrackerError::SnapshotApi(error.to_string()))?;
            let response = read_response_headers(&mut stream)?;
            let status = response
                .split(|byte| *byte == b'\r')
                .next()
                .and_then(|line| std::str::from_utf8(line).ok())
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| {
                    FirecrackerError::SnapshotApi("malformed HTTP status line".to_owned())
                })?;
            if status != 204 {
                return Err(FirecrackerError::SnapshotApi(format!(
                    "snapshot load returned HTTP {status}"
                )));
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
fn read_response_headers(stream: &mut UnixStream) -> Result<Vec<u8>, FirecrackerError> {
    let mut response = Vec::with_capacity(256);
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_API_RESPONSE_HEADER_BYTES {
            return Err(FirecrackerError::SnapshotApi(
                "snapshot API response headers exceed their bound".to_owned(),
            ));
        }
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|error| FirecrackerError::SnapshotApi(error.to_string()))?;
        response.push(byte[0]);
    }
    Ok(response)
}

#[cfg(unix)]
fn validate_socket_if_present(path: &Path) -> Result<(), FirecrackerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() => {
            Err(FirecrackerError::SnapshotApi(
                "Firecracker API path is not a non-symlink Unix socket".to_owned(),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FirecrackerError::SnapshotApi(error.to_string())),
    }
}
