use crate::FirecrackerError;
use runtrue_guest_core::{AuthenticatedEnvelope, MAX_GUEST_MESSAGE_BYTES};
use serde::de::DeserializeOwned;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::{os::unix::fs::FileTypeExt as _, os::unix::net::UnixStream, thread};

pub trait EnvelopeTransport: Send {
    fn send(&mut self, envelope: &AuthenticatedEnvelope) -> Result<(), FirecrackerError>;
    fn receive(&mut self) -> Result<AuthenticatedEnvelope, FirecrackerError>;
}

/// Four-byte big-endian length followed by strict JSON. Both directions share
/// the guest-core 2 MiB envelope ceiling.
pub struct FramedTransport<S> {
    stream: S,
    max_frame_bytes: usize,
}

impl<S> FramedTransport<S> {
    #[must_use]
    pub const fn new(stream: S) -> Self {
        Self {
            stream,
            max_frame_bytes: MAX_GUEST_MESSAGE_BYTES,
        }
    }

    pub fn with_limit(stream: S, max_frame_bytes: usize) -> Result<Self, FirecrackerError> {
        if max_frame_bytes == 0 || max_frame_bytes > MAX_GUEST_MESSAGE_BYTES {
            return Err(FirecrackerError::InvalidConfiguration(
                "guest frame bound is invalid".to_owned(),
            ));
        }
        Ok(Self {
            stream,
            max_frame_bytes,
        })
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write + Send> EnvelopeTransport for FramedTransport<S> {
    fn send(&mut self, envelope: &AuthenticatedEnvelope) -> Result<(), FirecrackerError> {
        let payload = serde_json::to_vec(envelope)?;
        if payload.is_empty() || payload.len() > self.max_frame_bytes {
            return Err(FirecrackerError::Transport(
                "outbound guest frame exceeds its bound".to_owned(),
            ));
        }
        let length = u32::try_from(payload.len()).map_err(|_| {
            FirecrackerError::Transport("outbound guest frame length overflows".to_owned())
        })?;
        self.stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| self.stream.write_all(&payload))
            .and_then(|()| self.stream.flush())
            .map_err(|error| FirecrackerError::Transport(error.to_string()))
    }

    fn receive(&mut self) -> Result<AuthenticatedEnvelope, FirecrackerError> {
        let mut length = [0_u8; 4];
        self.stream
            .read_exact(&mut length)
            .map_err(|error| FirecrackerError::Transport(error.to_string()))?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| {
            FirecrackerError::Transport("inbound guest frame length overflows".to_owned())
        })?;
        if length == 0 || length > self.max_frame_bytes {
            return Err(FirecrackerError::Transport(format!(
                "inbound guest frame has invalid length {length}"
            )));
        }
        let mut payload = vec![0_u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|error| FirecrackerError::Transport(error.to_string()))?;
        strict_json(&payload)
    }
}

pub trait GuestConnector: Send + Sync {
    fn connect(&self) -> Result<Box<dyn EnvelopeTransport>, FirecrackerError>;
}

#[derive(Debug, Clone)]
pub struct FirecrackerVsockConnector {
    uds_path: PathBuf,
    guest_port: u32,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl FirecrackerVsockConnector {
    pub fn new(
        uds_path: impl Into<PathBuf>,
        guest_port: u32,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, FirecrackerError> {
        let connector = Self {
            uds_path: uds_path.into(),
            guest_port,
            connect_timeout,
            io_timeout,
        };
        if !connector.uds_path.is_absolute()
            || connector.guest_port < 1024
            || connector.connect_timeout.is_zero()
            || connector.io_timeout.is_zero()
        {
            return Err(FirecrackerError::InvalidConfiguration(
                "invalid Firecracker vsock connector".to_owned(),
            ));
        }
        Ok(connector)
    }
}

impl GuestConnector for FirecrackerVsockConnector {
    fn connect(&self) -> Result<Box<dyn EnvelopeTransport>, FirecrackerError> {
        #[cfg(not(unix))]
        return Err(FirecrackerError::Transport(
            "Firecracker vsock requires Unix sockets".to_owned(),
        ));

        #[cfg(unix)]
        {
            let deadline = Instant::now()
                .checked_add(self.connect_timeout)
                .ok_or_else(|| {
                    FirecrackerError::InvalidConfiguration(
                        "vsock connect deadline overflows".to_owned(),
                    )
                })?;
            let mut stream = loop {
                validate_socket_if_present(&self.uds_path)?;
                let error = match UnixStream::connect(&self.uds_path) {
                    Ok(stream) => break stream,
                    Err(error) => error,
                };
                if Instant::now() >= deadline {
                    return Err(FirecrackerError::Transport(format!(
                        "vsock UDS connection timed out: {error}"
                    )));
                }
                thread::sleep(Duration::from_millis(10));
            };
            stream
                .set_read_timeout(Some(self.io_timeout))
                .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
                .map_err(|error| FirecrackerError::Transport(error.to_string()))?;
            let request = format!("CONNECT {}\n", self.guest_port);
            stream
                .write_all(request.as_bytes())
                .map_err(|error| FirecrackerError::Transport(error.to_string()))?;
            let mut response = Vec::with_capacity(32);
            loop {
                let mut byte = [0_u8; 1];
                stream
                    .read_exact(&mut byte)
                    .map_err(|error| FirecrackerError::Transport(error.to_string()))?;
                response.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if response.len() >= 64 {
                    return Err(FirecrackerError::Transport(
                        "vsock proxy response exceeds its bound".to_owned(),
                    ));
                }
            }
            let response = std::str::from_utf8(&response).map_err(|_| {
                FirecrackerError::Transport("vsock proxy returned non-UTF-8 data".to_owned())
            })?;
            let assigned_host_port = response
                .strip_prefix("OK ")
                .and_then(|value| value.strip_suffix('\n'))
                .and_then(|value| value.parse::<u32>().ok());
            if assigned_host_port.is_none_or(|port| port == 0) {
                return Err(FirecrackerError::Transport(
                    "vsock proxy rejected the guest port".to_owned(),
                ));
            }
            Ok(Box::new(FramedTransport::new(stream)))
        }
    }
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, FirecrackerError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

#[cfg(unix)]
fn validate_socket_if_present(path: &Path) -> Result<(), FirecrackerError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() => {
            Err(FirecrackerError::Transport(
                "vsock proxy path is not a non-symlink Unix socket".to_owned(),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FirecrackerError::Transport(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_guest_core::GUEST_PROTOCOL_VERSION;
    use std::io::Cursor;

    #[test]
    fn framed_transport_round_trips_with_a_bound() {
        let envelope = AuthenticatedEnvelope {
            protocol_version: GUEST_PROTOCOL_VERSION,
            session_id: "session".to_owned(),
            sequence: 1,
            payload: vec![1, 2, 3],
            authentication_tag: vec![4; 32],
        };
        let mut writer = FramedTransport::new(Cursor::new(Vec::new()));
        writer.send(&envelope).unwrap();
        let bytes = writer.into_inner().into_inner();
        let mut reader = FramedTransport::new(Cursor::new(bytes));
        assert_eq!(reader.receive().unwrap(), envelope);
    }

    #[test]
    fn oversized_prefix_is_rejected_before_allocation() {
        let length = u32::try_from(MAX_GUEST_MESSAGE_BYTES + 1).unwrap();
        let mut reader = FramedTransport::new(Cursor::new(length.to_be_bytes().to_vec()));
        assert!(reader.receive().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn accepts_firecrackers_assigned_host_port_acknowledgement() {
        use std::os::unix::net::UnixListener;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vsock.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 13];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"CONNECT 5000\n");
            stream.write_all(b"OK 1073741824\n").unwrap();
        });
        let connector = FirecrackerVsockConnector::new(
            path,
            5000,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let _transport = connector.connect().unwrap();
        server.join().unwrap();
    }
}
