use crate::GuestAgentError;
use runtrue_guest_core::{AuthenticatedEnvelope, MAX_GUEST_MESSAGE_BYTES};
use serde::de::DeserializeOwned;
use std::{
    io::{Read, Write},
    sync::Arc,
};

#[cfg(target_os = "linux")]
use nix::{
    sys::socket::{accept4, bind, listen, socket, AddressFamily, SockFlag, SockType, VsockAddr},
    unistd::{close, read, write},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

pub struct GuestFrameReader<R> {
    reader: R,
    max_frame_bytes: usize,
}

impl<R> GuestFrameReader<R> {
    #[must_use]
    pub const fn new(reader: R) -> Self {
        Self {
            reader,
            max_frame_bytes: MAX_GUEST_MESSAGE_BYTES,
        }
    }
}

impl<R: Read> GuestFrameReader<R> {
    pub fn receive(&mut self) -> Result<AuthenticatedEnvelope, GuestAgentError> {
        let mut prefix = [0_u8; 4];
        self.reader
            .read_exact(&mut prefix)
            .map_err(|error| GuestAgentError::Transport(error.to_string()))?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| GuestAgentError::Transport("guest frame length overflows".to_owned()))?;
        if length == 0 || length > self.max_frame_bytes {
            return Err(GuestAgentError::Transport(format!(
                "guest frame has invalid length {length}"
            )));
        }
        let mut payload = vec![0_u8; length];
        self.reader
            .read_exact(&mut payload)
            .map_err(|error| GuestAgentError::Transport(error.to_string()))?;
        strict_json(&payload)
    }
}

pub struct GuestFrameWriter<W> {
    writer: W,
    max_frame_bytes: usize,
}

impl<W> GuestFrameWriter<W> {
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            max_frame_bytes: MAX_GUEST_MESSAGE_BYTES,
        }
    }
}

impl<W: Write> GuestFrameWriter<W> {
    pub fn send(&mut self, envelope: &AuthenticatedEnvelope) -> Result<(), GuestAgentError> {
        let payload = serde_json::to_vec(envelope)?;
        if payload.is_empty() || payload.len() > self.max_frame_bytes {
            return Err(GuestAgentError::Transport(
                "outbound guest frame exceeds its bound".to_owned(),
            ));
        }
        let length = u32::try_from(payload.len()).map_err(|_| {
            GuestAgentError::Transport("outbound guest frame length overflows".to_owned())
        })?;
        self.writer
            .write_all(&length.to_be_bytes())
            .and_then(|()| self.writer.write_all(&payload))
            .and_then(|()| self.writer.flush())
            .map_err(|error| GuestAgentError::Transport(error.to_string()))
    }
}

#[derive(Clone)]
pub struct VsockStream {
    #[cfg(target_os = "linux")]
    descriptor: Arc<RawVsock>,
}

#[cfg(target_os = "linux")]
struct RawVsock(i32);

#[cfg(target_os = "linux")]
impl Drop for RawVsock {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

impl Read for VsockStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        return read(self.descriptor.0, buffer).map_err(nix_io);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buffer;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "AF_VSOCK is Linux-only",
            ))
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        return write(self.descriptor.0, buffer).map_err(nix_io);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buffer;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "AF_VSOCK is Linux-only",
            ))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bind the one configured guest port and accept exactly one host connection.
/// The listening descriptor is closed immediately afterward.
pub fn accept_vsock(port: u32) -> Result<VsockStream, GuestAgentError> {
    if port < 1024 {
        return Err(GuestAgentError::InvalidConfiguration(
            "guest vsock port must be unprivileged".to_owned(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    return Err(GuestAgentError::Transport(
        "AF_VSOCK is supported only on Linux".to_owned(),
    ));
    #[cfg(target_os = "linux")]
    {
        let listener = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|error| GuestAgentError::Transport(error.to_string()))?;
        bind(listener.as_raw_fd(), &VsockAddr::new(u32::MAX, port))
            .map_err(|error| GuestAgentError::Transport(error.to_string()))?;
        listen(&listener, 1).map_err(|error| GuestAgentError::Transport(error.to_string()))?;
        let descriptor = accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC)
            .map_err(|error| GuestAgentError::Transport(error.to_string()))?;
        drop(listener);
        Ok(VsockStream {
            descriptor: Arc::new(RawVsock(descriptor)),
        })
    }
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GuestAgentError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

#[cfg(target_os = "linux")]
fn nix_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_guest_core::GUEST_PROTOCOL_VERSION;
    use std::io::Cursor;

    #[test]
    fn framed_guest_transport_round_trips() {
        let envelope = AuthenticatedEnvelope {
            protocol_version: GUEST_PROTOCOL_VERSION,
            session_id: "session".to_owned(),
            sequence: 1,
            payload: vec![1, 2],
            authentication_tag: vec![3; 32],
        };
        let mut writer = GuestFrameWriter::new(Cursor::new(Vec::new()));
        writer.send(&envelope).unwrap();
        let bytes = writer.writer.into_inner();
        let mut reader = GuestFrameReader::new(Cursor::new(bytes));
        assert_eq!(reader.receive().unwrap(), envelope);
    }

    #[test]
    fn oversized_frame_fails_before_payload_allocation() {
        let size = u32::try_from(MAX_GUEST_MESSAGE_BYTES + 1).unwrap();
        let mut reader = GuestFrameReader::new(Cursor::new(size.to_be_bytes().to_vec()));
        assert!(reader.receive().is_err());
    }
}
