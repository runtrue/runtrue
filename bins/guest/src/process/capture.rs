use crate::GuestAgentError;
use std::thread;

pub(super) struct Captured {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
}

pub(super) struct Capture {
    thread: thread::JoinHandle<Result<Captured, std::io::Error>>,
}

impl Capture {
    pub(super) fn start<T: std::io::Read + Send + 'static>(mut stream: T, limit: usize) -> Self {
        Self {
            thread: thread::spawn(move || {
                let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
                let mut buffer = [0_u8; 16 * 1024];
                let mut truncated = false;
                loop {
                    let count = stream.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    let remaining = limit.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&buffer[..count.min(remaining)]);
                    truncated |= count > remaining;
                }
                Ok(Captured { bytes, truncated })
            }),
        }
    }

    pub(super) fn finish(self) -> Result<Captured, GuestAgentError> {
        self.thread
            .join()
            .map_err(|_| GuestAgentError::Process("guest capture thread panicked".to_owned()))?
            .map_err(|error| GuestAgentError::Process(error.to_string()))
    }
}
