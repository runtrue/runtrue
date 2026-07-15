//! Bounded stdout and stderr capture.

#[derive(Clone, Debug, Default)]
pub(super) struct CapturedStream {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
}

pub(super) fn capture_stream<R>(
    mut reader: R,
    limit: usize,
) -> (Arc<Mutex<CapturedStream>>, mpsc::Receiver<()>)
where
    R: Read + Send + 'static,
{
    let capture = Arc::new(Mutex::new(CapturedStream::default()));
    let writer = Arc::clone(&capture);
    let (done_sender, done_receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let Ok(read) = reader.read(&mut buffer) else {
                break;
            };
            if read == 0 {
                break;
            }
            let mut captured = writer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let remaining = limit.saturating_sub(captured.bytes.len());
            let retained = read.min(remaining);
            captured.bytes.extend_from_slice(&buffer[..retained]);
            captured.truncated |= retained < read;
        }
        let _ = done_sender.send(());
    });
    (capture, done_receiver)
}

pub(super) fn snapshot_capture(capture: &Arc<Mutex<CapturedStream>>) -> CapturedStream {
    capture
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
use super::{mpsc, thread, Arc, Duration, Mutex, Read};
