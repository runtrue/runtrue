use crate::WasmError;
use runtrue_engine::CancellationToken;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use wasmtime::Engine;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Interruption {
    None,
    Timeout,
    Canceled,
}

pub(crate) struct EpochWatchdog {
    stop: Arc<AtomicBool>,
    reason: Arc<AtomicU8>,
    join: Option<thread::JoinHandle<()>>,
}

impl EpochWatchdog {
    pub(crate) fn start(
        engine: Engine,
        cancellation: CancellationToken,
        timeout: Duration,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let reason = Arc::new(AtomicU8::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_reason = Arc::clone(&reason);
        let join = thread::spawn(move || {
            let started = Instant::now();
            while !thread_stop.load(Ordering::Acquire) {
                if cancellation.is_cancelled() {
                    thread_reason.store(2, Ordering::Release);
                    engine.increment_epoch();
                    return;
                }
                if started.elapsed() >= timeout {
                    thread_reason.store(1, Ordering::Release);
                    engine.increment_epoch();
                    return;
                }
                thread::sleep(Duration::from_millis(2));
            }
        });
        Self {
            stop,
            reason,
            join: Some(join),
        }
    }

    pub(crate) fn finish(mut self) -> Result<Interruption, WasmError> {
        self.stop.store(true, Ordering::Release);
        if self.join.take().is_some_and(|join| join.join().is_err()) {
            return Err(WasmError::Watchdog);
        }
        Ok(match self.reason.load(Ordering::Acquire) {
            0 => Interruption::None,
            1 => Interruption::Timeout,
            2 => Interruption::Canceled,
            _ => return Err(WasmError::Watchdog),
        })
    }
}

impl Drop for EpochWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
