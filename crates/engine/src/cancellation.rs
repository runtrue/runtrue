//! Cooperative execution cancellation.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// A clonable cancellation signal that can be triggered from another thread.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request cancellation. Calling this more than once is harmless.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
