use serde::{Deserialize, Serialize};

/// A half-open byte range in the original expression.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// First byte in the range.
    pub start: usize,
    /// First byte after the range.
    pub end: usize,
}

impl Span {
    /// Creates a span. Positions are byte offsets, not character offsets.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub(crate) fn through(self, other: Self) -> Self {
        Self::new(self.start, other.end)
    }
}
