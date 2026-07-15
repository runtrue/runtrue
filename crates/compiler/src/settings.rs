pub struct CompilerSettings {
    pub max_matrix_jobs: usize,
    pub allow_unsafe_interpolation: bool,
    pub max_reusable_depth: usize,
    pub max_reusable_jobs: usize,
}

impl Default for CompilerSettings {
    fn default() -> Self {
        Self {
            max_matrix_jobs: DEFAULT_MAX_MATRIX_JOBS,
            allow_unsafe_interpolation: false,
            max_reusable_depth: DEFAULT_MAX_REUSABLE_DEPTH,
            max_reusable_jobs: DEFAULT_MAX_REUSABLE_JOBS,
        }
    }
}
use super::{DEFAULT_MAX_MATRIX_JOBS, DEFAULT_MAX_REUSABLE_DEPTH, DEFAULT_MAX_REUSABLE_JOBS};
