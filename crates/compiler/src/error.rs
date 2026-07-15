#[derive(Debug, thiserror::Error)]

pub enum CompileError {
    #[error("{path}: {message}")]
    Semantic { path: String, message: String },
    #[error(transparent)]
    Parse(#[from] ast::ParseError),
    #[error("could not encode canonical data: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not encode execution capsule: {0}")]
    Capsule(#[from] ir::CapsuleError),
    #[error("lockfile admission failed: {0}")]
    Lock(#[from] runtrue_lock::LockError),
}

impl CompileError {
    pub(crate) fn semantic(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Semantic {
            path: path.into(),
            message: message.into(),
        }
    }

    pub(crate) fn model(path: impl Into<String>, error: ModelError) -> Self {
        Self::semantic(path, error.to_string())
    }
}
use super::{ast, ir, ModelError};
