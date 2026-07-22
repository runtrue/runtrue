//! Provider-neutral runner fleet reconciliation.
//!
//! The crate is deliberately embeddable: deployments may run it in the
//! standalone `runtrue-autoscaler` process or compose the same runtime into a
//! larger Rust binary. It never opens the control-plane database.

mod docker;
mod error;
mod http;
mod model;
mod reconciler;
mod runtime;
mod traits;

pub use docker::{DockerMount, DockerProvider, DockerTemplate};
pub use error::AutoscalerError;
pub use http::HttpControlPlane;
pub use model::*;
pub use reconciler::Reconciler;
pub use runtime::{read_private_token, AutoscalerConfig, AutoscalerRuntime};
pub use traits::{Clock, ControlPlaneClient, Provider, SystemClock};
