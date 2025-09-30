//! Element.SDK - Remote Secure Element client SDK
//!
//! Provides async access to key management, signing, verification, Kyber KEM operations,
//! CBID derivation and session token issuance for the Element remote secure element service.
//!
//! Feature flags:
//! - http (default): Enable HTTP/JSON transport via reqwest.
//! - retry (default): Simple exponential backoff for idempotent operations.
//! - quic: Placeholder for future QUIC overlay derivation.
//! - grpc: Placeholder for future gRPC streaming.
//! - structured-scope: Sign scope builder & future /sign/scope endpoint.
//! - metrics-json: Optional parsing helpers for /metrics JSON variant.

mod errors;
mod config;
mod client;
mod models;
mod nonce;
#[cfg(feature = "structured-scope")] mod scope;
#[cfg(feature = "quic")] mod quic;
mod retry;
mod util;

pub use crate::errors::Error;
pub use crate::client::{ElementClient, ElementClientBuilder};
pub use crate::models::*;
pub use crate::models::{CbidDeriveRequest, CbidDeriveResponse};

/// Crate version (runtime constant)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
