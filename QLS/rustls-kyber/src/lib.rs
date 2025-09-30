//! Entry point for rustls + Kyber hybrid integration helper crate.

pub mod kem;
pub mod hybrid;

pub use kem::{Impl as KyberKem, KyberKeypair, SharedSecret, KemError};
pub use hybrid::derive_hybrid_secret;
