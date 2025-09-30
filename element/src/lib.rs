/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
pub mod types;
pub mod signer;
pub mod kem;
pub mod metrics;
pub mod store;
pub mod config;
pub mod address;
pub mod server;
pub mod session;
pub use server::run_http_listener;
pub use crate::main_run_export::run_with_listener as bin_run_with_listener;

// Provide an internal module to expose the binary run function for tests and integration test harness.
mod main_run_export {
	// minimal shim to call the binary's run_with_listener
	pub async fn run_with_listener(listener: tokio::net::TcpListener) -> anyhow::Result<()> {
		// invoke the same initialization as main binary (simplified)
				// Start the HTTP listener using the server implementation (shares same router)
				super::server::run_http_listener(listener).await
	}
}
#[cfg(feature = "grpc")]
pub mod pb { include!(concat!(env!("OUT_DIR"), "/element.v1.rs")); }
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "quic-overlay")]
pub mod quic;
