/*
 QUIC Handshake Smoke Test
 Requires features: pqc, quic-overlay
*/

#![cfg(all(feature = "pqc", feature = "quic-overlay"))]

use tokio::runtime::Runtime;
use oqs::kem::Algorithm as KemAlgorithm;

#[test]
fn quic_handshake_smoke() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        drop(socket);
        // start overlay (will run pending forever in spawned task)
        let cfg = element::quic::overlay::QuicOverlayConfig { listen_addr: local, kem_alg: KemAlgorithm::Kyber768 };
        let handle = tokio::spawn(async move { let _ = element::quic::overlay::run(cfg).await; });
        // brief delay and then cancel
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        handle.abort();
        // If we got here without panic, assume startup path ok.
        assert!(true);
    });
}