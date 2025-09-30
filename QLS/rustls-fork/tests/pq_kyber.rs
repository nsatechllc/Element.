// Integration test: Kyber-only TLS 1.3 handshake
use rustls::{ClientConfig, ServerConfig, crypto::CryptoProvider, RootCertStore, Error, SignatureScheme};
use rustls::client::{ClientConnection, ServerName, ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::server::ServerConnection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

// Danger: A permissive verifier used only for this integration smoke test.
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn build_server_config(provider: Arc<CryptoProvider>) -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();
    let certs: Vec<CertificateDer<'static>> = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(key_der.into());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert setup")
}

fn build_client_config(provider: Arc<CryptoProvider>) -> ClientConfig {
    let roots = RootCertStore::empty();
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.dangerous().set_certificate_verifier(Arc::new(AcceptAllVerifier));
    cfg
}

#[test]
fn kyber_only_handshake_completes() {
    let provider = CryptoProvider::get_default().cloned().expect("default provider installed");
    let server_config = build_server_config(provider.clone());
    let client_config = build_client_config(provider.clone());

    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    // Simple driving loop
    for _ in 0..50 { // limit iterations
        // Client -> Server
        if client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() { server.read_tls(&mut &buf[..]).unwrap(); server.process_new_packets().unwrap(); }
        }
        // Server -> Client
        if server.wants_write() {
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() { client.read_tls(&mut &buf[..]).unwrap(); client.process_new_packets().unwrap(); }
        }
        if !client.is_handshaking() && !server.is_handshaking() { break; }
    }

    assert!(!client.is_handshaking(), "client still handshaking");
    assert!(!server.is_handshaking(), "server still handshaking");

    // Verify negotiated group is Kyber (experimental) if available
    let group = client.negotiated_key_exchange_group().expect("kx group");
    assert_eq!(format!("{:?}", group.name()), "Kyber768Exp", "expected Kyber group: got {group:?}");
}
