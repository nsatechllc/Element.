/*
 QUIC Overlay Prototype (Phase 4)
 - Provides an experimental QUIC listener with a Kyber KEM assisted session bootstrap.
 - Not production ready: no replay protection, no key rotation timing, limited error handling.
*/

#[cfg(feature = "quic-overlay")]
pub mod overlay {
    use quinn::{Endpoint, ServerConfig, TransportConfig};
    use std::{sync::Arc, net::SocketAddr, future, collections::HashMap};
    use anyhow::Result;
    use oqs::kem::{Kem, Algorithm as KemAlgorithm};
    use sha3::{Digest, Sha3_256, Sha3_256 as Sha3};
    use tokio::sync::RwLock;
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
    use rand::RngCore;
    // Using quinn stream convenience methods; no direct tokio Async* extension traits needed.

    pub struct QuicOverlayConfig { pub listen_addr: SocketAddr, pub kem_alg: KemAlgorithm }

    // Session representation
    #[derive(Clone)]
    #[allow(dead_code)] // stored for future message channel expansion
    struct SessionInfo { #[allow(dead_code)] key: Arc<ChaCha20Poly1305>, #[allow(dead_code)] cbid_short: String }

    #[derive(Clone, Default)]
    struct SessionStore { inner: Arc<RwLock<HashMap<String, SessionInfo>>> }
    impl SessionStore { async fn insert(&self, cbid: String, info: SessionInfo) { self.inner.write().await.insert(cbid, info); } }

    pub async fn run(cfg: QuicOverlayConfig) -> Result<()> {
        let kem = Kem::new(cfg.kem_alg).map_err(|e| anyhow::anyhow!("kem init: {e}"))?;
        let (srv_pk, srv_sk) = kem.keypair().map_err(|e| anyhow::anyhow!("kem keypair: {e}"))?;
    let endpoint = make_server(cfg.listen_addr)?;
        tracing::info!(addr=%cfg.listen_addr, kem=%format!("{:?}", cfg.kem_alg), "quic overlay listening");
        let sessions = SessionStore::default();
        let kem_state = Arc::new((kem, srv_pk, srv_sk, sessions));
        let kem_accept = kem_state.clone();
        // Local metrics instance; in a unified refactor this would be shared
        let metrics = crate::metrics::Metrics::new();
        tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let kem_state = kem_accept.clone();
                let m = metrics.clone();
                m.quic_active.inc();
                tokio::spawn(async move {
                    match connecting.await {
                        Ok(conn) => {
                            tracing::info!(remote=%conn.remote_address(), "quic conn established");
                            handshake(conn, kem_state).await;
                            m.quic_handshakes.inc();
                        }
                        Err(e) => tracing::warn!(?e, "quic connection failed"),
                    }
                    m.quic_active.dec();
                });
            }
        });
        // Keep the task alive indefinitely for prototype
        future::pending::<()>().await;
        Ok(())
    }

    fn make_server(addr: SocketAddr) -> Result<Endpoint> {
        let mut transport = TransportConfig::default();
        transport.max_concurrent_bidi_streams(32u32.into());
    // rcgen 0.13.* does not expose Certificate::from_params as an associated function
    // in this build context (feature set). Use helper to generate a simple self-signed cert.
    let cert = rcgen::generate_simple_self_signed(vec!["quic-local".into()])?;
    // rcgen 0.13 returns a CertifiedKey from generate_simple_self_signed
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];
    let priv_key = rustls::PrivateKey(key_der.clone());
        let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
        Arc::get_mut(&mut server_config.transport).unwrap().max_concurrent_bidi_streams(32u32.into());
        let endpoint = Endpoint::server(server_config, addr)?;
        Ok(endpoint)
    }

    async fn handshake(conn: quinn::Connection, kem_state: Arc<(Kem, oqs::kem::PublicKey, oqs::kem::SecretKey, SessionStore)>) {
        // Protocol (simplified / experimental):
        // 1. Server sends its Kyber public key (len + bytes) over uni stream A.
        // 2. Client responds on uni stream B with: ciphertext_len(u16) || ciphertext || optional tag_len(u8) || tag.
        // 3. Server decapsulates -> shared_secret.
        // 4. Derive session key = HKDF-SHA3(shared_secret, context=tag or empty, info="quic-overlay-v1")[0..32].
        // 5. Compute CBID = SHA3-256(shared_secret || tag) (matching HTTP cbid derivation style) and store session.
        // 6. Server opens uni stream C sending: cbid_len(u8) || cbid_hex || nonce(12) || test_ciphertext_len(u16) || test_ciphertext.
        // 7. Client can use same key for subsequent AEAD frames (NOT IMPLEMENTED HERE CLIENT SIDE).

        if let Err(e) = do_handshake(&conn, &kem_state).await { tracing::warn!(remote=%conn.remote_address(), error=%format!("{e:?}"), "quic handshake failed"); }
    }

    async fn do_handshake(conn: &quinn::Connection, kem_state: &Arc<(Kem, oqs::kem::PublicKey, oqs::kem::SecretKey, SessionStore)>) -> Result<()> {
    // Removed direct tokio Async* traits; using quinn's async I/O via streams directly.
        let (kem, srv_pk, srv_sk, sessions) = kem_state.as_ref();
        // 1. Send server public key
        if let Ok(mut out) = conn.open_uni().await {
            let pk = srv_pk.as_ref();
            out.write_all(&(pk.len() as u16).to_be_bytes()).await?;
            out.write_all(pk).await?;
        }
        // 2. Receive client ciphertext + tag
        let mut tag: Vec<u8> = Vec::new();
        let (ciphertext, tag) = if let Ok(mut incoming) = conn.accept_uni().await {
            let mut len_buf = [0u8;2]; incoming.read_exact(&mut len_buf).await?; let clen = u16::from_be_bytes(len_buf) as usize; if clen > 4096 { anyhow::bail!("ciphertext too large"); }
            let mut cbuf = vec![0u8; clen]; incoming.read_exact(&mut cbuf).await?;
            // optional tag
            let mut tlen_buf = [0u8;1]; match incoming.read_exact(&mut tlen_buf).await { Ok(()) => { let tlen = tlen_buf[0] as usize; if tlen > 64 { anyhow::bail!("tag too long"); } if tlen>0 { let mut t = vec![0u8; tlen]; incoming.read_exact(&mut t).await?; tag = t; } }, Err(_) => { /* no tag provided */ } }
            (cbuf, tag)
        } else { anyhow::bail!("client did not send ciphertext"); };
        // 3. Decapsulate (rebuild secret key ref then decap)
        let sk_ref = kem.secret_key_from_bytes(srv_sk.as_ref()).ok_or_else(|| anyhow::anyhow!("bad server sk bytes"))?;
        let ct_ref = kem.ciphertext_from_bytes(&ciphertext).ok_or_else(|| anyhow::anyhow!("bad ct bytes"))?;
        let shared = kem.decapsulate(&sk_ref, &ct_ref).map_err(|e| anyhow::anyhow!("decapsulate: {e}"))?;
        let shared_bytes = shared.as_ref();
        // 4. HKDF-SHA3
        let session_key = hkdf_sha3_256(shared_bytes, &tag, b"quic-overlay-v1"); // 32 bytes
        let key = Key::from_slice(&session_key);
        let aead = Arc::new(ChaCha20Poly1305::new(key));
        // 5. CBID
        let mut hasher = Sha3_256::new(); hasher.update(shared_bytes); hasher.update(&tag); let cbid_full = hasher.finalize(); let cbid_hex = hex::encode(&cbid_full); let cbid_short = cbid_hex[..32].to_string();
    sessions.insert(cbid_hex.clone(), SessionInfo { key: aead.clone(), cbid_short: cbid_short.clone() }).await;
        // 6. Send confirmation with encrypted test payload
        if let Ok(mut confirm) = conn.open_uni().await {
            // create a test encrypted message "ok"
            let mut nonce_bytes = [0u8;12]; rand::thread_rng().fill_bytes(&mut nonce_bytes); let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext_test = aead.encrypt(nonce, b"ok".as_ref()).unwrap_or_default();
            let cb = cbid_short.as_bytes();
            confirm.write_all(&[cb.len() as u8]).await?;
            confirm.write_all(cb).await?;
            confirm.write_all(&nonce_bytes).await?;
            confirm.write_all(&(ciphertext_test.len() as u16).to_be_bytes()).await?;
            confirm.write_all(&ciphertext_test).await?;
        }
        tracing::info!(remote=%conn.remote_address(), cbid=%cbid_short, tag_len=tag.len(), "quic kem handshake complete");
        Ok(())
    }

    fn hkdf_sha3_256(secret: &[u8], salt: &[u8], info: &[u8]) -> [u8;32] {
        // Simple HKDF-like: prk = H(salt || secret); okm = H(prk || info || 0x01)
        let mut h = Sha3::new(); h.update(salt); h.update(secret); let prk = h.finalize_reset();
        h.update(&prk); h.update(info); h.update([0x01]); let okm = h.finalize();
        let mut out = [0u8;32]; out.copy_from_slice(&okm[..32]); out
    }
}