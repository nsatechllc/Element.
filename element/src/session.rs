/*
 Session & Token Management
 - Maintains mapping of issued session tokens -> expiry
 - Bridges QUIC-derived CBIDs to HTTP auth tokens.
*/
use std::{time::{SystemTime, UNIX_EPOCH}, sync::Arc};
use dashmap::DashMap;
use rand::RngCore;
use base64::Engine;
use sha3::{Digest, Sha3_256};

#[derive(Clone)]
pub struct TokenStore { inner: Arc<DashMap<String, (u64, String)>> } // token -> (expires_at_unix, cbid)
impl TokenStore {
    pub fn new() -> Self { Self { inner: Arc::new(DashMap::new()) } }
    pub fn issue(&self, cbid: &str, ttl_secs: u64) -> (String, u64) {
        let mut rand_bytes = [0u8;32]; rand::thread_rng().fill_bytes(&mut rand_bytes);
        let mut h = Sha3_256::new(); h.update(b"TOKEN-V1"); h.update(cbid.as_bytes()); h.update(&rand_bytes);
        let digest = h.finalize();
        let mut token_raw = Vec::with_capacity(32+32);
        token_raw.extend_from_slice(&rand_bytes);
        token_raw.extend_from_slice(&digest[..]);
        let token = base64::engine::general_purpose::STANDARD.encode(token_raw);
        let exp_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + ttl_secs;
        self.inner.insert(token.clone(), (exp_unix, cbid.to_string()));
        (token, exp_unix)
    }
    pub fn validate(&self, token: &str) -> Option<String> {
        if let Some(entry) = self.inner.get(token) { if entry.value().0 >= now_unix() { return Some(entry.value().1.clone()); } }
        None
    }
    pub fn reap_expired(&self) { let now = now_unix(); let mut dead = Vec::new(); for kv in self.inner.iter() { if kv.value().0 < now { dead.push(kv.key().clone()); } } for k in dead { self.inner.remove(&k); } }
    pub fn count(&self) -> usize { self.inner.len() }
}

fn now_unix() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }

// Global singletons (set by main)
use once_cell::sync::OnceCell;
static TOKEN_STORE: OnceCell<TokenStore> = OnceCell::new();

pub fn init_global_token_store() -> TokenStore { let ts = TokenStore::new(); TOKEN_STORE.set(ts.clone()).ok(); ts }
pub fn global_token_store() -> Option<&'static TokenStore> { TOKEN_STORE.get() }
