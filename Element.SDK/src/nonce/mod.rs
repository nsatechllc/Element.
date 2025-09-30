use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct NonceTracker { inner: Arc<RwLock<HashMap<String, u64>>> }

impl NonceTracker {
    pub fn record_success(&self, key_id: &str, nonce: u64) { self.inner.write().insert(key_id.to_string(), nonce + 1); }
    pub fn expected(&self, key_id: &str) -> Option<u64> { self.inner.read().get(key_id).copied() }
}
