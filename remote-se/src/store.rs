use std::sync::Arc;
use dashmap::DashMap;
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::Alg;
use zeroize::Zeroize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct KeyRecord {
    pub key_id: String,
    pub alg: Alg,
    pub public_key: Arc<Vec<u8>>, // PQC public key
    pub secret_key: SecretMaterial,
    pub created_at: u64,
    pub usage_count: AtomicU64,
    pub last_nonce: AtomicU64,
}

impl KeyRecord {
    pub fn new(key_id: String, alg: Alg, public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            key_id,
            alg,
            public_key: Arc::new(public_key),
            secret_key: SecretMaterial::new(secret_key),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            usage_count: AtomicU64::new(0),
            last_nonce: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
pub struct SecretMaterial { inner: Vec<u8> }
impl SecretMaterial { pub fn new(inner: Vec<u8>) -> Self { Self { inner } } pub fn bytes(&self) -> &[u8] { &self.inner } }
impl Drop for SecretMaterial { fn drop(&mut self) { self.inner.zeroize(); } }

#[derive(Default)]
pub struct KeyStore { map: DashMap<String, Arc<KeyRecord>> }

impl KeyStore {
    pub fn new() -> Self { Self { map: DashMap::new() } }

    pub fn generate(&self, alg: Alg, pk: Vec<u8>, sk: Vec<u8>) -> Arc<KeyRecord> {
        let key_id = self.random_key_id();
        let rec = Arc::new(KeyRecord::new(key_id.clone(), alg, pk, sk));
        self.map.insert(key_id.clone(), rec.clone());
        rec
    }

    pub fn get(&self, key_id: &str) -> Option<Arc<KeyRecord>> { self.map.get(key_id).map(|v| v.clone()) }

    fn random_key_id(&self) -> String {
        let mut buf = [0u8; 8]; OsRng.fill_bytes(&mut buf); hex::encode(buf)
    }
}

pub fn next_nonce_strict(rec: &Arc<KeyRecord>, provided: u64) -> Result<(), &'static str> {
    let current = rec.last_nonce.load(Ordering::Relaxed);
    let expected = current + 1;
    if provided != expected { return Err("NONCE_OUT_OF_ORDER"); }
    match rec.last_nonce.compare_exchange(current, provided, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(()),
        Err(_) => Err("NONCE_OUT_OF_ORDER"),
    }
}