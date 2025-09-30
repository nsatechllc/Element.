use prometheus::{Registry, IntCounter, Histogram, HistogramOpts, IntCounterVec};

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    pub sign_total: IntCounter,
    pub sign_latency: Histogram,
    pub verify_fail: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let sign_total = IntCounter::new("se_sign_total", "Total sign operations").unwrap();
        let sign_latency = Histogram::with_opts(HistogramOpts::new("se_sign_latency_ms", "Sign latency ms").buckets(vec![0.5,1.0,2.0,5.0,10.0,25.0,50.0])).unwrap();
        let verify_fail = IntCounterVec::new(prometheus::Opts::new("se_verify_fail_total", "Failed verifications"), &["alg"]).unwrap();
        registry.register(Box::new(sign_total.clone())).ok();
        registry.register(Box::new(sign_latency.clone())).ok();
        registry.register(Box::new(verify_fail.clone())).ok();
        Self { registry, sign_total, sign_latency, verify_fail }
    }

    pub fn registry_gather(&self) -> serde_json::Value {
        let mf = self.registry.gather();
        serde_json::json!({
            "metrics_families": mf.iter().map(|m| m.get_name()).collect::<Vec<_>>()
        })
    }
}