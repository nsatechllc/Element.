/*
 Automated · Intelligent · Natural
  - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
#![cfg(feature = "pqc")]
use std::time::Duration;
use tokio::time::sleep;
use base64::{engine::general_purpose, Engine};

#[tokio::test]
async fn batch_sign_basic() {
    // Spin up server on ephemeral port
    let addr = "127.0.0.1:58081";
    std::env::set_var("SE_RATE_CAPACITY", "100");
    std::env::set_var("SE_RATE_FILL_PER_SEC", "100");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        element::run_http_listener(listener).await.unwrap();
    });
    sleep(Duration::from_millis(120)).await;

    let client = reqwest::Client::new();

    // Generate key
    let gen = client.post(format!("http://{addr}/keys"))
        .json(&serde_json::json!({"alg":"dilithium5"}))
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();
    let key_id = gen["key_id"].as_str().unwrap().to_string();

    let digest = [0x11u8;32];
    let ctx = [0x22u8;32];
    let d_b64 = general_purpose::STANDARD.encode(digest);
    let c_b64 = general_purpose::STANDARD.encode(ctx);

    let batch = serde_json::json!({
        "items": [
            {"key_id": key_id, "digest": d_b64, "context_binding": c_b64, "nonce":1}
        ]
    });
    let resp = client.post(format!("http://{addr}/sign/batch")).json(&batch).send().await.unwrap().json::<serde_json::Value>().await.unwrap();
    assert_eq!(resp["results"][0]["status"], "OK");
}
