/*
 Automated · Intelligent · Natural
  - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Expose git/hash/time for build info metric
    if let Ok(output) = std::process::Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
        if output.status.success() { println!("cargo:rustc-env=GIT_SHA={}", String::from_utf8_lossy(&output.stdout).trim()); }
    }
    // Use RFC3339-like timestamp via system time (no chrono dependency needed)
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    println!("cargo:rustc-env=BUILD_TS={}s", ts);
    if std::env::var("CARGO_FEATURE_GRPC").is_ok() {
        println!("cargo:rerun-if-changed=proto/element.proto");
        tonic_prost_build::configure()
            .build_server(true)
            .compile_protos(&["proto/element.proto"], &["proto"])?;
    }
    Ok(())
}