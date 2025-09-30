/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
use anyhow::Result; pub struct Config { pub listen_addr: String } impl Config { pub fn from_env() -> Result<Self> { let listen_addr = std::env::var("SE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()); Ok(Self { listen_addr }) } }