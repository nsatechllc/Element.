/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
use serde::Serialize; use thiserror::Error; #[derive(Debug, Error)] pub enum SeError { #[error("invalid request: {0}")] InvalidRequest(String), #[error("internal error")] Internal } #[derive(Serialize)] pub struct ErrorBody<'a> { pub error_code: &'a str, pub message: &'a str }