use thiserror::Error;
use std::time::Duration;

#[derive(Debug, Error)]
pub enum Error {
    #[error("http error: {0}")] Http(#[from] request::Error),
    #[error("timeout")] Timeout,
    #[error("rate limited")] RateLimited { retry_after: Option<Duration> },
    #[error("nonce out of order")] NonceOutOfOrder,
    #[error("invalid base64: {0}")] InvalidBase64(&'static str),
    #[error("invalid length: {0}")] InvalidLength(&'static str),
    #[error("key not found")] KeyNotFound,
    #[error("algorithm not allowed")] AlgNotAllowed,
    #[error("session invalid")] SessionInvalid,
    #[error("tag too long")] TagTooLong,
    #[error("server error code: {0}")] Server(String),
    #[error("decode error: {0}")] Decode(String),
    #[error("config error: {0}")] Config(String),
    #[error("unsupported: {0}")] Unsupported(&'static str),
}

impl Error {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::RateLimited { .. })
    }
}
