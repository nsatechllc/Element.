use std::time::Duration;
use tokio::time::sleep;

pub async fn backoff_retry<F, Fut, T, E>(mut f: F, max_retries: u8) -> Result<T, E>
where
    F: FnMut(u8) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempt = 0u8;
    loop {
        match f(attempt).await {
            Ok(v) => return Ok(v),
            Err(_e) if attempt < max_retries => {
                let delay_ms = 50u64 * (1u64 << attempt.min(5));
                sleep(Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}
