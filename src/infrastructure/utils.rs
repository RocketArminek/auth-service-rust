use std::fmt::Display;
use std::time::Duration;

pub async fn retry_with_backoff<T, E, F, Fut>(
    operation: F,
    description: &str,
    max_retries: u32,
    initial_delay: Duration,
    exponential: bool
) -> Result<T, E> where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: Display
{
    let mut retries = 0;
    let mut delay = initial_delay;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if retries >= max_retries {
                    tracing::error!(
                        "Maximum retry attempts for {} ({}) reached. Last error: {}",
                        description,
                        max_retries,
                        error
                    );

                    return Err(error);
                }

                tracing::warn!(
                    "Connection to {} attempt {} failed: {}. Retrying in {}ms...",
                    description,
                    retries + 1,
                    error,
                    delay.as_millis()
                );

                tokio::time::sleep(delay).await;
                retries += 1;
                delay *= if exponential { 2 } else { 1 };
            }
        }
    }
}
