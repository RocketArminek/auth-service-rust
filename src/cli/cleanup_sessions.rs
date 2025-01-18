use crate::domain::repositories::SessionRepository;
use chrono::Duration;
use std::sync::Arc;
use tokio::time::sleep;

pub async fn cleanup_expired_sessions(
    session_repository: Arc<dyn SessionRepository>,
    cleanup_interval_in_minutes: u64,
) {
    tracing::info!(
        "Cleanup expired session job started with interval {} minutes",
        cleanup_interval_in_minutes
    );

    loop {
        match session_repository.delete_expired().await {
            Ok(_) => tracing::debug!("Expired sessions cleaned up successfully"),
            Err(e) => tracing::error!("Failed to clean up expired sessions: {:?}", e),
        }

        sleep(
            Duration::minutes(cleanup_interval_in_minutes as i64)
                .to_std()
                .unwrap(),
        )
        .await;
    }
}
