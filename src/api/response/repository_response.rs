use crate::api::dto::MessageResponse;
use crate::infrastructure::repository::RepositoryError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

impl IntoResponse for RepositoryError {
    fn into_response(self) -> axum::response::Response {
        match self {
            RepositoryError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                Json(MessageResponse { message: msg }),
            )
                .into_response(),
            RepositoryError::Conflict(msg) => {
                (StatusCode::CONFLICT, Json(MessageResponse { message: msg })).into_response()
            }
            RepositoryError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                Json(MessageResponse { message: msg }),
            )
                .into_response(),
            RepositoryError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(MessageResponse {
                        message: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}
