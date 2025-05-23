use crate::api::dto::Pagination;
use crate::api::dto::{MessageResponse, SessionListResponse};
use crate::api::server_state::ServerState;
use crate::domain::jwt::UserDTO;
use crate::domain::session::Session;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

#[utoipa::path(get, path = "/v1/restricted/sessions",
    tag="sessions-management",
    params(
        ("page" = Option<i32>, Query, description = "Page number default 1"),
        ("limit" = Option<i32>, Query, description = "Number of items per page default 10"),
    ),
    responses(
        (status = 200, description = "List of sessions", content_type = "application/json", body = SessionListResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn list_sessions(
    State(state): State<ServerState>,
    Query(pagination): Query<Pagination>,
) -> impl IntoResponse {
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10);

    let sessions = state.session_repository.get_all(page, limit).await;

    match sessions {
        Ok((items, total)) => {
            let pages = (total as f32 / limit as f32).ceil() as i32;
            (
                StatusCode::OK,
                Json(SessionListResponse {
                    items,
                    total,
                    page,
                    limit,
                    pages,
                }),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(get, path = "/v1/restricted/sessions/{id}",
    tag="sessions-management",
    params(
        ("id" = String, Path, description = "Session ID")
    ),
    responses(
        (status = 200, description = "Session details", content_type = "application/json", body = Session),
        (status = 404, description = "Session not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn get_session(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.session_repository.get_session_with_user(&id).await {
        Ok((session, _)) => (StatusCode::OK, Json(session)).into_response(),
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/restricted/sessions/{id}",
    tag="sessions-management",
    params(
        ("id" = String, Path, description = "Session ID")
    ),
    responses(
        (status = 200, description = "Session deleted", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "Session not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn delete_session(
    State(state): State<ServerState>,
    Extension(current_user): Extension<UserDTO>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.session_repository.get_by_id(&id).await {
        Ok(session) => {
            if session.user_id == current_user.id {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(MessageResponse {
                        message: "Cannot delete your own session".to_string(),
                    }),
                )
                    .into_response();
            }

            match state.session_repository.delete(&id).await {
                Ok(_) => (
                    StatusCode::OK,
                    Json(MessageResponse {
                        message: "Session deleted successfully".to_string(),
                    }),
                )
                    .into_response(),
                Err(e) => e.into_response(),
            }
        }
        Err(e) => e.into_response(),
    }
}
