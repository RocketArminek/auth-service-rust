use crate::api::axum_extractor::StatelessLoggedInUser;
use crate::api::dto::MessageResponse;
use crate::api::server_state::ServerState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;

pub async fn restricted_acl(
    StatelessLoggedInUser(user): StatelessLoggedInUser,
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    tracing::info!("User: {:?}", user);

    let is_allowed = user
        .roles
        .iter()
        .any(|role| state.restricted_role_pattern.is_match(role.as_str()));

    if !is_allowed {
        return (
            StatusCode::FORBIDDEN,
            Json(MessageResponse {
                message: "Forbidden".to_string(),
            }),
        )
            .into_response();
    }

    let response = next.run(request).await;

    response
}
