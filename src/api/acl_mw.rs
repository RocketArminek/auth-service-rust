use crate::api::axum_extractor::LoggedInUser;
use crate::api::dto::MessageResponse;
use crate::api::server_state::ServerState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;

pub async fn restricted_acl(
    LoggedInUser(user): LoggedInUser,
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    tracing::debug!("Restricted acl mw: User: {:?}", user);

    let is_allowed = user.roles.iter().any(|role| {
        state
            .config
            .restricted_role_pattern()
            .is_match(role.as_str())
    });

    if !is_allowed {
        return (
            StatusCode::FORBIDDEN,
            Json(MessageResponse {
                message: "Forbidden".to_string(),
            }),
        )
            .into_response();
    }

    next.run(request).await
}

pub async fn verified_acl(
    LoggedInUser(user): LoggedInUser,
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    tracing::debug!("Verified acl mw user: {:?}", user);
    tracing::debug!("Verified acl mw config: {:?}", state.config);

    if state.config.verification_required() {
        if !user.is_verified {
            return (
                StatusCode::FORBIDDEN,
                Json(MessageResponse {
                    message: String::from("User is not verified!"),
                }),
            )
                .into_response();
        }
    }

    next.run(request).await
}
