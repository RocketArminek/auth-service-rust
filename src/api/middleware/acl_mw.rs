use crate::api::dto::MessageResponse;
use crate::api::extractor::auth_extractor::LoggedInUser;
use crate::api::server_state::ServerState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;

pub async fn restricted_acl(
    LoggedInUser(user): LoggedInUser,
    State(state): State<ServerState>,
    mut request: Request,
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

    request.extensions_mut().insert(user);
    next.run(request).await
}

pub async fn verified_acl(
    LoggedInUser(user): LoggedInUser,
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    tracing::debug!("Verified acl mw user: {:?}", user);

    if state.config.verification_required() && !user.is_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(MessageResponse {
                message: String::from("User is not verified!"),
            }),
        )
            .into_response();
    }

    next.run(request).await
}
