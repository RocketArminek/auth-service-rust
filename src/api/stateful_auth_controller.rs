use std::ops::Add;
use crate::api::dto::{LoginRequest, LoginResponse, MessageResponse, TokenResponse};
use crate::api::server_state::ServerState;
use crate::domain::crypto::{Hasher, SchemeAwareHasher};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use crate::api::axum_stateful_extractor::LoggedInUser;
use crate::domain::jwt::{StatelessClaims, UserDTO};
use crate::domain::user::PasswordHandler;
use crate::domain::jwt::{StatefulClaims, TokenType};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use crate::domain::session::Session;

#[utoipa::path(post, path = "/v1/stateful/login",
    tag="stateful",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login response", content_type = "application/json", body = LoginResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn login(
    State(state): State<ServerState>,
    request: Json<LoginRequest>,
) -> impl IntoResponse {
    let email = request.email.clone();
    let password = request.password.clone();
    let user = state
        .user_repository
        .lock()
        .await
        .get_by_email(&email)
        .await;

    match user {
        Ok(user) => {
            let hasher = SchemeAwareHasher::with_scheme(state.config.password_hashing_scheme());
            let at_duration_in_seconds = state.config.at_duration_in_seconds().to_signed();
            let rt_duration_in_seconds = state.config.rt_duration_in_seconds().to_signed();
            let secret = state.config.secret().to_string();

            if !user.verify_password(&hasher, &password) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(MessageResponse {
                        message: String::from("Unauthorized"),
                    }),
                )
                    .into_response();
            }

            if hasher.is_password_outdated(&user.password) {
                let mut outdated_user = user.clone();
                let scheme = state.config.password_hashing_scheme();
                tokio::task::spawn(async move {
                    tracing::debug!(
                        "Password hash outdated for {}({}), updating...",
                        &outdated_user.email,
                        &outdated_user.id
                    );
                    let new_password = SchemeAwareHasher::with_scheme(scheme)
                        .hash_password(&password)
                        .unwrap_or(outdated_user.password.clone());
                    outdated_user.set_password(new_password);
                    let outdated_user = outdated_user.into();
                    match state
                        .user_repository
                        .lock()
                        .await
                        .save(&outdated_user)
                        .await
                    {
                        Ok(_) => tracing::debug!(
                            "Password updated for {}({})",
                            &outdated_user.email,
                            &outdated_user.id
                        ),
                        Err(e) => tracing::error!("Could not update password hash {:?}", e),
                    }
                });
            }

            let user_response = UserDTO::from(user.clone());

            let now = Utc::now();

            let at_duration = Duration::new(at_duration_in_seconds, 0).unwrap_or_default();
            let at_exp = now.add(at_duration);

            let rt_duration = Duration::new(rt_duration_in_seconds, 0).unwrap_or_default();
            let rt_exp = now.add(rt_duration);

            let session = Session::now(user.id, rt_exp.clone());

            let at_body = StatefulClaims::new(
                at_exp.timestamp() as usize,
                user_response.clone(),
                TokenType::Access,
                session.id.clone()
            );

            let access_token = encode(
                &Header::default(),
                &at_body,
                &EncodingKey::from_secret(secret.as_ref()),
            );

            let rt_body = StatelessClaims::new(
                rt_exp.timestamp() as usize,
                user_response.clone(),
                TokenType::Refresh,
            );

            let refresh_token = encode(
                &Header::default(),
                &rt_body,
                &EncodingKey::from_secret(secret.as_ref()),
            );

            match (access_token, refresh_token) {
                (Ok(access_token), Ok(refresh_token)) => {
                    match state.session_repository.lock().await.save(&session).await {
                        Ok(_) => (
                            StatusCode::OK,
                            Json(LoginResponse {
                                user: user_response,
                                access_token: TokenResponse {
                                    value: access_token,
                                    expires_at: at_exp.timestamp() as usize,
                                },
                                refresh_token: TokenResponse {
                                    value: refresh_token,
                                    expires_at: rt_exp.timestamp() as usize,
                                },
                            }),
                        )
                            .into_response(),
                        Err(e) => {
                            tracing::error!("Could not create session: {:?}", e);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(MessageResponse {
                                    message: String::from("Could not create session"),
                                }),
                            )
                                .into_response()
                        }
                    }
                }
                _ => (
                    StatusCode::FORBIDDEN,
                    Json(MessageResponse {
                        message: String::from("Could not encode token"),
                    }),
                )
                    .into_response(),
            }
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(post, path = "/v1/stateful/logout",
    tag="stateful",
    responses(
        (status = 200, description = "Delete current session", content_type = "application/json",),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn logout(
    State(state): State<ServerState>,
    LoggedInUser{ session, .. }: LoggedInUser
) -> impl IntoResponse {
    let result = state.session_repository
        .lock().await.delete(&session.id).await;

    match result {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(get, path = "/v1/stateful/authenticate",
    tag="stateful",
    responses(
        (status = 200, description = "Session verified", content_type = "application/json", body = UserDTO),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn authenticate(
    LoggedInUser { user, .. }: LoggedInUser
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    let user_id = user.id;
    let user_roles = user.roles.join(",");
    headers.insert(
        "X-User-Id",
        HeaderValue::from_str(&user_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        "X-User-Roles",
        HeaderValue::from_str(&user_roles.as_str()).unwrap_or(HeaderValue::from_static("")),
    );

    (StatusCode::OK, headers, Json(UserDTO::from(user))).into_response()
}
