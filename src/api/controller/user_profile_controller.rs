use crate::api::dto::{
    ChangePasswordRequest, MessageResponse, UpdateUserRequest, VerifyUserRequest,
};
use crate::api::extractor::auth_extractor::{LoggedInUser, PasswordToken};
use crate::api::server_state::{SecretAware, ServerState};
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::error::UserError;
use crate::domain::event::UserEvents;
use crate::domain::event::UserEvents::PasswordReset;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use std::ops::Add;

#[utoipa::path(patch, path = "/v1/me/verification",
    request_body = VerifyUserRequest,
    tag="user",
    responses(
        (status = 200, description = "User verified", content_type = "application/json", body = UserDTO),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn verify(
    State(state): State<ServerState>,
    LoggedInUser(user): LoggedInUser,
    request: Json<VerifyUserRequest>,
) -> impl IntoResponse {
    let user = state.user_repository.get_by_id(&user.id).await;
    match user {
        Ok(mut user) => {
            if !state.config.verification_required() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(MessageResponse {
                        message: "Verification is not required!".to_string(),
                    }),
                )
                    .into_response();
            }
            if user.is_verified {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(MessageResponse {
                        message: "User is already verified!".to_string(),
                    }),
                )
                    .into_response();
            }

            let decoded = jsonwebtoken::decode::<Claims>(
                &request.token,
                &DecodingKey::from_secret(state.get_secret().as_ref()),
                &Validation::default(),
            );

            match decoded {
                Ok(t) => match t.claims.token_type {
                    TokenType::Verification => {
                        user.verify();
                        match state.user_repository.save(&user).await {
                            Ok(_) => {
                                let user_dto = UserDTO::from(user);

                                let result = state
                                    .message_publisher
                                    .publish(&UserEvents::Verified {
                                        user: user_dto.clone(),
                                    })
                                    .await;

                                if result.is_err() {
                                    tracing::error!(
                                        "Error publishing user verified event: {:?}",
                                        result
                                    );
                                }

                                (StatusCode::OK, Json(user_dto)).into_response()
                            }
                            Err(e) => {
                                tracing::error!("Failed to verify user: {:?}", e);
                                e.into_response()
                            }
                        }
                    }
                    _ => {
                        tracing::debug!("Invalid token type!");
                        (
                            StatusCode::BAD_REQUEST,
                            Json(MessageResponse {
                                message: "Invalid token type!".to_string(),
                            }),
                        )
                            .into_response()
                    }
                },
                Err(_) => {
                    tracing::debug!("Verification token is invalid!");
                    (
                        StatusCode::BAD_REQUEST,
                        Json(MessageResponse {
                            message: "Invalid token!".to_string(),
                        }),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            tracing::debug!("Failed to verify user");
            e.into_response()
        }
    }
}

#[utoipa::path(post, path = "/v1/me/verification/resend",
    tag="user",
    responses(
        (status = 200, description = "Ack", content_type = "application/json"),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn resend_verification(
    State(state): State<ServerState>,
    LoggedInUser(user): LoggedInUser,
) -> impl IntoResponse {
    let user = state.user_repository.get_by_id(&user.id).await;
    match user {
        Ok(user) => {
            if !state.config.verification_required() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(MessageResponse {
                        message: "Verification is not required!".to_string(),
                    }),
                )
                    .into_response();
            }
            if user.is_verified {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(MessageResponse {
                        message: "User is already verified!".to_string(),
                    }),
                )
                    .into_response();
            }

            let user_dto = UserDTO::from(user);
            let now = Utc::now();
            let vr_duration = Duration::new(state.config.vr_duration_in_seconds().to_signed(), 0)
                .unwrap_or_default();
            let vr_exp = now.add(vr_duration);

            let vr_body = Claims::new(
                vr_exp.timestamp() as usize,
                user_dto.clone(),
                TokenType::Verification,
                None,
            );

            let token = encode(
                &Header::default(),
                &vr_body,
                &EncodingKey::from_secret(state.get_secret().as_ref()),
            );

            match token {
                Ok(token) => {
                    let verification_requested = UserEvents::VerificationRequested {
                        user: user_dto,
                        token: token.clone(),
                    };

                    tracing::debug!("Resend verification requested. Token: {}", token);

                    let result = state
                        .message_publisher
                        .publish(&verification_requested)
                        .await;

                    match result {
                        Ok(_) => StatusCode::OK.into_response(),
                        Err(e) => {
                            tracing::error!("Error publishing user events: {:?}", e);
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to encode verification token {:?}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(e) => {
            tracing::debug!("Failed to resend user: {:?}", e);
            e.into_response()
        }
    }
}

#[utoipa::path(patch, path = "/v1/me/password/reset",
    request_body = ChangePasswordRequest,
    tag="user",
    responses(
        (status = 200, description = "Ack", content_type = "application/json"),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn reset_password(
    State(state): State<ServerState>,
    PasswordToken(user): PasswordToken,
    request: Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let user = state.user_repository.get_by_id(&user.id).await;

    match user {
        Ok(mut user) => {
            let result = user.change_password(
                &request.password,
                &SchemeAwareHasher::with_scheme(state.config.password_hashing_scheme()),
            );

            match result {
                Ok(_) => {
                    let result = state.user_repository.save(&user).await;

                    match result {
                        Ok(_) => {
                            let user_dto = UserDTO::from(user);
                            let password_reset = PasswordReset { user: user_dto };

                            let result = state.message_publisher.publish(&password_reset).await;

                            match result {
                                Ok(_) => StatusCode::OK.into_response(),
                                Err(e) => {
                                    tracing::error!(
                                        "Error publishing reset password requested: {:?}",
                                        e
                                    );
                                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to save user during password change: {:?}", e);
                            e.into_response()
                        }
                    }
                }
                Err(error) => match error {
                    UserError::InvalidPassword { reason } => (
                        StatusCode::BAD_REQUEST,
                        Json(MessageResponse {
                            message: format!(
                                "Invalid password: {}",
                                reason.unwrap_or("unknown".to_string())
                            ),
                        }),
                    )
                        .into_response(),
                    _ => (
                        StatusCode::BAD_REQUEST,
                        Json(MessageResponse {
                            message: "Something went wrong".to_string(),
                        }),
                    )
                        .into_response(),
                },
            }
        }
        Err(e) => {
            tracing::debug!("Failed to get user during change password request: {:?}", e);
            e.into_response()
        }
    }
}

#[utoipa::path(put, path = "/v1/me",
    request_body = UpdateUserRequest,
    tag="user",
    responses(
        (status = 200, description = "User updated", content_type = "application/json", body = UserDTO),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn update_profile(
    State(state): State<ServerState>,
    LoggedInUser(user): LoggedInUser,
    request: Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let first_name = request.first_name.clone();
    let last_name = request.last_name.clone();
    let avatar_path = request.avatar_path.clone();

    let user = state.user_repository.get_by_id(&user.id).await;
    match user {
        Ok(old_user) => {
            let mut user = old_user.clone();
            user.first_name = Some(first_name);
            user.last_name = Some(last_name);
            user.avatar_path = avatar_path;

            match state.user_repository.save(&user).await {
                Ok(_) => {
                    let user_dto = UserDTO::from(user);

                    let result = state
                        .message_publisher
                        .publish(&UserEvents::Updated {
                            old_user: UserDTO::from(old_user),
                            new_user: user_dto.clone(),
                        })
                        .await;

                    if result.is_err() {
                        tracing::error!("Error publishing user updated event: {:?}", result);
                    }

                    (StatusCode::OK, Json(user_dto)).into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to update user: {:?}", e);
                    e.into_response()
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to update user");
            e.into_response()
        }
    }
}
