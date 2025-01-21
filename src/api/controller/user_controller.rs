use crate::api::dto::{CreateUserRequest, CreatedResponse, MessageResponse, ResetPasswordRequest};
use crate::api::server_state::{SecretAware, ServerState};
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::error::UserError;
use crate::domain::event::UserEvents;
use crate::domain::event::UserEvents::PasswordResetRequested;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::user::{PasswordHandler, User};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::ops::Add;
use std::string::ToString;

#[utoipa::path(post, path = "/v1/users",
    request_body = CreateUserRequest,
    tag="user",
    responses(
        (status = 201, description = "New user registered", content_type = "application/json", body = CreatedResponse),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 409, description = "User already exists", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn register(
    State(state): State<ServerState>,
    request: Json<CreateUserRequest>,
) -> impl IntoResponse {
    let email = request.email.clone();
    let password = request.password.clone();
    let role = request.role.clone();
    if state
        .config
        .restricted_role_pattern()
        .is_match(role.as_str())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(MessageResponse {
                message: "Role is restricted".to_string(),
            }),
        )
            .into_response();
    }

    let existing = state.user_repository.get_by_email(&email).await;
    if let Ok(_) = existing {
        return (
            StatusCode::CONFLICT,
            Json(MessageResponse {
                message: "User already exists".to_string(),
            }),
        )
            .into_response();
    }

    let existing_role = state.role_repository.get_by_name(&role).await;
    if let Err(_) = existing_role {
        return (
            StatusCode::BAD_REQUEST,
            Json(MessageResponse {
                message: "Role does not exist".to_string(),
            }),
        )
            .into_response();
    }
    let existing_role = existing_role.unwrap();

    let is_verified = !state.config.verification_required();
    let user = User::now_with_email_and_password(email, password, None, None, Some(is_verified));

    match user {
        Ok(mut user) => {
            let id = user.id.clone();

            if let Err(e) = user.hash_password(&SchemeAwareHasher::with_scheme(
                state.config.password_hashing_scheme(),
            )) {
                tracing::error!("Failed to hash user's password: {:?}", e);

                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            user.add_roles(vec![existing_role.clone()]);
            match state.user_repository.save(&user).await {
                Ok(_) => {
                    tracing::debug!("User created: {}", &user.email);
                    let user_dto = UserDTO::from(user);
                    let user_created = UserEvents::Created {
                        user: user_dto.clone(),
                    };
                    let mut events = vec![&user_created];

                    if !user_dto.is_verified {
                        let now = Utc::now();
                        let vr_duration =
                            Duration::new(state.config.vr_duration_in_seconds().to_signed(), 0)
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

                        if let Ok(token) = token {
                            let verification_requested = UserEvents::VerificationRequested {
                                user: user_dto,
                                token: token.clone(),
                            };

                            tracing::debug!("User verification requested. Token {}", token);

                            events.push(&verification_requested);

                            let result = state.message_publisher.publish_all(events).await;

                            if result.is_err() {
                                tracing::error!("Error publishing user events: {:?}", result);
                            }

                            return (
                                StatusCode::CREATED,
                                Json(CreatedResponse { id: id.to_string() }),
                            )
                                .into_response();
                        }
                    }

                    let result = state.message_publisher.publish_all(events).await;

                    if result.is_err() {
                        tracing::error!("Error publishing user events: {:?}", result);
                    }
                }
                Err(error) => tracing::error!("Failed to create user {:?}", error),
            }

            (
                StatusCode::CREATED,
                Json(CreatedResponse { id: id.to_string() }),
            )
                .into_response()
        }
        Err(error) => {
            tracing::debug!("Failed to create user {:?}", error);
            match error {
                UserError::InvalidEmail { email } => (
                    StatusCode::BAD_REQUEST,
                    Json(MessageResponse {
                        message: format!("Invalid email: {}", email),
                    }),
                )
                    .into_response(),
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
            }
        }
    }
}

#[utoipa::path(post, path = "/v1/password/reset",
    request_body = ResetPasswordRequest,
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
pub async fn request_password_reset(
    State(state): State<ServerState>,
    request: Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    let user = state.user_repository.get_by_email(&request.email).await;

    match user {
        Ok(user) => {
            let user_dto = UserDTO::from(user);
            let now = Utc::now();
            let rp_duration = Duration::new(state.config.rp_duration_in_seconds().to_signed(), 0)
                .unwrap_or_default();
            let rp_exp = now.add(rp_duration);

            let rp_body = Claims::new(
                rp_exp.timestamp() as usize,
                user_dto.clone(),
                TokenType::Password,
                None,
            );

            let token = encode(
                &Header::default(),
                &rp_body,
                &EncodingKey::from_secret(state.get_secret().as_ref()),
            );

            match token {
                Ok(token) => {
                    let password_reset_requested = PasswordResetRequested {
                        user: user_dto,
                        token: token.clone(),
                    };

                    tracing::debug!("Reset password reset requested. Token: {}", token);

                    let result = state
                        .message_publisher
                        .publish(&password_reset_requested)
                        .await;

                    match result {
                        Ok(_) => StatusCode::OK.into_response(),
                        Err(e) => {
                            tracing::error!("Error publishing reset password requested: {:?}", e);
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to encode reset password token {:?}", e);

                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(e) => {
            tracing::debug!("Failed to get user during password request: {:?}", e);
            e.into_response()
        }
    }
}
