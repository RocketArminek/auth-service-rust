use crate::api::axum_extractor::{StatelessLoggedInUser};
use crate::api::dto::{CreateUserRequest, CreatedResponse, MessageResponse, UpdateUserRequest, VerifyUserRequest};
use crate::api::server_state::{SecretAware, ServerState};
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::error::UserError;
use crate::domain::event::UserEvents;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::user::{PasswordHandler, User};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header, Validation};
use std::ops::Add;
use std::string::ToString;

#[utoipa::path(post, path = "/v1/users",
    request_body = CreateUserRequest,
    tag="user",
    responses(
        (status = 201, description = "User created", content_type = "application/json", body = CreatedResponse),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 409, description = "User already exists", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn create_user(
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

    let existing = state
        .user_repository
        .lock()
        .await
        .get_by_email(&email)
        .await;
    if let Ok(_) = existing {
        return (
            StatusCode::CONFLICT,
            Json(MessageResponse {
                message: "User already exists".to_string(),
            }),
        )
            .into_response();
    }

    let existing_role = state.role_repository.lock().await.get_by_name(&role).await;
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

            tokio::task::spawn(async move {
                if let Err(e) = user.hash_password(&SchemeAwareHasher::with_scheme(
                    state.config.password_hashing_scheme(),
                )) {
                    tracing::error!("Failed to hash user's password: {:?}", e);

                    return;
                }

                user.add_roles(vec![existing_role.clone()]);
                match state.user_repository.lock().await.save(&user).await {
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
                            );

                            let token = encode(
                                &Header::default(),
                                &vr_body,
                                &EncodingKey::from_secret(state.get_secret().as_ref()),
                            );

                            if let Ok(token) = token {
                                let verification_requested = UserEvents::VerificationRequested {
                                    user: user_dto,
                                    token,
                                };

                                events.push(&verification_requested);

                                let result = state
                                    .message_publisher
                                    .lock()
                                    .await
                                    .publish_all(events)
                                    .await;

                                if result.is_err() {
                                    tracing::error!("Error publishing user events: {:?}", result);
                                }

                                return;
                            }
                        }

                        let result = state
                            .message_publisher
                            .lock()
                            .await
                            .publish_all(events)
                            .await;

                        if result.is_err() {
                            tracing::error!("Error publishing user events: {:?}", result);
                        }
                    }
                    Err(error) => tracing::error!("Failed to create user {:?}", error),
                }
            });

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
    StatelessLoggedInUser(user): StatelessLoggedInUser,
    request: Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let first_name = request.first_name.clone();
    let last_name = request.last_name.clone();
    let avatar_path = request.avatar_path.clone();

    let user = state.user_repository.lock().await.get_by_id(&user.id).await;
    match user {
        Ok(old_user) => {
            let mut user = old_user.clone();
            user.first_name = Some(first_name);
            user.last_name = Some(last_name);
            user.avatar_path = avatar_path;

            match state.user_repository.lock().await.save(&user).await {
                Ok(_) => {
                    let user_dto = UserDTO::from(user);

                    let result = state
                        .message_publisher
                        .lock()
                        .await
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
    StatelessLoggedInUser(user): StatelessLoggedInUser,
    request: Json<VerifyUserRequest>,
) -> impl IntoResponse {
    let user = state.user_repository.lock().await.get_by_id(&user.id).await;
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
                Ok(t) => {
                    match t.claims.token_type {
                        TokenType::Verification => {
                            user.verify();
                            match state.user_repository.lock().await.save(&user).await {
                                Ok(_) => {
                                    let user_dto = UserDTO::from(user);

                                    let result = state
                                        .message_publisher
                                        .lock()
                                        .await
                                        .publish(&UserEvents::Verified {
                                            user: user_dto.clone(),
                                        })
                                        .await;

                                    if result.is_err() {
                                        tracing::error!("Error publishing user verified event: {:?}", result);
                                    }

                                    (StatusCode::OK, Json(user_dto)).into_response()
                                }
                                Err(e) => {
                                    tracing::error!("Failed to verify user: {:?}", e);
                                    e.into_response()
                                }
                            }
                        },
                        _ => {
                            tracing::debug!("Invalid token type!");
                            (StatusCode::BAD_REQUEST, Json(MessageResponse {
                                message: "Invalid token type!".to_string(),
                            })).into_response()
                        },
                    }
                }
                Err(_) => {
                    tracing::debug!("Verification token is invalid!");
                    (StatusCode::BAD_REQUEST, Json(MessageResponse {
                        message: "Invalid token!".to_string(),
                    })).into_response()
                }
            }
        }
        Err(e) => {
            tracing::debug!("Failed to verify user");
            e.into_response()
        }
    }
}

#[utoipa::path(patch, path = "/v1/me/verification/resend",
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
    StatelessLoggedInUser(user): StatelessLoggedInUser,
) -> impl IntoResponse {
    let user = state.user_repository.lock().await.get_by_id(&user.id).await;
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
            let vr_duration =
                Duration::new(state.config.vr_duration_in_seconds().to_signed(), 0)
                    .unwrap_or_default();
            let vr_exp = now.add(vr_duration);

            let vr_body = Claims::new(
                vr_exp.timestamp() as usize,
                user_dto.clone(),
                TokenType::Verification,
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
                        token,
                    };

                    let result = state
                        .message_publisher
                        .lock()
                        .await
                        .publish(&verification_requested)
                        .await;

                    match result {
                        Ok(_) => {
                            StatusCode::OK.into_response()
                        }
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
