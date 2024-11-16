use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::user::{PasswordHandler, User};
use axum::extract::{State};
use axum::http::{StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use crate::api::axum_extractor::StatelessLoggedInUser;
use crate::api::dto::{CreatedResponse, CreateUserRequest, MessageResponse, UpdateUserRequest, UserDTO};
use crate::api::server_state::ServerState;
use crate::domain::error::UserError;

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
    if state.restricted_role_pattern.is_match(role.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(MessageResponse {
            message: "Role is restricted".to_string(),
        })).into_response();
    }

    let existing = state.user_repository
        .lock()
        .await
        .get_by_email(&email)
        .await;
    if existing.is_some() {
        return (StatusCode::CONFLICT, Json(MessageResponse {
            message: "User already exists".to_string(),
        })).into_response();
    }

    let existing_role = state.role_repository.lock().await.get_by_name(&role).await;
    if existing_role.is_none() {
        return (StatusCode::BAD_REQUEST, Json(MessageResponse {
            message: "Role does not exist".to_string(),
        })).into_response();
    }
    let existing_role = existing_role.unwrap();

    let user = User::now_with_email_and_password(
        email,
        password,
        None,
        None,
    );

    match user {
        Ok(mut user) => {
            let id = user.id.clone();

            tokio::task::spawn(
                async move {
                    user.hash_password(&SchemeAwareHasher::with_scheme(state.hashing_scheme));
                    match state.user_repository.lock().await.add_with_role(&user, existing_role.id).await {
                        Ok(_) => tracing::info!("User created: {}", user.email),
                        Err(error) => tracing::warn!("Failed to create user {:?}", error),
                    }
                }
            );

            (StatusCode::CREATED, Json(CreatedResponse {
                id: id.to_string(),
            })).into_response()
        }
        Err(error) => {
            tracing::info!("Failed to create user {:?}", error);
            match error {
                UserError::InvalidEmail { email} => {
                    (StatusCode::BAD_REQUEST, Json(MessageResponse {
                        message: format!("Invalid email: {}", email),
                    })).into_response()
                }
                UserError::InvalidPassword {reason} => {
                    (StatusCode::BAD_REQUEST, Json(MessageResponse {
                        message: format!("Invalid password: {}", reason.unwrap_or("unknown".to_string())),
                    })).into_response()
                }
                _ => {
                    (StatusCode::BAD_REQUEST, Json(MessageResponse {
                        message: "Something went wrong".to_string(),
                    })).into_response()
                }
            }
        }
    }
}

#[utoipa::path(put, path = "/v1/me",
    request_body = UpdateUserRequest,
    tag="user",
    params(
        ("id" = String, Path, description = "User ID")
    ),
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

    let user = state.user_repository.lock().await.get_by_id(user.id).await;
    match user {
        None => {
            (StatusCode::NOT_FOUND, Json(MessageResponse {
                message: "User not found".to_string(),
            })).into_response()
        }
        Some(user) => {
            let mut user = user.clone();
            user.first_name = Some(first_name);
            user.last_name = Some(last_name);
            user.avatar_path = avatar_path;

            match state.user_repository.lock().await.update(&user).await {
                Ok(_) => {
                    (StatusCode::OK, Json(UserDTO {
                        id: user.id,
                        email: user.email,
                        first_name: user.first_name,
                        last_name: user.last_name,
                        avatar_path: user.avatar_path,
                        roles: user.roles.iter().map(|role| role.name.clone()).collect()
                    })).into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to update user: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(MessageResponse {
                        message: "Failed to update user".to_string(),
                    })).into_response()
                }
            }
        }
    }
}
