use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::user::{PasswordHandler, User};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use uuid::Uuid;
use crate::api::dto::{CreateUserRequest, CreatedResponse, MessageResponse, Pagination, UpdateUserRequest, UserListResponse};
use crate::api::server_state::ServerState;
use crate::domain::error::UserError;
use crate::domain::jwt::UserDTO;

#[utoipa::path(post, path = "/v1/restricted/users",
    tag="admin",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", content_type = "application/json", body = CreatedResponse),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 409, description = "User already exists", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn create_restricted_user(
    State(state): State<ServerState>,
    request: Json<CreateUserRequest>,
) -> impl IntoResponse {
    let email = request.email.clone();
    let password = request.password.clone();
    let role = request.role.clone();

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
        None
    );

    match user {
        Ok(mut user) => {
            let id = user.id.clone();

            tokio::task::spawn(
                async move {
                    user.hash_password(&SchemeAwareHasher::with_scheme(state.hashing_scheme));
                    match state.user_repository.lock().await.add_with_role(&user, existing_role.id).await {
                        Ok(_) => tracing::info!("User created: {}", user.email),
                        Err(error) => tracing::error!("Failed to create user {:?}", error),
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

#[utoipa::path(get, path = "/v1/restricted/users",
    tag="admin",
    params(
        ("page" = Option<i32>, Query, description = "Page number default 1"),
        ("limit" = Option<i32>, Query, description = "Number of items per page default 10"),
    ),
    responses(
        (status = 200, description = "List of users", content_type = "application/json", body = UserListResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn get_all_users(
    State(state): State<ServerState>,
    Query(pagination): Query<Pagination>
) -> impl IntoResponse {
    let user_repo = state.user_repository.lock().await;
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10);

    match user_repo.find_all(page, limit).await {
        Ok((users, total)) => {
            let user_responses: Vec<UserDTO> = users
                .into_iter()
                .map(|user| UserDTO {
                    id: user.id,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    avatar_path: user.avatar_path,
                    roles: vec![]
                })
                .collect();

            (StatusCode::OK, Json(UserListResponse {
                total: total,
                page,
                limit,
                items: user_responses,
                pages: (total as f64 / limit as f64).ceil() as i32,
            })).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to list users: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(MessageResponse {
                message: "Failed to list users".to_string(),
            })).into_response()
        }
    }
}

#[utoipa::path(get, path = "/v1/restricted/users/{id}",
    tag="admin",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User details", content_type = "application/json", body = UserDTO),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn get_user(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.user_repository.lock().await.get_by_id(id).await {
        Some(user) => (StatusCode::OK, Json(UserDTO {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            avatar_path: user.avatar_path,
            roles: user.roles.iter().map(|role| role.name.clone()).collect()
        })).into_response(),
        None => (StatusCode::NOT_FOUND, Json(MessageResponse {
            message: "User not found".to_string(),
        })).into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/restricted/users/{id}",
    tag="admin",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User deleted", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn delete_user(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let user_repo = state.user_repository.lock().await;

    match user_repo.get_by_id(id).await {
        Some(user) => {
            match user_repo.delete_by_email(&user.email).await {
                Ok(_) => (StatusCode::OK, Json(MessageResponse {
                    message: "User deleted successfully".to_string(),
                })).into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(MessageResponse {
                    message: "Failed to delete user".to_string(),
                })).into_response(),
            }
        },
        None => (StatusCode::NOT_FOUND, Json(MessageResponse {
            message: "User not found".to_string(),
        })).into_response(),
    }
}

#[utoipa::path(put, path = "/v1/restricted/users/{id}",
    request_body = UpdateUserRequest,
    tag="admin",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User updated", content_type = "application/json", body = UserDTO),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn update_user(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
    request: Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let first_name = request.first_name.clone();
    let last_name = request.last_name.clone();
    let avatar_path = request.avatar_path.clone();

    let user = state.user_repository.lock().await.get_by_id(id).await;
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
