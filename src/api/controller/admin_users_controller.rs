use crate::api::dto::{
    AssignRoleRequest, CreateUserRequest, CreatedResponse, MessageResponse, Pagination,
    RemoveRoleRequest, UpdateUserRequest, UserListResponse, UserResponse,
};
use crate::api::server_state::ServerState;
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::error::UserError;
use crate::domain::event::UserEvents;
use crate::domain::jwt::UserDTO;
use crate::domain::user::{PasswordHandler, User};
use crate::infrastructure::repository::RepositoryError;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

#[utoipa::path(post, path = "/v1/restricted/users",
    tag="users-management",
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

    let existing = state.user_repository.get_by_email(&email).await;
    if existing.is_ok() {
        return (
            StatusCode::CONFLICT,
            Json(MessageResponse {
                message: "User already exists".to_string(),
            }),
        )
            .into_response();
    }

    let existing_role = state.role_repository.get_by_name(&role).await;

    if existing_role.is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(MessageResponse {
                message: "Role does not exist".to_string(),
            }),
        )
            .into_response();
    }
    let existing_role = existing_role.unwrap();
    let user = User::now_with_email_and_password(email, password, None, None, Some(true));

    match user {
        Ok(mut user) => {
            let id = user.id;
            let hashing_scheme = state.config.password_hashing_scheme();

            if let Err(e) = user.hash_password(&SchemeAwareHasher::with_scheme(hashing_scheme)) {
                tracing::error!("Failed to hash user's password: {:?}", e);

                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            user.add_roles(vec![existing_role.clone()]);
            match state.user_repository.save(&user).await {
                Ok(_) => {
                    tracing::debug!("User created: {}", user.email);
                    let result = state
                        .message_publisher
                        .publish(&UserEvents::Created {
                            user: UserDTO::from(user),
                        })
                        .await;

                    if result.is_err() {
                        tracing::error!("Error publishing user created event: {:?}", result);
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

#[utoipa::path(get, path = "/v1/restricted/users",
    tag="users-management",
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
pub async fn list_users(
    State(state): State<ServerState>,
    Query(pagination): Query<Pagination>,
) -> impl IntoResponse {
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10);

    match state.user_repository.find_all(page, limit).await {
        Ok((users, total)) => {
            let user_responses: Vec<UserResponse> =
                users.into_iter().map(UserResponse::from).collect();
            (
                StatusCode::OK,
                Json(UserListResponse {
                    total,
                    page,
                    limit,
                    items: user_responses,
                    pages: (total as f64 / limit as f64).ceil() as i32,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list users: {:?}", e);
            e.into_response()
        }
    }
}

#[utoipa::path(get, path = "/v1/restricted/users/{id}",
    tag="users-management",
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
pub async fn get_user(State(state): State<ServerState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.user_repository.get_by_id(&id).await {
        Ok(user) => (StatusCode::OK, Json(UserDTO::from(user))).into_response(),
        Err(e) => {
            match &e {
                RepositoryError::NotFound(e) => {
                    tracing::debug!("User not found {}", e);
                }
                e => {
                    tracing::error!("Failed to get user -> {:?}", e);
                }
            }

            e.into_response()
        }
    }
}

#[utoipa::path(delete, path = "/v1/restricted/users/{id}",
    tag="users-management",
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
    let locked_user_repository = state.user_repository;

    match locked_user_repository.get_by_id(&id).await {
        Ok(user) => match locked_user_repository.delete_by_email(&user.email).await {
            Ok(_) => {
                let result = state
                    .message_publisher
                    .publish(&UserEvents::Deleted {
                        user: UserDTO::from(user),
                    })
                    .await;

                if result.is_err() {
                    tracing::error!("Error publishing user created event: {:?}", result);
                }

                (
                    StatusCode::OK,
                    Json(MessageResponse {
                        message: "User deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("Failed to delete user {:?}", e);
                e.into_response()
            }
        },
        Err(e) => {
            tracing::error!("Failed to delete user {:?}", e);
            e.into_response()
        }
    }
}

#[utoipa::path(put, path = "/v1/restricted/users/{id}",
    request_body = UpdateUserRequest,
    tag="users-management",
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
    let user_locked_repository = state.user_repository;

    let user = user_locked_repository.get_by_id(&id).await;
    match user {
        Ok(old_user) => {
            let mut user = old_user.clone();
            user.first_name = Some(first_name);
            user.last_name = Some(last_name);
            user.avatar_path = avatar_path;

            match user_locked_repository.save(&user).await {
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
                        tracing::error!("Error publishing user created event: {:?}", result);
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
            tracing::error!("Failed to update user: {:?}", e);
            e.into_response()
        }
    }
}

#[utoipa::path(patch, path = "/v1/restricted/users/{id}/roles",
    tag="users-management",
    request_body = AssignRoleRequest,
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Role assigned to user", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User or role not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn assign_role_to_user(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
    Json(request): Json<AssignRoleRequest>,
) -> impl IntoResponse {
    let user = match state.user_repository.get_by_id(&id).await {
        Ok(user) => user,
        Err(e) => return e.into_response(),
    };

    let role = match state.role_repository.get_by_name(&request.role).await {
        Ok(role) => role,
        Err(e) => return e.into_response(),
    };

    let mut updated_user = user;
    updated_user.add_role(role.clone());

    match state.user_repository.save(&updated_user).await {
        Ok(_) => {
            let result = state
                .message_publisher
                .publish(&UserEvents::RoleAssigned {
                    user: UserDTO::from(updated_user.clone()),
                    role: role.name.clone(),
                })
                .await;

            if let Err(e) = result {
                tracing::error!("Failed to publish role assigned event: {:?}", e);
            }

            (
                StatusCode::OK,
                Json(MessageResponse {
                    message: format!("Role {} assigned successfully", role.name),
                }),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/restricted/users/{id}/roles",
    tag="users-management",
    request_body = RemoveRoleRequest,
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Role removed from user", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "User or role not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn remove_role_from_user(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
    Json(request): Json<RemoveRoleRequest>,
) -> impl IntoResponse {
    let user = match state.user_repository.get_by_id(&id).await {
        Ok(user) => user,
        Err(e) => return e.into_response(),
    };

    let role = match state.role_repository.get_by_name(&request.role).await {
        Ok(role) => role,
        Err(e) => return e.into_response(),
    };

    let mut updated_user = user;
    updated_user.remove_role(&role);

    match state.user_repository.save(&updated_user).await {
        Ok(_) => {
            let result = state
                .message_publisher
                .publish(&UserEvents::RoleRemoved {
                    user: UserDTO::from(updated_user.clone()),
                    role: role.name.clone(),
                })
                .await;

            if let Err(e) = result {
                tracing::error!("Failed to publish role removed event: {:?}", e);
            }

            (
                StatusCode::OK,
                Json(MessageResponse {
                    message: format!("Role {} removed successfully", role.name),
                }),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}
