use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::user::{PasswordHandler, User};
use axum::extract::{Query, State};
use axum::http::{StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use crate::api::dto::{CreatedResponse, CreateUserRequest, MessageResponse, Pagination, UserListResponse, UserResponse};
use crate::api::server_state::ServerState;
use crate::domain::error::UserError;

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

    let user = User::now_with_email_and_password(email, password);

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

#[utoipa::path(get, path = "/v1/restricted/users",
    tag="admin",
    params(
        ("page" = i32, Query, description = "Page number"),
        ("limit" = i32, Query, description = "Number of items per page")
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

    match user_repo.find_all(pagination.page, pagination.limit).await {
        Ok((users, total)) => {
            let user_responses: Vec<UserResponse> = users
                .into_iter()
                .map(|user| UserResponse {id: user.id.to_string(), email: user.email})
                .collect();

            (StatusCode::OK, Json(UserListResponse {
                size: total,
                page: pagination.page,
                limit: pagination.limit,
                items: user_responses,
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
