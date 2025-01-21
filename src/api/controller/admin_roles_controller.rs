use crate::api::dto::{
    AssignRoleRequest, CreateRoleRequest, CreatedResponse, MessageResponse, Pagination,
    RemoveRoleRequest, RoleListResponse, RoleResponse,
};
use crate::api::server_state::ServerState;
use crate::domain::event::UserEvents;
use crate::domain::jwt::UserDTO;
use crate::domain::role::Role;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use uuid::Uuid;

#[utoipa::path(post, path = "/v1/restricted/roles",
    tag="roles-management",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", content_type = "application/json", body = CreatedResponse),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 409, description = "Role already exists", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn create_role(
    State(state): State<ServerState>,
    Json(request): Json<CreateRoleRequest>,
) -> impl IntoResponse {
    let existing = state.role_repository.get_by_name(&request.name).await;
    if let Ok(_) = existing {
        return (
            StatusCode::CONFLICT,
            Json(MessageResponse {
                message: "Role already exists".to_string(),
            }),
        )
            .into_response();
    }

    let result = Role::now(request.name);
    match result {
        Ok(role) => match state.role_repository.save(&role).await {
            Ok(_) => (
                StatusCode::CREATED,
                Json(CreatedResponse {
                    id: role.id.to_string(),
                }),
            )
                .into_response(),
            Err(e) => e.into_response(),
        },
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(MessageResponse {
                message: "Bad request".to_string(),
            }),
        )
            .into_response(),
    }
}

#[utoipa::path(get, path = "/v1/restricted/roles",
    tag="roles-management",
    params(
        ("page" = Option<i32>, Query, description = "Page number default 1"),
        ("limit" = Option<i32>, Query, description = "Number of items per page default 10"),
    ),
    responses(
        (status = 200, description = "List of roles", content_type = "application/json", body = RoleListResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn list_roles(
    State(state): State<ServerState>,
    Query(pagination): Query<Pagination>,
) -> impl IntoResponse {
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    match state.role_repository.get_all(offset, limit).await {
        Ok(roles) => {
            let response = RoleListResponse {
                roles: roles
                    .into_iter()
                    .map(|role| RoleResponse {
                        id: role.id.to_string(),
                        name: role.name,
                        created_at: role.created_at.to_rfc3339(),
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(get, path = "/v1/restricted/roles/{id}",
    tag="roles-management",
    responses(
        (status = 200, description = "Role details", content_type = "application/json", body = RoleResponse),
        (status = 404, description = "Role not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn get_role(State(state): State<ServerState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.role_repository.get_by_id(&id).await {
        Ok(role) => {
            let response = RoleResponse {
                id: role.id.to_string(),
                name: role.name,
                created_at: role.created_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/restricted/roles/{id}",
    tag="roles-management",
    responses(
        (status = 204, description = "Role deleted", content_type = "application/json"),
        (status = 404, description = "Role not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn delete_role(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.role_repository.delete(&id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(patch, path = "/v1/restricted/users/{id}/roles",
    tag="roles-management",
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
    tag="roles-management",
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
