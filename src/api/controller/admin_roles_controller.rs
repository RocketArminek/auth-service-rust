use crate::api::dto::{
    AssignPermissionRequest, CreateRoleRequest, CreatedResponse, MessageResponse, Pagination,
    RemovePermissionRequest, RoleResponse, RoleWithPermissionsListResponse,
    RoleWithPermissionsResponse,
};
use crate::api::server_state::ServerState;
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
    if existing.is_ok() {
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

#[utoipa::path(
    get,
    path = "/v1/restricted/roles",
    tag = "roles-management",
    params(
        ("page" = Option<i32>, Query, description = "Page number"),
        ("limit" = Option<i32>, Query, description = "Items per page")
    ),
    responses(
        (status = 200, description = "List of roles with permissions", body = RoleWithPermissionsListResponse),
        (status = 403, description = "Forbidden", body = MessageResponse),
        (status = 401, description = "Unauthorized", body = MessageResponse),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_roles(
    State(state): State<ServerState>,
    Query(params): Query<Pagination>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(0);
    let limit = params.limit.unwrap_or(10);

    let roles_with_permissions = state
        .role_repository
        .get_all_with_permissions(page, limit)
        .await;

    match roles_with_permissions {
        Ok(roles) => {
            let response: Vec<RoleWithPermissionsResponse> = roles
                .into_iter()
                .map(|(role, permissions)| {
                    RoleWithPermissionsResponse::from_domain(role, permissions)
                })
                .collect();

            (
                StatusCode::OK,
                Json(RoleWithPermissionsListResponse { roles: response }),
            )
                .into_response()
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

#[utoipa::path(patch, path = "/v1/restricted/roles/{id}/permissions",
    tag="roles-management",
    request_body = AssignPermissionRequest,
    params(
        ("id" = String, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Permission assigned to role", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "Role or permission not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn assign_permission_to_role(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
    Json(request): Json<AssignPermissionRequest>,
) -> impl IntoResponse {
    let role = match state.role_repository.get_by_id(&id).await {
        Ok(role) => role,
        Err(e) => return e.into_response(),
    };

    let permission = match state
        .permission_repository
        .get_by_name(&request.name, &request.group_name)
        .await
    {
        Ok(permission) => permission,
        Err(e) => return e.into_response(),
    };

    match state
        .role_repository
        .add_permission(&role.id, &permission.id)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: format!(
                    "Permission {}/{} assigned to role {}",
                    permission.group_name, permission.name, role.name
                ),
            }),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/restricted/roles/{id}/permissions",
    tag="roles-management",
    request_body = RemovePermissionRequest,
    params(
        ("id" = String, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Permission removed from role", content_type = "application/json", body = MessageResponse),
        (status = 404, description = "Role or permission not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn remove_permission_from_role(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
    Json(request): Json<RemovePermissionRequest>,
) -> impl IntoResponse {
    let role = match state.role_repository.get_by_id(&id).await {
        Ok(role) => role,
        Err(e) => return e.into_response(),
    };

    let permission = match state
        .permission_repository
        .get_by_name(&request.name, &request.group_name)
        .await
    {
        Ok(permission) => permission,
        Err(e) => return e.into_response(),
    };

    match state
        .role_repository
        .remove_permission(&role.id, &permission.id)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: format!(
                    "Permission {}/{} removed from role {}",
                    permission.group_name, permission.name, role.name
                ),
            }),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}
