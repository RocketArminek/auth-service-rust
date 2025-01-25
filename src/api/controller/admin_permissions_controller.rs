use crate::api::dto::{
    CreatePermissionRequest, CreatedResponse, MessageResponse, Pagination, PermissionListResponse,
    PermissionResponse,
};
use crate::api::server_state::ServerState;
use crate::domain::permission::Permission;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use uuid::Uuid;

#[utoipa::path(post, path = "/v1/restricted/permissions",
    tag="permissions-management",
    request_body = CreatePermissionRequest,
    responses(
        (status = 201, description = "Permission created", content_type = "application/json", body = CreatedResponse),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
        (status = 409, description = "Permission already exists", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn create_permission(
    State(state): State<ServerState>,
    Json(request): Json<CreatePermissionRequest>,
) -> impl IntoResponse {
    let existing = state
        .permission_repository
        .get_by_name(&request.name, &request.group_name)
        .await;

    if existing.is_ok() {
        return (
            StatusCode::CONFLICT,
            Json(MessageResponse {
                message: "Permission already exists".to_string(),
            }),
        )
            .into_response();
    }

    let result = Permission::now(request.name, request.group_name, request.description);
    match result {
        Ok(permission) => match state.permission_repository.save(&permission).await {
            Ok(_) => (
                StatusCode::CREATED,
                Json(CreatedResponse {
                    id: permission.id.to_string(),
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

#[utoipa::path(get, path = "/v1/restricted/permissions",
    tag="permissions-management",
    params(
        ("page" = Option<i32>, Query, description = "Page number default 1"),
        ("limit" = Option<i32>, Query, description = "Number of items per page default 10"),
    ),
    responses(
        (status = 200, description = "List of permissions", content_type = "application/json", body = PermissionListResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn list_permissions(
    State(state): State<ServerState>,
    Query(pagination): Query<Pagination>,
) -> impl IntoResponse {
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    match state.permission_repository.get_all(offset, limit).await {
        Ok(permissions) => {
            let response = PermissionListResponse {
                permissions: permissions
                    .into_iter()
                    .map(|permission| PermissionResponse {
                        id: permission.id.to_string(),
                        name: permission.name,
                        group_name: permission.group_name,
                        description: permission.description,
                        is_system: permission.is_system,
                        created_at: permission.created_at.to_rfc3339(),
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(get, path = "/v1/restricted/permissions/{id}",
    tag="permissions-management",
    responses(
        (status = 200, description = "Permission details", content_type = "application/json", body = PermissionResponse),
        (status = 404, description = "Permission not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn get_permission(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.permission_repository.get_by_id(&id).await {
        Ok(permission) => {
            let response = PermissionResponse {
                id: permission.id.to_string(),
                name: permission.name,
                group_name: permission.group_name,
                description: permission.description,
                is_system: permission.is_system,
                created_at: permission.created_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/restricted/permissions/{id}",
    tag="permissions-management",
    responses(
        (status = 204, description = "Permission deleted"),
        (status = 404, description = "Permission not found", content_type = "application/json", body = MessageResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 409, description = "Cannot delete system permission", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn delete_permission(
    State(state): State<ServerState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.permission_repository.delete(&id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}
