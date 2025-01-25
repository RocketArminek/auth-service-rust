use crate::api::dto::{
    CreateRoleRequest, CreatedResponse, MessageResponse, Pagination,
    RoleListResponse, RoleResponse,
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
