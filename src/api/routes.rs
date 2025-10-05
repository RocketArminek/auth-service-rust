use crate::api::controller::admin_permissions_controller::*;
use crate::api::controller::admin_roles_controller::*;
use crate::api::controller::admin_users_controller::*;
use crate::api::controller::auth_controller::*;
use crate::api::controller::user_controller::*;
use crate::api::controller::user_profile_controller::*;
use crate::api::controller::utils_controller::*;
use crate::api::dto::*;
use crate::api::middleware::acl_mw::{restricted_acl, verified_acl};
use crate::api::middleware::security_mw::{restrict_methods, security_headers};
use crate::api::server_state::ServerState;
use crate::domain::jwt::UserDTO;
use axum::routing::{patch, post, put};
use axum::{Router, middleware, routing::get};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn routes(state: ServerState) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/", ApiDoc::openapi()))
        .route("/v1/health", get(health_action))
        .route("/v1/users", post(register))
        .route("/v1/me/verification", patch(verify))
        .route("/v1/me/verification/resend", post(resend_verification))
        .route("/v1/me/password/reset", patch(reset_password))
        .route("/v1/login", post(login))
        .route("/v1/logout", post(logout))
        .route("/v1/refresh", post(refresh))
        .route("/v1/password/reset", post(request_password_reset))
        .merge(
            Router::new()
                .route("/v1/me", put(update_profile).get(get_profile))
                .layer(
                    ServiceBuilder::new()
                        .layer(middleware::from_fn_with_state(state.clone(), verified_acl))
                        .layer(TraceLayer::new_for_http()),
                ),
        )
        .merge(
            Router::new()
                .route(
                    "/v1/restricted/users",
                    post(create_restricted_user).get(list_users),
                )
                .route(
                    "/v1/restricted/users/{id}",
                    get(get_user).delete(delete_user).put(update_user),
                )
                .route(
                    "/v1/restricted/users/{id}/roles",
                    patch(assign_role_to_user).delete(remove_role_from_user),
                )
                .route("/v1/restricted/roles", get(list_roles).post(create_role))
                .route(
                    "/v1/restricted/roles/{id}",
                    get(get_role).delete(delete_role),
                )
                .route(
                    "/v1/restricted/roles/{id}/permissions",
                    patch(assign_permission_to_role).delete(remove_permission_from_role),
                )
                .route(
                    "/v1/restricted/permissions",
                    get(list_permissions).post(create_permission),
                )
                .route(
                    "/v1/restricted/permissions/{id}",
                    get(get_permission).delete(delete_permission),
                )
                .layer(
                    ServiceBuilder::new()
                        .layer(middleware::from_fn_with_state(
                            state.clone(),
                            restricted_acl,
                        ))
                        .layer(TraceLayer::new_for_http()),
                ),
        )
        .layer(middleware::from_fn(restrict_methods))
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[utoipa::path(get, path = "/",
    tag="utils",
    responses(
        (status = 200, description = "Open api schema", content_type = "application/json"),
    )
)]
pub async fn open_api_docs() {
    panic!("This is only for documentation")
}

#[derive(OpenApi)]
#[openapi(
    servers(
        (description="dev", url="http://localhost:8080"),
    ),
    paths(
        open_api_docs,
        health_action,
        register,
        create_restricted_user,
        list_users,
        get_user,
        delete_user,
        login,
        refresh,
        update_profile,
        get_profile,
        update_user,
        verify,
        resend_verification,
        request_password_reset,
        reset_password,
        logout,
        create_role,
        list_roles,
        get_role,
        delete_role,
        assign_role_to_user,
        remove_role_from_user,
        list_permissions,
        get_permission,
        create_permission,
        delete_permission,
        assign_permission_to_role,
        remove_permission_from_role,
    ),
    components(
        schemas(
            HealthResponse,
            MessageResponse,
            UserDTO,
            LoginResponse,
            TokenResponse,
            CreateUserRequest,
            UpdateUserRequest,
            LoginRequest,
            CreatedResponse,
            UserListResponse,
            VerifyUserRequest,
            ResetPasswordRequest,
            ChangePasswordRequest,
            CreateRoleRequest,
            RoleResponse,
            RoleListResponse,
            AssignRoleRequest,
            RemoveRoleRequest,
            PermissionListResponse,
            PermissionResponse,
            CreatePermissionRequest,
            AssignPermissionRequest,
            RemovePermissionRequest,
            RoleWithPermissionsResponse,
            RoleWithPermissionsListResponse,
        ),
    )
)]
pub struct ApiDoc;
