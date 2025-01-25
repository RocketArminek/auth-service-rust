use crate::acceptance::utils;
use crate::utils::runners::run_integration_test_with_default;
use auth_service::api::dto::{CreatedResponse, PermissionListResponse, PermissionResponse};
use auth_service::domain::permission::Permission;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;

#[tokio::test]
async fn it_can_create_permission() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let response = c
            .server
            .post("/v1/restricted/permissions")
            .json(&json!({
                "name": "create_user",
                "group_name": "user_management",
                "description": "Allows creating new users"
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::CREATED);
        let body = response.json::<CreatedResponse>();
        assert!(!body.id.is_empty());

        let permission = c
            .permission_repository
            .get_by_name("create_user", "user_management")
            .await
            .unwrap();
        assert_eq!(permission.name, "create_user");
        assert_eq!(permission.group_name, "user_management");
        assert_eq!(
            permission.description,
            Some("Allows creating new users".to_string())
        );
    })
    .await;
}

#[tokio::test]
async fn it_cannot_create_duplicate_permission() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;
        let permission = Permission::now(
            "create_user".to_string(),
            "user_management".to_string(),
            Some("Allows creating new users".to_string()),
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        let response = c
            .server
            .post("/v1/restricted/permissions")
            .json(&json!({
                "name": "create_user",
                "group_name": "user_management",
                "description": "Allows creating new users"
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::CONFLICT);
    })
    .await;
}

#[tokio::test]
async fn it_can_list_permissions() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let permission1 = Permission::now(
            "create_user".to_string(),
            "user_management".to_string(),
            Some("Allows creating new users".to_string()),
        )
        .unwrap();
        let permission2 = Permission::now(
            "delete_user".to_string(),
            "user_management".to_string(),
            Some("Allows deleting users".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();

        let response = c
            .server
            .get("/v1/restricted/permissions?page=1&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<PermissionListResponse>();
        assert_eq!(body.permissions.len(), 2);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_single_permission() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let permission = Permission::now(
            "create_user".to_string(),
            "user_management".to_string(),
            Some("Allows creating new users".to_string()),
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        let response = c
            .server
            .get(&format!("/v1/restricted/permissions/{}", permission.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<PermissionResponse>();
        assert_eq!(body.name, "create_user");
        assert_eq!(body.group_name, "user_management");
        assert_eq!(body.description, Some("Allows creating new users".to_string()));
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_permission() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let permission = Permission::now(
            "delete_me".to_string(),
            "test_group".to_string(),
            None,
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        let response = c
            .server
            .delete(&format!("/v1/restricted/permissions/{}", permission.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

        let get_result = c.permission_repository.get_by_id(&permission.id).await;
        assert!(get_result.is_err());
    })
    .await;
}

#[tokio::test]
async fn it_cannot_delete_system_permission() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let permission = Permission::now(
            "system_permission".to_string(),
            "system".to_string(),
            None,
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();
        c.permission_repository
            .mark_as_system(&permission.id)
            .await
            .unwrap();

        let response = c
            .server
            .delete(&format!("/v1/restricted/permissions/{}", permission.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::CONFLICT);
    })
    .await;
}

#[tokio::test]
async fn it_requires_admin_role() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_user(&c).await;

        let response = c
            .server
            .get("/v1/restricted/permissions")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    })
    .await;
}
