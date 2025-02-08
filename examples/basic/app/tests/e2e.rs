use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

const BASE_URL: &str = "http://localhost";

struct TestUser {
    id: String,
    access_token: String,
}

async fn setup_test_user(client: &Client) -> TestUser {
    let email = format!("test{}@example.com", rand::random::<u32>());
    
    let create_response = client
        .post(format!("{}/v1/users", BASE_URL))
        .header("Host", "auth.localhost")
        .json(&json!({
            "email": email,
            "password": "Test#123",
            "role": "USER"
        }))
        .send()
        .await
        .expect("Failed to create user");
    
    assert!(create_response.status().is_success());

    let login_response = client
        .post(format!("{}/v1/login", BASE_URL))
        .header("Host", "auth.localhost")
        .json(&json!({
            "email": email,
            "password": "Test#123"
        }))
        .send()
        .await
        .expect("Failed to login");

    assert!(login_response.status().is_success());

    let login_data: Value = login_response.json().await.expect("Failed to parse login response");

    let access_token = login_data["accessToken"]["value"]
        .as_str()
        .expect("No access token in response")
        .to_string();

    let id = login_data["user"]["id"]
        .as_str()
        .expect("No user ID in response")
        .to_string();

    TestUser {
        id,
        access_token,
    }
}

#[tokio::test]
async fn test_auth_flow() {
    tokio::time::sleep(Duration::from_secs(5)).await;

    let client = Client::new();
    let test_user = setup_test_user(&client).await;

    let test_cases = vec![
        (
            client.get(BASE_URL)
                .header("Host", "app.localhost")
                .header("Authorization", format!("Bearer {}", test_user.access_token)),
            "GET request",
        ),
        (
            client.post(format!("{}/api/users", BASE_URL))
                .header("Host", "app.localhost")
                .header("Authorization", format!("Bearer {}", test_user.access_token))
                .json(&json!({"name": "test"})),
            "POST request",
        ),
        (
            client.put(format!("{}/api/users/123", BASE_URL))
                .header("Host", "app.localhost")
                .header("Authorization", format!("Bearer {}", test_user.access_token))
                .json(&json!({"name": "updated"})),
            "PUT request",
        ),
        (
            client.delete(format!("{}/api/users/123", BASE_URL))
                .header("Host", "app.localhost")
                .header("Authorization", format!("Bearer {}", test_user.access_token)),
            "DELETE request",
        ),
        (
            client.patch(format!("{}/any/other/path", BASE_URL))
                .header("Host", "app.localhost")
                .header("Authorization", format!("Bearer {}", test_user.access_token))
                .json(&json!({"status": "active"})),
            "PATCH request",
        ),
    ];

    for (request_builder, test_name) in test_cases {
        let response = request_builder
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed to send {}: {}", test_name, e));

        assert!(
            response.status().is_success(),
            "{} failed with status: {}",
            test_name,
            response.status()
        );

        let response_data: Value = response
            .json()
            .await
            .unwrap_or_else(|e| panic!("Failed to parse {} response: {}", test_name, e));

        println!("{} response: {}", test_name, response_data);
        assert_eq!(
            response_data["user_info"]["id"].as_str().unwrap(),
            test_user.id,
            "Unexpected user ID in {}",
            test_name
        );
    }
}
