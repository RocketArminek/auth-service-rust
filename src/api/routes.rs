use axum::{
    routing::{get},
    Router,
};

use crate::api::health_controller::health_action;

pub fn routes() -> Router {
    Router::new()
        .route("/v1/health", get(health_action))
}
