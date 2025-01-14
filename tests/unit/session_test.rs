use auth_service::domain::session::Session;
use chrono::{Duration, Utc};
use std::thread::sleep;
use std::time::Duration as StdDuration;
use uuid::Uuid;

#[test]
fn it_can_be_created() {
    let id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let created_at = Utc::now();
    let expires_at = created_at + Duration::hours(1);

    let session = Session::new(id, user_id, created_at, expires_at);

    assert_eq!(session.id, id);
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.created_at, created_at);
    assert_eq!(session.expires_at, expires_at);
}

#[test]
fn it_can_be_created_with_current_time() {
    let user_id = Uuid::now_v7();
    let expires_at = Utc::now() + Duration::hours(1);

    let session = Session::now(user_id, expires_at);

    assert_eq!(session.user_id, user_id);
    assert_eq!(session.expires_at, expires_at);
    assert!(session.created_at <= Utc::now());
}

#[test]
fn it_is_not_expired_when_expiry_is_in_future() {
    let id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let created_at = Utc::now();
    let expires_at = created_at + Duration::hours(1);

    let session = Session::new(id, user_id, created_at, expires_at);
    assert!(!session.is_expired());
}

#[test]
fn it_is_expired_after_expiry_time() {
    let id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let created_at = Utc::now();
    let expires_at = created_at + Duration::seconds(1);

    let session = Session::new(id, user_id, created_at, expires_at);
    sleep(StdDuration::from_secs(2));
    assert!(session.is_expired());
}

#[test]
fn it_is_expired_when_expiry_is_in_past() {
    let id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let created_at = Utc::now();
    let expires_at = created_at - Duration::seconds(1);

    let session = Session::new(id, user_id, created_at, expires_at);
    assert!(session.is_expired());
}

#[test]
fn it_generates_ordered_ids() {
    let user_id = Uuid::now_v7();
    let expires_at = Utc::now() + Duration::hours(1);

    let session1 = Session::now(user_id, expires_at);
    sleep(StdDuration::from_millis(1));
    let session2 = Session::now(user_id, expires_at);

    assert!(session1.id < session2.id);
}
