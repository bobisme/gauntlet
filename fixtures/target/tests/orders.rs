mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::{body, login, send};

const ORDERS: &str = "/app/api/orders";

async fn create(app: &Router, cookie: &str, note: &str) -> String {
    let response = send(app, "POST", ORDERS, Some(cookie), json!({"note": note})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let response = body(response).await;
    let id = response.pointer("/id").unwrap().as_str().unwrap();
    assert!(Uuid::parse_str(id).is_ok());
    id.to_owned()
}

async fn assert_note(app: &Router, cookie: &str, path: &str, note: &str) {
    let response = send(app, "GET", path, Some(cookie), Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(body(response).await.pointer("/note"), Some(&json!(note)));
}

#[tokio::test]
async fn each_create_identifies_its_own_order_and_the_owner_can_change_and_delete_it() {
    let app = scourge_fixture::app("reset-secret".into());
    let (alice, _) = login(&app, "alice").await;
    let (alice_second_session, _) = login(&app, "alice").await;
    let note = "first line\nsecond line with \"quotes\", \\ and ☕";
    let first = create(&app, &alice, note).await;
    let second = create(&app, &alice, "").await;
    let third = create(&app, &alice, note).await;
    assert_ne!(first, second);
    assert_ne!(first, third);
    assert_ne!(second, third);
    let first_path = format!("{ORDERS}/{first}");
    let second_path = format!("{ORDERS}/{second}");
    let third_path = format!("{ORDERS}/{third}");
    assert_note(&app, &alice_second_session, &first_path, note).await;
    assert_note(&app, &alice, &second_path, "").await;
    assert_note(&app, &alice, &third_path, note).await;

    let updated = "0123456789abcdef0123456789abcdef";
    assert_eq!(
        send(
            &app,
            "PATCH",
            &first_path,
            Some(&alice_second_session),
            json!({"note": updated}),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_note(&app, &alice, &first_path, updated).await;
    assert_note(&app, &alice, &third_path, note).await;

    let removed = send(&app, "DELETE", &first_path, Some(&alice), Value::Null).await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    for method in ["GET", "PATCH", "DELETE"] {
        let response = send(
            &app,
            method,
            &first_path,
            Some(&alice),
            json!({"note": "gone"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    assert_note(&app, &alice, &third_path, note).await;
}

#[tokio::test]
async fn orders_are_private_to_the_subject_and_denied_requests_leave_state_intact() {
    let app = scourge_fixture::app("reset-secret".into());
    let (alice, _) = login(&app, "alice").await;
    let (bob, _) = login(&app, "bob").await;
    let (same_tenant, _) = login(&app, "alice-verify").await;
    let (admin, _) = login(&app, "admin").await;
    let (revoked, _) = login(&app, "alice").await;
    assert_eq!(
        send(&app, "POST", "/app/logout", Some(&revoked), Value::Null)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let duplicated = format!("{alice}; {alice}");
    let private_note = "1234567890abcdef1234567890abcdef";
    let alice_id = create(&app, &alice, private_note).await;
    let bob_id = create(&app, &bob, "Bob's order").await;
    assert_ne!(alice_id, bob_id);
    let alice_path = format!("{ORDERS}/{alice_id}");
    let bob_path = format!("{ORDERS}/{bob_id}");
    for cookie in [None, Some(revoked.as_str()), Some(duplicated.as_str())] {
        let response = send(&app, "POST", ORDERS, cookie, json!({"note": "unowned"})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body(response).await,
            json!({"error": "authentication_required"})
        );
    }

    // Exercise anonymous access both before and after the owner's read.
    let anonymous_read = send(&app, "GET", &alice_path, None, Value::Null).await;
    assert_eq!(anonymous_read.status(), StatusCode::UNAUTHORIZED);
    assert_note(&app, &alice, &alice_path, private_note).await;

    for (cookie, status, error) in [
        (Some(bob.as_str()), StatusCode::NOT_FOUND, "order_not_found"),
        (Some(&same_tenant), StatusCode::NOT_FOUND, "order_not_found"),
        (Some(&admin), StatusCode::NOT_FOUND, "order_not_found"),
        (None, StatusCode::UNAUTHORIZED, "authentication_required"),
        (
            Some(&revoked),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        ),
        (
            Some(&duplicated),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        ),
    ] {
        for method in ["GET", "PATCH", "DELETE"] {
            let response = send(
                &app,
                method,
                &alice_path,
                cookie,
                json!({"note": "attempted change"}),
            )
            .await;
            assert_eq!(response.status(), status, "{method}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(body(response).await, json!({"error": error}));
            assert_note(&app, &alice, &alice_path, private_note).await;
        }
    }
    assert_note(&app, &bob, &bob_path, "Bob's order").await;
}

#[tokio::test]
async fn order_writes_require_a_note_string_and_reject_client_supplied_identity() {
    let app = scourge_fixture::app("reset-secret".into());
    let (alice, _) = login(&app, "alice").await;
    let id = create(&app, &alice, "before").await;
    let path = format!("{ORDERS}/{id}");
    for payload in [
        json!({}),
        json!({"note": null}),
        json!({"note": 42}),
        json!({"note": "changed", "id": id}),
        json!({"note": "changed", "owner_id": "user-bob"}),
    ] {
        for (method, path) in [("POST", ORDERS), ("PATCH", path.as_str())] {
            let response = send(&app, method, path, Some(&alice), payload.clone()).await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
    assert_note(&app, &alice, &path, "before").await;
}

#[tokio::test]
async fn authorized_reset_clears_orders_and_leaves_old_sessions_revoked() {
    let app = scourge_fixture::app("reset-secret".into());
    let (alice, _) = login(&app, "alice").await;
    let id = create(&app, &alice, "before reset").await;
    let path = format!("{ORDERS}/{id}");
    let response = send(&app, "POST", "/app/_reset", Some(&alice), Value::Null).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_note(&app, &alice, &path, "before reset").await;

    let request = Request::builder()
        .method("POST")
        .uri("/app/_reset")
        .header("x-fixture-admin-secret", "reset-secret")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let response = send(&app, "GET", &path, Some(&alice), Value::Null).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (new_session, _) = login(&app, "alice").await;
    let response = send(&app, "GET", &path, Some(&new_session), Value::Null).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(id, create(&app, &new_session, "after reset").await);
}
