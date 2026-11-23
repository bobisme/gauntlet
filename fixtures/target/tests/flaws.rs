mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use common::{body, login, send};
use scourge_fixture::{FixtureFlaws, app_with_flaws};
use serde_json::{Value, json};
use tower::ServiceExt;

const ORDERS: &str = "/app/api/orders";
const PRIVATE: &str = "/app/api/private-reports";
const CACHED: &str = "/app/api/cached-reports";

fn switches(value: bool) -> FixtureFlaws {
    FixtureFlaws {
        cross_user_order_read: value,
        cross_user_order_patch: value,
        anonymous_private_read: value,
        shared_private_cache: value,
    }
}

async fn create(app: &Router, owner: &str, collection: &str, note: &str) -> String {
    let response = send(app, "POST", collection, Some(owner), json!({"note": note})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    format!(
        "{collection}/{}",
        body(response).await["id"].as_str().unwrap()
    )
}

async fn assert_note(app: &Router, path: &str, cookie: Option<&str>, note: &str) {
    let response = send(app, "GET", path, cookie, Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, json!({"note": note}));
}

// Exercise each switch both in isolation and with every other defect enabled.
#[tokio::test]
async fn cross_user_order_read_is_independently_switchable_and_does_not_mutate() {
    for others in [false, true] {
        for enabled in [false, true] {
            let mut flaws = switches(others);
            flaws.cross_user_order_read = enabled;
            let app = app_with_flaws("reset-secret".into(), flaws);
            let (alice, _) = login(&app, "alice").await;
            let (bob, _) = login(&app, "bob").await;
            let path = create(&app, &alice, ORDERS, "owner canary").await;
            let response = send(&app, "GET", &path, Some(&bob), Value::Null).await;
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            );
            assert_eq!(
                body(response).await,
                if enabled {
                    json!({"note": "owner canary"})
                } else {
                    json!({"error": "order_not_found"})
                }
            );
            assert_note(&app, &path, Some(&alice), "owner canary").await;
            assert_eq!(
                send(&app, "GET", &path, None, Value::Null).await.status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                send(&app, "DELETE", &path, Some(&bob), Value::Null)
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_note(&app, &path, Some(&alice), "owner canary").await;
        }
    }
}

#[tokio::test]
async fn cross_user_order_patch_is_independently_switchable_and_denials_do_not_mutate() {
    for others in [false, true] {
        for enabled in [false, true] {
            let mut flaws = switches(others);
            flaws.cross_user_order_patch = enabled;
            let app = app_with_flaws("reset-secret".into(), flaws);
            let (alice, _) = login(&app, "alice").await;
            let (bob, _) = login(&app, "bob").await;
            let path = create(&app, &alice, ORDERS, "original").await;
            let untouched = create(&app, &alice, ORDERS, "untouched").await;
            let response = send(
                &app,
                "PATCH",
                &path,
                Some(&bob),
                json!({"note": "fresh replacement"}),
            )
            .await;
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::NOT_FOUND
                }
            );
            let expected = if enabled {
                "fresh replacement"
            } else {
                "original"
            };
            assert_note(&app, &path, Some(&alice), expected).await;
            assert_note(&app, &untouched, Some(&alice), "untouched").await;
            for cookie in [None, Some("scourge_session=unknown")] {
                assert_eq!(
                    send(&app, "PATCH", &path, cookie, json!({"note": "anonymous"}))
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
                assert_note(&app, &path, Some(&alice), expected).await;
            }
            assert_eq!(
                send(
                    &app,
                    "PATCH",
                    "/app/api/orders/missing",
                    Some(&bob),
                    json!({"note": "missing"})
                )
                .await
                .status(),
                StatusCode::NOT_FOUND
            );
        }
    }
}

#[tokio::test]
async fn anonymous_private_read_is_independently_switchable_and_owner_private_for_other_users() {
    for others in [false, true] {
        for enabled in [false, true] {
            let mut flaws = switches(others);
            flaws.anonymous_private_read = enabled;
            let app = app_with_flaws("reset-secret".into(), flaws);
            let (alice, _) = login(&app, "alice").await;
            let (bob, _) = login(&app, "bob").await;
            let path = create(&app, &alice, PRIVATE, "private canary").await;
            for _ in 0..2 {
                let response = send(&app, "GET", &path, None, Value::Null).await;
                assert_eq!(
                    response.status(),
                    if enabled {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                );
                assert_eq!(
                    body(response).await,
                    if enabled {
                        json!({"note": "private canary"})
                    } else {
                        json!({"error": "authentication_required"})
                    }
                );
                assert_note(&app, &path, Some(&alice), "private canary").await;
            }
            assert_eq!(
                send(&app, "GET", &path, Some(&bob), Value::Null)
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                send(&app, "DELETE", &path, None, Value::Null)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_note(&app, &path, Some(&alice), "private canary").await;
        }
    }
}

#[tokio::test]
async fn shared_private_cache_is_independently_switchable_and_requires_an_owner_read() {
    for others in [false, true] {
        for enabled in [false, true] {
            let mut flaws = switches(others);
            flaws.shared_private_cache = enabled;
            let app = app_with_flaws("reset-secret".into(), flaws);
            let (alice, _) = login(&app, "alice").await;
            let (bob, _) = login(&app, "bob").await;
            let path = create(&app, &alice, CACHED, "cached canary").await;
            for cookie in [None, Some("scourge_session=unknown")] {
                assert_eq!(
                    send(&app, "GET", &path, cookie, Value::Null).await.status(),
                    StatusCode::UNAUTHORIZED
                );
            }
            assert_eq!(
                send(&app, "GET", &path, Some(&bob), Value::Null)
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                send(&app, "GET", &path, None, Value::Null).await.status(),
                StatusCode::UNAUTHORIZED
            );
            assert_note(&app, &path, Some(&alice), "cached canary").await;
            let response = send(&app, "GET", &path, None, Value::Null).await;
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
            assert_eq!(
                body(response).await,
                if enabled {
                    json!({"note": "cached canary"})
                } else {
                    json!({"error": "authentication_required"})
                }
            );
            assert_eq!(
                send(&app, "GET", &path, Some(&bob), Value::Null)
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_note(&app, &path, Some(&alice), "cached canary").await;
        }
    }
}

#[tokio::test]
async fn cache_is_per_object_and_app_and_cleared_on_owner_delete_and_reset() {
    let app = scourge_fixture::app("reset-secret".into());
    let other_app = scourge_fixture::app("reset-secret".into());
    let (alice, _) = login(&app, "alice").await;
    let (bob, _) = login(&app, "bob").await;
    let path = create(&app, &alice, CACHED, "alice warm").await;
    let cold = create(&app, &alice, CACHED, "alice cold").await;
    let bob_path = create(&app, &bob, CACHED, "bob warm").await;
    assert_note(&app, &path, Some(&alice), "alice warm").await;
    assert_note(&app, &bob_path, Some(&bob), "bob warm").await;
    assert_note(&app, &path, None, "alice warm").await;
    assert_note(&app, &bob_path, None, "bob warm").await;
    assert_eq!(
        send(&app, "GET", &cold, None, Value::Null).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&other_app, "GET", &path, None, Value::Null)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let private_path = path.replace(CACHED, PRIVATE);
    assert_eq!(
        send(&app, "GET", &private_path, Some(&alice), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, "DELETE", &path, Some(&bob), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_note(&app, &path, None, "alice warm").await;
    assert_eq!(
        send(&app, "DELETE", &path, Some(&alice), Value::Null)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&app, "GET", &path, None, Value::Null).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let reset = Request::builder()
        .method("POST")
        .uri("/app/_reset")
        .header("x-fixture-admin-secret", "reset-secret")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(reset).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&app, "GET", &bob_path, None, Value::Null)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let (new_alice, _) = login(&app, "alice").await;
    assert_eq!(
        send(&app, "GET", &bob_path, Some(&new_alice), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn default_app_enables_all_four_defects() {
    let app = scourge_fixture::app("reset-secret".into());
    let (alice, _) = login(&app, "alice").await;
    let (bob, _) = login(&app, "bob").await;
    let order = create(&app, &alice, ORDERS, "order canary").await;
    assert_note(&app, &order, Some(&bob), "order canary").await;
    assert_eq!(
        send(
            &app,
            "PATCH",
            &order,
            Some(&bob),
            json!({"note": "changed"})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_note(&app, &order, Some(&alice), "changed").await;
    let private = create(&app, &alice, PRIVATE, "private canary").await;
    assert_note(&app, &private, None, "private canary").await;
    let cached = create(&app, &alice, CACHED, "cache canary").await;
    assert_eq!(
        send(&app, "GET", &cached, None, Value::Null).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_note(&app, &cached, Some(&alice), "cache canary").await;
    assert_note(&app, &cached, None, "cache canary").await;
}
