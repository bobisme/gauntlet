mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{body, login, send};
use http_body_util::BodyExt;
use scourge_fixture::{FixtureFlaws, app_with_flaws};
use serde_json::{Value, json};
use tower::ServiceExt;

// Decoy routes must work independently of the four pre-existing defect switches.
fn apps() -> [Router; 2] {
    [false, true].map(|enabled| {
        app_with_flaws(
            "reset-secret".into(),
            FixtureFlaws {
                cross_user_order_read: enabled,
                cross_user_order_patch: enabled,
                anonymous_private_read: enabled,
                shared_private_cache: enabled,
            },
        )
    })
}

async fn create(app: &Router, cookie: &str, family: &str, note: &str) -> String {
    let collection = format!("/app/api/{family}-reports");
    let response = send(
        app,
        "POST",
        &collection,
        Some(cookie),
        json!({"note": note}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    format!(
        "{collection}/{}",
        body(response).await["id"].as_str().unwrap()
    )
}

async fn note(app: &Router, path: &str, cookie: Option<&str>, status: StatusCode, note: &str) {
    let response = send(app, "GET", path, cookie, Value::Null).await;
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(body(response).await, json!({"note": note}));
}

#[tokio::test]
async fn f03_private_object_returns_200_login_html_without_the_canary() {
    for app in apps() {
        let (alice, _) = login(&app, "alice").await;
        let (bob, _) = login(&app, "bob").await;
        let path = create(&app, &alice, "login", "private fresh canary").await;
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "private fresh canary",
        )
        .await;
        for cookie in [None, Some(bob.as_str()), Some("scourge_session=unknown")] {
            let response = send(&app, "GET", &path, cookie, Value::Null).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                bytes,
                "<!doctype html><title>Sign in</title><h1>Sign in required</h1>"
            );
        }
        // A valid identity probe still does not make the HTML an object response.
        assert_eq!(
            body(send(&app, "GET", "/app/api/me", Some(&bob), Value::Null).await).await["id"],
            "user-bob"
        );
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "private fresh canary",
        )
        .await;
    }
}

#[tokio::test]
async fn f06_stale_victim_snapshot_lacks_the_fresh_canary() {
    for app in apps() {
        let (alice, _) = login(&app, "alice").await;
        let (bob, _) = login(&app, "bob").await;
        let path = create(&app, &alice, "stale", "previous-round canary").await;
        for (cookie, status) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(bob.as_str()), StatusCode::NOT_FOUND),
        ] {
            assert_eq!(
                send(&app, "GET", &path, cookie, Value::Null).await.status(),
                status
            );
        }
        // Only the owner can prime the old response.
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "previous-round canary",
        )
        .await;
        for cookie in [None, Some(bob.as_str())] {
            assert_eq!(
                send(
                    &app,
                    "PATCH",
                    &path,
                    cookie,
                    json!({"note":"unauthorized mutation"})
                )
                .await
                .status(),
                if cookie.is_none() {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
        assert_eq!(
            send(
                &app,
                "PATCH",
                &path,
                Some(&alice),
                json!({"note":"fresh-round canary"})
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "fresh-round canary",
        )
        .await;
        for cookie in [None, Some(bob.as_str()), Some("scourge_session=unknown")] {
            note(&app, &path, cookie, StatusCode::OK, "previous-round canary").await;
        }
        let cold = create(&app, &alice, "stale", "unrelated canary").await;
        assert_eq!(
            send(&app, "GET", &cold, None, Value::Null).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, "DELETE", &path, Some(&bob), Value::Null)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        note(&app, &path, None, StatusCode::OK, "previous-round canary").await;
        assert_eq!(
            send(&app, "DELETE", &path, Some(&alice), Value::Null)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        let response = send(&app, "GET", &path, None, Value::Null).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body(response).await, json!({"error":"resource_not_found"}));
    }
}

#[tokio::test]
async fn f05_forbidden_status_still_exposes_the_exact_private_object() {
    for app in apps() {
        let (alice, _) = login(&app, "alice").await;
        let (bob, _) = login(&app, "bob").await;
        let path = create(&app, &alice, "forbidden", "fresh exposed canary").await;
        let other = create(&app, &alice, "forbidden", "different object").await;
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "fresh exposed canary",
        )
        .await;
        for cookie in [None, Some(bob.as_str())] {
            note(
                &app,
                &path,
                cookie,
                StatusCode::FORBIDDEN,
                "fresh exposed canary",
            )
            .await;
            note(
                &app,
                &other,
                cookie,
                StatusCode::FORBIDDEN,
                "different object",
            )
            .await;
            let response = send(
                &app,
                "GET",
                "/app/api/forbidden-reports/missing",
                cookie,
                Value::Null,
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(body(response).await, json!({"error":"resource_not_found"}));
        }
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "fresh exposed canary",
        )
        .await;
    }
}

#[tokio::test]
async fn f08_recent_canaries_are_echoed_for_unrelated_and_nonexistent_objects() {
    for app in apps() {
        let (alice, _) = login(&app, "alice").await;
        let (bob, _) = login(&app, "bob").await;
        let missing = "/app/api/echo-reports/missing";
        assert_eq!(
            body(send(&app, "GET", missing, None, Value::Null).await).await,
            json!({"echoes":[]})
        );
        let old = create(&app, &alice, "echo", "earlier canary").await;
        let fresh = create(&app, &alice, "echo", "fresh canary").await;
        for path in [&old, &fresh, missing] {
            for cookie in [None, Some(alice.as_str()), Some(bob.as_str())] {
                let response = send(&app, "GET", path, cookie, Value::Null).await;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert_eq!(
                    body(response).await,
                    json!({"echoes":["earlier canary", "fresh canary"]})
                );
            }
        }
        // History is bounded and ordered; only this route records echoes.
        for index in 0..8 {
            create(&app, &alice, "echo", &format!("canary-{index}")).await;
        }
        create(&app, &bob, "login", "not an echo").await;
        let expected: Vec<_> = (0..8).map(|index| format!("canary-{index}")).collect();
        assert_eq!(
            body(send(&app, "GET", missing, None, Value::Null).await).await,
            json!({"echoes": expected})
        );
    }
}

#[tokio::test]
async fn f07_designated_read_expires_only_its_requesting_session_before_next_probe() {
    for app in apps() {
        let (alice, _) = login(&app, "alice").await;
        let (independent, _) = login(&app, "alice").await;
        let (bob, _) = login(&app, "bob").await;
        let path = create(&app, &alice, "expiring", "one-round canary").await;
        for cookie in [&alice, &independent, &bob] {
            assert_eq!(
                send(&app, "GET", "/app/api/me", Some(cookie), Value::Null)
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        // A denied read cannot revoke another caller's session.
        assert_eq!(
            send(&app, "GET", &path, Some(&bob), Value::Null)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            body(send(&app, "GET", "/app/api/me", Some(&alice), Value::Null).await).await["id"],
            "user-alice"
        );
        note(
            &app,
            &path,
            Some(&alice),
            StatusCode::OK,
            "one-round canary",
        )
        .await;
        let probe = send(&app, "GET", "/app/api/me", Some(&alice), Value::Null).await;
        assert_eq!(probe.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body(probe).await,
            json!({"error":"authentication_required"})
        );
        assert_eq!(
            send(&app, "GET", &path, Some(&alice), Value::Null)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            body(send(&app, "GET", "/app/api/me", Some(&independent), Value::Null).await).await["id"],
            "user-alice"
        );
        assert_eq!(
            body(send(&app, "GET", "/app/api/me", Some(&bob), Value::Null).await).await["id"],
            "user-bob"
        );
        note(
            &app,
            &path,
            Some(&independent),
            StatusCode::OK,
            "one-round canary",
        )
        .await;
        assert_eq!(
            send(&app, "GET", "/app/api/me", Some(&independent), Value::Null)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let (new_alice, _) = login(&app, "alice").await;
        note(
            &app,
            &path,
            Some(&new_alice),
            StatusCode::OK,
            "one-round canary",
        )
        .await;
    }
}

#[tokio::test]
async fn decoy_state_is_app_local_and_reset_clears_objects_snapshots_and_echoes() {
    let [app, other] = apps();
    let (alice, _) = login(&app, "alice").await;
    let mut paths = Vec::new();
    for family in ["login", "stale", "forbidden", "echo", "expiring"] {
        paths.push(create(&app, &alice, family, "before reset").await);
    }
    note(
        &app,
        &paths[1],
        Some(&alice),
        StatusCode::OK,
        "before reset",
    )
    .await;
    assert_eq!(
        send(&other, "GET", &paths[1], None, Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        body(send(&other, "GET", &paths[3], None, Value::Null).await).await,
        json!({"echoes":[]})
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
    for path in paths {
        let response = send(&app, "GET", &path, None, Value::Null).await;
        if path.contains("/echo-reports/") {
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await, json!({"echoes":[]}));
        } else {
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(body(response).await, json!({"error":"resource_not_found"}));
        }
    }
}
