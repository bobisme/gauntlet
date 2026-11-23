mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body, login, send};

const ACCOUNTS: [(&str, &str, &str, Option<&str>); 5] = [
    ("alice", "user-alice", "user", Some("tenant-a")),
    ("bob", "user-bob", "user", Some("tenant-b")),
    ("admin", "user-admin", "admin", None),
    (
        "alice-verify",
        "user-alice-verify",
        "user",
        Some("tenant-a"),
    ),
    ("bob-verify", "user-bob-verify", "user", Some("tenant-b")),
];

#[tokio::test]
async fn private_verifier_passwords_survive_reset() {
    let app = scourge_fixture::app_with_verifier_passwords(
        "reset-secret".into(),
        ["random-alice".into(), "random-bob".into()],
    );
    for phase in 0..2 {
        for (name, password) in [
            ("alice-verify", "random-alice"),
            ("bob-verify", "random-bob"),
        ] {
            let rejected = send(
                &app,
                "POST",
                "/app/login",
                None,
                json!({"username": name, "password": format!("{name}-password")}),
            )
            .await;
            assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
            let accepted = send(
                &app,
                "POST",
                "/app/login",
                None,
                json!({"username": name, "password": password}),
            )
            .await;
            assert_eq!(accepted.status(), StatusCode::OK);
        }
        if phase == 0 {
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
        }
    }
}

#[tokio::test]
async fn every_account_can_login_probe_and_logout() {
    let app = scourge_fixture::app("reset-secret".into());
    let mut subjects = std::collections::HashSet::new();
    for (username, id, role, tenant) in ACCOUNTS {
        let expected = json!({"id": id, "username": username, "role": role, "tenant": tenant});
        let (cookie, identity) = login(&app, username).await;
        assert_eq!(identity, expected);
        assert!(
            subjects.insert(identity["id"].as_str().unwrap().to_owned()),
            "principals must be distinct"
        );
        let response = send(&app, "GET", "/app/api/me", Some(&cookie), Value::Null).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(body(response).await, expected);
        let response = send(&app, "POST", "/app/logout", Some(&cookie), Value::Null).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let response = send(&app, "GET", "/app/api/me", Some(&cookie), Value::Null).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            send(&app, "POST", "/app/logout", Some(&cookie), Value::Null)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
}

#[tokio::test]
async fn separate_session_labels_keep_the_same_subject_and_independent_revocation() {
    let app = scourge_fixture::app("reset-secret".into());
    for (username, id, _, _) in ACCOUNTS {
        let (label_one, _) = login(&app, username).await;
        let (label_two, _) = login(&app, username).await;
        assert_ne!(label_one, label_two);
        for label in [&label_one, &label_two] {
            let response = send(&app, "GET", "/app/api/me", Some(label), Value::Null).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await["id"], id);
        }
        // F-01: a second label reading this private invoice is still the owner,
        // as established by the two HTTP identity probes above.
        let created = send(
            &app,
            "POST",
            "/app/api/invoices",
            Some(&label_one),
            json!({"note":"same subject canary"}),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let path = format!(
            "/app/api/invoices/{}",
            body(created).await["id"].as_str().unwrap()
        );
        let response = send(&app, "GET", &path, Some(&label_two), Value::Null).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await, json!({"note":"same subject canary"}));
        assert_eq!(
            send(&app, "POST", "/app/logout", Some(&label_one), Value::Null)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(&app, "GET", "/app/api/me", Some(&label_one), Value::Null)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = send(&app, "GET", "/app/api/me", Some(&label_two), Value::Null).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await["id"], id);
    }
}

#[tokio::test]
async fn authentication_rejects_unknown_bad_missing_and_ambiguous_credentials() {
    let app = scourge_fixture::app("reset-secret".into());
    for (username, password) in [("missing", "missing-password"), ("alice", "bad-password")] {
        let response = send(
            &app,
            "POST",
            "/app/login",
            None,
            json!({"username": username,"password": password}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    let (cookie, _) = login(&app, "alice").await;
    let duplicate = format!("{cookie}; {cookie}");
    for cookie in [
        None,
        Some("scourge_session=unknown"),
        Some("scourge_session="),
        Some(duplicate.as_str()),
    ] {
        assert_eq!(
            send(&app, "GET", "/app/api/me", cookie, Value::Null)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/app/api/me")
                .header(header::COOKIE, &cookie)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rotates_an_existing_browser_session() {
    let app = scourge_fixture::app("reset-secret".into());
    let (old_cookie, _) = login(&app, "alice").await;
    let response = send(
        &app,
        "POST",
        "/app/login",
        Some(&old_cookie),
        json!({"username":"bob", "password":"bob-password"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let new_cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(body(response).await["id"], "user-bob");
    assert_eq!(
        send(&app, "GET", "/app/api/me", Some(&old_cookie), Value::Null)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        body(send(&app, "GET", "/app/api/me", Some(&new_cookie), Value::Null).await).await["id"],
        "user-bob"
    );
}

#[tokio::test]
async fn reset_requires_its_secret_and_revokes_every_session_without_changing_subjects() {
    let app = scourge_fixture::app("reset-secret".into());
    let mut cookies = Vec::new();
    for (username, _, _, _) in ACCOUNTS {
        cookies.push(login(&app, username).await.0);
    }
    // Neither anonymity, a bad secret, nor the admin account authorizes reset.
    for cookie in [None, Some(cookies[2].as_str())] {
        assert_eq!(
            send(&app, "POST", "/app/_reset", cookie, Value::Null)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    for secrets in [vec!["wrong"], vec!["reset-secret", "reset-secret"]] {
        let mut request = Request::builder().method("POST").uri("/app/_reset");
        for secret in secrets {
            request = request.header("x-fixture-admin-secret", secret);
        }
        assert_eq!(
            app.clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    for cookie in &cookies {
        assert_eq!(
            send(&app, "GET", "/app/api/me", Some(cookie), Value::Null)
                .await
                .status(),
            StatusCode::OK
        );
    }
    // Reset is repeatable and never resurrects a pre-reset session.
    for _ in 0..2 {
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
        for cookie in &cookies {
            assert_eq!(
                send(&app, "GET", "/app/api/me", Some(cookie), Value::Null)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    for (username, id, _, _) in ACCOUNTS {
        assert_eq!(login(&app, username).await.1["id"], id);
    }
}
