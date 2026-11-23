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

const INVOICES: &str = "/app/api/invoices";
const TENANT_NOTES: &str = "/app/api/tenant-notes";
const BULLETINS: &str = "/app/api/bulletins";
const CATALOG: &str = "/app/api/catalog";
const PRIVATE_REPORTS: &str = "/app/api/private-reports";
const CACHED_REPORTS: &str = "/app/api/cached-reports";
fn secure_app() -> Router {
    scourge_fixture::app_with_flaws(
        "reset-secret".into(),
        scourge_fixture::FixtureFlaws {
            cross_user_order_read: false,
            cross_user_order_patch: false,
            anonymous_private_read: false,
            shared_private_cache: false,
        },
    )
}

const ORDERS: &str = "/app/api/orders";
const SHARING: &str = "/app/api/settings/sharing";

async fn create(app: &Router, cookie: &str, collection: &str, note: &str) -> String {
    let response = send(app, "POST", collection, Some(cookie), json!({"note": note})).await;
    assert_eq!(response.status(), StatusCode::CREATED, "{collection}");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let response = body(response).await;
    let id = response["id"].as_str().unwrap();
    assert!(Uuid::parse_str(id).is_ok());
    format!("{collection}/{id}")
}

async fn assert_note(app: &Router, path: &str, cookie: Option<&str>, note: &str) {
    let response = send(app, "GET", path, cookie, Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(body(response).await, json!({"note": note}));
}

async fn assert_denied_read(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    status: StatusCode,
    error: &str,
) {
    let response = send(app, "GET", path, cookie, Value::Null).await;
    assert_eq!(response.status(), status, "{path}");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(body(response).await, json!({"error": error}));
}

async fn set_sharing(app: &Router, cookie: &str, recipient: Option<&str>) {
    let response = send(
        app,
        "PUT",
        SHARING,
        Some(cookie),
        json!({"share_new_with": recipient}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

async fn assert_sharing(app: &Router, cookie: &str, recipient: Option<&str>) {
    let response = send(app, "GET", SHARING, Some(cookie), Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(body(response).await, json!({"share_new_with": recipient}));
}

#[tokio::test]
async fn each_resource_is_readable_by_exactly_its_default_audience() {
    let app = secure_app();
    let (owner, _) = login(&app, "alice").await;
    let (same_tenant, _) = login(&app, "alice-verify").await;
    let (other_tenant, _) = login(&app, "bob").await;
    let (other_tenant_second_account, _) = login(&app, "bob-verify").await;
    let (admin, _) = login(&app, "admin").await;
    let note = "first line\nsecond line with \"quotes\", \\ and ☕";
    let readers = [
        owner.as_str(),
        same_tenant.as_str(),
        other_tenant.as_str(),
        other_tenant_second_account.as_str(),
        admin.as_str(),
    ];
    for (collection, allowed, anonymous_allowed) in [
        (INVOICES, [true, false, false, false, false], false),
        (TENANT_NOTES, [true, true, false, false, false], false),
        (BULLETINS, [true, true, true, true, true], false),
        (CATALOG, [true, true, true, true, true], true),
        (PRIVATE_REPORTS, [true, false, false, false, false], false),
        (CACHED_REPORTS, [true, false, false, false, false], false),
    ] {
        let path = create(&app, &owner, collection, note).await;
        for cookie in [None, Some("scourge_session=unknown")] {
            if anonymous_allowed {
                assert_note(&app, &path, cookie, note).await;
            } else {
                assert_denied_read(
                    &app,
                    &path,
                    cookie,
                    StatusCode::UNAUTHORIZED,
                    "authentication_required",
                )
                .await;
            }
        }
        for (cookie, allowed) in readers.into_iter().zip(allowed) {
            if allowed {
                assert_note(&app, &path, Some(cookie), note).await;
            } else {
                assert_denied_read(
                    &app,
                    &path,
                    Some(cookie),
                    StatusCode::NOT_FOUND,
                    "resource_not_found",
                )
                .await;
            }
        }
    }
}

#[tokio::test]
async fn resource_creation_requires_a_session_and_deletion_requires_the_owner() {
    let app = secure_app();
    let (owner, _) = login(&app, "alice").await;
    let (same_tenant, _) = login(&app, "alice-verify").await;
    let (other_tenant, _) = login(&app, "bob").await;
    let (admin, _) = login(&app, "admin").await;
    let note = "owned";
    for collection in [
        INVOICES,
        TENANT_NOTES,
        BULLETINS,
        CATALOG,
        PRIVATE_REPORTS,
        CACHED_REPORTS,
    ] {
        let response = send(&app, "POST", collection, None, json!({"note": note})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{collection}");
        let response = send(
            &app,
            "POST",
            collection,
            Some(&owner),
            json!({"note": note, "owner_id": "user-bob"}),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{collection}"
        );
        let path = create(&app, &owner, collection, note).await;
        let id = path.rsplit_once('/').unwrap().1;
        for other_collection in [
            INVOICES,
            TENANT_NOTES,
            BULLETINS,
            CATALOG,
            PRIVATE_REPORTS,
            CACHED_REPORTS,
        ] {
            if other_collection != collection {
                assert_denied_read(
                    &app,
                    &format!("{other_collection}/{id}"),
                    Some(&owner),
                    StatusCode::NOT_FOUND,
                    "resource_not_found",
                )
                .await;
            }
        }
        for (cookie, status) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(same_tenant.as_str()), StatusCode::NOT_FOUND),
            (Some(other_tenant.as_str()), StatusCode::NOT_FOUND),
            (Some(admin.as_str()), StatusCode::NOT_FOUND),
        ] {
            let response = send(&app, "DELETE", &path, cookie, Value::Null).await;
            assert_eq!(response.status(), status, "{path}");
            assert_note(&app, &path, Some(&owner), note).await;
        }
        let response = send(&app, "DELETE", &path, Some(&owner), Value::Null).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
        assert_denied_read(
            &app,
            &path,
            Some(&owner),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        )
        .await;
    }
}

#[tokio::test]
async fn sharing_is_per_account_and_grants_read_only_on_subsequent_creates() {
    let app = secure_app();
    let (alice, _) = login(&app, "alice").await;
    let (alice_second_session, _) = login(&app, "alice").await;
    let (alice_verify, _) = login(&app, "alice-verify").await;
    let (bob, _) = login(&app, "bob").await;
    let (bob_verify, _) = login(&app, "bob-verify").await;
    assert_sharing(&app, &alice, None).await;
    let old_order = create(&app, &alice, ORDERS, "private before sharing").await;
    let old_invoice = create(&app, &alice, INVOICES, "private before sharing").await;
    set_sharing(&app, &alice, Some("bob")).await;
    assert_sharing(&app, &alice_second_session, Some("bob")).await;
    assert_sharing(&app, &alice_verify, None).await;

    for (cookie, payload, status) in [
        (
            None,
            json!({"share_new_with": null}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(bob.as_str()),
            json!({"share_new_with": null, "username": "alice"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Some(alice.as_str()),
            json!({"share_new_with": "alice"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Some(alice.as_str()),
            json!({"share_new_with": "unknown"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Some(alice.as_str()),
            json!({}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let response = send(&app, "PUT", SHARING, cookie, payload).await;
        assert_eq!(response.status(), status);
        assert_sharing(&app, &alice, Some("bob")).await;
    }
    assert_denied_read(
        &app,
        SHARING,
        None,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    set_sharing(&app, &bob, Some("alice")).await;
    assert_sharing(&app, &alice, Some("bob")).await;

    let mut shared_paths = Vec::new();
    for (collection, existing, missing) in [
        (ORDERS, old_order, "order_not_found"),
        (INVOICES, old_invoice, "resource_not_found"),
    ] {
        let path = create(&app, &alice_second_session, collection, "explicitly shared").await;
        assert_note(&app, &path, Some(&bob), "explicitly shared").await;
        for (path, cookie) in [
            (&existing, &bob),
            (&path, &bob_verify),
            (&path, &alice_verify),
        ] {
            assert_denied_read(&app, path, Some(cookie), StatusCode::NOT_FOUND, missing).await;
        }
        assert_denied_read(
            &app,
            &path,
            None,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
        let separate = create(&app, &alice_verify, collection, "separate account").await;
        assert_denied_read(&app, &separate, Some(&bob), StatusCode::NOT_FOUND, missing).await;
        let response = send(&app, "DELETE", &path, Some(&bob), Value::Null).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        if collection == ORDERS {
            let response = send(
                &app,
                "PATCH",
                &path,
                Some(&bob),
                json!({"note": "replacement"}),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        assert_note(&app, &path, Some(&alice), "explicitly shared").await;
        shared_paths.push((collection, path, missing));
    }
    let shared_tenant_note = create(&app, &alice, TENANT_NOTES, "shared outside tenant").await;
    assert_note(
        &app,
        &shared_tenant_note,
        Some(&alice_verify),
        "shared outside tenant",
    )
    .await;
    assert_note(
        &app,
        &shared_tenant_note,
        Some(&bob),
        "shared outside tenant",
    )
    .await;

    set_sharing(&app, &alice, None).await;
    assert_sharing(&app, &alice, None).await;
    for (collection, shared, missing) in shared_paths {
        assert_note(&app, &shared, Some(&bob), "explicitly shared").await;
        let later = create(&app, &alice, collection, "private after disabling").await;
        assert_denied_read(&app, &later, Some(&bob), StatusCode::NOT_FOUND, missing).await;
    }
}

#[tokio::test]
async fn reset_clears_policy_resources_and_sharing_settings() {
    let app = secure_app();
    let (alice, _) = login(&app, "alice").await;
    set_sharing(&app, &alice, Some("bob")).await;
    let mut paths = Vec::new();
    for collection in [
        INVOICES,
        TENANT_NOTES,
        BULLETINS,
        CATALOG,
        PRIVATE_REPORTS,
        CACHED_REPORTS,
    ] {
        paths.push(create(&app, &alice, collection, "before reset").await);
    }
    let response = send(&app, "POST", "/app/_reset", Some(&alice), Value::Null).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_sharing(&app, &alice, Some("bob")).await;
    for path in &paths {
        assert_note(&app, path, Some(&alice), "before reset").await;
    }

    let reset = Request::builder()
        .method("POST")
        .uri("/app/_reset")
        .header("x-fixture-admin-secret", "reset-secret")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(reset).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let (alice, _) = login(&app, "alice").await;
    assert_sharing(&app, &alice, None).await;
    for path in paths {
        assert_denied_read(
            &app,
            &path,
            Some(&alice),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        )
        .await;
    }
}
