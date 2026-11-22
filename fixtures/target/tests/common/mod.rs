use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

pub async fn send(
    app: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

pub async fn body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

pub async fn login(app: &Router, username: &str) -> (String, Value) {
    let response = send(
        app,
        "POST",
        "/app/login",
        None,
        json!({"username": username, "password": format!("{username}-password")}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    (cookie, body(response).await)
}
