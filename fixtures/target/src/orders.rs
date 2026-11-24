use std::collections::hash_map::Entry;
use std::io::Write;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use flate2::{
    Compression,
    write::{GzEncoder, ZlibEncoder},
};
use uuid::Uuid;

use crate::{
    AppState, CreatedObject, FixMode, Identity, Note, Ownership, TargetState, admin_authorized,
    error, no_store,
};

pub(super) struct Order {
    ownership: Ownership,
    note: Note,
}

enum OrderError {
    AuthenticationRequired,
    NotFound,
}

impl IntoResponse for OrderError {
    fn into_response(self) -> Response {
        match self {
            Self::AuthenticationRequired => {
                error(StatusCode::UNAUTHORIZED, "authentication_required")
            }
            Self::NotFound => error(StatusCode::NOT_FOUND, "order_not_found"),
        }
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/app/api/orders", post(create))
        .route(
            "/app/api/order-lookup/{id}",
            get(read_alt).patch(update_alt),
        )
        .route(
            "/app/api/orders/{id}",
            get(read).patch(update).delete(remove),
        )
        .layer(middleware::map_response(no_store))
}

impl TargetState {
    fn authorized_order(
        &self,
        headers: &HeaderMap,
        id: &str,
        permitted: impl FnOnce(&Ownership, &Identity) -> bool,
    ) -> Result<&Order, OrderError> {
        let identity = self
            .identity(headers)
            .ok_or(OrderError::AuthenticationRequired)?;
        self.orders
            .get(id)
            .filter(|order| permitted(&order.ownership, identity))
            .ok_or(OrderError::NotFound)
    }
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(note): Json<Note>,
) -> Result<Response, OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let account = target
        .account(&headers)
        .ok_or(OrderError::AuthenticationRequired)?;
    let ownership = Ownership::from_account(account);
    let id = loop {
        let Entry::Vacant(slot) = target.orders.entry(Uuid::new_v4().to_string()) else {
            continue;
        };
        let id = slot.key().clone();
        slot.insert(Order { ownership, note });
        break id;
    };
    drop(target);

    let mut mode = headers.get_all("x-fixture-act-then-drop").iter();
    if matches!((mode.next(), mode.next()), (Some(value), None) if value == "1") {
        // An error on the first body poll aborts HTTP/1 before Hyper flushes the response.
        let body = Body::from_stream(futures_util::stream::iter([Err::<Bytes, _>(
            std::io::Error::other("fixture dropped the order creation response"),
        )]));
        return Ok((StatusCode::CREATED, body).into_response());
    }
    Ok((StatusCode::CREATED, Json(CreatedObject { id })).into_response())
}

async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, OrderError> {
    read_impl(state, headers, id, false).await
}

async fn read_alt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, OrderError> {
    read_impl(state, headers, id, true).await
}

async fn read_impl(
    state: AppState,
    headers: HeaderMap,
    id: String,
    alternate: bool,
) -> Result<Response, OrderError> {
    let mut modes = headers.get_all("x-fixture-response-mode").iter();
    let selected = modes.next();
    if selected.is_some() && !admin_authorized(&state, &headers) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "administration_secret_required",
        ));
    }
    if modes.next().is_some() {
        return Ok(error(StatusCode::BAD_REQUEST, "invalid_response_mode"));
    }
    let mode_name = match selected.map(|v| v.to_str()) {
        None => None,
        Some(Ok(
            value @ ("gzip" | "deflate" | "chunked" | "escaped_json" | "oversized" | "expansion"
            | "truncated"),
        )) => Some(value),
        _ => return Ok(error(StatusCode::BAD_REQUEST, "invalid_response_mode")),
    };
    let target = state.target.read().expect("target state lock poisoned");
    let mode = target.mode("cross_user_order_read");
    if mode == FixMode::RemovedRoute && !alternate {
        return Err(OrderError::NotFound);
    }
    let order = target.authorized_order(&headers, &id, |ownership, identity| {
        (state.flaws.cross_user_order_read
            && (matches!(
                mode,
                FixMode::Vulnerable | FixMode::PartialField | FixMode::BrokenLogin
            ) || (alternate && matches!(mode, FixMode::PartialRoute | FixMode::RemovedRoute))))
            || ownership.permits_read(identity)
    })?;
    let mut note = order.note.clone();
    if mode == FixMode::PartialField
        && !target
            .identity(&headers)
            .is_some_and(|identity| order.ownership.permits_read(identity))
    {
        note.note.clear();
    }
    drop(target);
    Ok(response_mode(note, mode_name))
}

// These fixed payload sizes are fixture parameters, not verifier limits.
const OVERSIZED_PADDING: usize = 8 * 1024 * 1024;
const EXPANSION_PADDING: usize = 1024 * 1024;

fn response_mode(note: Note, mode: Option<&str>) -> Response {
    let Some(mode) = mode else {
        return Json(note).into_response();
    };
    let value = match mode {
        "escaped_json" => {
            serde_json::json!({"document": serde_json::to_string(&note).expect("serialize note")})
        }
        "oversized" | "expansion" => {
            serde_json::json!({"note": note.note, "detail": note.detail, "padding": "x".repeat(if mode == "oversized" { OVERSIZED_PADDING } else { EXPANSION_PADDING })})
        }
        _ => serde_json::to_value(note).expect("serialize note"),
    };
    let mut bytes = serde_json::to_vec(&value).expect("serialize fixture response");
    let encoding = match mode {
        "gzip" | "expansion" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&bytes)
                .expect("compress fixture response");
            bytes = encoder.finish().expect("finish fixture compression");
            Some("gzip")
        }
        "deflate" => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&bytes)
                .expect("compress fixture response");
            bytes = encoder.finish().expect("finish fixture compression");
            Some("deflate")
        }
        _ => None,
    };
    let length = bytes.len();
    let body = match mode {
        "chunked" => {
            let split = length / 2;
            let chunks = vec![
                Ok::<_, std::io::Error>(Bytes::copy_from_slice(&bytes[..split])),
                Ok(Bytes::copy_from_slice(&bytes[split..])),
            ];
            Body::from_stream(futures_util::stream::iter(chunks))
        }
        "truncated" => {
            let partial = Bytes::copy_from_slice(&bytes[..length / 2]);
            let chunks = futures_util::stream::unfold(0, move |step| {
                let partial = partial.clone();
                async move {
                    match step {
                        0 => Some((Ok::<_, std::io::Error>(partial), 1)),
                        1 => {
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            Some((Err(std::io::Error::other("fixture truncated response")), 2))
                        }
                        _ => None,
                    }
                }
            });
            Body::from_stream(chunks)
        }
        _ => Body::from(bytes),
    };
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(encoding) = encoding {
        response
            .headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    }
    if mode == "truncated" {
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string()).expect("valid length"),
        );
    }
    response
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(note): Json<Note>,
) -> Result<StatusCode, OrderError> {
    update_impl(state, headers, id, note, false).await
}

async fn update_alt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(note): Json<Note>,
) -> Result<StatusCode, OrderError> {
    update_impl(state, headers, id, note, true).await
}

async fn update_impl(
    state: AppState,
    headers: HeaderMap,
    id: String,
    note: Note,
    alternate: bool,
) -> Result<StatusCode, OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let mode = target.mode("cross_user_order_patch");
    if mode == FixMode::RemovedRoute && !alternate {
        return Err(OrderError::NotFound);
    }
    target.authorized_order(&headers, &id, |ownership, identity| {
        (state.flaws.cross_user_order_patch
            && (matches!(
                mode,
                FixMode::Vulnerable | FixMode::PartialField | FixMode::BrokenLogin
            ) || (alternate && matches!(mode, FixMode::PartialRoute | FixMode::RemovedRoute))))
            || ownership.is_owner(identity)
    })?;
    target
        .orders
        .get_mut(&id)
        .expect("order exists under the same lock")
        .note = note;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    target.authorized_order(&headers, &id, Ownership::is_owner)?;
    target.orders.remove(&id);
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
        sync::{Arc, RwLock},
        time::Duration,
    };

    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::*;
    use crate::{FixtureFlaws, app_with_state};

    fn request(addr: SocketAddr, method: &str, path: &str, headers: &str, body: &str) -> String {
        String::from_utf8(request_bytes(addr, method, path, headers, body)).unwrap()
    }

    fn request_bytes(
        addr: SocketAddr,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> Vec<u8> {
        let timeout = Duration::from_secs(5);
        let mut stream = TcpStream::connect_timeout(&addr, timeout).unwrap();
        stream.set_read_timeout(Some(timeout)).unwrap();
        stream.set_write_timeout(Some(timeout)).unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len(),
        )
        .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }

    async fn check_response_mode(mode: &str) {
        let state = AppState {
            target: Arc::new(RwLock::new(TargetState::seeded())),
            admin_secret: "reset-secret".into(),
            flaws: FixtureFlaws::default(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server =
            tokio::spawn(
                async move { axum::serve(listener, app_with_state(state)).await.unwrap() },
            );
        let close = "Connection: close\r\n";
        let login = request(
            addr,
            "POST",
            "/app/login",
            close,
            r#"{"username":"alice","password":"alice-password"}"#,
        );
        let cookie = login
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let auth = format!("Cookie: {cookie}\r\n{close}");
        let marker = "0123456789abcdef0123456789abcdef";
        let created = request(
            addr,
            "POST",
            "/app/api/orders",
            &auth,
            &format!(r#"{{"note":"{marker}"}}"#),
        );
        let id = serde_json::from_str::<Value>(created.split_once("\r\n\r\n").unwrap().1).unwrap()
            ["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let path = format!("/app/api/orders/{id}");
        for bad in [
            "",
            "X-Fixture-Admin-Secret: wrong\r\n",
            "X-Fixture-Admin-Secret: reset-secret\r\nX-Fixture-Admin-Secret: reset-secret\r\n",
        ] {
            let response = request(
                addr,
                "GET",
                &path,
                &format!("{auth}X-Fixture-Response-Mode: gzip\r\n{bad}"),
                "",
            );
            assert!(response.starts_with("HTTP/1.1 403 "), "{response:?}");
        }
        let no_session = request(
            addr,
            "GET",
            &path,
            &format!(
                "{close}X-Fixture-Admin-Secret: reset-secret\r\nX-Fixture-Response-Mode: {mode}\r\n"
            ),
            "",
        );
        assert!(no_session.starts_with("HTTP/1.1 401 "), "{no_session:?}");
        let duplicate = request(
            addr,
            "GET",
            &path,
            &format!(
                "{auth}X-Fixture-Admin-Secret: reset-secret\r\nX-Fixture-Response-Mode: {mode}\r\nX-Fixture-Response-Mode: {mode}\r\n"
            ),
            "",
        );
        assert!(duplicate.starts_with("HTTP/1.1 400 "), "{duplicate:?}");
        {
            let raw = request_bytes(
                addr,
                "GET",
                &path,
                &format!(
                    "{auth}X-Fixture-Admin-Secret: reset-secret\r\nX-Fixture-Response-Mode: {mode}\r\n"
                ),
                "",
            );
            let boundary = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let headers = std::str::from_utf8(&raw[..boundary]).unwrap();
            let body = &raw[boundary + 4..];
            assert!(headers.starts_with("HTTP/1.1 200 "), "{mode}: {headers}");
            match mode {
                "gzip" | "deflate" | "expansion" => {
                    let encoding = if mode == "deflate" { "deflate" } else { "gzip" };
                    assert!(headers.contains(&format!("content-encoding: {encoding}")));
                    let mut decoded = Vec::new();
                    if mode == "deflate" {
                        flate2::read::ZlibDecoder::new(body)
                            .read_to_end(&mut decoded)
                            .unwrap();
                    } else {
                        flate2::read::GzDecoder::new(body)
                            .read_to_end(&mut decoded)
                            .unwrap();
                    }
                    assert_eq!(
                        serde_json::from_slice::<Value>(&decoded).unwrap()["note"],
                        marker
                    );
                    if mode == "expansion" {
                        assert_eq!((body.len(), decoded.len()), (1111, 1048646));
                    }
                }
                "chunked" => {
                    assert!(headers.contains("transfer-encoding: chunked"));
                    let wire = std::str::from_utf8(body).unwrap();
                    assert!(wire.ends_with("0\r\n\r\n"));
                    let mut remaining = body;
                    let mut decoded = Vec::new();
                    loop {
                        let end = remaining.windows(2).position(|w| w == b"\r\n").unwrap();
                        let size = usize::from_str_radix(
                            std::str::from_utf8(&remaining[..end]).unwrap(),
                            16,
                        )
                        .unwrap();
                        remaining = &remaining[end + 2..];
                        if size == 0 {
                            break;
                        }
                        decoded.extend_from_slice(&remaining[..size]);
                        remaining = &remaining[size + 2..];
                    }
                    assert_eq!(
                        serde_json::from_slice::<Value>(&decoded).unwrap()["note"],
                        marker
                    );
                }
                "escaped_json" => {
                    let document: Value = serde_json::from_slice(body).unwrap();
                    let inner: Value =
                        serde_json::from_str(document["document"].as_str().unwrap()).unwrap();
                    assert_eq!(inner["note"], marker);
                    assert!(body.windows(2).any(|w| w == b"\\\""));
                }
                "oversized" => {
                    assert_eq!(body.len(), 8388678);
                    assert_eq!(
                        serde_json::from_slice::<Value>(body).unwrap()["note"],
                        marker
                    );
                }
                "truncated" => {
                    let declared: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!(!body.is_empty() && body.len() < declared);
                    assert!(serde_json::from_slice::<Value>(body).is_err());
                }
                _ => unreachable!(),
            }
        }
        let normal = request(addr, "GET", &path, &auth, "");
        assert_eq!(
            serde_json::from_str::<Value>(normal.split_once("\r\n\r\n").unwrap().1).unwrap()["note"],
            marker
        );
        server.abort();
    }

    macro_rules! wire_test {
        ($name:ident, $mode:literal) => {
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $name() {
                check_response_mode($mode).await;
            }
        };
    }
    wire_test!(gzip_wire, "gzip");
    wire_test!(deflate_wire, "deflate");
    wire_test!(chunked_wire, "chunked");
    wire_test!(escaped_json_wire, "escaped_json");
    wire_test!(oversized_wire, "oversized");
    wire_test!(expansion_wire, "expansion");
    wire_test!(truncated_wire, "truncated");

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_create_closes_without_response_after_one_insert() {
        let state = AppState {
            target: Arc::new(RwLock::new(TargetState::seeded())),
            admin_secret: "reset-secret".into(),
            flaws: FixtureFlaws::default(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = app_with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let orders = "/app/api/orders";
        let drop_header = "X-Fixture-Act-Then-Drop: 1\r\n";
        let close = "Connection: close\r\n";
        let note = r#"{"note":"committed before EOF"}"#;
        let denied = request(addr, "POST", orders, &format!("{close}{drop_header}"), note);
        assert!(denied.starts_with("HTTP/1.1 401 "), "{denied:?}");
        assert!(state.target.read().unwrap().orders.is_empty());

        let login = request(
            addr,
            "POST",
            "/app/login",
            close,
            r#"{"username":"alice","password":"alice-password"}"#,
        );
        assert!(login.starts_with("HTTP/1.1 200 "), "{login:?}");
        let cookie = login
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let auth = format!("Cookie: {cookie}\r\n");

        // Keep-alive is the HTTP/1.1 default, so EOF is caused by the fixture.
        let lost = request(addr, "POST", orders, &format!("{auth}{drop_header}"), note);
        assert!(
            lost.is_empty(),
            "the client received response bytes: {lost:?}"
        );
        let id = {
            let target = state.target.read().unwrap();
            assert_eq!(target.orders.len(), 1);
            target.orders.keys().next().unwrap().clone()
        };

        let normal = format!("{auth}{close}");
        let read = request(addr, "GET", &format!("{orders}/{id}"), &normal, "");
        assert!(read.starts_with("HTTP/1.1 200 "), "{read:?}");
        let (_, body) = read.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({"note": "committed before EOF"})
        );

        let created = request(addr, "POST", orders, &normal, r#"{"note":"ordinary"}"#);
        assert!(created.starts_with("HTTP/1.1 201 "), "{created:?}");
        server.abort();
    }
}
