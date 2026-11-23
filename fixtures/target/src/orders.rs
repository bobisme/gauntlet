use std::collections::hash_map::Entry;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use uuid::Uuid;

use crate::{
    AppState, CreatedObject, FixMode, Identity, Note, Ownership, TargetState, error, no_store,
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
) -> Result<Json<Note>, OrderError> {
    read_impl(state, headers, id, false).await
}

async fn read_alt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Note>, OrderError> {
    read_impl(state, headers, id, true).await
}

async fn read_impl(
    state: AppState,
    headers: HeaderMap,
    id: String,
    alternate: bool,
) -> Result<Json<Note>, OrderError> {
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
    Ok(Json(note))
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
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

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
