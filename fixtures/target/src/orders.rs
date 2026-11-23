use std::collections::hash_map::Entry;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use uuid::Uuid;

use crate::{AppState, CreatedObject, Identity, Note, Ownership, TargetState, error, no_store};

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
) -> Result<(StatusCode, Json<CreatedObject>), OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let account = target
        .account(&headers)
        .ok_or(OrderError::AuthenticationRequired)?;
    let ownership = Ownership::from_account(account);
    loop {
        let Entry::Vacant(slot) = target.orders.entry(Uuid::new_v4().to_string()) else {
            continue;
        };
        let id = slot.key().clone();
        slot.insert(Order { ownership, note });
        return Ok((StatusCode::CREATED, Json(CreatedObject { id })));
    }
}

async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Note>, OrderError> {
    let target = state.target.read().expect("target state lock poisoned");
    let order = target.authorized_order(&headers, &id, |ownership, identity| {
        state.flaws.cross_user_order_read || ownership.permits_read(identity)
    })?;
    Ok(Json(order.note.clone()))
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(note): Json<Note>,
) -> Result<StatusCode, OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    target.authorized_order(&headers, &id, |ownership, identity| {
        state.flaws.cross_user_order_patch || ownership.is_owner(identity)
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
