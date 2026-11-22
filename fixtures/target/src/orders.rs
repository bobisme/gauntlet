use std::collections::hash_map::Entry;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, TargetState, error};

pub(super) struct Order {
    owner_id: String,
    note: OrderNote,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OrderNote {
    note: String,
}

#[derive(Serialize)]
struct CreatedOrder {
    id: String,
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
        .layer(middleware::map_response(async |mut response: Response| {
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }))
}

impl TargetState {
    fn owned_order(&self, headers: &HeaderMap, id: &str) -> Result<&Order, OrderError> {
        let identity = self
            .identity(headers)
            .ok_or(OrderError::AuthenticationRequired)?;
        self.orders
            .get(id)
            .filter(|order| order.owner_id == identity.id)
            .ok_or(OrderError::NotFound)
    }
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(note): Json<OrderNote>,
) -> Result<(StatusCode, Json<CreatedOrder>), OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let owner_id = target
        .identity(&headers)
        .ok_or(OrderError::AuthenticationRequired)?
        .id
        .clone();
    loop {
        let Entry::Vacant(slot) = target.orders.entry(Uuid::new_v4().to_string()) else {
            continue;
        };
        let id = slot.key().clone();
        slot.insert(Order { owner_id, note });
        return Ok((StatusCode::CREATED, Json(CreatedOrder { id })));
    }
}

async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<OrderNote>, OrderError> {
    let target = state.target.read().expect("target state lock poisoned");
    let order = target.owned_order(&headers, &id)?;
    Ok(Json(order.note.clone()))
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(note): Json<OrderNote>,
) -> Result<StatusCode, OrderError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    target.owned_order(&headers, &id)?;
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
    target.owned_order(&headers, &id)?;
    target.orders.remove(&id);
    Ok(StatusCode::NO_CONTENT)
}
