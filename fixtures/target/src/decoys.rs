//! Isolated wire-behavior controls; these do not change the four flaw switches.
use std::collections::{HashMap, VecDeque};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use uuid::Uuid;

use crate::{AppState, CreatedObject, Note, Ownership, error, no_store, session_token};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum Kind {
    Login,
    Stale,
    Forbidden,
    Echo,
    Expiring,
}

struct Object {
    ownership: Ownership,
    note: Note,
    snapshot: Option<Note>,
}

#[derive(Default)]
pub(super) struct DecoyState {
    objects: HashMap<(Kind, String), Object>,
    recent: VecDeque<String>,
}

pub(super) fn routes() -> Router<AppState> {
    let mut routes = Router::new();
    for (kind, collection, member) in [
        (
            Kind::Login,
            "/app/api/login-reports",
            "/app/api/login-reports/{id}",
        ),
        (
            Kind::Stale,
            "/app/api/stale-reports",
            "/app/api/stale-reports/{id}",
        ),
        (
            Kind::Forbidden,
            "/app/api/forbidden-reports",
            "/app/api/forbidden-reports/{id}",
        ),
        (
            Kind::Echo,
            "/app/api/echo-reports",
            "/app/api/echo-reports/{id}",
        ),
        (
            Kind::Expiring,
            "/app/api/expiring-reports",
            "/app/api/expiring-reports/{id}",
        ),
    ] {
        let mut family = Router::new()
            .route(collection, post(create))
            .route(member, get(read).delete(remove));
        if kind == Kind::Stale {
            family = family.route(member, axum::routing::patch(update));
        }
        routes = routes.merge(family.layer(Extension(kind)));
    }
    routes.layer(middleware::map_response(no_store))
}

async fn create(
    State(state): State<AppState>,
    Extension(kind): Extension<Kind>,
    headers: HeaderMap,
    Json(note): Json<Note>,
) -> Response {
    let mut target = state.target.write().expect("target state lock poisoned");
    let Some(account) = target.account(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "authentication_required");
    };
    let ownership = Ownership::from_account(account);
    let id = loop {
        let id = Uuid::new_v4().to_string();
        if !target.decoys.objects.contains_key(&(kind, id.clone())) {
            break id;
        }
    };
    if kind == Kind::Echo {
        // A bounded, app-local history deliberately ignores the requested object.
        target.decoys.recent.push_back(note.note.clone());
        if target.decoys.recent.len() > 8 {
            target.decoys.recent.pop_front();
        }
    }
    target.decoys.objects.insert(
        (kind, id.clone()),
        Object {
            ownership,
            note,
            snapshot: None,
        },
    );
    (StatusCode::CREATED, Json(CreatedObject { id })).into_response()
}

#[derive(Serialize)]
struct Echoes<'a> {
    echoes: &'a VecDeque<String>,
}

async fn read(
    State(state): State<AppState>,
    Extension(kind): Extension<Kind>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let mut target = state.target.write().expect("target state lock poisoned");
    if kind == Kind::Echo {
        return Json(Echoes {
            echoes: &target.decoys.recent,
        })
        .into_response();
    }
    let reader_id = target
        .identity(&headers)
        .map(|identity| identity.id.clone());
    let Some(object) = target.decoys.objects.get_mut(&(kind, id)) else {
        return error(StatusCode::NOT_FOUND, "resource_not_found");
    };
    let owner = reader_id.as_deref() == Some(object.ownership.owner_id.as_str());
    if owner {
        let note = object.note.clone();
        if kind == Kind::Stale {
            // Keep the first authorized response even after an owner PATCH.
            object.snapshot.get_or_insert_with(|| note.clone());
        }
        if kind == Kind::Expiring
            && let Some(token) = session_token(&headers)
        {
            // Deliver this response, then fail the next identity observation.
            target.sessions.remove(token);
        }
        return Json(note).into_response();
    }
    match kind {
        Kind::Login => {
            Html("<!doctype html><title>Sign in</title><h1>Sign in required</h1>").into_response()
        }
        Kind::Forbidden => (StatusCode::FORBIDDEN, Json(object.note.clone())).into_response(),
        Kind::Stale if object.snapshot.is_some() => {
            Json(object.snapshot.clone().unwrap()).into_response()
        }
        _ if reader_id.is_none() => error(StatusCode::UNAUTHORIZED, "authentication_required"),
        _ => error(StatusCode::NOT_FOUND, "resource_not_found"),
    }
}

async fn update(
    State(state): State<AppState>,
    Extension(kind): Extension<Kind>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(note): Json<Note>,
) -> Response {
    let mut target = state.target.write().expect("target state lock poisoned");
    let Some(reader) = target.identity(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "authentication_required");
    };
    let reader_id = reader.id.clone();
    let Some(object) = target
        .decoys
        .objects
        .get_mut(&(kind, id))
        .filter(|object| object.ownership.owner_id == reader_id)
    else {
        return error(StatusCode::NOT_FOUND, "resource_not_found");
    };
    object.note = note;
    StatusCode::NO_CONTENT.into_response()
}

async fn remove(
    State(state): State<AppState>,
    Extension(kind): Extension<Kind>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let mut target = state.target.write().expect("target state lock poisoned");
    let Some(reader) = target.identity(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "authentication_required");
    };
    let key = (kind, id);
    if !target
        .decoys
        .objects
        .get(&key)
        .is_some_and(|object| object.ownership.is_owner(reader))
    {
        return error(StatusCode::NOT_FOUND, "resource_not_found");
    }
    target.decoys.objects.remove(&key);
    StatusCode::NO_CONTENT.into_response()
}
