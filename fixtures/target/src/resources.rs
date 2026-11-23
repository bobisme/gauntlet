use std::collections::hash_map::Entry;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, CreatedObject, Identity, Note, Ownership, error, no_store};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResourceKind {
    Invoice,
    TenantNote,
    Bulletin,
    Catalog,
}

pub(super) struct Resource {
    ownership: Ownership,
    owner_tenant: Option<String>,
    note: Note,
}

impl Resource {
    fn readable_by(&self, kind: ResourceKind, reader: Option<&Identity>) -> bool {
        match kind {
            ResourceKind::Invoice => {
                reader.is_some_and(|reader| self.ownership.permits_read(reader))
            }
            ResourceKind::TenantNote => reader.is_some_and(|reader| {
                self.ownership.permits_read(reader)
                    || (self.owner_tenant.is_some() && reader.tenant == self.owner_tenant)
            }),
            ResourceKind::Bulletin => reader.is_some(),
            ResourceKind::Catalog => true,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SharingSetting {
    // Require the field so an empty object cannot silently disable sharing.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    share_new_with: Option<String>,
}

enum ResourceError {
    AuthenticationRequired,
    NotFound,
    InvalidSharingRecipient,
}

impl IntoResponse for ResourceError {
    fn into_response(self) -> Response {
        match self {
            Self::AuthenticationRequired => {
                error(StatusCode::UNAUTHORIZED, "authentication_required")
            }
            Self::NotFound => error(StatusCode::NOT_FOUND, "resource_not_found"),
            Self::InvalidSharingRecipient => error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_sharing_recipient",
            ),
        }
    }
}

pub(super) fn routes() -> Router<AppState> {
    let mut router = Router::new().route(
        "/app/api/settings/sharing",
        get(read_sharing).put(set_sharing),
    );
    for (kind, collection, member) in [
        (
            ResourceKind::Invoice,
            "/app/api/invoices",
            "/app/api/invoices/{id}",
        ),
        (
            ResourceKind::TenantNote,
            "/app/api/tenant-notes",
            "/app/api/tenant-notes/{id}",
        ),
        (
            ResourceKind::Bulletin,
            "/app/api/bulletins",
            "/app/api/bulletins/{id}",
        ),
        (
            ResourceKind::Catalog,
            "/app/api/catalog",
            "/app/api/catalog/{id}",
        ),
    ] {
        router = router.merge(
            Router::new()
                .route(collection, post(create))
                .route(member, get(read).delete(remove))
                .layer(Extension(kind)),
        );
    }
    router.layer(middleware::map_response(no_store))
}

async fn create(
    State(state): State<AppState>,
    Extension(kind): Extension<ResourceKind>,
    headers: HeaderMap,
    Json(note): Json<Note>,
) -> Result<(StatusCode, Json<CreatedObject>), ResourceError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let owner = target
        .account(&headers)
        .ok_or(ResourceError::AuthenticationRequired)?;
    let resource = Resource {
        ownership: Ownership::from_account(owner),
        owner_tenant: owner.identity.tenant.clone(),
        note,
    };
    loop {
        let id = Uuid::new_v4().to_string();
        let Entry::Vacant(slot) = target.resources.entry((kind, id.clone())) else {
            continue;
        };
        slot.insert(resource);
        return Ok((StatusCode::CREATED, Json(CreatedObject { id })));
    }
}

async fn read(
    State(state): State<AppState>,
    Extension(kind): Extension<ResourceKind>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Note>, ResourceError> {
    let target = state.target.read().expect("target state lock poisoned");
    let reader = target.identity(&headers);
    if kind != ResourceKind::Catalog && reader.is_none() {
        return Err(ResourceError::AuthenticationRequired);
    }
    let resource = target
        .resources
        .get(&(kind, id))
        .filter(|resource| resource.readable_by(kind, reader))
        .ok_or(ResourceError::NotFound)?;
    Ok(Json(resource.note.clone()))
}

async fn remove(
    State(state): State<AppState>,
    Extension(kind): Extension<ResourceKind>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ResourceError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let owner = target
        .identity(&headers)
        .ok_or(ResourceError::AuthenticationRequired)?;
    let key = (kind, id);
    target
        .resources
        .get(&key)
        .filter(|resource| resource.ownership.is_owner(owner))
        .ok_or(ResourceError::NotFound)?;
    target.resources.remove(&key);
    Ok(StatusCode::NO_CONTENT)
}

async fn read_sharing(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SharingSetting>, ResourceError> {
    let target = state.target.read().expect("target state lock poisoned");
    let account = target
        .account(&headers)
        .ok_or(ResourceError::AuthenticationRequired)?;
    Ok(Json(SharingSetting {
        share_new_with: account.share_new_with.clone(),
    }))
}

async fn set_sharing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(setting): Json<SharingSetting>,
) -> Result<StatusCode, ResourceError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let username = target
        .identity(&headers)
        .ok_or(ResourceError::AuthenticationRequired)?
        .username
        .clone();
    if let Some(recipient) = &setting.share_new_with
        && (recipient == &username || !target.accounts.contains_key(recipient))
    {
        return Err(ResourceError::InvalidSharingRecipient);
    }
    target
        .accounts
        .get_mut(&username)
        .expect("authenticated account exists under the same lock")
        .share_new_with = setting.share_new_with;
    Ok(StatusCode::NO_CONTENT)
}
