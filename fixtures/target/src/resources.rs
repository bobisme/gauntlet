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

use crate::{AppState, CreatedObject, FixMode, Identity, Note, Ownership, error, no_store};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResourceKind {
    Invoice,
    TenantNote,
    Bulletin,
    Catalog,
    PrivateReport,
    CachedReport,
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
            ResourceKind::PrivateReport | ResourceKind::CachedReport => {
                reader.is_some_and(|reader| self.ownership.is_owner(reader))
            }
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
        (
            ResourceKind::PrivateReport,
            "/app/api/private-reports",
            "/app/api/private-reports/{id}",
        ),
        (
            ResourceKind::CachedReport,
            "/app/api/cached-reports",
            "/app/api/cached-reports/{id}",
        ),
    ] {
        router = router.merge(
            Router::new()
                .route(collection, post(create))
                .route(member, get(read).delete(remove))
                .layer(Extension(kind)),
        );
    }
    for (kind, path) in [
        (
            ResourceKind::PrivateReport,
            "/app/api/private-report-lookup/{id}",
        ),
        (
            ResourceKind::CachedReport,
            "/app/api/cached-report-lookup/{id}",
        ),
    ] {
        router = router.merge(
            Router::new()
                .route(path, get(read_alt))
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
    read_impl(state, kind, headers, id, false).await
}

async fn read_alt(
    State(state): State<AppState>,
    Extension(kind): Extension<ResourceKind>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Note>, ResourceError> {
    read_impl(state, kind, headers, id, true).await
}

async fn read_impl(
    state: AppState,
    kind: ResourceKind,
    headers: HeaderMap,
    id: String,
    alternate: bool,
) -> Result<Json<Note>, ResourceError> {
    let mut target = state.target.write().expect("target state lock poisoned");
    let issue = match kind {
        ResourceKind::PrivateReport => "anonymous_private_read",
        ResourceKind::CachedReport => "shared_private_cache",
        _ => "",
    };
    let mode = target.mode(issue);
    if mode == FixMode::RemovedRoute && !alternate && !issue.is_empty() {
        return Err(ResourceError::NotFound);
    }
    let vulnerable = matches!(
        mode,
        FixMode::Vulnerable | FixMode::PartialField | FixMode::BrokenLogin
    ) || (alternate
        && matches!(mode, FixMode::PartialRoute | FixMode::RemovedRoute));
    let reader = target.identity(&headers);
    // This cache deliberately omits the caller from its key. Only an authorized
    // owner read populates it; a cold anonymous read still requires authentication.
    if kind == ResourceKind::CachedReport
        && state.flaws.shared_private_cache
        && vulnerable
        && reader.is_none()
        && let Some(note) = target.private_cache.get(&id)
    {
        let mut note = note.clone();
        if mode == FixMode::PartialField {
            note.note.clear();
        }
        return Ok(Json(note));
    }
    let missing_auth = kind == ResourceKind::PrivateReport
        && state.flaws.anonymous_private_read
        && vulnerable
        && reader.is_none();
    if kind != ResourceKind::Catalog && reader.is_none() && !missing_auth {
        return Err(ResourceError::AuthenticationRequired);
    }
    let resource = target
        .resources
        .get(&(kind, id.clone()))
        .filter(|resource| missing_auth || resource.readable_by(kind, reader))
        .ok_or(ResourceError::NotFound)?;
    let mut note = resource.note.clone();
    if mode == FixMode::PartialField && missing_auth {
        note.note.clear();
    }
    if kind == ResourceKind::CachedReport && state.flaws.shared_private_cache {
        target.private_cache.insert(id, note.clone());
    }
    Ok(Json(note))
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
    if kind == ResourceKind::CachedReport {
        target.private_cache.remove(&key.1);
    }
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
