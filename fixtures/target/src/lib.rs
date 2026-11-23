//! Development-only target with seeded accounts, cookie sessions and resource policies.

mod orders;
mod resources;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SESSION_COOKIE: &str = "scourge_session";

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub role: String,
    pub tenant: Option<String>,
}

#[derive(Clone)]
struct Account {
    identity: Identity,
    password: String,
    share_new_with: Option<String>,
}

struct Ownership {
    owner_id: String,
    shared_with: Option<String>,
}

impl Ownership {
    fn from_account(account: &Account) -> Self {
        Self {
            owner_id: account.identity.id.clone(),
            shared_with: account.share_new_with.clone(),
        }
    }

    fn is_owner(&self, identity: &Identity) -> bool {
        self.owner_id == identity.id
    }

    fn permits_read(&self, identity: &Identity) -> bool {
        self.is_owner(identity) || self.shared_with.as_deref() == Some(&identity.username)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Note {
    note: String,
}

#[derive(Serialize)]
struct CreatedObject {
    id: String,
}

struct TargetState {
    accounts: HashMap<String, Account>,
    sessions: HashMap<String, String>,
    orders: HashMap<String, orders::Order>,
    resources: HashMap<(resources::ResourceKind, String), resources::Resource>,
    private_cache: HashMap<String, Note>,
}

impl TargetState {
    fn seeded() -> Self {
        let accounts = [
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
        ]
        .into_iter()
        .map(|(username, id, role, tenant)| {
            (
                username.to_owned(),
                Account {
                    identity: Identity {
                        id: id.to_owned(),
                        username: username.to_owned(),
                        role: role.to_owned(),
                        tenant: tenant.map(str::to_owned),
                    },
                    password: format!("{username}-password"),
                    share_new_with: None,
                },
            )
        })
        .collect();
        Self {
            accounts,
            sessions: HashMap::new(),
            orders: HashMap::new(),
            resources: HashMap::new(),
            private_cache: HashMap::new(),
        }
    }

    fn account(&self, headers: &HeaderMap) -> Option<&Account> {
        session_token(headers)
            .and_then(|token| self.sessions.get(token))
            .and_then(|username| self.accounts.get(username))
    }

    fn identity(&self, headers: &HeaderMap) -> Option<&Identity> {
        self.account(headers).map(|account| &account.identity)
    }
}

#[derive(Clone)]
struct AppState {
    target: Arc<RwLock<TargetState>>,
    admin_secret: Arc<str>,
    flaws: FixtureFlaws,
}

/// Internal fixture harness controls. The CLI switch contract is owned by M0.2.7.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct FixtureFlaws {
    pub cross_user_order_read: bool,
    pub cross_user_order_patch: bool,
    pub anonymous_private_read: bool,
    pub shared_private_cache: bool,
}

impl Default for FixtureFlaws {
    fn default() -> Self {
        Self {
            cross_user_order_read: true,
            cross_user_order_patch: true,
            anonymous_private_read: true,
            shared_private_cache: true,
        }
    }
}

/// Build an independent seeded target with the development defects enabled.
/// The administration secret must be nonempty, separate from the seeded admin account.
pub fn app(admin_secret: String) -> Router {
    app_with_flaws(admin_secret, FixtureFlaws::default())
}

/// Internal constructor for tests that independently exercise defect repairs.
#[doc(hidden)]
pub fn app_with_flaws(admin_secret: String, flaws: FixtureFlaws) -> Router {
    assert!(
        !admin_secret.is_empty(),
        "administration secret must not be empty"
    );
    Router::new()
        .route("/app/login", post(login))
        .route("/app/logout", post(logout))
        .route("/app/api/me", get(me))
        .route("/app/_reset", post(reset))
        .merge(orders::routes())
        .merge(resources::routes())
        .with_state(AppState {
            target: Arc::new(RwLock::new(TargetState::seeded())),
            admin_secret: admin_secret.into(),
            flaws,
        })
}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// Reject ambiguous duplicate session cookies, including across Cookie headers.
fn session_token(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for cookie in header.to_str().ok()?.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name == SESSION_COOKIE {
                if found.is_some() || value.is_empty() {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Response {
    let mut target = state.target.write().expect("target state lock poisoned");
    let Some(account) = target.accounts.get(&login.username) else {
        return error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    };
    if account.password != login.password {
        return error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    }
    let identity = account.identity.clone();
    // Rotate an existing browser session; independent cookie jars remain independent.
    if let Some(token) = session_token(&headers) {
        target.sessions.remove(token);
    }
    let token = Uuid::new_v4().to_string();
    target.sessions.insert(token.clone(), login.username);
    let mut response = Json(identity).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={token}; Path=/app; HttpOnly; SameSite=Lax"
        ))
        .expect("UUID cookie is a valid header"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        state
            .target
            .write()
            .expect("target state lock poisoned")
            .sessions
            .remove(token);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("scourge_session=; Path=/app; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let target = state.target.read().expect("target state lock poisoned");
    let mut response = match target.identity(&headers) {
        Some(identity) => Json(identity).into_response(),
        None => error(StatusCode::UNAUTHORIZED, "authentication_required"),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn reset(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut secrets = headers.get_all("x-fixture-admin-secret").iter();
    if secrets.next().and_then(|value| value.to_str().ok()) != Some(state.admin_secret.as_ref())
        || secrets.next().is_some()
    {
        return error(StatusCode::FORBIDDEN, "administration_secret_required");
    }
    *state.target.write().expect("target state lock poisoned") = TargetState::seeded();
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn reset_restores_modified_seed_accounts() {
        let state = AppState {
            target: Arc::new(RwLock::new(TargetState::seeded())),
            admin_secret: "reset-secret".into(),
            flaws: FixtureFlaws::default(),
        };
        {
            let mut target = state.target.write().unwrap();
            target.accounts.remove("alice");
            target.accounts.get_mut("bob").unwrap().password = "changed".into();
            target.accounts.get_mut("admin").unwrap().identity.role = "user".into();
        }
        let router = Router::new()
            .route("/app/_reset", post(reset))
            .with_state(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/app/_reset")
                    .header("x-fixture-admin-secret", "reset-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let restored = state.target.read().unwrap();
        assert_eq!(restored.accounts.len(), 5);
        assert_eq!(restored.accounts["alice"].identity.id, "user-alice");
        assert_eq!(restored.accounts["bob"].password, "bob-password");
        assert_eq!(restored.accounts["admin"].identity.role, "admin");
    }
}
