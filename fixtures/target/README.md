# Development target

`scourge-fixture` is a self-contained, in-memory HTTP target for Scourge's development tests. It has no database, frontend, instrument, or external service dependency. It provides seeded accounts, cookie sessions, orders, resource read policies, and deliberately planted authorization defects for local verifier development. The binary and `app()` enable all four defects by default. There is no public fix control yet; M0.2.7 (`bn-189`) owns that operator interface.

From the repository root:

```sh
cargo build --locked
cargo run --locked -p scourge-fixture -- --listen 127.0.0.1:3000 --admin-secret local-reset-secret
```

The prebuilt binary is `target/debug/scourge-fixture`. `--listen` accepts an IP address and port; its default is `127.0.0.1:3000`, and port `0` selects an available port. The actual listening address is printed on stderr. The administration secret is required, must be nonempty, and can instead be supplied through `SCOURGE_FIXTURE_ADMIN_SECRET`. It is never printed. `--help` and `--version` are available. Exit codes are 0 for a normal stop/help/version, 1 for invalid configuration, and 2 for a runtime failure. Ctrl-C stops the server gracefully.

All data is process-local. Restarting or resetting restores these seeded identities:

| Username | Password | Stable `/id` | Role | Tenant |
|---|---|---|---|---|
| alice | alice-password | user-alice | user | tenant-a |
| bob | bob-password | user-bob | user | tenant-b |
| admin | admin-password | user-admin | admin | null |
| alice-verify | alice-verify-password | user-alice-verify | user | tenant-a |
| bob-verify | bob-verify-password | user-bob-verify | user | tenant-b |

The verifier accounts have the same roles and tenants as their exploration counterparts, with distinct subjects. These development credentials are intentionally known; the later evaluation boundary must withhold verifier credentials and fixture administration from the worker to establish target isolation.

```sh
curl --fail-with-body -c /tmp/scourge-alice.cookies \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-password"}' \
  http://127.0.0.1:3000/app/login
curl --fail-with-body -b /tmp/scourge-alice.cookies http://127.0.0.1:3000/app/api/me
curl --fail-with-body -b /tmp/scourge-alice.cookies -c /tmp/scourge-alice.cookies \
  -X POST http://127.0.0.1:3000/app/logout
curl --fail-with-body -X POST -H 'X-Fixture-Admin-Secret: local-reset-secret' \
  http://127.0.0.1:3000/app/_reset
```

`POST /app/login` accepts JSON credentials and returns the identity plus an opaque `HttpOnly`, `SameSite=Lax`, `/app`-scoped cookie. Cookies use plain HTTP for local development. A login rotates any supplied existing session. Independent cookie jars may hold independent sessions for one account: session labels never change that account's stable `/id`.

`GET /app/api/me` returns `{"id":"user-alice","username":"alice","role":"user","tenant":"tenant-a"}` for Alice. Missing, revoked, unknown or ambiguous session cookies return 401. Invalid credentials return 401. `POST /app/logout` revokes the supplied session and expires the cookie; repeated logout returns 204. Identity responses are marked `Cache-Control: no-store`.

`POST /app/_reset` requires the exact `X-Fixture-Admin-Secret` header and returns 204 after reseeding accounts, revoking every session, and clearing orders, policy resources and sharing settings. Missing, wrong, or repeated secret headers return 403 and leave state intact. An admin login does not grant reset authority. Subjects stay stable after reset; old cookies never regain access.

## Owner-private orders

| Request | JSON body | Successful response |
|---|---|---|
| `POST /app/api/orders` | `{"note":"free text"}` | 201 with a fresh `{"id":"…"}` |
| `GET /app/api/orders/{id}` | | 200 with `{"note":"…"}` |
| `PATCH /app/api/orders/{id}` | `{"note":"replacement text"}` | 204 |
| `DELETE /app/api/orders/{id}` | | 204 |

By default, a successful create inserts a new order and returns its ID. The server assigns ownership to the signed-in account, which can use independent sessions to access its orders. The intended policy permits only the owner to read an order. The owner can [share new orders](#account-sharing) with a named account. The intended policy permits only the owner to PATCH or DELETE. The default development fixture deliberately omits the cross-user read and PATCH ownership checks; any authenticated account can perform those two operations. DELETE remains owner-only. Unknown IDs and inaccessible orders return 404. A well-formed request without a valid session receives 401. The order routes send `Cache-Control: no-store`.

### Lose an order creation response

Add `X-Fixture-Act-Then-Drop: 1` to a chosen `POST /app/api/orders` request. Once the ordinary authentication and JSON checks succeed, the fixture creates the order and closes the HTTP/1 connection before sending any response bytes. Send the header exactly once on the selected request. The header applies only to that request. An authenticated fixture reset clears the order along with other fixture data.

### Teapot create-order macro

Start the fixture on its default address, `127.0.0.1:3000`. With Teapot and `jq` available, create a Teapot project for the fixture and install [the macro](teapot/create-order.toml). If the fixture uses a different address, set `steps.request.url` in the installed macro to match.

```sh
teapot_project=$(mktemp -d)
teapot --project "$teapot_project" projects init
install -m 600 fixtures/target/teapot/create-order.toml "$teapot_project/.teapot/macros/create-order.toml"
teapot --project "$teapot_project" proxy start --listen 127.0.0.1:0 --detach
teapot --project "$teapot_project" scope add 127.0.0.1

teapot --project "$teapot_project" sessions create alice
teapot --project "$teapot_project" requests send POST http://127.0.0.1:3000/app/login \
  --session alice --header 'Content-Type: application/json' \
  --body '{"username":"alice","password":"alice-password"}'

note='0123456789abcdef0123456789abcdef'
note_json=$(jq -cn --arg note "$note" '$note')
creation_flow=$(
  teapot --project "$teapot_project" --json --yes flows replay \
    --macro create-order --step 1 --session alice --set "json:note=$note_json" |
    jq -er '.flow.macro_replay.replayed | select(.status == 201 and .outcome == "complete") | .flow'
)
order_id=$(
  teapot --project "$teapot_project" --json flows show "$creation_flow" --part response |
    jq -er '.flow.response_body | fromjson | .id'
)
printf '%s\n' "$order_id"
```

The macro sends one POST and takes `/id` from its response. The replay edit binds `/note` as a JSON string. Once finished, stop the engine with `teapot --project "$teapot_project" proxy stop`.

## Resource read policies

| Collection | Default readers |
|---|---|
| `/app/api/invoices` | The owner |
| `/app/api/tenant-notes` | The owner and accounts in the owner's tenant |
| `/app/api/bulletins` | Any signed-in account |
| `/app/api/catalog` | Anyone, including visitors without a session |
| `/app/api/private-reports` | The owner (intended policy) |
| `/app/api/cached-reports` | The owner (intended policy) |

POST to any collection with `{"note":"free text"}` and a valid session. The server assigns ownership to the signed-in account and returns 201 with a fresh `{"id":"…"}`. GET `{collection}/{id}` returns 200 with `{"note":"…"}` for an authorized reader. DELETE `{collection}/{id}` returns 204 for the owner.

Requests that require authentication return 401 without a valid session. Unknown IDs and inaccessible resources return 404. Resource routes send `Cache-Control: no-store`.

The two report collections use the same create/read/delete JSON contract and server-assigned ownership as the other collections. In the default fixture, private reports omit the authentication check for anonymous reads, while other signed-in accounts still receive 404. Cached reports deny a cold anonymous read, then deliberately return an owner's response to an anonymous reader after the owner's GET. Only an authorized owner GET primes this in-memory cache. The cache is scoped to the object and app instance, and owner DELETE or reset clears it. Responses still use `Cache-Control: no-store`; this defect models server-side cache behavior independent of HTTP client caching.

The hidden Rust harness `app_with_flaws(secret, FixtureFlaws { ... })` lets tests toggle `cross_user_order_read`, `cross_user_order_patch`, `anonymous_private_read`, and `shared_private_cache` independently. `true` enables each defect. Earlier policy regression tests explicitly set all four to `false`; the defect suite tests each switch both alone and with the other switches enabled. This temporary harness has no environment or HTTP control and does not implement later partial-fix, broken-login, or removed-route modes. Ground-truth packaging and isolation are deferred to M0.2.8; this change adds no answer-key artifact.

## Decoy and edge-case routes

These isolated route families are always available in this development fixture. They do not alter the four `FixtureFlaws` switches or the policy-resource routes. Each accepts an authenticated `POST /app/api/{family}-reports` with `{"note":"free text"}`, returns 201 with a fresh `{"id":"…"}`, and supports owner-only DELETE of that ID. Creation-time sharing does not grant another account ownership or change these behaviors. Every response carries `Cache-Control: no-store`.

| Family | GET `/app/api/{family}-reports/{id}` |
|---|---|
| `login` | The owner receives 200 with `{"note":"…"}`. Other readers receive 200 HTML containing a sign-in page without the note. |
| `stale` | The first owner GET captures a snapshot; later owner GETs return the current note. Before a snapshot exists, anonymous readers receive 401 and other signed-in accounts receive 404. After it exists, those readers receive 200 with the snapshot. |
| `forbidden` | The owner receives 200 with the note. Other readers receive **403 with the same note body**, an intentional real data exposure. |
| `echo` | Every GET returns 200 with `{"echoes":["…"]}` containing the last eight notes POSTed to this family, oldest first, regardless of the requested ID or session. A nonexistent ID returns the same echoes. |
| `expiring` | An owner GET returns 200 with the note and immediately revokes only its requesting session. The next `/app/api/me` with that cookie returns 401. Other sessions remain valid. Denied and missing-object reads do not revoke sessions. |

The `stale` family additionally supports owner-only `PATCH /app/api/stale-reports/{id}` with `{"note":"replacement text"}`, returning 204. PATCH changes the stored note without refreshing the snapshot. To reproduce a stale round, create an old note, GET as owner to capture it, PATCH a fresh canary, GET as owner to confirm the fresh value, then GET as another reader: that reader sees only the old value. Owner DELETE removes both the object and its snapshot.

For `echo`, POST records recent notes; GET does not expose an object-specific `note` field. Negative-control GETs for unrelated and nonexistent IDs receive the same recent markers. Deleting an echo object leaves its marker in the bounded history until it is displaced or reset. Missing IDs in the other families return 404. For `expiring`, probe `/app/api/me`, GET the owned object, then probe `/app/api/me` again without a client logout or login: the target drives the transition. An independent session for the same subject remains valid until it performs its own designated read.

The existing independent-login scenario covers the same-subject case: create two cookie jars by logging into the same account, probe both `/app/api/me` responses, then read a private invoice created by one jar from the other. The stable subject is identical despite different session cookies. Revoking one cookie does not revoke the other.

All decoy objects, snapshots and echo history belong to one app instance and are cleared by authenticated fixture reset; sessions are revoked by that reset as usual. `tests/decoys.rs` exercises response status, headers, bodies and ordered HTTP sequences with the original switches both all off and all on. `tests/sessions.rs` extends the established same-subject scenario with an owner-private invoice read.

Handoff: M0.2.7 (`bn-189`) owns public/operator mode consolidation; this module uses only route-local state and adds no public switches. M0.2.8 (`bn-2ag`) owns the ground-truth catalog and answer-key isolation; this implementation deliberately adds no such artifact.

## Account sharing

`GET /app/api/settings/sharing` returns the signed-in account's setting as `{"share_new_with":null}` by default. Send `PUT /app/api/settings/sharing` with `{"share_new_with":"bob"}` to include Bob among the readers of orders, invoices, and tenant notes the signed-in account creates from then on. The two report collections remain owner-private under their intended policy. A successful PUT returns 204. Use `{"share_new_with":null}` to disable sharing for future objects. The username must name a different seeded account.

The recipient can read the shared objects and the creator retains exclusive permission to change or delete them. Each object keeps the recipient it had at creation, and other accounts have their own independent settings.

Run **every repository test from the root** with `just test`. `just check` additionally checks formatting and Clippy. Future suites must be added to the root `test` recipe so this command stays comprehensive.
