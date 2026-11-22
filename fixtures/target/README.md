# Development target

`scourge-fixture` is a self-contained, in-memory HTTP target for Scourge's development tests. It has no database, frontend, instrument, or external service dependency. It provides seeded accounts, cookie sessions and owner-private orders.

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

`POST /app/_reset` requires the exact `X-Fixture-Admin-Secret` header and returns 204 after reseeding accounts, revoking every session and clearing all orders. Missing, wrong, or repeated secret headers return 403 and leave state intact. An admin login does not grant reset authority. Subjects stay stable after reset; old cookies never regain access.

## Owner-private orders

| Request | JSON body | Successful response |
|---|---|---|
| `POST /app/api/orders` | `{"note":"free text"}` | 201 with a fresh `{"id":"…"}` |
| `GET /app/api/orders/{id}` | | 200 with `{"note":"…"}` |
| `PATCH /app/api/orders/{id}` | `{"note":"replacement text"}` | 204 |
| `DELETE /app/api/orders/{id}` | | 204 |

Every successful create inserts a new order and returns the ID of that order. The server assigns ownership to the signed-in account. The same account can use independent sessions to access its orders. GET, PATCH and DELETE return 404 for unknown IDs or orders belonging to another account. A well-formed request without a valid session receives 401. The order routes send `Cache-Control: no-store`.

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

Run **every repository test from the root** with `just test`. `just check` additionally checks formatting and Clippy. Future suites must be added to the root `test` recipe so this command stays comprehensive.
