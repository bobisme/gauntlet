# Development target

`scourge-fixture` is a self-contained, in-memory HTTP target for Scourge's development tests. It has no database, frontend, instrument, or external service dependency. This skeleton implements accounts and sessions only; resource APIs, planted flaws and fix switches arrive in later bones.

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

`POST /app/_reset` requires the exact `X-Fixture-Admin-Secret` header and returns 204 after reseeding accounts and revoking every session. Missing, wrong, or repeated secret headers return 403 and leave state intact. An admin login does not grant reset authority. Subjects stay stable after reset; old cookies never regain access.

Run **every repository test from the root** with `just test`. `just check` additionally checks formatting and Clippy. Future suites must be added to the root `test` recipe so this command stays comprehensive.
