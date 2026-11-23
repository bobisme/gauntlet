Report written to `/tmp/scourge-realapp/sessions/m0.4.3-20261123T164242Z/workspace-a/report.md`. Summary:

## Supported findings (3)

**1. `books` / `read` — BOLA (secret disclosure)**
- `alice` → `GET /books/v1/bob-book-m043` → **200**, `{"book_title":"bob-book-m043","owner":"bob","secret":"bob-secret-m043"}`
- Violates "readable by the creating account only". Full 3×3 reader×owner matrix leaked every owner's `secret`.
- Controls: owner read = same body; no token = 401; unknown title = 404. Title is discoverable via the intentionally public listing, but the `secret` is not in that listing.

**2. `user_password` / `update` — cross-user password overwrite**
- `bob` → `PUT /users/v1/carol/password {"password":"cross-set-carol-m043-pw"}` → **204**
- State evidence: Carol's old password login failed; the injected password logged in as `carol` (JWT `sub=carol`). Bob's own login was unaffected, proving the write landed on Carol.
- No-token control = 401. Reverted to `carol-smoke-pw` and re-verified.

**3. `user_debug` / `read` — unauthenticated credential dump**
- No token → `GET /users/v1/_debug` → **200**, all 6 accounts with plaintext `password` and `admin` flag.
- Violates "readable by nobody". Compared against public `/users/v1` (username/email only) to isolate the leak; `/me` with bad token = 401 shows sessions are otherwise enforced.

## Tested, not supported
- **`user_email` update cross-user**: returns a misleading **204**, but only the *acting* account's email changes (path `{username}` is ignored). No cross-user effect → not an authorization bypass.
- **`users` read** and **books collection listing** expose only the fields the engagement declares public.
- **Book read without token** = 401 (control).

Scope: only `127.0.0.1:43939`; identities name1/name2/admin/alice/bob/carol; no registration, no admin account deletion; all test mutations restored to original state (final listing confirms).
