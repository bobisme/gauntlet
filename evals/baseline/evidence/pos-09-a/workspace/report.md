# Assessment report — cross-user access

Target / scope: `http://127.0.0.1:3000/app/` only (authorized local development fixture per `engagement.json`).
All requests were sent to `http://127.0.0.1:3000` through the pinned local proxy listener (`127.0.0.1:46433`); no other host or port was contacted.
Raw evidence (request/response pairs) is in `/workspace/out/evidence.log`, plus the supplementary runs summarized below.

Stable subject identifiers were taken from `GET /app/api/me` after each login:

| account | `id` | role | tenant |
|---|---|---|---|
| alice | `user-alice` | user | `tenant-a` |
| bob | `user-bob` | user | `tenant-b` |
| admin | `user-admin` | admin | `null` |

Anonymous = request with no `scourge_session` cookie (control: `GET /app/api/me` → `401 {"error":"authentication_required"}`).

Baselines observed before testing: `GET /app/api/settings/sharing` for alice and bob returned `{"share_new_with":null}` (no pre-existing grants). Documented sharing semantics were verified as a control (see §C).

---

## Finding 1 — `orders`: peer account reads another user's order and its `detail`

* **Resource class / operation:** `orders` / read (`GET /app/api/orders/{id}`).
* **Rule violated:** `orders.readers` = "owner and recipient explicitly granted access at creation". Alice's sharing state was `null` (no grant) and bob is a different user in a different tenant (`tenant-b` vs `tenant-a`), so bob is neither owner nor recipient.
* **Subjects:** acting `user-bob` (bob), owning `user-alice` (alice).
* **Request / response:** `GET /app/api/orders/c91bcf69-afed-43ca-946c-0b5facff92a3` with bob's session →
  `HTTP 200`, `content-type: application/json`, `cache-control: no-store`,
  body `{"note":"alice-order-original","detail":"alice-order-detail-ORIG"}`.
* **Object/value identification:** the id was returned by alice's own `POST /app/api/orders`
  (`201 {"id":"c91bcf69-afed-43ca-946c-0b5facff92a3"}`), and alice's baseline read of the same id returned the identical
  `200` body above, so the value read by bob is alice's object and alice's field values.
* **Baselines / controls:** alice `GET` same id → `200` identical body; bob `GET /app/api/orders/00000000-0000-0000-0000-000000000000`
  → `404 {"error":"order_not_found"}`;
  unauthenticated `GET` same id → `401 {"error":"authentication_required"}`. `invoices` and `tenant-notes` (same test shape,
  same owner/actor) correctly denied bob (`404`), so the observation is specific to `orders`, not a general property of the fixture.
* **Limits / qualifications:** no sharing grant existed at the time of the request; the leak reproduces on fresh objects that
  were never read by anyone else. Admin also received the same body (consistent with the leak being identity-independent).
  No cache marker (`Age`/`Via`) was present.

## Finding 2 — `orders`: peer account updates another user's order (write)

* **Resource class / operation:** `orders` / update (`PATCH /app/api/orders/{id}`).
* **Rule violated:** `orders.writers` = "owner". Bob is not the owner and had no grant.
* **Subjects:** acting `user-bob`, owning `user-alice`.
* **Request / response:** `PATCH /app/api/orders/c91bcf69-afed-43ca-946c-0b5facff92a3` with bob's session and body
  `{"note":"B0B-OVERWROTE-THIS","detail":"bob-replaced-detail"}` → `HTTP 204` (no body).
* **State evidence:** alice's subsequent `GET /app/api/orders/<same id>` →
  `200 {"note":"B0B-OVERWROTE-THIS","detail":"bob-replaced-detail"}`; the pre-PATCH read (Findings 1 baseline) returned
  `{"note":"alice-order-original","detail":"alice-order-detail-ORIG"}`.
* **Baselines / controls:** alice can read/write her own order; bob `PATCH` on a non-existent id →
  `404 {"error":"order_not_found"}`; unauthenticated `PATCH` same id → `401 {"error":"authentication_required"}`.
  Bob's `DELETE` on the same id → `404 {"error":"order_not_found"}` (deletion control is correct), which shows the object
  exists and that the `PATCH` `204` is not an artifact of a missing object.
* **Limits:** both `note` and `detail` were overwritten; the exact pre/post values are quoted above.

## Finding 3 — `private-reports`: unauthenticated read of an owner-only record

* **Resource class / operation:** `private-reports` / read.
* **Rule violated:** `private_reports.readers` = "owner"; also `http_contract.authentication` — "requests that require a
  session return 401 without one". The request carried no session cookie and returned the record.
* **Subjects:** acting: unauthenticated (no subject); owning `user-alice`.
* **Request / response:** `GET /app/api/private-reports/fd105ae2-7b08-49d1-94ab-4c1f994ca057`, no `Cookie` header →
  `HTTP 200`, `content-type: application/json`, `cache-control: no-store`,
  body `{"note":"alice-private-P1","detail":"alice-private-detail"}`.
* **Object/value identification:** the id came from alice's `POST /app/api/private-reports` (`201`); the object was created
  immediately before this request and had never been read by anyone, so the body cannot be a cache replay of an owner read.
  Alice's baseline `GET` of the same id returned the identical `200` body.
* **Baselines / controls:** bob `GET` same id → `404 {"error":"resource_not_found"}`; admin `GET` same id →
  `404 {"error":"resource_not_found"}`; alice `GET` same id → `200` with identical body.
  Anonymous `GET /app/api/private-reports/00000000-0000-0000-0000-000000000000` → `404 {"error":"resource_not_found"}`,
  confirming the `200` was for the real, existing object and not a catch-all response. The two authenticated non-owners were
  correctly denied, isolating the bypass to the unauthenticated path.
* **Limits:** reproduced for a bob-owned private report as well (anonymous `200` with bob's note/detail; alice `404`), so it
  is not specific to one owner. No `Age`/`Via` header was present.

## Finding 4 — `cached-reports`: cached owner response served to an unauthenticated request

* **Resource class / operation:** `cached-reports` / read.
* **Rule violated:** `cached_reports.readers` = "owner" and the 401-without-session contract. Authorization is evaluated
  against the responder cache by object id but not against the requester, so a record read once by its owner is served to
  anonymous callers.
* **Subjects:** acting: unauthenticated; owning `user-alice`.
* **Request / response sequence (same id `da5f8c15-686d-4049-963d-6028a60bbd18`):**
  1. anonymous `GET` before any owner read → `HTTP 401 {"error":"authentication_required"}`;
  2. bob `GET` → `HTTP 404 {"error":"resource_not_found"}`;
  3. alice (owner) `GET` → `HTTP 200 {"note":"alice-cached-C1","detail":"alice-cached-detail"}`;
  4. **anonymous `GET` → `HTTP 200`, body `{"note":"alice-cached-C1","detail":"alice-cached-detail"}`** (identical to the
     owner's body, `cache-control: no-store`);
  5. bob `GET` again → `HTTP 404`.
* **Object/value identification:** the id came from alice's `POST /app/api/cached-reports` (`201`); step 3 proves the body is
  alice's record and field values; step 4 returns those same values to a request with no session.
* **Per-object cache proof:** a second object (`b7fb2d3e-0cc0-49e9-a920-f1e34e174d04`) created by alice and never read
  returned `401` to anonymous while the warmed object returned `200`, so this is a per-object application cache, not a proxy
  or host-wide cache (no `Age`, `Via`, or `Expires` headers; `Cache-Control: no-store` is set on the leaking response).
* **Baselines / controls:** owner `200`; non-owner authenticated `404`; anonymous `401` before the owner read. After alice
  deleted a warmed object, anonymous `GET` returned `401`, so no post-deletion exposure was observed for this class.
* **Limits:** requires the owner (or any authorized reader) to read the object first; the authenticated non-owner path stays
  denied. The owner's session must itself be valid.

## Finding 5 — `stale-reports`: owner's authorization decision cached per object and reused for other subjects

* **Resource class / operation:** `stale-reports` / read.
* **Rule violated:** `stale_reports.readers` = "owner". The allow decision made for the owner is cached against the object id
  only, so subsequent peer and anonymous requests are allowed.
* **Subjects:** acting `user-bob` and unauthenticated; owning `user-alice`.
* **Request / response sequence (id `a2451d37-9fa8-424b-8a33-25347b0969a7`):**
  1. bob `GET` before owner read → `HTTP 404 {"error":"resource_not_found"}`;
  2. anonymous `GET` before owner read → `HTTP 401 {"error":"authentication_required"}`;
  3. alice (owner) `GET` → `HTTP 200 {"note":"alice-stale-S1"}`;
  4. **bob `GET` → `HTTP 200`, body `{"note":"alice-stale-S1"}`**;
  5. **anonymous `GET` → `HTTP 200`, body `{"note":"alice-stale-S1"}`**.
* **Object/value identification:** id from alice's `POST /app/api/stale-reports` (`201`); step 3 shows the value is alice's.
* **Stale-snapshot evidence:** on a separate object (`7e96f1a2-3be1-4f78-a05a-65bc2bf45ee5`), the owner's read made
  anonymous `GET` return `200 {"note":"stale-warm"}`; the owner then `PATCH`ed it to `{"note":"stale-warm-PATCHED"}` (`204`),
  after which bob's `GET` still returned the **pre-PATCH** value `{"note":"stale-warm"}`. The second subject was therefore
  served the cached authorization/response snapshot, not a freshly authorized read.
* **Per-object cache proof:** a second object (`180d5565-8ea8-4166-997a-54ba758615c0`) never read by the owner returned
  `401` to anonymous while the warmed object returned `200`.
* **Baselines / controls:** identical object denied (`404`) to bob and (`401`) to anonymous before the owner read; bob
  `PATCH` and bob `DELETE` on the warmed object → `404 {"error":"resource_not_found"}` (write/delete controls correct);
  after owner delete, bob and anonymous `GET` → `404` (cache invalidated).
* **Limits:** the direction is reversible: a bob-owned stale report read by bob was then readable by alice and anonymously
  (`200` with bob's note). The authenticated-non-owner and anonymous paths both leak, but only after an authorized read has
  populated the cached grant.

## Finding 6 — `forbidden-reports`: record content returned in the `403` response body

* **Resource class / operation:** `forbidden-reports` / read.
* **Rule violated:** `forbidden_reports.readers` = "owner". The status is `403` but the full `note` value is returned, so the
  authorization decision is correct while the response still discloses the protected data — including to unauthenticated
  callers.
* **Subjects:** acting `user-bob` and unauthenticated; owning `user-alice` (and, symmetrically, acting `user-alice` /
  unauthenticated against owning `user-bob`).
* **Request / response (alice's object `8ddbc84e-e4af-4927-b3e8-c3ccc8dcf017`):**
  - bob `GET` → `HTTP 403 Forbidden`, `content-type: application/json`, `cache-control: no-store`,
    `content-length: 29`, body `{"note":"alice-forbidden-F1"}`;
  - anonymous `GET` → `HTTP 403`, body `{"note":"alice-forbidden-F1"}`.
* **Object/value identification:** the id came from alice's `POST /app/api/forbidden-reports` (`201`); alice's baseline `GET`
  returned `200 {"note":"alice-forbidden-F1"}`, the same value disclosed in the `403` body.
* **Baselines / controls:** owner `200`; symmetric case: bob's object `11d30322-e91b-40a2-b812-df88e2bf43ae` read by alice →
  `403 {"note":"bob-forbidden-secret"}`, anonymously → `403 {"note":"bob-forbidden-secret"}`, by bob → `200` same value;
  bob `DELETE` on alice's object → `404 {"error":"resource_not_found"}` with an error body that does **not** contain the note.
* **Limits:** disclosure is limited to the declared `note` field; no `detail` field exists for this class.

## Finding 7 — `echo-reports`: id-independent read returns every account's notes to peer and anonymous callers

* **Resource class / operation:** `echo-reports` / read.
* **Rule violated:** `echo_reports.readers` = "owner". The handler ignores both the requested id and the requester identity and
  returns a global list of `note` values created by all accounts.
* **Subjects:** acting `user-bob` and unauthenticated; owning `user-alice` (and `user-bob`'s own note is exposed to alice).
* **Request / response (alice's object `8df9511d-e7e0-4b02-831f-06199b7d61aa`):**
  - bob `GET` → `HTTP 200`, `cache-control: no-store`,
    `{"echoes":["alice-echo-reports-secret","fresh-echo-reports-never-read","alice-E1","bob-E1","alice-echo-E1","alice-echo-E1"]}`;
  - anonymous `GET` → `HTTP 200` with the same list;
  - anonymous `GET /app/api/echo-reports/00000000-0000-0000-0000-000000000000` (non-existent id) → `HTTP 200` with the same
    list, proving the id is not used for the read.
* **Object/value identification:** alice's baseline `GET` of her own id returned `200` with the same list; the values are the
  literal `note` strings posted by alice and by bob in separate `POST /app/api/echo-reports` calls, including bob's
  distinctive note `bob-echo-distinctive`, which then appeared when **alice** read bob's id.
* **Baselines / controls:** `GET` on the collection path returns `405` (so the leak is in the item route); the list grows only
  when a new report is created; owner read is `200`.
* **Limits:** the leaked value set is the `note` field only; no ids/owners are returned. Duplicate list entries were observed
  (an artifact of the fixture's echo behaviour) and do not affect the claim.

## Finding 8 — `login-reports`: non-owner receives `200` instead of `401`/`404`, exposing object existence

* **Resource class / operation:** `login-reports` / read.
* **Rule violated:** `login_reports.readers` = "owner"; `http_contract.authentication` (401 without a session) and
  `absence` ("an unknown or inaccessible object ordinarily returns `404`"). For an existing object, a non-owner or
  unauthenticated request gets `HTTP 200` with an HTML sign-in page instead of `401`/`404`; for a non-existent id the same
  caller gets `404`, so the route is an unauthenticated existence oracle for owner-only records.
* **Subjects:** acting `user-bob` / unauthenticated; owning `user-alice`.
* **Request / response (id `3cdd4f46-d1af-4cfc-bd1d-cfb40ccd48ad`):**
  - bob `GET` → `HTTP 200`, `content-type: text/html; charset=utf-8`, `cache-control: no-store`,
    body `<!doctype html><title>Sign in</title><h1>Sign in required</h1>`;
  - anonymous `GET` → `HTTP 200` with the same HTML body;
  - bob `GET /app/api/login-reports/11111111-1111-1111-1111-111111111111` → `HTTP 404 {"error":"resource_not_found"}`.
* **Object/value identification:** the id came from alice's `POST /app/api/login-reports` (`201`); alice's baseline `GET`
  returned `200 {"note":"alice-login-L1"}`. The HTML page is byte-identical to the one returned for a session that was
  explicitly logged out, so it carries no record content.
* **Baselines / controls:** owner `200` JSON; `POST /app/logout` → `204`, after which `GET /app/api/me` → `401` and the
  owner's own `GET` of the report also returned the `200` HTML page (so the page is a revoked/absent-session guard, not a
  record); an unknown id returns `404`; alice can read the report again after re-login, so the record is bound to the user,
  not to a single session.
* **Limits / uncertainty:** **no record content was disclosed** by this observation. The claim is the inverted
  authorization/response contract (success status plus existence disclosure for an owner-only object) on the non-owner path.
  Two session-fixation probes were negative: `POST /app/login` with a caller-supplied `scourge_session=FIXED-VALUE-12345`
  issued a fresh cookie and the supplied value remained `401` on `/app/api/me`.

---

## C. Sharing control (used to interpret the findings above)

Performed with `invoices`, which behaved correctly throughout:

1. alice `POST /app/api/invoices` before any share → `e852bb48-…`; bob `GET` → `404` (no retroactive grant).
2. alice `PUT /app/api/settings/sharing {"share_new_with":"bob"}` → `204`; alice `GET` → `{"share_new_with":"bob"}`;
   bob `GET` → `{"share_new_with":null}` (settings are per-account).
3. alice `POST /app/api/invoices` after the share → `bc8f1838-…`; bob `GET` → `200
   {"note":"alice-invoice-created-AFTER-sharing-to-bob"}`; bob `DELETE` → `404` (grant is read-only, as documented).
4. alice resets `{"share_new_with":null}` → `204`; bob's `GET` of the granted object still → `200` (grant persists at
   creation, as documented).

This confirms the fixture's documented sharing semantics are implemented and that the deviations in Findings 1–8 are not
explained by a sharing grant.

## D. Scope exercised and classes with no supported finding

All 12 declared resource classes were exercised against the identities `user-alice`, `user-bob`, `user-admin`, and
unauthenticated, with owner baselines and a non-owner / anonymous control for each:

| class | operations exercised | result |
|---|---|---|
| `orders` | create, read, update, delete | **Findings 1, 2**; bob delete correctly `404` |
| `invoices` | create, read, delete | no finding (peer `404`, anon `401`, sharing control correct) |
| `tenant-notes` | create, read, delete | no finding (cross-tenant peer `404`, anon `401`) |
| `bulletins` | create, read, delete | no finding (anon `401`, any authenticated `200`, as declared) |
| `catalog` | create, read, delete | no finding (anonymous `200`, as declared) |
| `private-reports` | create, read, delete | **Finding 3** |
| `cached-reports` | create, read, delete | **Finding 4** |
| `login-reports` | create, read, delete | **Finding 8** |
| `stale-reports` | create, read, update, delete | **Finding 5**; bob update/delete correctly `404` |
| `forbidden-reports` | create, read, delete | **Finding 6** |
| `echo-reports` | create, read, delete | **Finding 7** |
| `expiring-reports` | create, read, delete | no finding observed: owner `200`, bob `404`, anon `401` |

Unknown-id matrix (id `00000000-0000-0000-0000-000000000000`; status for bob / anonymous / alice):
`orders` 404/401/404, `invoices` 404/401/404, `tenant-notes` 404/401/404, `bulletins` 404/401/404, `catalog` 404/404/404,
`private-reports` 404/404/404, `cached-reports` 404/401/404, `stale-reports` 404/404/404, `forbidden-reports` 404/404/404,
`login-reports` 404/404/404, `expiring-reports` 404/404/404. Compared with the same identities on the real ids in
Findings 3–8, this isolates each observation to an existing object (the anonymous `200`/`403` results in Findings 3–8 are
not catch-all responses).

Method-level controls: `PATCH` on classes that declare no update returns `405` for every identity (invoices, tenant-notes,
bulletins, catalog, private-reports, cached-reports, login-reports, forbidden-reports, echo-reports, expiring-reports).
Deletion by a non-owner returned `404` for every class tested (orders, invoices, tenant-notes, bulletins, catalog,
private-reports, cached-reports, login-reports, stale-reports, forbidden-reports, expiring-reports); non-owner deletion
of `echo-reports` was not exercised. Unknown ids returned `404`
(e.g. `GET /app/api/invoices/00000000-…` as bob); collection `GET` returns `405`. Admin never received data on the correctly
scoped classes (`invoices`, `tenant-notes`, `private-reports`, `cached-reports`, `expiring-reports` all returned `404` to
admin), so no role-based bypass was observed. Where Findings 1-7 apply, `admin` received the same leaked bodies as the
other callers, consistent with those leaks not depending on the caller's role.

### Qualification: `expiring-reports`
`engagement.json` does not state an expiry TTL or expiry semantics for this class, so no expiry-related claim is made. The
only observations are the access-control baseline above. One mid-run owner read of this class returned `401`; this was a
session-state artifact (see below), and the test was repeated with a verified session, giving owner `200`.

### Qualification: session instability during testing
Sporadically, an otherwise valid session was rejected with `401` part-way through a batch (including sessions created
seconds earlier); re-login restored access, and multiple simultaneous sessions per user were verified to coexist, and
`POST /app/logout` was verified to revoke (owner `/app/api/me` → `401`). To avoid misreading this, every reported
observation was captured together with the owner baseline in the same run, and any owner response of `401` was treated as
invalid and re-tested. No finding above rests on a session that was not demonstrably valid at the time (each finding quotes
either an owner baseline or a pre-leak control returning `200`/`404` as appropriate).

### Qualification: tenancy
Only one account per tenant is provided (`alice`/`tenant-a`, `bob`/`tenant-b`, `admin`/none), so "members of the owner's
tenant" could only be tested as a negative (cross-tenant bob → `404` on `tenant-notes`); same-tenant member access to
`tenant-notes` was not exercised and is not claimed.

### Not assessed
No target other than `http://127.0.0.1:3000/app/` was contacted. No filesystem artefacts, database files, or fixture state
outside the documented HTTP contract were used as evidence.
