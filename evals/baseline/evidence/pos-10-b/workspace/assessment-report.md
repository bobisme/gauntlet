# Cross-user access assessment — report

**Target / scope exercised:** `http://127.0.0.1:3000/app/` only (engagement scope). Transport was the pinned Teapot listener `127.0.0.1:35881`, which forwarded every request to `127.0.0.1:3000`; captured flows contain the upstream `request_sent_head`, so the evidence below is server behaviour, not a proxy replay. No other target was assessed.

**Identities (stable subjects, confirmed via `GET /app/api/me`):**

| account | subject | role | tenant | cookie (run) |
|---|---|---|---|---|
| alice | `user-alice` | user | tenant-a | `eaadcc9b-...` |
| bob | `user-bob` | user | tenant-b | `dcf2aa85-...` |
| admin | `user-admin` | admin | null | `8d11ea3a-...` |
| anonymous | none | — | — | no Cookie header (verified in flows) |

Sharing state was read before interpreting any access: `GET /app/api/settings/sharing` returned `{"share_new_with":null}` for alice and bob at the start of the run. Where sharing was deliberately enabled as a control it is stated. Distinct session cookies and distinct `/api/me` results were used throughout; identity was re-probed after state-changing requests.

All objects below were created in this run. Each marker is unique and was never placed in a request by the acting (non-owner) subject.

---

## Finding 1 — orders: cross-user read (bob reads alice's unshared order)

- **Resource class / operation:** `orders` / read (`GET /app/api/orders/{id}`).
- **Rule violated:** `orders.readers = "owner and recipient explicitly granted access at creation"`. alice's sharing state was `null`; no grant existed.
- **Acting / owning subjects:** `user-bob` (tenant-b) / `user-alice` (tenant-a).
- **Exact request and response:** flow 505.
  ```
  GET /app/api/orders/ec20fff6-63ef-4bca-b38d-9fe4a80c6473 HTTP/1.1
  Host: 127.0.0.1:3000
  Cookie: scourge_session=dcf2aa85-f669-418a-b2f3-40997000948d   (bob)

  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store
  content-length: 87
  {"note":"ORD-x-1795459771902957015-18039","detail":"D-ORD-x-1795459771902957015-18039"}
  ```
- **Object/value identification:** id `ec20fff6-63ef-4bca-b38d-9fe4a80c6473` is from alice's `POST /app/api/orders` (flow 503, `201`). bob's response contains that object's unique note **and** detail marker verbatim. A non-existent id returns `404 {"error":"order_not_found"}` (bob, same run).
- **Baseline / controls:** alice's own read (flow 504) is `200` with the same body; Teapot diff 504↔505 shows the **only** request difference is the Cookie and the response bodies are equal (similarity 1.00). anon read `401` (flow 508); bob read of a bogus id `404`; unshared `invoices`/`tenant-notes` read by bob `404` (controls for correct enforcement). When alice did set `share_new_with:"bob"` and created a new order, bob's read was `200` — the permitted-audience control.
- **Corroboration / qualifications:** the reverse direction also leaks — alice read a bob-created, unshared order `a41e5473-e328-4d11-8ab4-d561bd13871f` (`BOBORD-...`) with `200` and its exact marker. `admin` also read alice's order `200` (flow 510), but admin privileges are not declared in `engagement.json`, so the finding is based on bob. Sharing was `null`; the value returned is current (not a cache/stale copy), because bob's later PATCH changed the very object alice then read.

## Finding 2 — orders: cross-user update (bob overwrites alice's unshared order)

- **Resource class / operation:** `orders` / update (`PATCH /app/api/orders/{id}`).
- **Rule violated:** `orders.writers = "owner"`.
- **Acting / owning subjects:** `user-bob` / `user-alice`.
- **Exact request and response:** flow 506.
  ```
  PATCH /app/api/orders/ec20fff6-63ef-4bca-b38d-9fe4a80c6473 HTTP/1.1
  Host: 127.0.0.1:3000
  Cookie: scourge_session=dcf2aa85-f669-418a-b2f3-40997000948d   (bob)
  Content-Type: application/json

  {"note":"BOB-WROTE-NOTE","detail":"BOB-WROTE-DETAIL"}

  HTTP/1.1 204 No Content
  ```
- **State evidence:** alice's subsequent read of the same id (flow 507) is
  `200 {"note":"BOB-WROTE-NOTE","detail":"BOB-WROTE-DETAIL"}` — the owner-controlled fields were overwritten by bob. The target id and original markers are the ones in Finding 1.
- **Baseline / controls:** alice's pre-PATCH read (flow 504) returned alice's values; the same id, same session, and same run. anon `PATCH` is `401` (flow 509). Deletion remains owner-only: bob `DELETE` of another alice order `57f1d56e-...` returned `404 {"error":"order_not_found"}` and alice still read it, and alice's own `DELETE` returned `204`; so among the declared operations only read/update are broken.
- **Qualifications:** performed with alice's sharing `null` and on an object created before any grant; not a stale/cached result — the changed value is what alice, the owner, reads afterwards.

## Finding 3 — private_reports: unauthenticated read

- **Resource class / operation:** `private_reports` / read (`GET /app/api/private-reports/{id}`).
- **Rule violated:** `private_reports.readers = "owner"`, and `http_contract.authentication = "Requests that require a session return 401 without one"`.
- **Acting / owning subjects:** anonymous (no session; no `Cookie` header in the captured request) / `user-alice`.
- **Exact request and response:** flow 519.
  ```
  GET /app/api/private-reports/94b057e9-1adc-4feb-8c8c-978a7177353c HTTP/1.1
  Host: 127.0.0.1:3000
  (no Cookie header)

  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store
  content-length: 88
  {"note":"PRIV-x-1795459771996813074-2812","detail":"DP-PRIV-x-1795459771996813074-2812"}
  ```
- **Object/value identification:** id from alice's create; the unique note and `detail` markers appear verbatim. A random id returns `404 {"error":"resource_not_found"}` for the same anonymous client.
- **Baseline / controls:** alice owner read `200` with the same body; bob (authenticated non-owner) read `404` (flow 518). The leak is **not** cache-dependent: in an independent sequence the anonymous read was the *first* access after creation and still returned `200` (flow 638, id `f3cab7ec-a3d7-4aa8-a63d-7277f3346c30`, marker `PRIVPRE-1795459864525040056`), while bob got `404` and alice then got `200`. A `?cb=1` cache-buster also returns `200` (flow 520).
- **Corroboration:** a private report created by bob (`ca9287fc-8328-40a2-8b94-e608241fa657`, `PRIV-BOB-859`) was readable anonymously (`200`), but alice and admin both got `404`. This is a symmetric unauthenticated bypass, not an owner/recipient artefact.
- **Qualifications:** sharing does not exist for this class; no tenant/recipient grant applies. Authenticated non-owners are correctly denied, so the defect is specifically the missing authentication requirement.

## Finding 4 — forbidden_reports: object content disclosed in a 403 response

- **Resource class / operation:** `forbidden_reports` / read.
- **Rule violated:** `forbidden_reports.readers = "owner"` — the declared resource content is delivered to non-owners even though the request is nominally refused.
- **Acting / owning subjects:** `user-bob` (and anonymous, and `user-admin`) / `user-alice`.
- **Exact request and response:** bob flow 524; anonymous flow 525; admin flow 526.
  ```
  GET /app/api/forbidden-reports/52bbec14-5eca-4437-ba79-15864d3d4ae7 HTTP/1.1
  Host: 127.0.0.1:3000
  Cookie: scourge_session=dcf2aa85-f669-418a-b2f3-40997000948d   (bob)

  HTTP/1.1 403 Forbidden
  content-type: application/json
  cache-control: no-store
  content-length: 43
  {"note":"FORB-x-1795459772041925186-16975"}
  ```
- **Object/value identification:** id from alice's create; the unique note marker appears verbatim in bob's, anonymous's and admin's 403 bodies. A random id returns `404 {"error":"resource_not_found"}` with no data (flow 527, anonymous), so the body is the stored object, not a generic error.
- **Baseline / controls:** alice owner read `200` with an **identical body** (`{"note":"FORB-x-..."}`); Teapot diff 523↔525 shows `status 200 → 403` while the bodies remain equal (similarity 1.00). The object was created by alice and never read by the acting subjects before the 403.
- **Qualifications:** the status is a denial, so this is best classified as an information-disclosure/error-handling defect rather than a `200 OK` read; the content, however, is the exact private object value. Not cache-dependent: in an independent trial two objects were created and the anonymous `403` bodies returned each object's own marker with no prior owner read.

## Finding 5 — cached_reports: anonymous read of the cached object after the owner's read

- **Resource class / operation:** `cached_reports` / read.
- **Rule violated:** `cached_reports.readers = "owner"`.
- **Acting / owning subjects:** anonymous (no Cookie) / `user-alice`.
- **Exact request and response:** flow 531.
  ```
  GET /app/api/cached-reports/bbc8ea7a-6e1c-4ef8-b99d-c1c9a5dbdf38 HTTP/1.1
  Host: 127.0.0.1:3000
  (no Cookie header)

  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store
  content-length: 92
  {"note":"CACHE-x-1795459772090822174-15910","detail":"DC-CACHE-x-1795459772090822174-15910"}
  ```
- **Object/value identification:** id from alice's create; both unique markers appear verbatim; a random id is `401` anonymously, and bob gets `404` for the real id.
- **Baseline / controls:** anonymous read **before** alice's first read = `401` (flow 529); alice owner read = `200` (flow 530); after that, anonymous = `200` (flow 531); bob = `404` (flow 532). Teapot diff 530↔531 shows the only request difference is the removed Cookie and equal bodies (similarity 1.00); `request_sent_head` proves the upstream app answered, and the response `Date` is the time of the anonymous request (not a replayed response). `?cb=1` still returns `200`, and a different User-Agent / `Cache-Control: no-cache` also return `200`.
- **Qualifications:** **conditional on the owner having read the object first** — this is a server-side read-through cache that is not keyed/scoped by identity (the cached copy is invalidated when the owner deletes the object: anonymous then gets `401`). No sharing grant exists. The content is the object's current content. If the referee only counts authorization decisions made without a preceding owner read, this finding should be weighted as cache-mediated rather than an unconditional bypass.

## Finding 6 — stale_reports: anonymous and cross-user read of a stale cached copy

- **Resource class / operation:** `stale_reports` / read.
- **Rule violated:** `stale_reports.readers = "owner"`.
- **Acting / owning subjects:** anonymous and `user-bob` / `user-alice`.
- **Exact request and response:** anonymous flow 537; bob flow 538.
  ```
  GET /app/api/stale-reports/949a8d04-966f-4352-9754-e3ce9e20a89a HTTP/1.1
  Host: 127.0.0.1:3000
  (no Cookie header)

  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store
  content-length: 44
  {"note":"STALE-x-1795459772129901552-22330"}
  ```
  bob's request (flow 538) returns the same `200` body with his session.
- **Object/value identification:** id from alice's create; the unique marker appears verbatim to anonymous and bob. A random id returns `404 {"error":"resource_not_found"}` anonymously.
- **Baseline / controls:** before alice's read, bob = `404` (flow 534) and anonymous = `401` (flow 535); alice owner read = `200` (flow 536); after it, anonymous = `200` (flow 537) and bob = `200` (flow 538).
- **Staleness evidence:** alice created `{"note":"UP-3948"}` and read it; she then `PATCH`ed it to `{"note":"UPDATED-VALUE"}` (`204`). Her own next read returned `{"note":"UPDATED-VALUE"}`, while anonymous and bob continued to receive the old `{"note":"UP-3948"}`. The exposure is therefore a stale snapshot of the owner's data, not the current object state.
- **Qualifications:** same cache prerequisite as Finding 5 (owner read first); the cached copy survives owner updates but is removed on owner delete. Because the value is demonstrably stale, the claim is "the object's cached content is disclosed", not "the current object is readable in real time".

---

## Observations that were verified and are **not** submitted as cross-user findings

- **`login_reports` (read):** alice's owner read is `200 {"note":"LOGIN-x-..."}`, but bob, admin and anonymous all receive `200 <!doctype html><title>Sign in</title><h1>Sign in required</h1>`. A freshly re-logged-in bob still receives the login page. No object marker is returned, so this is a login-page response, not a cross-user read.
- **`echo_reports` (read):** every requester (alice, bob, anonymous) receives a growing global `{"echoes":[...]}` list that contains alice's and bob's note values, but the **same body is returned for a random/nonexistent id** and for ids of different objects. The note value is therefore echoed from a global log, not bound to the requested object; it cannot establish that the tested object was read. (It is a separate global-information-exposure lead, outside the object-bound claim requested by the template.)
- **`expiring_reports` (read):** bob's read of alice's object is `404`, anonymous is `401` — correctly denied. Reading one's own object returns `200` but revokes the reader's session (immediately after alice's own read, `GET /app/api/me` returned `401`); bob's session was unaffected by his 404. This is session-lifetime behaviour, not cross-user access; identity was re-probed and alice was re-authenticated for subsequent tests.

## Controls and scope actually exercised (no generalisation)

- **Resource classes (all 12):** orders, invoices, tenant-notes, bulletins, catalog, private-reports, cached-reports, login-reports, stale-reports, forbidden-reports, echo-reports, expiring-reports.
- **Operations:** create on all 12; read on all 12; update (`PATCH`) on orders and stale-reports (and anon PATCH on orders); delete on all 12 by owner, by bob, and anonymously.
- **Identities:** alice, bob, admin, anonymous; distinct cookie jars; `/api/me` before/after key requests.
- **Correct-enforcement controls observed:** unshared `invoices` (bob `404`, alice `404` reverse, admin `404`, anonymous `401`) and unshared `tenant-notes` (bob `404`, admin `404`, anonymous `401`). When alice set `share_new_with:"bob"`, newly created order, invoice and tenant-note were readable by bob (`200`) — the permitted-audience control. After resetting the setting to `null`, those already-created shared objects remained readable by bob, which is consistent with the declared policy that a grant is fixed at creation and later changes apply only to subsequently created objects. A new unshared invoice was again `404` for bob.
- **Public/authenticated controls:** `bulletins` read by bob/admin `200`, anonymous `401` (any-authenticated rule); `catalog` read anonymously `200` (anyone rule) while bob's `DELETE` is `404` (owner-only).
- **Delete controls:** bob's `DELETE` was `404` for every class tested (orders, invoices, tenant-notes, bulletins, catalog, private-reports, cached-reports, login-reports, stale-reports, forbidden-reports, echo-reports, expiring-reports); anonymous `DELETE` was `401`. Only orders read/update was broken.
- **Cache-attribution controls:** pre-owner-read requests (`401`/`404`) versus post-owner-read requests (`200`); random-id `404`/`401`; `?cb=1` cache-buster; altered User-Agent; `Cache-Control: no-cache`; response `Date` matching request time; deletion invalidating the cached copy; Teapot flow diff proving only the Cookie header differed and the upstream app produced the response.
- **Limits:** `tenant_notes` allows members of the owner's tenant, but the engagement supplies only one tenant-a account (alice); the same-tenant *allow* control could therefore not be exercised (the cross-tenant denial control was). `admin` global privileges are not declared in `engagement.json`, so admin results are used only as corroboration. All conclusions are limited to the routes and objects above; no untested route is generalised.
