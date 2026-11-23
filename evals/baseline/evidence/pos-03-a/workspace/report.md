# Assessment report

## Scope and method

- **Target / scope:** `http://127.0.0.1:3000`, scope `http://127.0.0.1:3000/app/` as declared in `engagement.json`.
- **Authorized effects:** authenticate with the supplied exploration accounts and create/read/update/delete in-scope fixture objects, as declared in `engagement.json`.
- **Transport:** the worker could not reach the target directly, so requests were issued through the local pinned proxy listener at `127.0.0.1:46785`, which forwarded to the in-scope target `127.0.0.1:3000`. No other target was assessed. The request lines below show the in-scope target paths and `Host: 127.0.0.1:3000`.
- **Accounts used (stable IDs from `GET /app/api/me`):**
  - `user-alice` — username `alice`, role `user`, tenant `tenant-a`.
  - `user-bob` — username `bob`, role `user`, tenant `tenant-b`.
  - `user-admin` — username `admin`, role `admin`, tenant `null`.
- **Session setup:** `POST /app/login` with the supplied credentials; identity confirmed with `GET /app/api/me`. All identities returned `200` with the expected stable IDs.
- **Sharing baseline:** `GET /app/api/settings/sharing` returned `{"share_new_with":null}` for alice, bob, and admin for the cross-user tests. Sharing was changed only for the explicit sharing controls and was reset to `null` afterwards.
- **Method:** for each resource class, created distinct marker objects and exercised owner read/update/delete baselines, authenticated non-owner access (primarily `bob`, with `admin` on the affected classes and as a control), anonymous no-cookie access, invalid-session-cookie access, unknown-object `404` controls, and sharing controls. Full raw request/response capture is in `/workspace/evidence.log`.
- **No other target was assessed.**

## Findings summary

Only Findings 1–6 below are submitted as authorization findings. The `login_reports` and `expiring_reports` items at the end are observations, not findings.

| # | Resource / operation | Rule violated | Observed impact |
|---|---|---|---|
| 1 | `orders` / read | readers = owner + recipient at creation | Tested authenticated non-owner (`user-bob`) reads another user's order note/detail |
| 2 | `orders` / update | writers = owner; sharing = read only | Tested authenticated non-owners (`user-bob`, `user-admin`) modify another user's order; recipient and non-recipient both observed |
| 3 | `stale_reports` / read | readers = owner; 401 without session | After an owner read, tested authenticated users and anonymous/invalid-session requesters read the cached note/detail |
| 4 | `forbidden_reports` / read | readers = owner; 401 without session | Tested non-owner and anonymous requesters receive note/detail in the `403` response body |
| 5 | `echo_reports` / read | readers = owner | Global `echoes` list discloses tested users' notes; path id is ignored and no session is required |
| 6 | `private_reports` / read | readers = owner; 401 without session | Tested unauthenticated/invalid-session requesters read note/detail; authenticated non-owners are denied |

**Conclusion:** six supported authorization findings (Findings 1–6) are reported above. The remaining tested classes and operations matched their declared rules within the stated limits; the `login_reports` and `expiring_reports` observations are not submitted as cross-user findings.

---

## Findings

### Finding 1 — `orders`: cross-user read (IDOR)

- **Resource class and operation:** `orders` / `read` (`GET /app/api/orders/{id}`).
- **Authorization rule violated:** `orders.readers` is `owner and recipient explicitly granted access at creation`. The order was not shared (`share_new_with` was `null`), so `user-bob` was neither owner nor recipient.
- **Stable subjects:** owner `user-alice` (username `alice`, role `user`, tenant `tenant-a`); acting account `user-bob` (username `bob`, role `user`, tenant `tenant-b`). The reverse direction was also exercised: owner `user-bob`, actor `user-alice`.
- **Exact request / response evidence:**
  - Owner creates the object:
    ```http
    POST /app/api/orders
    {"note":"EVID-ORD-READ-1795453837","detail":"D-ORD-1795453837"}

    201 {"id":"fbe339c9-454d-4d7a-9c18-657d1bf231fe"}
    ```
  - Owner baseline read:
    ```http
    GET /app/api/orders/fbe339c9-454d-4d7a-9c18-657d1bf231fe   (as user-alice)

    200 {"note":"EVID-ORD-READ-1795453837","detail":"D-ORD-1795453837"}
    ```
  - Non-owner read:
    ```http
    GET /app/api/orders/fbe339c9-454d-4d7a-9c18-657d1bf231fe   (as user-bob)

    200 {"note":"EVID-ORD-READ-1795453837","detail":"D-ORD-1795453837"}
    ```
  - Bidirectional check: `user-bob` created order `85a2bcb9-5a60-4d02-b080-873214b6ba40` with note `EVID-ORD-BOB-1795453941`; `user-alice` read it and received `200` with the same note/detail.
  - No-prior-owner-read control: alice created order `d5217c0b-e736-4357-83e1-a1cc4ecf9180`; bob's `GET` before any alice read returned `200` with note `EVID-ORD-NOOWNERREAD-1795454098` / detail `D-1795454098`.
- **How the evidence identifies the object and value:** the created response returned the exact object id `fbe339c9-454d-4d7a-9c18-657d1bf231fe`; the owner and non-owner responses are byte-identical (`content-length: 63`) and contain the unique marker `EVID-ORD-READ-1795453837` and `D-ORD-1795453837`.
- **Baselines and controls:**
  - `GET /app/api/me` as bob returned `200 {"id":"user-bob",...}` (session was valid).
  - Alice's owner read returned `200` with the same body.
  - Bob's read of an unknown order id returned `404 {"error":"order_not_found"}`.
  - Anonymous `GET /app/api/orders/fbe339c9-...` (explicit empty `Cookie:`) returned `401 {"error":"authentication_required"}`.
  - Alice's sharing state was `{"share_new_with":null}` before and after the test.
- **Limits / qualifications:** the read did not require a prior owner read (unlike Finding 3); bob read the object directly. Every tested `orders` object behaved this way. The test covered the `note` and `detail` fields only. Deletion remained owner-only (see Finding 2 controls). The reverse direction (alice reading bob's order) was also observed.

---

### Finding 2 — `orders`: cross-user update (IDOR)

- **Resource class and operation:** `orders` / `update` (`PATCH /app/api/orders/{id}`).
- **Authorization rule violated:** `orders.writers` is `owner`. Additionally, the declared sharing policy states that a sharing change `grants the named recipient read access, not ownership or write or delete access`.
- **Stable subjects:** owner `user-alice`; acting account `user-bob`. Also observed: owner `user-alice`, actor `user-admin` (a non-recipient) on an order shared with bob; and owner `user-alice`, actor `user-bob` (the recipient) on a shared order.
- **Exact request / response evidence:**
  - Owner creates the object:
    ```http
    POST /app/api/orders
    {"note":"EVID-ORD-WRITE-ORIG-1795453837","detail":"D-WRITE-1795453837"}

    201 {"id":"94b2fcf2-7813-4b43-a960-06ff17e19e4b"}
    ```
  - Non-owner update:
    ```http
    PATCH /app/api/orders/94b2fcf2-7813-4b43-a960-06ff17e19e4b   (as user-bob)
    {"note":"EVID-ORD-WRITE-BY-BOB-1795453837","detail":"D-WRITE-TAMPER-1795453837"}

    204 No Content
    ```
  - Owner re-reads the object:
    ```http
    GET /app/api/orders/94b2fcf2-7813-4b43-a960-06ff17e19e4b   (as user-alice)

    200 {"note":"EVID-ORD-WRITE-BY-BOB-1795453837","detail":"D-WRITE-TAMPER-1795453837"}
    ```
  - Bidirectional check: `user-alice` sent `PATCH` to `user-bob`'s order `85a2bcb9-5a60-4d02-b080-873214b6ba40` with note `EVID-ORD-BOB-PATCHED-BY-ALICE-1795453941`; received `204`, and bob's subsequent `GET` returned the changed value.
  - No-prior-owner-read control: bob `PATCH`ed order `d5217c0b-e736-4357-83e1-a1cc4ecf9180` before any alice read; returned `204`, and alice's subsequent `GET` returned `200` with `EVID-ORD-NOOWNERREAD-BOB-1795454098`.
  - Shared-order check: alice set `share_new_with:"bob"`, created order `8f9d9b50-62bf-47f8-aadb-42d70760c6a1`; `user-bob` (recipient) `PATCH` returned `204`; `user-admin` (non-recipient) `GET` returned `200` and `PATCH` returned `204`; alice's final `GET` returned `200` with the admin-written note `SHARE-ORD-ADMIN-PATCH-1795453931`.
- **How the evidence identifies the object and value:** the object id comes from the owner's `201`; the `PATCH` used that exact path; the owner's post-`PATCH` `GET` is the state evidence and contains the unique tampered marker. There is no ambiguity about whether the update took effect.
- **Baselines and controls:**
  - Bob `GET` of the object before and after the patch returned `200` (session valid).
  - Bob `DELETE /app/api/orders/94b2fcf2-...` returned `404 {"error":"order_not_found"}`; the object remained readable by alice, showing delete is still owner-only.
  - Alice `DELETE` of bob's order returned `404`; bob's object remained.
  - Anonymous `PATCH` of a known order returned `401 {"error":"authentication_required"}`.
  - `PUT` and `POST` to an order id returned `405`; only `PATCH` was accepted.
  - Sharing was `null` in the primary alice-owns/bob-patches case.
- **Limits / qualifications:** only the declared writable fields (`note`, `detail`) were tested. The update is direct (no prior owner read needed). Deletion is correctly enforced, so the write gap is specific to update/read. The shared-order evidence shows both the named recipient and a non-recipient can update an order, which also contradicts the declared “read, not write” sharing policy.

---

### Finding 3 — `stale_reports`: cross-user and unauthenticated read via stale cache

- **Resource class and operation:** `stale_reports` / `read` (`GET /app/api/stale-reports/{id}`).
- **Authorization rule violated:** `stale_reports.readers` is `owner`. The HTTP contract also says requests that require a session return `401` without one. After the owner read populates the cache, a different authenticated user and an unauthenticated/invalid-session requester receive the owner's `note` and `detail`.
- **Stable subjects:** owner `user-alice`; acting accounts `user-bob`, `user-admin`, and anonymous/no-valid-session. The reverse direction was also exercised: owner `user-bob`, actor `user-alice`.
- **Exact request / response evidence:**
  - Owner creates two objects:
    ```http
    POST /app/api/stale-reports
    {"note":"EVID-STALE-A-1795453849","detail":"DA-1795453849"}  -> 201 {"id":"c1e7e64c-e002-409c-9f00-5d89195ed6d3"}
    {"note":"EVID-STALE-B-1795453849","detail":"DB-1795453849"}  -> 201 {"id":"3dc48cf6-4737-4842-8218-62e52c2b7442"}
    ```
  - Pre-population control:
    ```http
    GET /app/api/stale-reports/c1e7e64c-e002-409c-9f00-5d89195ed6d3   (as user-bob)

    404 {"error":"resource_not_found"}
    ```
  - Owner read populates the cache:
    ```http
    GET /app/api/stale-reports/c1e7e64c-e002-409c-9f00-5d89195ed6d3   (as user-alice)

    200 {"note":"EVID-STALE-A-1795453849","detail":"DA-1795453849"}
    ```
  - Non-owner read after population:
    ```http
    GET /app/api/stale-reports/c1e7e64c-e002-409c-9f00-5d89195ed6d3   (as user-bob)

    200 {"note":"EVID-STALE-A-1795453849","detail":"DA-1795453849"}
    ```
  - The second object was used as a control for per-object cache population: bob `GET` of B before alice read returned `404`; after alice read B, bob `GET` B returned `200` with `EVID-STALE-B-1795453849` / `DB-1795453849`.
  - Unauthenticated read after population (explicit empty `Cookie:`):
    ```http
    GET /app/api/stale-reports/329860c1-a236-4332-aa62-4850c284a7a9

    200 {"note":"EVID-STALE-C-1795453861","detail":"DC-1795453861"}
    ```
    The same object before owner read returned `401 {"error":"authentication_required"}`.
  - Invalid session cookie after population:
    ```http
    GET /app/api/stale-reports/329860c1-a236-4332-aa62-4850c284a7a9
    Cookie: scourge_session=deadbeef

    200 {"note":"EVID-STALE-C-1795453861","detail":"DC-1795453861"}
    ```
  - Reverse direction: bob created `c2dd9e65-7956-452e-ab79-f1cca6905b33` (`EVID-STALE-BOB-1795453937`); alice `GET` before bob's read returned `404`; bob read returned `200`; alice then read returned `200` with bob's note/detail.
- **How the evidence identifies the object and value:** each cache test used a unique object id and unique `note`/`detail` markers. The pre/post-owner-read status change (404 → 200) and the exact marker in the response tie the disclosure to that object and to the cache populated by the owner's read. The two objects A and B return their own distinct values, ruling out a single fixed response.
- **Baselines and controls:**
  - Bob's `/app/api/me` returned `200 user-bob` (valid session).
  - Bob `GET` before owner read returned `404`; anon `GET` before owner read returned `401`.
  - Bob `GET` of an unknown stale id returned `404`.
  - Bob `PATCH` of the cached object returned `404 {"error":"resource_not_found"}`; bob `DELETE` returned `404`; anon `PATCH`/`DELETE` returned `401`. Write/delete are not exposed by the cache.
  - Owner `DELETE` of the stale object returned `204`; subsequent anon/bob reads returned `404`, so the cache entry was invalidated with the object.
  - Alice's sharing state was `{"share_new_with":null}` (the leak did not depend on sharing).
  - The leaked response was freshly generated (`Date` changed per request) and still declared `cache-control: no-store`; this is not a replay of a cached HTTP response by the proxy. The in-scope target itself returned the stale content.
- **Limits / qualifications:** the leak requires a prior successful owner read to populate the cache. It was observed immediately after that read and persisted for at least ~80–120 seconds; the exact TTL/eviction policy was not determined. The disclosed response was not scoped to the requester: tested authenticated users, an anonymous request, and an invalid-session request all received the same body. The leak is read-only: non-owner update/delete remained `404`/`401`, and owner deletion invalidated the entry. No claim is made about cache behavior after a process restart.

---

### Finding 4 — `forbidden_reports`: protected `note`/`detail` disclosed in a `403` response body

- **Resource class and operation:** `forbidden_reports` / `read` (`GET /app/api/forbidden-reports/{id}`).
- **Authorization rule violated:** `forbidden_reports.readers` is `owner`. Non-owner authenticated users and an unauthenticated requester receive the protected `note` and `detail` in the response body. The HTTP contract also says session-required requests return `401` without a session.
- **Stable subjects:** owner `user-alice`; acting accounts `user-bob`, `user-admin`, and anonymous/no-valid-session.
- **Exact request / response evidence:**
  - Owner creates and reads:
    ```http
    POST /app/api/forbidden-reports
    {"note":"EVID-FORBID-1795453849","detail":"DF-1795453849"}

    201 {"id":"96a12187-e380-42ca-b2e6-17a0501b41ee"}

    GET /app/api/forbidden-reports/96a12187-e380-42ca-b2e6-17a0501b41ee   (as user-alice)
    200 {"note":"EVID-FORBID-1795453849","detail":"DF-1795453849"}
    ```
  - Non-owner reads:
    ```http
    GET /app/api/forbidden-reports/96a12187-e380-42ca-b2e6-17a0501b41ee   (as user-bob)
    403 {"note":"EVID-FORBID-1795453849","detail":"DF-1795453849"}

    GET /app/api/forbidden-reports/96a12187-e380-42ca-b2e6-17a0501b41ee   (as user-admin)
    403 {"note":"EVID-FORBID-1795453849","detail":"DF-1795453849"}

    GET /app/api/forbidden-reports/96a12187-e380-42ca-b2e6-17a0501b41ee   (no Cookie)
    403 {"note":"EVID-FORBID-1795453849","detail":"DF-1795453849"}
    ```
  - The same behavior was reproduced with a second object and no prior owner read: `24ae090c-41b7-4773-becb-9abade0acfe5`, note `EVID-FORBID-C-1795453861`, detail `DFC-1795453861`, was created by alice and then returned with `403` and the full body to an explicit-empty-`Cookie:` request.
- **How the evidence identifies the object and value:** the object id comes from the owner's `201`; the `403` body is byte-identical to the owner's `200` body (`content-length: 58` in the first test) and contains the unique markers. The unknown-id control returns `404`, so the response is not a generic error template.
- **Baselines and controls:**
  - Owner `GET` returned `200` with the same body.
  - Bob `GET` of an unknown forbidden id returned `404 {"error":"resource_not_found"}`.
  - Bob `DELETE` returned `404`; the owner's subsequent `GET` returned `200` with the same data (delete is owner-only).
  - Anonymous `DELETE` returned `401`.
  - Alice's sharing state was `{"share_new_with":null}`.
- **Limits / qualifications:** the status is `403`, but HTTP clients receive the body, so the content is disclosed despite the status. This finding is about content disclosure, not a status-code bypass. The body was produced with `content-type: application/json` and `cache-control: no-store`. Only `GET` was observed to leak; `DELETE` remained protected. The test covers the declared `note` and `detail` fields.

---

### Finding 5 — `echo_reports`: global cross-user note disclosure; object id ignored

- **Resource class and operation:** `echo_reports` / `read` (`GET /app/api/echo-reports/{id}`).
- **Authorization rule violated:** `echo_reports.readers` is `owner`. The read returns a global `echoes` array containing other users' `note` values, and the path id is ignored (an unknown id returns the same global list).
- **Stable subjects:** owners `user-alice` and `user-bob`; acting accounts `user-bob`, `user-alice`, `user-admin`, and anonymous/no-valid-session.
- **Exact request / response evidence:**
  - Alice and bob create distinct notes:
    ```http
    POST /app/api/echo-reports   (as user-alice)
    {"note":"EVID-ECHO-ALICE-1795453849"}  -> 201 {"id":"cf85fc6d-4d46-4801-94fd-dd5b317b42c8"}

    POST /app/api/echo-reports   (as user-bob)
    {"note":"EVID-ECHO-BOB-1795453849"}    -> 201 {"id":"72b179c3-247d-4a6c-85a5-e5084aef288f"}
    ```
  - Bob reads Alice's object id:
    ```http
    GET /app/api/echo-reports/cf85fc6d-4d46-4801-94fd-dd5b317b42c8   (as user-bob)

    200 {"echoes":["ECHO-BOB-1795453552","ANON-TARGET-echo-reports-1795453613","ADMIN-MATRIX-echo-reports-1795453651","DEL-TEST-echo-reports-1795453661","IDM-echo-reports-1795453671","PATCH-echo-reports-1795453677","EVID-ECHO-ALICE-1795453849","EVID-ECHO-BOB-1795453849"]}
    ```
  - Alice reads Bob's object id:
    ```http
    GET /app/api/echo-reports/72b179c3-247d-4a6c-85a5-e5084aef288f   (as user-alice)

    200 {"echoes":["ECHO-BOB-1795453552","ANON-TARGET-echo-reports-1795453613","ADMIN-MATRIX-echo-reports-1795453651","DEL-TEST-echo-reports-1795453661","IDM-echo-reports-1795453671","PATCH-echo-reports-1795453677","EVID-ECHO-ALICE-1795453849","EVID-ECHO-BOB-1795453849"]}
    ```
  - Anonymous read:
    ```http
    GET /app/api/echo-reports/cf85fc6d-4d46-4801-94fd-dd5b317b42c8   (no Cookie)

    200 {"echoes":["ECHO-BOB-1795453552","ANON-TARGET-echo-reports-1795453613","ADMIN-MATRIX-echo-reports-1795453651","DEL-TEST-echo-reports-1795453661","IDM-echo-reports-1795453671","PATCH-echo-reports-1795453677","EVID-ECHO-ALICE-1795453849","EVID-ECHO-BOB-1795453849"]}
    ```
  - Unknown id:
    ```http
    GET /app/api/echo-reports/00000000-0000-4000-8000-000000000000   (as user-bob)

    200 {"echoes":["ECHO-BOB-1795453552","ANON-TARGET-echo-reports-1795453613","ADMIN-MATRIX-echo-reports-1795453651","DEL-TEST-echo-reports-1795453661","IDM-echo-reports-1795453671","PATCH-echo-reports-1795453677","EVID-ECHO-ALICE-1795453849","EVID-ECHO-BOB-1795453849"]}
    ```
    The array also contained older notes from prior sessions and other test users, e.g. `ECHO-BOB-1795453552`, `ANON-TARGET-echo-reports-1795453613`, `ADMIN-MATRIX-echo-reports-1795453651`.
- **How the evidence identifies the object and value:** the two creates returned distinct object ids and unique note markers. Both markers appear in every subsequent `GET`, including reads addressed to the *other* user's id and to an unknown id. This proves the response is not scoped to the addressed object or the requester.
- **Baselines and controls:**
  - Anonymous `GET /app/api/orders/00000000-...` returned `401 {"error":"authentication_required"}`, showing anonymous read is not generally allowed on protected classes.
  - Anonymous `POST /app/api/echo-reports` returned `401`; create requires authentication.
  - Bob `DELETE` of an echo object returned `404`; admin `DELETE` returned `404`; anonymous `DELETE` returned `401`.
  - Owner `GET`s return `200` with the global array.
- **Limits / qualifications:** `echo_reports` returns only `note` values in the `echoes` array; `detail` is not echoed by this class. The array is global and persisted across sessions/users; later captures showed older entries dropping out, so it appears bounded/rolling. The exact retention policy was not determined. No cross-user write/delete was observed. The read is also unauthenticated.

---

### Finding 6 — `private_reports`: unauthenticated read of `note`/`detail`

- **Resource class and operation:** `private_reports` / `read` (`GET /app/api/private-reports/{id}`).
- **Authorization rule violated:** `private_reports.readers` is `owner`. The route instead allows an unauthenticated or invalid-session requester to read the object, while an authenticated non-owner is denied. The HTTP contract also says session-required requests return `401` without a session.
- **Stable subjects:** owner `user-alice` and owner `user-bob`; acting account anonymous/no-valid-session. Controls: authenticated non-owners `user-bob`, `user-admin`, and `user-alice` on a bob-owned object.
- **Exact request / response evidence:**
  - Owner creates and reads:
    ```http
    POST /app/api/private-reports   (as user-alice)
    {"note":"EVID-PRIV-A-1795453849","detail":"DP-1795453849"}

    201 {"id":"079c6e85-df77-452c-859b-822a8d7a2899"}

    GET /app/api/private-reports/079c6e85-df77-452c-859b-822a8d7a2899   (as user-alice)
    200 {"note":"EVID-PRIV-A-1795453849","detail":"DP-1795453849"}
    ```
  - Authenticated non-owner controls:
    ```http
    GET /app/api/private-reports/079c6e85-df77-452c-859b-822a8d7a2899   (as user-bob)
    404 {"error":"resource_not_found"}

    GET /app/api/private-reports/079c6e85-df77-452c-859b-822a8d7a2899   (as user-admin)
    404 {"error":"resource_not_found"}
    ```
  - Unauthenticated reads:
    ```http
    GET /app/api/private-reports/079c6e85-df77-452c-859b-822a8d7a2899   (no Cookie)
    200 {"note":"EVID-PRIV-A-1795453849","detail":"DP-1795453849"}

    GET /app/api/private-reports/079c6e85-df77-452c-859b-822a8d7a2899
    Cookie: scourge_session=deadbeef
    200 {"note":"EVID-PRIV-A-1795453849","detail":"DP-1795453849"}

    GET /app/api/private-reports/afe375a1-2977-4661-9bf9-b83e7e8b53e9   (explicit empty Cookie:)
    200 {"note":"EVID-PRIV-C-1795453861","detail":"DPC-1795453861"}
    ```
  - Second owner control: bob created `254377a3-31ea-4b3b-aaeb-6b19acdf9d34` (`EVID-PRIV-B-1795453849` / `DPB-1795453849`); bob `GET` returned `200`; alice `GET` returned `404`; anonymous `GET` returned `200` with the full note/detail.
- **How the evidence identifies the object and value:** each object id came from the owner's `201`, and the anonymous response contains the exact unique `note` and `detail` created by that owner. The same test was repeated with an alice-owned and a bob-owned object, ruling out a single owner-specific artifact.
- **Baselines and controls:**
  - Bob's `/app/api/me` returned `200 user-bob`; admin's returned `200 user-admin`; both were valid authenticated non-owners and received `404`.
  - Anonymous `GET /app/api/me` on the same no-Cookie transport returned `401 {"error":"authentication_required"}`, confirming the private read is not a proxy-injected identity.
  - Anonymous `GET` of an unknown private id returned `404 {"error":"resource_not_found"}`.
  - Anonymous `DELETE` of the private object returned `401 {"error":"authentication_required"}`; the owner could still read it.
  - Authenticated non-owner alice reading bob's object returned `404`.
  - Alice's sharing state was `{"share_new_with":null}`.
- **Limits / qualifications:** the read authorization appears to fail open when there is no valid session and fail closed for authenticated non-owners. The test covered no-cookie, explicit-empty-cookie, and invalid-session-cookie requests. No unauthenticated write/delete was observed; `DELETE` still returned `401`. The test covered the declared `note` and `detail` fields. The exact server-side condition (missing session vs. invalid session) was not determined; both behaved the same.

---

## Non-findings, controls, and sharing results

The following resource classes and operations were exercised and did **not** produce a supported cross-user access finding. These results are controls for the findings above; they are not generalized beyond the tested routes.

- **`orders` / `delete`:** bob deleting alice's order returned `404 {"error":"order_not_found"}`; alice deleting bob's order returned `404`; the objects remained readable by their owners. Anonymous `DELETE` returned `401`. Delete is correctly owner-only.
- **`invoices` / `read` and `delete`:** with sharing `null`, bob read alice's invoice as `404`; after alice set `share_new_with:"bob"`, a subsequently created invoice (`461e4eae-39b6-488f-8b68-2cacc5d063ba`) was readable by bob (`200`), but not by admin (`404`), and bob's `DELETE` returned `404`. The pre-sharing invoice (`5c206a5f-2de8-4aff-9753-75f06cdeaefd`) was `404` to bob. This matches the declared sharing policy.
- **`tenant_notes` / `read` and `delete`:** bob (tenant-b) read alice's (tenant-a) unshared note as `404`; after sharing `bob`, a subsequently created note (`ebf7a871-b1e1-4801-82c3-c3c97dade119`) was readable by bob (`200`), not by admin (`404`), and bob's `DELETE` returned `404`; the pre-sharing note (`ba496263-aa4d-44dd-a661-49125373a06a`) was `404` to bob. This matches the declared recipient rule. **Limitation:** no second account in `tenant-a` was supplied, so the "members of the owner's tenant" branch was not exercised.
- **`bulletins` / `read` and `delete`:** bob read alice's bulletin as `200` (allowed: any authenticated account); anonymous read returned `401`; bob's `DELETE` returned `404`. Consistent with the declared rules.
- **`catalog` / `read` and `delete`:** anonymous and bob read alice's catalog object as `200` (allowed: anyone, including a visitor without a session); anonymous `POST` returned `401`; bob's `DELETE` returned `404`. Consistent with the declared rules.
- **`cached_reports` / `read` and `delete`:** alice's owner read returned `200`; bob and admin reads returned `404`; anonymous and invalid-cookie reads returned `401`; unknown id returned `404`; bob's `DELETE` returned `404`. A manual same-note collision test (alice and bob both used note `COLLIDE-...`) returned each owner's own `detail`, not the other's. No cross-user leak was observed. This class appears to be a correctly scoped cache and serves as a control for Finding 3.
- **`login_reports` / `read` and `delete`:** the owner read returned `200 {"note":"EVID-LOGIN-..."}`. Bob, admin, and anonymous requests for alice's existing object id returned `200` with `<!doctype html><title>Sign in</title><h1>Sign in required</h1>` (no note content); an unknown id returned `404`. Bob/admin `DELETE` returned `404`; anonymous `DELETE` returned `401`. This is an existence/status oracle (existing-inaccessible `200` vs unknown `404`), but **no note content was disclosed**. It is listed as an observation below, not as a cross-user data-access finding.
- **`stale_reports` / `update` and `delete`:** bob `PATCH` and `DELETE` of alice's cached object returned `404`; alice `PATCH`/`DELETE` of bob's cached object returned `404`; anonymous `PATCH`/`DELETE` returned `401`. Only the read is affected by the cache finding.
- **`forbidden_reports` / `delete`:** bob and admin `DELETE` returned `404`; anonymous `DELETE` returned `401`; the owner could still read the object.
- **`echo_reports` / `delete`:** bob and admin `DELETE` returned `404`; anonymous `DELETE` returned `401`.
- **`expiring_reports` / `read` and `delete`:** bob read alice's expiring report as `404` at multiple intervals up to ~120 seconds and again after ~3 minutes; anonymous read returned `401`; owner read returned `200`; bob `DELETE` returned `404`. No cross-user read was observed. (Separate observation below.)
- **Sharing controls:** alice set `share_new_with:"bob"`; subsequent invoices and tenant notes were readable by bob and not by admin; pre-sharing objects remained inaccessible to bob; recipient `DELETE` was denied; the setting was reset to `null`. Bob's attempt to set another user's sharing through a query parameter or `X-Username` header returned `422` and did not change alice's setting. Self-sharing (`share_new_with:"alice"`) returned `422`.
- **Identity and absence controls:** `GET /app/api/me` returned the expected stable IDs for alice, bob, and admin. Unknown ids returned `404` for every tested class except `echo_reports` (which ignores the id and returned `200`); `login_reports` returned `404` for unknown ids but `200` for an existing-inaccessible id (see the observation below). Anonymous requests to protected classes returned `401` where expected.

---

## Observations not submitted as findings

- **`login_reports` existence oracle:** an existing but inaccessible `login_reports` object returns `200` with a sign-in HTML page, while a nonexistent id returns `404`. This distinguishes existence but does not disclose the object's `note`. It is recorded for completeness; it is not submitted as a cross-user data-access finding because no protected value was returned.
- **`expiring_reports` session invalidation:** reading an `expiring_reports` object as its owner caused the owner's subsequent `GET /app/api/me` to return `401` (the owner's session was invalidated), while reading a `private_reports` object did not. This is a session/availability side effect, not a cross-user access finding; no cross-user read was observed for this class.

---

## Evidence location

The raw request/response capture, including the exact HTTP status, headers (`content-type`, `cache-control`, `content-length`), bodies, object ids, and control results summarized above, is at:

- `/workspace/evidence.log`

All object ids and marker values quoted in this report appear in that log.

- The final `### Final reproducibility smoke test` section in the log re-confirms Findings 1–6 with fresh objects.
