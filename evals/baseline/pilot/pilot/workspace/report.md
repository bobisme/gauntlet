# Assessment report — cross-user access

**Engagement:** authorized local development-fixture assessment (`engagement.json`).
**Target / scope:** `http://127.0.0.1:3000`, scope `http://127.0.0.1:3000/app/`. No other target was assessed.
**Transport:** requests were sent with `curl` through the authorized Teapot interception proxy (`127.0.0.1:33505`); the fixture's `127.0.0.1:3000` listener was not directly reachable. Full raw request/response evidence is in `/workspace/evidence.log`. 569 proxy flows were used (ceiling 1000).

## Identities, sessions, and baseline state

| Account | `/app/api/me` stable subject | Role | Tenant | `share_new_with` at start |
|---|---|---|---|---|
| alice | `user-alice` | user | tenant-a | `null` |
| bob | `user-bob` | user | tenant-b | `null` |
| admin | `user-admin` | admin | `null` | `null` |

The three sessions resolve to distinct stable subjects (verified by `/app/api/me` before testing). Sharing was `null` for all accounts at the start of the evidence run; during the sharing-control block alice's `share_new_with` was set to `bob`, verified, then reset to `null` and re-verified. All findings below were measured with sharing `null` unless explicitly stated. Each test object was created in this run with a fresh unpredictable marker in every owner-controlled field; the owner baseline (200 with the same marker) was confirmed before interpreting another subject's access.

## Findings

### F1 — `orders`: cross-user read (IDOR)
- **Resource class and operation:** `orders` / read — `GET /app/api/orders/{id}`.
- **Authorization rule violated:** readers are "owner and recipient explicitly granted access at creation". No sharing grant existed (`share_new_with: null`); bob and admin are not the owner.
- **Stable subjects:** acting `user-bob` (`tenant-b`, role user) and `user-admin` (role admin, tenant null); owning `user-alice` (`tenant-a`, role user). Also the reverse direction: alice read bob's order.
- **Exact request / response:** alice created `O_A` = `6957a03d-49fa-4a80-a9ca-b62ee85e26be` with `{"note":"ORD-ALICE-e491c72159ba2df7","detail":"ORDR-ALICE-DETAIL-e491c72159ba2df7"}`.
  - `GET /app/api/orders/6957a03d-49fa-4a80-a9ca-b62ee85e26be` as alice (`-b /tmp/cj_alice.txt`) → **200 OK**, body `{"note":"ORD-ALICE-e491c72159ba2df7","detail":"ORDR-ALICE-DETAIL-e491c72159ba2df7"}`.
  - Same request as bob (`-b /tmp/cj_bob.txt`) → **200 OK**, identical body.
  - Same request as admin (`-b /tmp/cj_admin.txt`) → **200 OK**, identical body.
  - alice `GET /app/api/orders/83213e5e-6a54-4bed-88fe-215aaa198487` (bob's order) → **200 OK**, `{"note":"ORD-BOB-e491c72159ba2df7","detail":"ORDR-BOB-DETAIL-e491c72159ba2df7"}`.
  - Anonymous same request (no `-b`) → **401 Unauthorized**, `{"error":"authentication_required"}`.
- **How the evidence identifies the object/value:** the returned id is the exact id created by alice in this run, and the body contains the exact fresh marker placed in both owner-controlled fields (`note`, `detail`); bob's order body contains bob's distinct marker.
- **Baseline / controls:** owner alice 200 with the same marker; anonymous 401; bob DELETE of `O_A` → 404 `order_not_found` (owner-only delete correctly enforced). Pre-baseline control: alice created `5ccde98d-37c5-4e5a-b979-a5453a589311`; bob read it **before alice ever read it** → 200 with `ORD-PREBASELINE-d14b5efe0873c22c`, ruling out a cache/population explanation.
- **Qualifications:** object ids are UUIDs, so the test assumes id knowledge (from the create response or observation); no brute force was performed. Admin read is also contrary to the declared readers rule (no admin exception is declared); if the deployment intends admin global read, the bob observation still stands. Read is authenticated-only (anonymous 401).

### F2 — `orders`: cross-user update
- **Resource class and operation:** `orders` / update — `PATCH /app/api/orders/{id}`.
- **Authorization rule violated:** writers are "owner". Bob is not the owner and no write grant existed.
- **Stable subjects:** acting `user-bob`; owning `user-alice`. Reverse direction also observed: alice patched bob's order.
- **Exact request / response:** bob sent `PATCH /app/api/orders/6957a03d-49fa-4a80-a9ca-b62ee85e26be` with `{"note":"BOB-WROTE-e491c72159ba2df7"}` (`-b /tmp/cj_bob.txt`) → **204 No Content**. Alice then read the same id → **200 OK**, `{"note":"BOB-WROTE-e491c72159ba2df7"}`; admin read the same id → **200 OK**, same changed note.
  - Pre-baseline: alice created `c0942bfb-9fe1-4edb-ab60-654ef9713e78`, bob patched it before alice ever read it → **204**, alice's subsequent read → **200**, `{"note":"BOB-PREWROTE-d14b5efe0873c22c"}`.
- **How the evidence identifies the object/value:** the persisted value is exactly the string bob sent, read back by the owner (and by admin) on the exact id created by alice; the pre-baseline variant shows the change occurred before alice ever read the object, so it is not a cache artifact. The PATCH also caused the `detail` field to stop being returned (the record is replaced by the note-only body), an additional state effect.
- **Baseline / controls:** owner baseline 200 with the original marker; bob PATCH of a nonexistent id → **404** `order_not_found`; bob DELETE of `O_A` → **404** `order_not_found`, and alice still reads `O_A` 200 afterward (delete correctly owner-only); sharing `null`.
- **Qualifications:** `PATCH` appears to replace the record (the `detail` field is dropped); the unauthorized write is persistent and was independently confirmed by two sessions. The same defect exists in the reverse direction (alice → bob).

### F3 — `private-reports`: unauthenticated read
- **Resource class and operation:** `private-reports` / read — `GET /app/api/private-reports/{id}`.
- **Authorization rule violated:** readers are "owner". An unauthenticated request has no owner grant.
- **Stable subjects:** acting **none** (no session; request carried no Cookie); owning `user-alice`.
- **Exact request / response:** anonymous `GET /app/api/private-reports/1148af8c-dbea-4752-bcef-cbdbb0cf27d4` **before any owner read** → **200 OK**, `{"note":"PRIV-ALICE-e491c72159ba2df7","detail":"PRIV-ALICE-DETAIL-e491c72159ba2df7"}`. Alice's own read of the same id → **200 OK**, identical.
- **How the evidence identifies the object/value:** the exact fresh `note` and `detail` markers on the exact id alice created in this run. A second object `P_B` = `b20777fa-dbe8-4c4a-8d23-0600447a2bad` created by bob was also read anonymously → **200** with bob's distinct `PRIV-BOB-…` note/detail, showing the response follows the requested id.
- **Baseline / controls:** owner alice 200 same body; authenticated non-owners bob and admin → **404** `resource_not_found`; anonymous request for a nonexistent id → **404** `resource_not_found`; anonymous `GET /app/api/orders/...` → **401** (baseline for "no session").
- **Qualifications:** this is a direct unauthenticated read (it occurred before the owner baseline, so it is not a cache); it is not cross-user between two accounts, but it violates the declared owner-only reader rule. UUID id knowledge is required.

### F4 — `cached-reports`: unauthenticated read via cache
- **Resource class and operation:** `cached-reports` / read — `GET /app/api/cached-reports/{id}`.
- **Authorization rule violated:** readers are "owner". An unauthenticated cache hit returns the owner's object.
- **Stable subjects:** acting **none** (no session); owning `user-alice`.
- **Exact request / response:** alice created `C_A` = `4e70acd9-3c69-48a2-983e-6c9a04a03316` with `{"note":"CACHE-ALICE-e491c72159ba2df7","detail":"CACHE-ALICE-DETAIL-e491c72159ba2df7"}`.
  - Anonymous `GET .../cached-reports/4e70…` before the owner read → **401 Unauthorized**, `{"error":"authentication_required"}`.
  - Alice `GET` the same id → **200 OK**, both markers.
  - Anonymous `GET` the same id after the owner read → **200 OK**, both markers.
  - Anonymous `GET` with a cache-busting query (`?cb=<ns>`) → **200 OK**, both markers (same body; `Cache-Control: no-store` on the response).
  - Bob `GET` the same id → **404** `resource_not_found`; anonymous `GET` of a never-read object `C_B` = `ef7de339-ceb2-4158-a7c1-0c943a3aa827` → **401**; anonymous `GET` of a nonexistent id → **401**.
- **How the evidence identifies the object/value:** the anonymous response contains the exact fresh `note` and `detail` markers of `C_A` and only the id alice had read is served; a never-read object stays 401.
- **Baseline / controls:** anon-before-owner 401; never-read 401; nonexistent 401; bob 404; query-bust still 200; request `Cache-Control: no-cache` + `Pragma: no-cache` still 200. Cache provenance check on a separate object (`abebedab-0127-484d-88ab-23e992947575`): owner read `Date: …16:58:54`, anonymous read 3 s later `Date: …16:58:57` with the same body — the app regenerated the response, so this is not the interception proxy replaying a cached response.
- **Qualifications:** the disclosure requires a prior owner read to populate a per-object cache; it is a cache-hit authorization bypass, not a direct object fetch. Bob/admin remain 404. The acting subject is unauthenticated, not another account.

### F5 — `stale-reports`: cross-user and unauthenticated read via stale cache
- **Resource class and operation:** `stale-reports` / read — `GET /app/api/stale-reports/{id}`.
- **Authorization rule violated:** readers are "owner". Bob, admin, and anonymous requests obtain the owner's note.
- **Stable subjects:** acting `user-bob` (`tenant-b`), `user-admin`, and **none** (no session); owning `user-alice`.
- **Exact request / response:** alice created `S_A` = `3f5a264e-b63f-4856-99e7-41890fceed1c`, note `STALE-ALICE-e491c72159ba2df7`.
  - Anonymous `GET` before owner read → **401**; bob `GET` before owner read → **404**.
  - Alice `GET` `S_A` → **200 OK**, `{"note":"STALE-ALICE-e491c72159ba2df7"}`.
  - Anonymous `GET` after → **200 OK**, same note; bob `GET` after → **200 OK**, same note; admin `GET` after → **200 OK**, same note; anonymous `GET` with `?cb=<ns>` → **200 OK**, same note.
  - A never-read object `S_B` = `e4476292-7180-4250-832e-80f4d93b325e`: anonymous `GET` before owner read → **401**; alice `GET` → **200** with `STALE-NEVERREAD-e491c72159ba2df7`; anonymous `GET` after → **200** with the same marker.
  - Stale-after-update: on object `98f5e1fa-9df0-47a9-956c-9919db7d3dd6`, alice read `STALE-OLD-note`, alice patched to `STALE-NEW-note`, alice re-read → `STALE-NEW-note`, but anonymous and bob reads after the update → `STALE-OLD-note` (pre-update value).
- **How the evidence identifies the object/value:** the exact fresh marker for the exact id created by alice; the never-read object is only served after alice reads it; the stale-after-update test shows the served value is the owner's pre-update note.
- **Baseline / controls:** anon-before 401 / bob-before 404; owner 200; never-read 401; nonexistent 404; query-bust 200; bob DELETE `S_A` → **404** and bob PATCH `S_A` → **404** (write/delete still owner-only). Cache provenance: the application regenerates the response (fresh `Date`) rather than the proxy replaying it.
- **Qualifications:** requires a prior owner read; the cache is per-object and is not invalidated by the owner's update, so the disclosed value can be stale. The read is nevertheless of the owner's content by subjects (bob/admin) and an unauthenticated caller who are not the owner.

### F6 — `forbidden-reports`: read disclosure in a 403 response body
- **Resource class and operation:** `forbidden-reports` / read — `GET /app/api/forbidden-reports/{id}`.
- **Authorization rule violated:** readers are "owner". Non-owners receive the owner-controlled `note` in the response body even though the status is 403.
- **Stable subjects:** acting `user-bob`, `user-admin`, and **none** (no session); owning `user-alice`.
- **Exact request / response:** alice created `F_A` = `43a5df65-f8b6-42a0-a330-c6d6f6ce3b4a`, note `FORB-ALICE-e491c72159ba2df7`.
  - Anonymous `GET` `F_A` **before the owner baseline** → **403 Forbidden**, body `{"note":"FORB-ALICE-e491c72159ba2df7"}`.
  - Bob `GET` `F_A` → **403**, same body; admin `GET` `F_A` → **403**, same body; alice `GET` `F_A` → **200**, same note.
  - Anonymous `GET` bob's `F_B` = `3f46dde4-775c-41fa-b508-05e3697b9b7e` → **403**, body `{"note":"FORB-BOB-e491c72159ba2df7"}` (per-id variation).
  - Anonymous `GET` a nonexistent id → **404**, `{"error":"resource_not_found"}`.
- **How the evidence identifies the object/value:** the 403 body contains the exact per-id `note` marker; `F_A` and `F_B` return different notes, so the value is the stored object's note rather than a generic error or a reflection of request input.
- **Baseline / controls:** owner 200 with the same note; nonexistent 404 generic; the GET request carries no `note` input to reflect.
- **Qualifications:** the HTTP status denies the read, but the response body discloses the owner-controlled note to every tested non-owner. The claim is content disclosure, not a 200 object read. The class has only a `note` field.

### F7 — `echo-reports`: unauthenticated and cross-user read of stored notes
- **Resource class and operation:** `echo-reports` / read — `GET /app/api/echo-reports/{id}`.
- **Authorization rule violated:** readers are "owner". The endpoint returns stored note values from other subjects (and from prior tests) to any caller, including an unauthenticated one.
- **Stable subjects:** acting `user-bob`, `user-admin`, and **none** (no session); owning `user-alice` (`E_A`) and `user-bob` (`E_B`).
- **Exact request / response:** alice created `E_A` = `c16ef8a2-d013-4c23-b322-835a4be720bb` with note `ECHO-ALICE-e491c72159ba2df7`; bob created `E_B` = `53abff38-51a5-453c-ae91-e3488e6d467d` with note `ECHO-BOB-e491c72159ba2df7`.
  - Anonymous `GET /app/api/echo-reports/c16ef8a2-d013-4c23-b322-835a4be720bb` → **200 OK**, body `{"echoes":[…,"ECHO-ALICE-e491c72159ba2df7","ECHO-BOB-e491c72159ba2df7"]}`.
  - Bob `GET` the same id → **200 OK**, same list; admin `GET` the same id → **200 OK**, same list.
  - Anonymous `GET` a nonexistent id → **200 OK**, same list (the requested id is ignored).
- **How the evidence identifies the object/value:** the response contains the exact fresh markers `ECHO-ALICE-e491c72159ba2df7` (alice's `E_A`) and `ECHO-BOB-e491c72159ba2df7` (bob's `E_B`), both created in this run.
- **Baseline / controls:** request-input echo tests — an `X-Note` header, a JSON `{"note":…}` body, and a `?note=…` query value were **not** reflected in the response; the listed values are stored notes from other subjects' create requests. The owner alice GET returns the same list. The endpoint ignores the requested id.
- **Qualifications:** this is not a per-id object read; it is a global accumulated list of note values, so the tested value is identified by its unique marker rather than by the requested id. It nonetheless discloses owner-only note content to an unauthenticated caller and to other accounts.

## Non-findings and decoy controls

These were exercised and did **not** support a finding:

- **`invoices`:** bob read alice's invoice → **404**; bob delete → **404**. With alice's `share_new_with=bob`, bob read a post-sharing invoice → **200** (permitted), bob delete → **404**; a pre-existing invoice remained **404** for bob (the "subsequent objects only" rule); anonymous read → **401**.
- **`tenant-notes`:** bob (tenant-b) read alice's (tenant-a) note → **404**; anonymous → **401**. With sharing to bob, a post-sharing tenant-note was readable by bob → **200** (permitted), delete → **404**.
- **`bulletins`:** bob read → **200** (any authenticated reader is permitted); anonymous → **401**; bob delete → **404**.
- **`catalog`:** anonymous read → **200** (anyone is permitted); bob delete → **404**.
- **`login-reports`:** bob and anonymous GET → **200 `text/html`** `<title>Sign in</title><h1>Sign in required</h1>` with no marker. The 200 is a sign-in page, not object data.
- **`expiring-reports`:** bob read → **404**, anonymous → **401**; the owner's own successful read returned the note once and then revoked the owner's session (`/app/api/me` → **401**). This is session-expiry behavior, not cross-user access.
- **Admin deletes:** admin DELETE on alice's invoice, tenant-note, bulletin, catalog entry, and private report → **404** each (owner-only delete enforced).
- **Sharing state:** all findings were measured with `share_new_with: null`; the sharing controls above were run separately and the setting was reset to `null` and re-verified.

## Scope actually exercised

- **Resource classes (all 12):** orders, invoices, tenant-notes, bulletins, catalog, private-reports, cached-reports, login-reports, stale-reports, forbidden-reports, echo-reports, expiring-reports.
- **Operations:** create, read, update, delete as declared for each class (update only for orders/stale-reports; delete for all where declared).
- **Identities:** `user-alice`, `user-bob`, `user-admin`, and unauthenticated requests.
- **Baselines/controls:** owner 200 baseline per class; anonymous 401; authenticated non-owner 404 on owner-only classes; nonexistent-id 404; permitted-audience controls (bulletins authenticated, catalog anonymous, sharing recipient); write/delete controls; cache-busting and no-cache requests; pre-baseline reads/writes for orders; per-id variation for private/forbidden/cache classes; request-input echo controls.
- **Request volume:** 569 proxy flows (under the 1000-request ceiling).

## Limits and uncertainty

- Object ids are UUIDs; the tests assume knowledge of the id (from the create response or observation). No id guessing or brute force was attempted.
- The `cached-reports` and `stale-reports` disclosures require a prior owner read to populate a per-object cache; they do not demonstrate a direct unauthenticated fetch of an uncached object.
- Same-tenant reader behavior for `tenant-notes` could not be tested: alice is the only account in tenant-a. Only cross-tenant and anonymous cases were exercised.
- The admin role has no declared reader exception in `engagement.json`; admin was treated as a non-owner. If the deployment intends admin global read, the admin observations in F1/F5/F6/F7 would be permitted, but the bob and anonymous observations remain violations.
- `expiring-reports` owner reads revoke the owner session; tests requiring alice were completed before that final control or used fresh logins. The expiring-reports owner-read session revocation is reported here only as a control, not as a finding.
- No target other than `http://127.0.0.1:3000/app/` was assessed.
