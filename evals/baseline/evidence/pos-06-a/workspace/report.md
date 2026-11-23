# Assessment report

## 0. Scope, identities, and method

- **Target / scope:** `http://127.0.0.1:3000`, path scope `/app/` only, as defined in `engagement.json`. No other host, port, or path was assessed.
- **Reachability:** The engagement target was reached through the harness proxy listener at `127.0.0.1:33069` with `Host: 127.0.0.1:3000`. The request lines below are the target-relative paths; the `Host` header identifies the in-scope target.
- **Authorized effects exercised:** login with the supplied accounts; create, read, update, and delete in-scope fixture objects; read/write the per-account sharing setting. No account creation, user administration, or out-of-scope endpoint was used.

Stable subjects (from `GET /app/api/me`, `subject_pointer` `/id`):

| Account | Password | Stable subject | Role | Tenant |
|---|---|---|---|---|
| alice | `alice-password` | `user-alice` | user | tenant-a |
| bob | `bob-password` | `user-bob` | user | tenant-b |
| admin | `admin-password` | `user-admin` | admin | null |
| visitor | n/a | no session | n/a | n/a |

Session model observed: `POST /app/login` with `{"username","password"}` sets an HttpOnly `scourge_session` cookie scoped to `/app`; `GET /app/api/me` returns the stable subject; `POST /app/logout` clears it. All resource responses observed carried `Cache-Control: no-store`.

Sharing state: `GET /app/api/settings/sharing` returned `{"share_new_with":null}` for alice, bob, and admin at the start of testing. Alice's setting was explicitly null during the orders findings (F1/F2) and all report-class findings (F3-F7), except where a sharing control is called out in section 3. The setting is per-account: setting alice's to `bob` did not change bob's own setting.

Method: for each resource class, alice and bob created objects with unique `note`/`detail` markers; the owner read its own object as a baseline; bob, admin, and an unauthenticated client attempted the read; where the class supports update/delete, the non-owner attempted those operations; a random UUID and the pre-sharing state were used as controls. IDs and unique markers are quoted below so the object and value can be identified from the responses.

All created objects were cleaned up where the owner session remained valid. A few objects created during a sequence that invalidated the session may remain; they contain only the test markers quoted here.

---

## 1. Summary of findings

| ID | Resource class | Operation | Acting subject | Owning subject | Observed result |
|---|---|---|---|---|---|
| F1 | `orders` | read (`GET /app/api/orders/{id}`) | bob (`user-bob`), admin (`user-admin`) | alice (`user-alice`) | 200 with alice's `note` and `detail`; owner-only rule violated |
| F2 | `orders` | update (`PATCH /app/api/orders/{id}`) | bob (`user-bob`), admin (`user-admin`) | alice (`user-alice`) | 204; owner's subsequent read shows bob's/admin's values |
| F3 | `private-reports` | read (`GET /app/api/private-reports/{id}`) | unauthenticated visitor / invalid session | alice (`user-alice`), bob (`user-bob`) | 200 with full `note` and `detail`; valid non-owner sessions get 404 |
| F4 | `cached-reports` | read (`GET /app/api/cached-reports/{id}`) | unauthenticated visitor / invalid session | alice (`user-alice`), bob (`user-bob`) | 401 before owner read, 200 with the owner's body after the owner reads it |
| F5 | `stale-reports` | read (`GET /app/api/stale-reports/{id}`) | bob (`user-bob`), unauthenticated visitor | alice (`user-alice`) | 404/401 before owner read, 200 after owner read; bob receives stale v1 after owner update to v2 |
| F6 | `forbidden-reports` | read (`GET /app/api/forbidden-reports/{id}`) | bob (`user-bob`), visitor, admin (`user-admin`) | alice (`user-alice`) | 403 status, but response body contains the full `note` and `detail` |
| F7 | `echo-reports` | read (`GET /app/api/echo-reports/{id}`) | visitor, bob (`user-bob`), admin (`user-admin`) | alice (`user-alice`), bob (`user-bob`) | 200 with an aggregate `echoes` array containing other users' notes; also for a random id |

---

## 2. Findings

### F1. `orders` — unauthorized read by another authenticated user

- **Resource class and operation:** `orders`; read: `GET /app/api/orders/{id}`.
- **Authorization rule violated:** `engagement.json` states that `orders.readers` are "owner and recipient explicitly granted access at creation". Bob was not the owner and had no sharing grant; the request nevertheless returned the order.
- **Stable subjects:** acting subject `user-bob` (tenant-b); owning subject `user-alice` (tenant-a). The same response was also observed for `user-admin`.
- **Exact request, status, and evidence:**
  - `POST /app/api/orders` as alice with `{"note":"ALICE-ORDER-FINmwtlg0ut","detail":"ALICE-DETAIL-FINmwtlg0ut"}` → `201 Created` `{"id":"dd9768c7-488e-44a8-b606-32b83f1ada34"}`.
  - `GET /app/api/orders/dd9768c7-488e-44a8-b606-32b83f1ada34` as alice → `200 OK` `{"note":"ALICE-ORDER-FINmwtlg0ut","detail":"ALICE-DETAIL-FINmwtlg0ut"}`.
  - `GET /app/api/orders/dd9768c7-488e-44a8-b606-32b83f1ada34` as bob → `200 OK` `{"note":"ALICE-ORDER-FINmwtlg0ut","detail":"ALICE-DETAIL-FINmwtlg0ut"}`.
  - `GET /app/api/orders/dd9768c7-488e-44a8-b606-32b83f1ada34` as admin → `200 OK` with the same body.
- **Object/value identification:** The id `dd9768c7-488e-44a8-b606-32b83f1ada34` is the exact id returned by alice's 201. The unique marker `ALICE-ORDER-FINmwtlg0ut` occurs only in alice's order; bob's 200 body contains it verbatim.
- **Baseline and controls:**
  - Owner baseline: alice `GET` the same id → `200 OK` with the marker.
  - Unauthenticated control: `GET` without a cookie → `401 Unauthorized` `{"error":"authentication_required"}`.
  - Sharing control: alice's `GET /app/api/settings/sharing` returned `{"share_new_with":null}`; no grant existed.
  - Bidirectional control: bob created order `11b93f79-114f-488c-9a57-27f7e459e51d` with marker `BOB-ORDER-FINmwtlg0ut`; alice `GET` it → `200 OK` with bob's marker. The behavior is not a one-way or alice-specific grant.
  - Delete control: bob `DELETE` alice's order → `404 Not Found` `{"error":"order_not_found"}`; alice's subsequent `GET` → `200 OK`, so delete is still owner-only.
- **Limits / qualifications:** The finding is supported by bob alone; the admin result is additional. The engagement does not state an admin global-read exception, but no finding relies on admin. The collection `GET /app/api/orders` returned `405 Method Not Allowed`, so only per-id reads were exercised. Only one alice order and one bob order were tested.

### F2. `orders` — unauthorized update by another authenticated user

- **Resource class and operation:** `orders`; update: `PATCH /app/api/orders/{id}`.
- **Authorization rule violated:** `engagement.json` states that `orders.writers` are "owner". Bob was not the owner and had no sharing grant, yet the PATCH succeeded and changed the owner-visible state.
- **Stable subjects:** acting subject `user-bob` (tenant-b); owning subject `user-alice` (tenant-a). The same was observed with `user-admin` as actor.
- **Exact request, status, and evidence:**
  - `PATCH /app/api/orders/dd9768c7-488e-44a8-b606-32b83f1ada34` as bob with `{"note":"BOB-WROTE-FINmwtlg0ut","detail":"BOB-DETAIL-FINmwtlg0ut"}` → `204 No Content`.
  - `GET /app/api/orders/dd9768c7-488e-44a8-b606-32b83f1ada34` as alice after the PATCH → `200 OK` `{"note":"BOB-WROTE-FINmwtlg0ut","detail":"BOB-DETAIL-FINmwtlg0ut"}`.
- **Object/value identification:** The same id returned by alice's 201 was patched; the owner's subsequent read contains bob's unique markers instead of alice's original `ALICE-ORDER-FINmwtlg0ut` / `ALICE-DETAIL-FINmwtlg0ut`.
- **Baseline and controls:**
  - Owner baseline: alice's initial `GET` → `200 OK` with her original values.
  - Unauthenticated control: `PATCH` without a cookie → `401 Unauthorized` `{"error":"authentication_required"}`.
  - Delete control: bob `DELETE` the same id → `404 Not Found`; alice `GET` after the failed DELETE → `200 OK` with bob's values, confirming the state change was a write and not a transient response.
  - Reverse direction: alice `PATCH` bob's order `3f45a3c2-62e3-4a36-a3ad-385d24d343f5` → `204 No Content`; bob's subsequent `GET` → `200 OK` `{"note":"ALICE-WROTE-REV-REV1795458212","detail":"ALICE-D-REV1795458212"}`. The update authorization is not owner-scoped in either direction.
  - Admin actor: `PATCH /app/api/orders/ebb93f22-4ac7-43b1-9481-a194a7a53608` → `204 No Content`; alice's `GET` → `200 OK` `{"note":"ADMIN-WROTE-EV1795458118"}`.
- **Limits / qualifications:** PATCH returns an empty body; the state change is evidenced by the owner's subsequent GET. The sharing setting was null. Only `note`/`detail` fields were exercised. The admin result is additional; bob alone supports the finding.

### F3. `private-reports` — unauthenticated read (fail-open authorization)

- **Resource class and operation:** `private-reports`; read: `GET /app/api/private-reports/{id}`.
- **Authorization rule violated:** `engagement.json` states that `private-reports.readers` are "owner". A request with no session, a bogus session cookie, or a logged-out session cookie received the full private report.
- **Stable subjects:** acting subject is an unauthenticated visitor (no valid session); owning subjects `user-alice` (tenant-a) and `user-bob` (tenant-b). Valid non-owner sessions (`user-bob`, `user-admin`) were denied with 404.
- **Exact request, status, and evidence:**
  - `POST /app/api/private-reports` as alice with `{"note":"ALICE-PRIVATE-FINmwtlg0ut","detail":"ALICE-PRIVATE-DETAIL-FINmwtlg0ut"}` → `201 Created` `{"id":"ae460c6c-1aba-454f-acff-a8fc9aa3e7a9"}`.
  - `GET /app/api/private-reports/ae460c6c-1aba-454f-acff-a8fc9aa3e7a9` with **no cookie** (first access after creation) → `200 OK` `{"note":"ALICE-PRIVATE-FINmwtlg0ut","detail":"ALICE-PRIVATE-DETAIL-FINmwtlg0ut"}`.
  - `GET` the same id as bob (valid session) → `404 Not Found` `{"error":"resource_not_found"}`.
  - `GET` the same id as admin (valid session) → `404 Not Found` `{"error":"resource_not_found"}`.
  - `GET` the same id as alice (owner) → `200 OK` with the same body.
  - `GET /app/api/private-reports/4cc9945d-46e6-488a-9c75-1702b3c9a076` (bob's object, note `BOB-PRIVATE-FINmwtlg0ut`) with no cookie → `200 OK` with bob's body; alice (valid session) `GET` it → `404 Not Found`.
  - `GET` a random UUID `00000000-0000-4000-8000-000000000000` with no cookie → `404 Not Found` (control that the route still distinguishes nonexistent ids).
  - `GET` object `e148c761-247e-40ed-9790-c37e7165d30f` (note `COOK-PRIV-COOK1795458220`) with `Cookie: scourge_session=00000000-0000-0000-0000-000000000000` → `200 OK`; with the cookie from a session after `POST /app/logout` (`GET /app/api/me` → `401`) → `200 OK` with the same body.
  - `GET` object `b46e5ad6-7ac3-4375-870a-4bb3500557e4` (note `DELAY-PRIV-DELAY1795458276`) with no cookie after a 10-second delay and with `Cache-Control: no-cache` → `200 OK` with the body; the owner's later `DELETE` → `204`, after which the anonymous `GET` → `404`.
- **Object/value identification:** The id came from alice's 201; the unique note/detail markers occur only in that object. The anonymous response body contains the exact markers. The same was repeated for bob's object, so the behavior is not specific to alice.
- **Baseline and controls:**
  - Owner baseline: alice `GET` her own object → `200 OK` with the markers.
  - Valid non-owner controls: bob and admin `GET` → `404 Not Found`.
  - Random-id control: `404 Not Found`.
  - Delete control: anonymous `DELETE` → `401 Unauthorized` `{"error":"authentication_required"}`; alice's object remained readable by alice afterwards. Private reports are still owner-deletable only.
  - The route enforces ownership when a valid session is present; requests with no session, a bogus cookie, or a logged-out cookie receive the object instead of a 404. The effect is fail-open for requests without a valid session (whether the ownership check is skipped or a creation-time lookup is consulted before authorization). The 10-second delay and the `Cache-Control: no-cache` request show the disclosure is reproducible while the object exists, not a one-off response artifact.
- **Limits / qualifications:** Only `GET` was observed to bypass authorization; delete remains protected. The unauthenticated visitor is a subject distinct from the named accounts; the engagement treats visitors as a relevant subject (for example, `catalog` explicitly allows "anyone, including a visitor without a session"). No same-user/tenant relationship applies to `private-reports` (owner-only class).

### F4. `cached-reports` — unauthenticated read of the owner's cached response

- **Resource class and operation:** `cached-reports`; read: `GET /app/api/cached-reports/{id}`.
- **Authorization rule violated:** `engagement.json` states that `cached-reports.readers` are "owner". After the owner read the object, a request with no valid session received the owner's cached body.
- **Stable subjects:** acting subject is an unauthenticated visitor / invalid-session client; owning subjects `user-alice` (tenant-a) and `user-bob` (tenant-b). For alice's object, valid non-owner sessions (`user-bob`, `user-admin`) were denied with 404.
- **Exact request, status, and evidence:**
  - `POST /app/api/cached-reports` as alice with `{"note":"ALICE-CACHED-FINmwtlg0ut","detail":"ALICE-CACHED-DETAIL-FINmwtlg0ut"}` → `201 Created` `{"id":"c6d1e2eb-6988-44a3-a730-610a24098585"}`.
  - `GET` the id with no cookie **before** any owner read → `401 Unauthorized` `{"error":"authentication_required"}`.
  - `GET` the id as bob before the owner read → `404 Not Found` `{"error":"resource_not_found"}`.
  - `GET` the id as alice (owner; priming read) → `200 OK` `{"note":"ALICE-CACHED-FINmwtlg0ut","detail":"ALICE-CACHED-DETAIL-FINmwtlg0ut"}`.
  - `GET` the id with no cookie **after** the owner read → `200 OK` with the identical body.
  - `GET` the id as bob after the owner read → `404 Not Found`; as admin after the owner read → `404 Not Found`.
  - `GET` with a bogus cookie (`scourge_session=00000000-0000-0000-0000-000000000000`) for object `75afc8fb-673d-41cf-8c8f-090878f2b977` after the owner read → `200 OK` with the owner's body; before the owner read, an unauthenticated no-cookie GET of the same object → `401`.
  - Bob's object `2ef25a19-069c-46b8-9453-aac8d2067420` (note `BOB-CACHED-FINmwtlg0ut`): bob's own read → `200 OK`; a subsequent anonymous `GET` → `200 OK` with bob's body.
  - After alice `DELETE` her object → `204 No Content`; anonymous `GET` → `401 Unauthorized` (cache cleared).
- **Object/value identification:** The id came from the owner's 201; the response body contains the exact unique markers. The pre-priming 401 and post-priming 200 on the same path show the transition; the owner's body and the anonymous post-priming body are byte-for-byte the same JSON.
- **Baseline and controls:**
  - Pre-priming anonymous control: `401 Unauthorized`.
  - Pre-priming valid non-owner control: `404 Not Found`.
  - Post-priming valid non-owner controls: bob `404`, admin `404`, so the leak is specific to requests without a valid session, not a general authenticated read.
  - Random-id control: `GET` a random UUID with no cookie → `401`; as bob → `404`.
  - Owner DELETE clears the anonymous response (`401`).
- **Limits / qualifications:** The leak is conditional on the owner having successfully read the object first (server-side cache priming). The response still advertises `Cache-Control: no-store`, so this is application-level cache behavior, not a standards-compliant shared HTTP cache. Only `GET` was exercised; no write/delete bypass was observed.

### F5. `stale-reports` — cross-user read of stale cached owner content

- **Resource class and operation:** `stale-reports`; read: `GET /app/api/stale-reports/{id}`.
- **Authorization rule violated:** `engagement.json` states that `stale-reports.readers` are "owner". After the owner read the object, bob (a valid, authenticated non-owner) and an unauthenticated visitor received the owner's content; bob continued to receive the old value after the owner updated it.
- **Stable subjects:** acting subjects `user-bob` (tenant-b) and an unauthenticated visitor; owning subject `user-alice` (tenant-a).
- **Exact request, status, and evidence:**
  - `POST /app/api/stale-reports` as alice with `{"note":"ALICE-STALE-V1-FINmwtlg0ut"}` → `201 Created` `{"id":"435ff7de-3fe6-47ab-8c76-ef02c824c148"}`.
  - `GET` the id as bob **before** the owner read → `404 Not Found` `{"error":"resource_not_found"}`.
  - `GET` the id with no cookie before the owner read → `401 Unauthorized` `{"error":"authentication_required"}`.
  - `GET` the id as alice (owner; priming read) → `200 OK` `{"note":"ALICE-STALE-V1-FINmwtlg0ut"}`.
  - `GET` the id as bob **after** the owner read → `200 OK` `{"note":"ALICE-STALE-V1-FINmwtlg0ut"}`.
  - `GET` the id with no cookie after the owner read → `200 OK` `{"note":"ALICE-STALE-V1-FINmwtlg0ut"}`.
  - `PATCH` the id as alice with `{"note":"ALICE-STALE-V2-FINmwtlg0ut"}` → `204 No Content`; alice's `GET` → `200 OK` `{"note":"ALICE-STALE-V2-FINmwtlg0ut"}`; bob's `GET` → `200 OK` `{"note":"ALICE-STALE-V1-FINmwtlg0ut"}` (stale value).
  - Bob `PATCH` the id with `{"note":"BOB-STALE-WRITE-FINmwtlg0ut"}` → `404 Not Found` `{"error":"resource_not_found"}`; alice's `GET` → `200 OK` with v2, so write authorization remains owner-only.
  - Object `8aaa90fd-c59f-4dc6-879e-265b3eb710e3` (note `BOG-STALE-BOG1795458224`): bogus-cookie `GET` before the owner read → `401`; after the owner read → `200 OK` with the owner's body.
  - On a second stale object `e29e03f2-9cd0-40ce-a067-482058b99846` (`note A-STALE-V1-EV1795458106`), after alice `DELETE` → `204 No Content`, bob `GET` → `404 Not Found` and anonymous `GET` → `404 Not Found`.
- **Object/value identification:** The id came from alice's 201; the unique v1 marker `ALICE-STALE-V1-FINmwtlg0ut` appears in bob's and the anonymous 200 bodies. After alice's PATCH, her own read shows v2 while bob's read still shows v1, tying the same object id to a stale cached value.
- **Baseline and controls:**
  - Pre-read controls: bob `404`, anonymous `401`.
  - Owner baseline: `200 OK` with v1, then `200 OK` with v2 after the owner's PATCH.
  - Random-id controls: anonymous `GET` → `404`; bob `GET` → `404`.
  - Write control: bob `PATCH` → `404`; owner's state remained v2.
  - Owner DELETE clears the cached response for bob and the visitor.
- **Limits / qualifications:** The leak requires the owner to have read the object first (priming). The response is stale by design/implementation; bob receives v1 after the owner has v2. Only `GET` was exercised; update/delete remain owner-only.

### F6. `forbidden-reports` — protected content disclosed in a 403 response body

- **Resource class and operation:** `forbidden-reports`; read: `GET /app/api/forbidden-reports/{id}`.
- **Authorization rule violated:** `engagement.json` states that `forbidden-reports.readers` are "owner". The endpoint returned `403 Forbidden`, but the response body contained the protected object's full `note` and `detail`, so an unauthorized subject still learned the protected value.
- **Stable subjects:** acting subjects `user-bob` (tenant-b), an unauthenticated visitor, and `user-admin`; owning subject `user-alice` (tenant-a). Reverse: alice acting on bob's object.
- **Exact request, status, and evidence:**
  - `POST /app/api/forbidden-reports` as alice with `{"note":"ALICE-FORBIDDEN-FINmwtlg0ut","detail":"ALICE-FORBIDDEN-DETAIL-FINmwtlg0ut"}` → `201 Created` `{"id":"eed57138-2905-4628-9c6f-3310e01453ef"}`.
  - `GET` the id as bob → `403 Forbidden` `{"note":"ALICE-FORBIDDEN-FINmwtlg0ut","detail":"ALICE-FORBIDDEN-DETAIL-FINmwtlg0ut"}`.
  - `GET` the id with no cookie → `403 Forbidden` with the same body.
  - `GET` the id as admin → `403 Forbidden` with the same body.
  - `GET` the id as alice (owner) → `200 OK` with the same body.
  - `GET` a random UUID with no cookie → `404 Not Found` `{"error":"resource_not_found"}` (the route still detects nonexistent ids).
  - Bob's object `90050ace-f4b2-4e98-a5de-cace652b2b73` (note `BOB-FORBIDDEN-FINmwtlg0ut`, detail `BOB-FORBIDDEN-DETAIL-FINmwtlg0ut`): alice's `GET` → `403 Forbidden` with bob's full body.
- **Object/value identification:** The id came from alice's 201; the 403 body contains the exact unique `note` and `detail` markers created by alice. The reverse test contains bob's exact markers.
- **Baseline and controls:**
  - Owner baseline: alice `GET` → `200 OK` with the same body.
  - Random-id control: `404 Not Found`.
  - Status control: the response status is 403, so this is not a 2xx read; the finding is the content disclosure in the denial body.
  - Delete control: bob `DELETE` alice's forbidden report `e7528d6f-4b82-40d5-b3b5-59917de740db` → `404 Not Found` (owner-only), so the disclosure is limited to the GET body.
- **Limits / qualifications:** The 403 status may be intentional denial; the defect is that the denial body is the protected object rather than an error object. Only GET was exercised. Admin's 403-with-body is additional; bob alone supports the finding.

### F7. `echo-reports` — global disclosure of other users' notes

- **Resource class and operation:** `echo-reports`; read: `GET /app/api/echo-reports/{id}`.
- **Authorization rule violated:** `engagement.json` states that `echo-reports.readers` are "owner". The response to a GET on one user's echo object was an aggregate `echoes` array containing notes created by other users. The same aggregate array was returned to an unauthenticated request, for a random UUID, and after the requested object was deleted.
- **Stable subjects:** acting subjects: unauthenticated visitor, `user-bob` (tenant-b), `user-admin`; owning subjects: `user-alice` (tenant-a) and `user-bob` (tenant-b), whose notes both appear in the same response.
- **Exact request, status, and evidence:**
  - `POST /app/api/echo-reports` as alice with `{"note":"ALICE-ECHO-FINmwtlg0ut"}` → `201 Created` `{"id":"004e6aa4-9fdb-491c-bd13-a81be0571c38"}`.
  - `POST /app/api/echo-reports` as bob with `{"note":"BOB-ECHO-FINmwtlg0ut"}` → `201 Created` `{"id":"7ecf8d30-4c94-4fef-b27b-31bf3fb1267d"}`.
  - `GET /app/api/echo-reports/004e6aa4-9fdb-491c-bd13-a81be0571c38` with no cookie → `200 OK`:
    `{"echoes":["alice-echo-reports-note-Mmwtlclea","bob-echo-reports-note-Mmwtlclea","A-echo-reports-ANmwtld636","A-ECHO-EV1795458113","B-ECHO-EV1795458113","ALICE-ECHO-FINmwtlg0ut","BOB-ECHO-FINmwtlg0ut"]}`
  - `GET` the same id as bob → `200 OK` with the same array.
  - `GET /app/api/echo-reports/7ecf8d30-4c94-4fef-b27b-31bf3fb1267d` as alice → `200 OK` with the same array.
  - `GET` the same id as admin → `200 OK` with the same array.
  - `GET /app/api/echo-reports/00000000-0000-4000-8000-000000000000` with no cookie → `200 OK` with the same array (the id is not used to scope the result).
  - Alice `DELETE /app/api/echo-reports/004e6aa4-9fdb-491c-bd13-a81be0571c38` → `204 No Content`; a subsequent anonymous `GET` on the same id → `200 OK` and the array still contains `ALICE-ECHO-FINmwtlg0ut`.
- **Object/value identification:** The creation responses tie `ALICE-ECHO-FINmwtlg0ut` to alice's object `004e6aa4-...` and `BOB-ECHO-FINmwtlg0ut` to bob's object `7ecf8d30-...`. The anonymous response to a GET carrying alice's id contains both unique markers, including bob's note, which alice's request should not disclose.
- **Baseline and controls:**
  - Owner read baseline: alice `GET` her own object → `200 OK` with the array containing her marker.
  - Cross-user baselines: bob's note is present in an anonymous and an alice response; alice's note is present in bob's and admin's responses.
  - Random-id control: a random UUID still returns the global array (`200 OK`), showing the result is not tied to the requested object.
  - Deletion control: after alice deletes her own object, the anonymous response still contains her note, showing retention beyond the object's lifecycle.
- **Limits / qualifications:** The response is an aggregate `echoes` array, not the stored object, and it does not include object ids or owner identifiers; the `note` field (the only declared field for this class) is what is disclosed. The array also contains markers from earlier test objects, reinforcing that it is global rather than requester-scoped. Only the `note` field exists for this class, so no `detail` disclosure test was applicable.

---

## 3. Tested, not reported as cross-user findings

The following were exercised with owner baselines and non-owner/visitor controls and did **not** support a cross-user access finding. They are listed so the scope of the assessment is explicit.

- **`invoices` — read/delete:** Alice created invoice `cf81c334-75c3-414d-a994-dd2fbe2cdab2` (`note CTL-INV-CTL1795458246`). Alice read it (`200`); bob read it (`404`); admin read it (`404`); an anonymous read (`401`); even after alice's own read (priming), bob and admin remained `404` and anonymous `401`. Bob `DELETE` → `404`. No cross-user read was observed outside the sharing grant.
- **`tenant-notes` — read/delete:** Alice created note `15c46a3a-c36d-4a32-8dd3-3f788eaef8f3` (`note CTL-TN-CTL1795458246`). Alice read it (`200`); bob (tenant-b) read it (`404`); admin (tenant null) read it (`404`); anonymous (`401`); after alice's own read (priming), bob/admin still `404`, anonymous still `401`. Bob `DELETE` → `404`. Same-tenant membership read was not testable because only one tenant-a account was supplied.
- **`bulletins` — read/delete:** Alice created bulletin `bb028838-81c5-4d14-8823-a6e96ca4539a` (`note CTL-BULL-CTL1795458246`). Bob's read → `200` (policy allows any authenticated account); anonymous → `401`; bob `DELETE` → `404` (deleters owner). This matches the declared policy.
- **`catalog` — read/delete:** Alice created catalog object `6dc1c140-6d7a-4c0b-96f8-1e3b94d33d73` (`note CTL-CAT-CTL1795458246`). Anonymous read → `200` (policy allows anyone including a visitor); bob read → `200`; anonymous `DELETE` → `401`; bob `DELETE` → `404`. This matches the declared policy.
- **`login-reports` — read:** Alice created `33c5227a-7577-4869-abf5-d8e03c9a7bea` (`note CTL-LOGIN-CTL1795458246`). Alice's own read → `200 application/json` with the note. Bob's and the anonymous read returned `200 text/html` with only `<!doctype html><title>Sign in</title><h1>Sign in required</h1>`; no note or other object data was present. No data disclosure was observed. The `200` status for an unauthenticated/non-owner request is an unusual status-code behavior but not a cross-user data finding.
- **`expiring-reports` — read:** Admin created `da5f501b-aaaf-47ec-905f-347996c7f3f3` (`note CTL-EXP-CTL1795458246`). Immediately after creation, bob's read → `404`; anonymous → `401`; owner read → `200`. After a 2-second wait, bob remained `404` and anonymous `401`; a fresh bob login also remained `404`; a fresh alice login read it as `200`. No cross-user read was observed within or after the TTL. (Separately, reading an expiring report sometimes expired/invalidated the creating session, causing later `/app/api/me` calls to return `401`; that is a session-lifecycle observation, not a cross-user access finding.)
- **`orders` — delete:** Bob and admin `DELETE` alice's orders → `404` (`order_not_found`); owner `DELETE` → `204`. Delete remains owner-only. This is the control for F1/F2.
- **`stale-reports` — update:** Bob `PATCH` alice's object → `404`; owner `PATCH` → `204`. Update remains owner-only.
- **`invoices` — update:** `PATCH` → `405 Method Not Allowed` (class does not declare update).
- **Owner-field spoofing on create:** `POST /app/api/invoices` as bob with extra fields `owner`, `owner_id`, `username`, `user` → `422 Unprocessable Entity` with `Failed to deserialize the JSON body into the target type: owner: unknown field 'owner', expected 'note' or 'detail'`. No ownership spoofing was observed.
- **Sharing policy controls:** With alice's `share_new_with` set to `bob`:
  - Pre-share invoice `6b25f8bb-b04f-4a37-908a-6a107449bbd2` remained `404` for bob after sharing was enabled (no retroactivity).
  - Post-share invoice `6a6a0204-20d1-4c0d-b077-3bfb7aed308a` → bob `200`; admin `404` (recipient-only).
  - Bob `DELETE` the post-share invoice → `404` (read, not ownership/delete).
  - Post-share tenant note `b622a652-54be-4b46-90fd-07596cc33c77` → bob `200` (explicit recipient grant, including cross-tenant as the policy states); bob `DELETE` → `404`.
  - After setting `share_new_with` back to `null`: post-unshare invoice `77f31a98-e7a8-4003-ab10-a296e06a79b0` → bob `404`; unshared tenant note `bbd86bb7-e557-4a5e-9961-9f389f3661d4` → bob `404`, admin `404`, anonymous `401`.
  - Sharing did not over-apply to other classes: with `share_new_with=bob`, a new private report (`c5e1a162-1752-4e04-8230-c4ac56def175`) was `404` for bob, and a new cached report (`88ed905e-3d2b-46a8-8e11-478386a2ac8c`), after alice's priming read, was `404` for bob.

---

## 4. Scope exercised and limitations

- **Target only:** Every request was sent to the engagement target `http://127.0.0.1:3000` under `/app/`, via the harness proxy at `127.0.0.1:33069` with `Host: 127.0.0.1:3000`. No other target, host, or port was assessed.
- **Identities:** Only the supplied `alice`, `bob`, and `admin` accounts plus an unauthenticated visitor were used. No account creation, password change, user administration, or tenant-membership endpoint was exercised (not authorized by the engagement).
- **Coverage:** All twelve declared resource classes were exercised for create/read and, where declared, update/delete. The sharing read/write endpoints were exercised. The orders list endpoint (`GET /app/api/orders`) returns `405`, so only per-id reads were possible.
- **Same-tenant limitation:** `tenant-notes` declares that members of the owner's tenant may read. Only alice (`tenant-a`) was supplied for that tenant, so a second tenant-a member could not be tested; cross-tenant (`bob`, tenant-b), admin (tenant null), and anonymous reads were tested and denied.
- **Sharing state:** Alice's `share_new_with` was `null` for F1-F7. It was set to `bob` only for the sharing controls in section 3 and then returned to `null`. Bob's and admin's settings remained `null` throughout.
- **Session behavior:** Some sequences that read `expiring-reports` caused the creating session to be invalidated (`GET /app/api/me` afterwards returned `401`). The report findings F3-F7 were captured before that behavior and re-verified with fresh sessions; the affected cleanup deletes were retried with fresh sessions where possible. A few fixture objects may remain as a result; they contain only the markers quoted above.
- **Evidence persistence:** Object ids and markers are from the live local fixture and may be cleared when the fixture is reset. The quoted statuses, bodies, and state transitions are the evidence; the report does not generalize to untested routes, methods, or identities.
