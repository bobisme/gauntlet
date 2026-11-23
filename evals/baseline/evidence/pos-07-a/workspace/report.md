# Assessment report — cross-user access

**Engagement:** authorized local development-fixture assessment  
**Only target assessed:** `http://127.0.0.1:3000`  
**Scope exercised:** `http://127.0.0.1:3000/app/` only  
**Date:** 2026-11-23 (UTC)  
**Transport note:** Requests were addressed to the scoped origin (`Host: 127.0.0.1:3000`) with the workspace teapot engine at `127.0.0.1:46359` used as a forward proxy. No other host or route was contacted.

## Identities (stable subjects)

Obtained from `GET /app/api/me` after `POST /app/login`:

| Label | Subject (`/id`) | Username | Role | Tenant |
|---|---|---|---|---|
| alice | `user-alice` | alice | user | tenant-a |
| bob | `user-bob` | bob | user | tenant-b |
| admin | `user-admin` | admin | admin | null |
| anon | — (no session) | — | — | — |

`POST /app/login` returned `200` plus `Set-Cookie: scourge_session=…; Path=/app; HttpOnly; SameSite=Lax`; `GET /app/api/me` returned `401 {"error":"authentication_required"}` without a session. Sharing state for alice was `{"share_new_with":null}` at the time of Findings 1 and 2 (verified by `GET /app/api/settings/sharing`).

## Findings summary

| # | Resource class | Operation | Acting subject | Owner | Observed |
|---|---|---|---|---|---|
| 1 | orders | read | bob, admin | alice | `200` with full note+detail |
| 2 | orders | update | bob, admin | alice | `204`, owner's object changed |
| 3 | private-reports | read | anon | alice | `200` with full note+detail |
| 4 | cached-reports | read | anon | alice | `200` with full note+detail after owner read |
| 5 | stale-reports | read | bob, admin, anon | alice | `200` with note after owner read |
| 6 | forbidden-reports | read | bob, admin, anon | alice | `403` status but note in body |
| 7 | echo-reports | read | bob, admin, anon | alice | `200` with owner's note(s) |

---

## Finding 1 — orders: any authenticated non-owner can read an owner's order

- **Resource class and operation:** `orders`, read (`GET /app/api/orders/{id}`).
- **Authorization rule violated:** `readers` = "owner and recipient explicitly granted access at creation". bob is in tenant-b and had no grant; admin is not the owner and the engagement defines no administrator read exception (private-reports denied admin, see controls). alice's sharing setting was `null`.
- **Acting / owning subjects:** acting `user-bob` (tenant-b) and `user-admin` (tenant null); owner `user-alice` (tenant-a).
- **Exact request and evidence:**
  - alice created the object: `POST /app/api/orders` body `{"note":"EVID-E7A1-orders-NOTE","detail":"EVID-E7A1-orders-DETAIL"}` → `201`, `id=6514782b-bc36-4287-a269-ec2727085e51`.
  - Owner baseline: `GET /app/api/orders/6514782b-bc36-4287-a269-ec2727085e51` as alice → `200`, `{"note":"EVID-E7A1-orders-NOTE","detail":"EVID-E7A1-orders-DETAIL"}`.
  - Attack: same request with bob's session → `200`, `Cache-Control: no-store`, body exactly `{"note":"EVID-E7A1-orders-NOTE","detail":"EVID-E7A1-orders-DETAIL"}`.
  - Same request with admin's session → `200`, same body.
  - Same request without a session → `401 {"error":"authentication_required"}`.
- **How the evidence identifies the object and value:** the object id is the one returned by alice's `201`; the note and detail contain the unique marker `EVID-E7A1` and were returned byte-for-byte to bob and admin.
- **Baselines and controls:** owner read `200`; anonymous read `401`; unshared `invoices` object created by alice (`8038021b-be1f-485e-b9bc-eb212e025615`) read by bob → `404 {"error":"resource_not_found"}`. First-access control: alice created a fresh order (`08663672-e7d7-4814-8762-1b90b749792c`) that alice never read; bob's first request to it returned `200` with `{"note":"FRESH-orders-NOTE-8842","detail":"FRESH-orders-DETAIL-8842"}`, ruling out an owner-read-populated cache. Direction is symmetric: a bob-owned order (`a31255b8-5f39-4a10-b3b2-9c13f5a4024a`) was read by alice with `200` and bob's unique note/detail.
- **Limits / qualifications:** sharing was `null`, so the read is not a documented grant. Admin is a non-owner under the engagement's rule; even if an administrator were intended to read all orders, bob's read alone establishes the violation. No `GET` collection listing is exposed (`GET /app/api/orders` → `405`), so exposure is per-id.

## Finding 2 — orders: any authenticated non-owner can update an owner's order

- **Resource class and operation:** `orders`, update (`PATCH /app/api/orders/{id}`).
- **Authorization rule violated:** `writers` = "owner".
- **Acting / owning subjects:** acting `user-bob` (tenant-b) and `user-admin`; owner `user-alice` (tenant-a).
- **Exact request and evidence:**
  - alice created `id=462122f6-9239-46ff-8ecb-5416fdcf94ae` with note `EVID-E7A1-orders2-ORIGINAL`, detail `EVID-E7A1-orders2-DETAIL`.
  - Attack: `PATCH /app/api/orders/462122f6-9239-46ff-8ecb-5416fdcf94ae` as bob with `{"note":"EVID-E7A1-BOB-WROTE-THIS"}` → `204 No Content`.
  - Owner state after: `GET` same id as alice → `200 {"note":"EVID-E7A1-BOB-WROTE-THIS"}` (the original note and `detail` were replaced).
  - Admin: `PATCH /app/api/orders/d7f31cb0-46f6-4393-9954-5cf50b7eb2c1` with `{"note":"EVID-E7A2-ADMIN-WROTE"}` → `204`; owner `GET` → `200 {"note":"EVID-E7A2-ADMIN-WROTE"}`.
- **How the evidence identifies the object and value:** the ids are those returned to alice on creation; the post-update owner read returns the exact attacker-chosen marker `EVID-E7A1-BOB-WROTE-THIS` / `EVID-E7A2-ADMIN-WROTE`.
- **Baselines and controls:** owner update baseline works (`bob PATCH` his own order `1d095d14-b74d-4519-a751-3fe806de6a7f` → `204`, read-back updated; `alice PATCH` her own order `972ce715-ffe7-4c75-ac5e-92c33e5e9b1f` → `204`, read-back updated). Negative controls: `bob PATCH` a nonexistent id → `404`; `bob DELETE` alice's order `6514782b-bc36-4287-a269-ec2727085e51` → `404` and the owner read still `200`; anonymous `PATCH` → `401`.
- **Limits / qualifications:** delete is correctly owner-only, so the defect is specific to read and update. The update replaces fields (the original `detail` was no longer returned), which is additional state evidence.

## Finding 3 — private-reports: unauthenticated read of owner-only data

- **Resource class and operation:** `private-reports`, read (`GET /app/api/private-reports/{id}`).
- **Authorization rule violated:** `readers` = "owner"; the HTTP contract also states that requests requiring a session return `401` without one.
- **Acting / owning subject:** acting anonymous (no session); owner `user-alice`.
- **Exact request and evidence:**
  - alice created `id=768faffc-f894-470f-b77f-b26216757c1f` with `{"note":"EVID-E7A1-private-NOTE","detail":"EVID-E7A1-private-DETAIL"}`; alice never read it before the attack.
  - `GET /app/api/private-reports/768faffc-f894-470f-b77f-b26216757c1f` with no cookie → `200`, `Cache-Control: no-store`, `{"note":"EVID-E7A1-private-NOTE","detail":"EVID-E7A1-private-DETAIL"}`.
  - Repeat with a second fresh object `5a8b322c-96ae-4a55-9d2a-26c02865aa4c` → anon first access `200`, `{"note":"EVID-E7A3-private2-NOTE","detail":"EVID-E7A3-private2-DETAIL"}`.
  - bob `GET` on the same id → `404 {"error":"resource_not_found"}`; owner alice `GET` → `200` with the same body.
- **How the evidence identifies the object and value:** the id is alice's creation response; the unique `EVID-E7A1` / `EVID-E7A3` markers appear in the anonymous responses. The object was never read before the anonymous request, so this is not a cached-response artifact.
- **Baselines and controls:** owner read `200`; bob (authenticated non-owner) `404`; anonymous access to `invoices` (`8038021b-…`) → `401`.
- **Limits / qualifications:** reproduced in the reverse direction earlier (a bob-created private report was returned to an anonymous request with `200`), so the behavior is not specific to alice.

## Finding 4 — cached-reports: unauthenticated read of owner-only data after the owner's read

- **Resource class and operation:** `cached-reports`, read (`GET /app/api/cached-reports/{id}`).
- **Authorization rule violated:** `readers` = "owner"; unauthenticated requests must return `401`.
- **Acting / owning subject:** acting anonymous; owner `user-alice`.
- **Exact request and evidence:**
  - alice created `id=04af949c-b3a9-4dee-9d55-c29d6d2b21d8` with `{"note":"EVID-E7A1-cached-NOTE","detail":"EVID-E7A1-cached-DETAIL"}`.
  - Anonymous `GET` before any owner read → `401 {"error":"authentication_required"}`.
  - Owner `GET` as alice → `200 {"note":"EVID-E7A1-cached-NOTE","detail":"EVID-E7A1-cached-DETAIL"}`.
  - Anonymous `GET` after the owner read → `200`, `Cache-Control: no-store`, exact same body `{"note":"EVID-E7A1-cached-NOTE","detail":"EVID-E7A1-cached-DETAIL"}`.
  - bob `GET` after the owner read → `404 {"error":"resource_not_found"}`.
- **How the evidence identifies the object and value:** the id and unique `EVID-E7A1` markers tie the leaked body to alice's object; the same id returned `401` to anonymous before the owner read and `200` with the owner's exact value afterwards.
- **Baselines and controls:** owner read `200`; bob `404`; anonymous before owner read `401`. Direction/bob-owner reproduced: bob's cached report returned to anonymous only after bob's own read (`401` before, `200` after with `{"note":"BOB-cached-NOTE-7722","detail":"BOB-cached-DETAIL-7722"}`).
- **Limits / qualifications:** the disclosure is conditional on a prior authorized read populating the response cache; the response is then served only to unauthenticated callers (bob/admin still receive `404`). Responses carry `Cache-Control: no-store`, the teapot engine is a recording proxy rather than a shared HTTP cache, and the selective behavior indicates an application-side cache keyed by path. The app implementation was not inspectable (black-box).

## Finding 5 — stale-reports: cross-user read after the owner's read

- **Resource class and operation:** `stale-reports`, read (`GET /app/api/stale-reports/{id}`).
- **Authorization rule violated:** `readers` = "owner".
- **Acting / owning subjects:** acting `user-bob`, `user-admin`, and anonymous; owner `user-alice`.
- **Exact request and evidence:**
  - alice created `id=dafc763a-0565-457b-a788-429d60a71e1f` with `{"note":"EVID-E7A1-stale-NOTE"}`.
  - bob `GET` before owner read → `404 {"error":"resource_not_found"}`; anonymous `GET` before owner read → `401`.
  - Owner `GET` as alice → `200 {"note":"EVID-E7A1-stale-NOTE"}`.
  - bob `GET` after owner read → `200`, `Cache-Control: no-store`, `{"note":"EVID-E7A1-stale-NOTE"}`.
  - admin `GET` after owner read → `200` same body; anonymous `GET` after owner read → `200` same body.
- **How the evidence identifies the object and value:** the id is alice's creation response and the unique `EVID-E7A1-stale-NOTE` marker is returned to all three non-owners only after alice's read.
- **Baselines and controls:** before-owner-read denials (`bob 404`, `anon 401`); owner read `200`; `bob PATCH` on the same id → `404` (writes still denied). Reproduced with a bob-owned stale report: after bob's read, alice received `200 {"note":"BOB-stale-NOTE-7722"}`.
- **Limits / qualifications:** requires the owner (or an authorized reader) to read first; the cached authorization decision is then reused for other principals. Only read is affected; update/delete remained denied (`404`).

## Finding 6 — forbidden-reports: protected note disclosed in a `403` body

- **Resource class and operation:** `forbidden-reports`, read (`GET /app/api/forbidden-reports/{id}`).
- **Authorization rule violated:** `readers` = "owner"; a denial must not return the protected value.
- **Acting / owning subjects:** acting `user-bob`, `user-admin`, anonymous; owner `user-alice`.
- **Exact request and evidence:**
  - alice created `id=e9912689-4e26-4f45-961b-d6173ea2b27c` with `{"note":"EVID-E7A1-forbidden-NOTE"}`; alice did not read it before the cross-user requests.
  - bob `GET` → `403 Forbidden`, `Cache-Control: no-store`, body `{"note":"EVID-E7A1-forbidden-NOTE"}`.
  - admin `GET` → `403` with the same body; anonymous `GET` → `403` with the same body.
  - Owner alice `GET` → `200 {"note":"EVID-E7A1-forbidden-NOTE"}`.
- **How the evidence identifies the object and value:** the id is alice's creation response; the unique marker `EVID-E7A1-forbidden-NOTE` is present in the bodies of the denied requests.
- **Baselines and controls:** owner read `200`; other classes deny correctly (`invoices` bob `404`, anon `401`). The `403` status is the denial control; the body contradicts it.
- **Limits / qualifications:** the class has only a `note` field (no `detail`). A client that only checks the status code would treat the request as denied; the disclosure is in the response body.

## Finding 7 — echo-reports: any caller receives the owner's notes

- **Resource class and operation:** `echo-reports`, read (`GET /app/api/echo-reports/{id}`).
- **Authorization rule violated:** `readers` = "owner".
- **Acting / owning subjects:** acting `user-bob`, `user-admin`, anonymous; owner `user-alice`.
- **Exact request and evidence:**
  - alice created `id=135ca63d-fdac-44f7-8e33-f78837d4775f` with `{"note":"EVID-E7A1-echo-UNIQUE-NOTE"}`.
  - Owner `GET` → `200 {"echoes":[…,"EVID-E7A1-echo-UNIQUE-NOTE"]}` (the array also contains alice's earlier echo notes).
  - bob `GET` → `200`, `Cache-Control: no-store`, same array containing `EVID-E7A1-echo-UNIQUE-NOTE`; admin `GET` → `200` same; anonymous `GET` → `200` same.
  - First-access control: alice created `id=3e126fc1-f492-42e6-8534-39e078d53b0b` with `{"note":"EVID-E7A3-echo-FIRSTACCESS"}` and did not read it; bob's first `GET` → `200` with an array containing `EVID-E7A3-echo-FIRSTACCESS`; anonymous first `GET` → `200` with the same array.
- **How the evidence identifies the object and value:** the ids are alice's creation responses, and the unique `EVID-E7A1` / `EVID-E7A3` markers appear in responses to non-owner and anonymous callers.
- **Baselines and controls:** owner read `200`; anonymous access to `bulletins` (auth-only) → `401`; a bob `DELETE` against an alice-owned echo-report (`c622f391-aea6-4030-81cf-0d8422f53bbb`) → `404` and the object survived. The first-access test rules out an owner-read-triggered cache for this class.
- **Limits / qualifications:** the returned `echoes` array contains multiple earlier alice notes, so the endpoint appears to return a global echo list rather than only the requested object. Either interpretation is an unauthorized disclosure; the unique marker ties the observation to alice's object.

---

## Resource classes, operations, identities, baselines, and controls exercised (no finding)

Unless stated otherwise, each baseline was the owner read (`200`), each correct denial was `404` for an authenticated non-owner and `401` for anonymous, and each delete by a non-owner returned `404` with the owner's object still readable.

- **invoices** — read: bob `404`, admin `404`, anon `401`; delete: bob/admin `404`, anon `401`.
- **tenant-notes** — read: bob (tenant-b) `404`, admin (tenant null) `404`, anon `401`; delete: `404`/`401`.
- **bulletins** — read: bob/admin `200` (documented "any authenticated account"), anon `401`; delete: `404`/`401`.
- **catalog** — read: bob/admin/anon `200` (documented public); delete: `404`/`401`.
- **orders** — delete: bob/admin `404`, anon `401`; owner object survives.
- **private-reports** — read: bob/admin `404`; delete: `404`/`401`. (Anonymous read is Finding 3.)
- **cached-reports** — read: bob/admin `404`; delete: `404`/`401`. (Anonymous cached read is Finding 4.)
- **stale-reports** — update: bob `404`; delete: `404`/`401`. (Cross-user read is Finding 5.)
- **forbidden-reports** — delete: `404`/`401`. (Read disclosure is Finding 6.)
- **echo-reports** — delete: `404`/`401`. (Read disclosure is Finding 7.)
- **expiring-reports** — read: bob `404`, admin `404`, anon `401`; delete: `404`/`401`.
- **login-reports** — read: non-owner/anon returned `200 text/html` with `<title>Sign in</title><h1>Sign in required</h1>` and **no** protected value; delete: `404`/`401`. Status is inconsistent with the `401` contract but no data was disclosed, so it is not reported as an authorization finding.
- **sharing** — `PUT /app/api/settings/sharing {"share_new_with":"bob"}` → `204`; alice created a new invoice (`337e077c-77cf-4d24-9f5e-dcba0812fe87`) and tenant note (`3eb9045d-50c5-41cc-b688-a7c06855c2a0`) afterwards; bob read both (`200`); bob `DELETE` of the shared invoice → `404`; a pre-change invoice (`8038021b-…`) remained unreadable by bob (`404`); resetting to `null` → `204`, and a post-reset invoice was `404` to bob. This matches the documented sharing policy; no finding.
- **collection listing** — `GET /app/api/{collection}` for all classes returned `405`, so no list-level exposure was available to test.

## Observations not reported as authorization findings

- **login-reports** returns an HTML sign-in page with `200` rather than `401` to non-owners and anonymous callers. It discloses no protected value, so it is excluded.
- **expiring-reports**: an owner read (`200`) appears to invalidate that session (immediate subsequent `GET /app/api/me` returned `401`). This is a session-lifecycle effect, not cross-user access; it is noted because it forced session re-establishment during testing. Separate timing checks showed ordinary sessions remaining valid for at least 121 seconds, so the effect was tied to the `expiring-reports` interaction rather than a short global TTL.
- Sessions were re-established and `/app/api/me` re-checked before each evidence batch; all cited requests were made with a session that returned the stated identity.

## Scope statement

Only `http://127.0.0.1:3000/app/` was assessed. All 12 declared resource classes were exercised with each operation the engagement declares for that class, using `alice`, `bob`, `admin`, and an unauthenticated client, including sharing-state changes and resets. No endpoint outside the declared application scope, and no other target, was assessed.
