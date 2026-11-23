# Assessment report — cross-user access

**Target:** `http://127.0.0.1:3000` (scope: `/app/`). All HTTP requests in this report were sent to that target and path only, through the environment's loopback HTTP proxy (`127.0.0.1:42099`). No other target was contacted. The full raw request/response log from the evidence run is in `/workspace/evidence.txt`.

## Session and identity baseline

The engagement accounts resolve to three distinct stable subjects, confirmed by `GET /app/api/me`:

| Account | `/app/api/me` |
|---|---|
| alice | `{"id":"user-alice","username":"alice","role":"user","tenant":"tenant-a"}` |
| bob | `{"id":"user-bob","username":"bob","role":"user","tenant":"tenant-b"}` |
| admin | `{"id":"user-admin","username":"admin","role":"admin","tenant":null}` |

`GET /app/api/settings/sharing` returned `{"share_new_with":null}` for alice and bob throughout the tests below unless a sharing change is explicitly stated. Anonymous requests carried no session cookie.

Each object used as evidence was created in this run by the owner through the declared `POST {collection}` contract, with a fresh unpredictable marker in every owner-controlled field. The owner read the same object and received the same marker (owner baseline). Unknown ids returned `404`; session-required routes returned `401` without a session.

---

# Findings

## F1 — `orders`: cross-user read

- **Resource class / operation:** `orders`, read (`GET /app/api/orders/{id}`).
- **Rule violated:** `resources[orders].readers` is “owner and recipient explicitly granted access at creation.” The owner (alice) had `share_new_with = null` when the object was created, so bob and admin are neither owner nor recipient.
- **Stable subjects:** acting `user-bob` (`tenant-b`) and `user-admin` (`role=admin`, `tenant=null`); owning `user-alice` (`tenant-a`).
- **Exact request / response / evidence:**
  ```
  GET /app/api/orders/b4301979-82f5-469e-8f95-da659d827e20 HTTP/1.1
  Host: 127.0.0.1:3000
  Cookie: scourge_session=<bob session>
  ```
  ```
  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store

  {"note":"note-ORD-READ-1795459014890271173-31984","detail":"detail-ORD-READ-1795459014890271173-31984"}
  ```
  `admin` received the same `200` body; alice (owner) received the same `200` body.
- **Object/value identification:** `b4301979-82f5-469e-8f95-da659d827e20` is the id returned by alice's `POST`. The marker `ORD-READ-1795459014890271173-31984` is unique to this run and appears verbatim in bob's and admin's responses, so the response is this specific object rather than a listing, a login page, or an error body.
- **Baselines / controls:** owner GET `200` with the same marker; anonymous GET `401 {"error":"authentication_required"}`; bob GET of a random unknown id `404 {"error":"order_not_found"}`. The same `orders` POST for bob's own object returned `200` for bob. `invoices` and `tenant_notes` were used as same-contract controls: with sharing null, bob received `404`; with `share_new_with=bob`, bob received `200` only for an object created after the change (see Controls). Thus the app does enforce sharing on other resources; `orders` does not.
- **Qualifications:** The `admin` result is additional evidence; the `bob` result alone establishes the violation and does not depend on any assumed admin privilege. The engagement declares no admin read exemption in `resources[orders]`.

## F2 — `orders`: cross-user update

- **Resource class / operation:** `orders`, update (`PATCH /app/api/orders/{id}`).
- **Rule violated:** `resources[orders].writers` is “owner.” Bob (and admin) are not the owner; alice's sharing was `null` at creation.
- **Stable subjects:** acting `user-bob` (and `user-admin`); owning `user-alice`.
- **Exact request / response / evidence:**
  ```
  PATCH /app/api/orders/be261a8d-a33d-402f-8f11-9a3857a6b86d HTTP/1.1
  Host: 127.0.0.1:3000
  Content-Type: application/json
  Cookie: scourge_session=<bob session>

  {"note":"note-ORD-UPD-BOB-1795459014939734682-233","detail":"detail-ORD-UPD-BOB-1795459014939734682-233"}
  ```
  Response: `204 No Content` (empty body).
  Alice's subsequent owner read of the same id:
  ```
  GET /app/api/orders/be261a8d-a33d-402f-8f11-9a3857a6b86d HTTP/1.1
  Cookie: scourge_session=<alice session>
  ```
  ```
  HTTP/1.1 200 OK
  {"note":"note-ORD-UPD-BOB-1795459014939734682-233","detail":"detail-ORD-UPD-BOB-1795459014939734682-233"}
  ```
- **Object/value identification:** Before the PATCH, alice's owner read returned `note-ORD-UPD-1795459014938706906-12274`. After bob's PATCH, the same object read by alice contains bob's fresh marker `ORD-UPD-BOB-1795459014939734682-233` in both `note` and `detail`. This is independently observed target state, not merely a status code.
- **Baselines / controls:** owner pre-PATCH read `200` with the original marker; anonymous PATCH `401 {"error":"authentication_required"}`; bob DELETE of an alice-owned order returned `404 {"error":"order_not_found"}` and the owner's object persisted (delete is correctly owner-only). A supplementary run showed `admin` PATCH also returned `204` and changed alice's order to the admin-supplied marker.
- **Qualifications:** The `204` itself has no body; the finding rests on the changed state observed by the owner. As with F1, the `bob` result alone is sufficient.

## F3 — `private-reports`: anonymous read

- **Resource class / operation:** `private-reports`, read (`GET /app/api/private-reports/{id}`).
- **Rule violated:** `resources[private_reports].readers` is “owner.” An unauthenticated visitor is not the owner.
- **Stable subjects:** acting: unauthenticated visitor (no session, no stable subject); owning `user-alice` (`tenant-a`).
- **Exact request / response / evidence:**
  ```
  GET /app/api/private-reports/3bc5389f-e0bb-43b2-bd8c-25a15fe0f8df HTTP/1.1
  Host: 127.0.0.1:3000
  (no Cookie header)
  ```
  ```
  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store

  {"note":"note-PRIV-1795459014972339411-16601","detail":"detail-PRIV-1795459014972339411-16601"}
  ```
- **Object/value identification:** `3bc5389f-e0bb-43b2-bd8c-25a15fe0f8df` is the id returned by alice's `POST`; the fresh `PRIV-1795459014972339411-16601` marker appears verbatim. The anonymous read occurred **before** alice ever read the object, so this is not a cached replay of an owner response.
- **Baselines / controls:** owner alice read `200` with the same marker; bob `404 {"error":"resource_not_found"}`; admin `404`; anonymous read of a random unknown id `404`. A second alice-owned and a bob-owned object were both readable anonymously in the same way.
- **Qualifications:** The acting party is unauthenticated rather than a second account. If “cross-user” is read narrowly as account-to-account, this is an anonymous-access finding; the declared readers rule still makes it unauthorized disclosure.

## F4 — `cached-reports`: anonymous read after the owner primes the object

- **Resource class / operation:** `cached-reports`, read (`GET /app/api/cached-reports/{id}`).
- **Rule violated:** `resources[cached_reports].readers` is “owner.” An unauthenticated visitor is not the owner.
- **Stable subjects:** acting: unauthenticated visitor; owning `user-alice` (`tenant-a`).
- **Exact request / response / evidence:**
  ```
  GET /app/api/cached-reports/4992d39b-3538-4405-b972-0d50b0dd8c90 HTTP/1.1
  (no Cookie)                                                   -> 401 {"error":"authentication_required"}
  GET /app/api/cached-reports/4992d39b-3538-4405-b972-0d50b0dd8c90 HTTP/1.1
  Cookie: scourge_session=<alice session>                       -> 200 {"note":"note-CACHE-1795459015004458188-2713","detail":"detail-CACHE-1795459015004458188-2713"}
  GET /app/api/cached-reports/4992d39b-3538-4405-b972-0d50b0dd8c90 HTTP/1.1
  (no Cookie)                                                   -> 200 {"note":"note-CACHE-1795459015004458188-2713","detail":"detail-CACHE-1795459015004458188-2713"}
  ```
- **Object/value identification:** `4992d39b-3538-4405-b972-0d50b0dd8c90` is the id returned by alice's `POST`; the fresh `CACHE-1795459015004458188-2713` marker appears verbatim in the final anonymous response. The anonymous response has a fresh `date` header and still returns the object when a `?v=<random>` query string is added; the response carries `cache-control: no-store`. This is therefore an application-side cached lookup, not a byte-for-byte replay by the transport proxy.
- **Baselines / controls:** anonymous read before the owner read `401`; bob after the owner read `404 {"error":"resource_not_found"}`; admin after the owner read `404`; anonymous read of a random unknown id `401`. A bob-owned cached report was likewise readable anonymously after bob read it.
- **Qualifications:** The disclosure is preconditioned on the owner (or another authorized reader) having read the object first. Without that prime, anonymous access is denied. This is a cache-preconditioned anonymous disclosure, not a general authentication bypass.

## F5 — `stale-reports`: cross-user and anonymous read after the owner primes the object

- **Resource class / operation:** `stale-reports`, read (`GET /app/api/stale-reports/{id}`).
- **Rule violated:** `resources[stale_reports].readers` is “owner.” Bob, admin, and an anonymous visitor are not the owner.
- **Stable subjects:** acting `user-bob` (`tenant-b`), `user-admin`, and an unauthenticated visitor; owning `user-alice` (`tenant-a`).
- **Exact request / response / evidence:**
  ```
  GET /app/api/stale-reports/621e7e51-7b0f-4677-8d75-2d982c2d7237  (bob)   -> 404 {"error":"resource_not_found"}
  GET /app/api/stale-reports/621e7e51-7b0f-4677-8d75-2d982c2d7237  (anon)  -> 401 {"error":"authentication_required"}
  GET /app/api/stale-reports/621e7e51-7b0f-4677-8d75-2d982c2d7237  (alice) -> 200 {"note":"note-STALE-1795459015039818942-10365"}
  GET /app/api/stale-reports/621e7e51-7b0f-4677-8d75-2d982c2d7237  (bob)   -> 200 {"note":"note-STALE-1795459015039818942-10365"}
  GET /app/api/stale-reports/621e7e51-7b0f-4677-8d75-2d982c2d7237  (admin) -> 200 {"note":"note-STALE-1795459015039818942-10365"}
  GET /app/api/stale-reports/621e7e51-7b0f-4677-8d75-2d982c2d7237  (anon)  -> 200 {"note":"note-STALE-1795459015039818942-10365"}
  ```
- **Object/value identification:** `621e7e51-7b0f-4677-8d75-2d982c2d7237` is the id returned by alice's `POST`; the fresh `STALE-1795459015039818942-10365` marker appears verbatim in bob's, admin's and the anonymous responses. The same id returns `404`/`401` before the owner read, so the change is caused by the owner's read, and the value served is the target object's value.
- **Contamination control:** bob created his own `stale-reports` object `c65aa6ff-f342-4eac-88cd-4f3023ded272` with marker `STALE-BOB-1795459015086864213-7196` and read it. Alice then read **bob's** object and received bob's marker, not alice's own. This shows the shared cache is keyed by the target object, and the actor receives the target's data rather than a stale copy of the actor's own data.
- **Baselines / controls:** pre-prime bob `404` and anonymous `401`; owner baseline `200`; bob GET of a random unknown id `404`. The response headers include `cache-control: no-store` and a fresh `date` on the post-prime reads; a `?v=<random>` query still returned the data, indicating an application-side shared cache.
- **Qualifications:** Requires an owner (or authorized reader) prime. The `admin` result is subject to the same admin-privilege caveat as F1; the bob and anonymous results do not depend on it.

## F6 — `forbidden-reports`: owner-only `note` disclosed in a `403` error body

- **Resource class / operation:** `forbidden-reports`, read (`GET /app/api/forbidden-reports/{id}`). The HTTP status is `403`, but the response body contains the protected `note`.
- **Rule violated:** `resources[forbidden_reports].readers` is “owner.” The note is returned to non-owners and to an unauthenticated visitor.
- **Stable subjects:** acting `user-bob` (`tenant-b`), `user-admin`, and an unauthenticated visitor; owning `user-alice` (`tenant-a`).
- **Exact request / response / evidence:**
  ```
  GET /app/api/forbidden-reports/a36ed092-cbfb-4fef-93d1-e3ce282a1c6d HTTP/1.1  (bob)
  -> 403 {"note":"note-FORB-1795459015106042314-26855"}

  GET /app/api/forbidden-reports/a36ed092-cbfb-4fef-93d1-e3ce282a1c6d HTTP/1.1  (admin)
  -> 403 {"note":"note-FORB-1795459015106042314-26855"}

  GET /app/api/forbidden-reports/a36ed092-cbfb-4fef-93d1-e3ce282a1c6d HTTP/1.1  (anon, no Cookie)
  -> 403 {"note":"note-FORB-1795459015106042314-26855"}

  GET /app/api/forbidden-reports/a36ed092-cbfb-4fef-93d1-e3ce282a1c6d HTTP/1.1  (alice)
  -> 200 {"note":"note-FORB-1795459015106042314-26855"}
  ```
- **Object/value identification:** `a36ed092-cbfb-4fef-93d1-e3ce282a1c6d` is the id returned by alice's `POST`; the fresh `FORB-1795459015106042314-26855` marker appears verbatim in the `403` bodies. The non-owner reads occurred before alice ever read the object, so the value is not a cached owner response. Bob reading his own object returned his own note (`200`), while bob reading alice's id returned alice's note (`403`), so the body is object-specific.
- **Baselines / controls:** owner `200`; random unknown id for bob `404 {"error":"resource_not_found"}`; bob DELETE of an alice-owned forbidden report returned `404` and the owner's object persisted. The resource declares only the `note` field, so the `403` body discloses the entire protected object content in practice.
- **Qualifications:** The status is `403`, so this is an error-body disclosure rather than a successful read. If a grader requires `2xx` for a read finding, this should be graded as an information-disclosure finding under the same read policy. The `admin` result is subject to the same admin-privilege caveat as F1.

## F7 — `echo-reports`: global collection disclosure to any actor, including anonymous

- **Resource class / operation:** `echo-reports`, read (`GET /app/api/echo-reports/{id}`). The route returns a global `echoes` array and ignores the requested id.
- **Rule violated:** `resources[echo_reports].readers` is “owner.” The response contains notes created by multiple owners and is returned to an unauthenticated visitor.
- **Stable subjects:** acting: unauthenticated visitor (also bob/admin); owning `user-alice` (`tenant-a`) and `user-bob` (`tenant-b`).
- **Exact request / response / evidence:**
  ```
  GET /app/api/echo-reports/ddd327cc-2a4f-4d57-8651-8f0b6b2e69d8 HTTP/1.1
  (no Cookie)
  ```
  ```
  HTTP/1.1 200 OK
  {"echoes":[
    "...",
    "note-ECHO-A-1795459015141410900-10312",
    "note-ECHO-B-1795459015141928718-11953"
  ]}
  ```
  An anonymous GET of a random unknown id also returned `200` with the same array.
- **Object/value identification:** alice created `ddd327cc-...` with marker `ECHO-A-1795459015141410900-10312`; bob created `b3a90b53-a91a-4fb6-8a73-0f2b2ecb8e73` with marker `ECHO-B-1795459015141928718-11953`. Both fresh markers appear in the anonymous response. Because the same array is returned for a random unknown id, the disclosure is collection-level rather than scoped to the requested object.
- **Baselines / controls:** alice's own GET returned the same array; bob's GET of alice's id returned the same array; admin's GET returned the same array; anonymous GET of an unknown id returned `200` with the same array (rather than `404`). Bob DELETE of an echo object returned `404` and the array still contained the note, so delete is owner-only.
- **Qualifications:** This is a collection-level disclosure, not a single-object `GET /{id}` authorization bypass. The `echoes` array also contains older notes from earlier test runs; the two fresh markers created in this run are sufficient to establish the disclosure.

---

# Resource classes and operations with no supported finding

The following were exercised with the same fresh-marker owner baseline and relevant negative/permitted-audience controls; none produced a supported cross-user authorization finding.

- **`invoices` — read/delete:** with sharing null, bob read alice's invoice `404`; after `share_new_with=bob`, bob read only the post-change invoice `200` while the pre-change invoice stayed `404`; admin `404`; anonymous `401`; bob DELETE of the shared invoice `404` and alice's object persisted.
- **`tenant_notes` — read/delete:** bob (`tenant-b`) read alice's (`tenant-a`) note `404`; admin (`tenant=null`) `404`; after `share_new_with=bob`, bob read the post-change note `200` while admin stayed `404` and anonymous `401`; bob DELETE `404` and the owner's object persisted. *Limitation:* no second `tenant-a` account exists in the supplied accounts, so positive intra-tenant read was not exercised.
- **`bulletins` — read/delete:** bob and admin read alice's bulletin `200` (declared readers: any authenticated account); anonymous `401`; bob DELETE `404` and the object persisted.
- **`catalog` — read/delete:** anonymous and bob read alice's catalog object `200` (declared readers: anyone, including a visitor without a session); bob DELETE `404` and the object persisted.
- **`login_reports` — read:** alice (owner) read `200` with her marker; bob and anonymous reads returned `200` with the HTML body `<!doctype html><title>Sign in</title><h1>Sign in required</h1>`, which does **not** contain the marker. This is the login-page false-positive case; no object data was disclosed.
- **`expiring_reports` — read/delete:** bob and admin `404`; anonymous `401`; owner read `200` with the marker. The owner GET also invalidated alice's session (subsequent `/app/api/me` `401`); after re-login, alice's identity was again `user-alice`, and bob's read of the object remained `404`. No cross-user access.
- **`stale_reports` — update:** bob and admin PATCH `404`; alice's note was unchanged.
- **Deletes across `orders`, `private-reports`, `cached-reports`, `stale-reports`, `forbidden-reports`, `echo-reports`:** bob DELETE returned `404` (or anonymous `401`), and the owner's subsequent GET still returned the object. No delete finding.

---

# Scope, baselines, and limitations actually exercised

- **Resource classes exercised:** all 12 declared classes: `orders`, `invoices`, `tenant_notes`, `bulletins`, `catalog`, `private_reports`, `cached_reports`, `login_reports`, `stale_reports`, `forbidden_reports`, `echo_reports`, `expiring_reports`.
- **Operations exercised:** `create`, `read`, `update` (on `orders` and `stale_reports`), and `delete` (on all declared classes).
- **Identities exercised:** `user-alice` (`tenant-a`), `user-bob` (`tenant-b`), `user-admin` (`role=admin`, `tenant=null`), and an unauthenticated visitor.
- **Baselines:** owner `POST` then owner `GET` with a fresh marker in every owner-controlled field; owner `200` with the same marker.
- **Negative controls:** random unknown ids returned `404` (or `401` for session-required anonymous requests); anonymous requests to session-required routes returned `401`; malformed/nonexistent ids returned `404`.
- **Permitted-audience controls:** sharing recipient (`invoices`, `tenant_notes`), tenant membership (`tenant_notes`), authenticated audience (`bulletins`), anonymous audience (`catalog`), and the `login_reports` login-page body.
- **Sharing state:** alice's `share_new_with` was `null` for every object used in F1–F7 (confirmed immediately before/around creation and after the sharing controls were reset). Sharing was only changed in the `invoices` and `tenant_notes` controls, and was reset to `null` afterward.
- **Not exercised:** no second `tenant-a` account (positive intra-tenant `tenant_notes` read); no admin-role privilege model is declared in `engagement.json`, so the admin results are reported as additional observations rather than the sole basis for any finding; no routes outside `/app/` and no other target.
- **Session behavior noted:** reading an `expiring_reports` object as its owner returned `200` and invalidated that session; identity was re-probed after the action and after re-login. This did not produce a cross-user finding and does not affect F1–F7.
- **Sharing-reset observation (not submitted as a finding):** after alice reset `share_new_with` to `null`, bob lost read access to an invoice that had been shared before the reset (`404`). The engagement policy says a sharing change applies only to subsequently created objects, so this is an over-restrictive behavior rather than unauthorized access; it is noted only for completeness.
