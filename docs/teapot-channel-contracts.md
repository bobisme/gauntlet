# Teapot send channel observations

Run `python3 scripts/channel-contracts.py --binary /absolute/path/to/teapot`.
The harness checks the source commit and binary SHA-256 in the existing contract
manifest before starting an isolated project, proxy, and HTTP server on loopback.
The observed binary was built from Teapot `6238d5a78a6514466d54ad16dd5737f43c1d4961`,
SHA-256 `6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458`.
It is the same source-pinned build as the other contracts, not the moving
`.stack-target` executable. The engine is stopped in a finally block.

At that pin, with the exact commands and markers in the harness:

| Case | Observed result |
|---|---|
| Response `replace` rule, `original` to `replaced` | A control sent through the proxy returned `replaced`; `requests send` stored base64 `b3JpZ2luYWw=` (`original`), whole response. |
| Intercept enabled with one active in-scope rule | `requests send` completed with HTTP 200 and zero paused; this check has no positive proxy-intercept control. |
| Lua request hook setting `X-Hook: yes` | Independently loaded and running; a proxy control reached the server with the header, while `requests send` reached it without the header. |
| Lua response hook setting `X-Hook: yes` | Independently loaded and running; the proxy control returned the header, while the stored response from `requests send` had no such header. |

For a configured `status:401` logged-out rule and a one-step `GET /login`
macro that returns 200 without changing the expired state, the server recorded
these method/path sequences (ephemeral port omitted):

* Ordinary session POST: `POST /expired-post`, `GET /login`. Relogin reported
  `ran: true`, `retried: false`, `not_retried: "state-changing"`, and
  `paused: false`. The write was sent once.
* A fresh session GET: `GET /expired-get`, `GET /login`, `GET /expired-get`.
  Relogin reported `ran: true`, `retried: true`, `paused: true`, and
  `reason: "logged-out-again"`. The second 401 pauses the session.

Each session request had an empty body and no `X-Hook` at the server. Flow and job
IDs, ephemeral ports, timings, paths and process metadata are run-specific;
the harness prints the full relogin objects and request records on each run.
One unmodified harness output is saved in
[`channel-observed.txt`](../fixtures/contracts/channel-observed.txt); its flow
and job IDs are specific to that run.
This ordinary synchronous send test does not test uncertain transport outcomes
or job retry policies. At the pinned source, `sessions/sender.rs` describes the
separate opt-in `retry_unknown_once` behavior and restricts it to GET/HEAD;
`crawl/http/mod.rs` opts into it for GET. Those are source observations,
not exercised here, and do not establish that every job avoids other retries.

No tested edit reached `requests send`. This is limited to these specific
configured edits and is not proof of atomic edit-surface isolation. The verifier
must still read the edit surface on every run (INV-49); no bypass guarantee is
established. The intercept case shows active configuration and completion, but
its lack of an intercept positive control limits that case.
