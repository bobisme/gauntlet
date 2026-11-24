# Teapot instrument contract

This is the M0.1 observation for plan §7.2, not a promise that the verifier's
requirements are met. The machine-readable argument, result and error schemas
are captured under [`fixtures/contracts`](../fixtures/contracts/); their
`schema-*.json` files are verbatim `teapot schema ... --json` envelopes. Each
other JSON file records a real invocation, argv excluding the executable, exit
code and unmodified JSON output. Values such as ports, process IDs and paths
are specific to that capture. All target traffic was to a temporary loopback
HTTP server; the project and engine were isolated and the engine was stopped.

The [inventory](inventory.json) is a historical snapshot: its Teapot checkout
HEAD is source evidence, and its installed digest identifies different bytes.
The installed binary reported no commit, and those bytes were no longer present
when these captures were made. The contract manifest identifies a separate
clean, locked offline build from the exact recorded Git object, not a claim
about the provenance of that historical binary. A build digest is specific to
its toolchain and source export path. The capture harness refuses a binary
whose digest or inventory source pin differs from the manifest.

Each command below is an argv array after the binary, with `P` the project
directory and placeholders each representing one argument. JSON is requested
with `--json`; `advice` accompanies each top-level result. Schemas, rather than
examples below, are the complete output-shape reference.

| Operation | Exact argv and principal JSON result |
|---|---|
| Describe | `--project P --json version` → `version` including `answered_by`, `protocol`, `commit`, and `engine` with `instance`, `project_id`, `enforced`, `policy_locked`; `--project P --json proxy status` → `proxy.engine` and `proxy.health`. Require `answered_by: engine` and match the instance; the CLI alone can answer when no engine is running. |
| Check session | `--project P --json sessions check NAME --url URL` → `check.state`, `reason`, `session_flow`, `anon_flow`, `units`. It sends two requests, not a passive identity test. The captured fixture has `unknown` and `no-rule`; logged-in is not an identity assertion. |
| Send | `--project P --json requests send METHOD URL --session NAME` → `sent.flow` (nullable), `sent.hops[]` with flow, outcome and status, plus `relogin` and `csrf`. Add repeated `--header VALUE`, `--body VALUE`, `--set VALUE`, or `--follow N` only as needed. The success fixture uses a single GET. |
| Multi-step plant | `--project P --json --yes macros run NAME --session NAME` → `run.job`, `outcome`, `steps[]` with each `flow`, and `units`. `--until N` bounds steps. The fixture actually executes a two-step macro. `--project P --json --yes flows replay --macro NAME --step N --session NAME --set EDIT` runs preceding macro steps then replays the selected step with edits; its schema is captured, but that variant was not run here. |
| Read flow | `--project P --json flows show ID --base64 --stored` → `flow` with heads, body base64 and `*_body_info`, state, URL and timing. Bodies are windowed (default 32768, maximum 1048576 per call); use `--offset N --max-body N` and inspect completeness. Captured heads are rendered strings, not proof of original wire bytes. |
| Dry run | `--project P --json macros run NAME --session NAME --dry-run` → `run.units`, `units_left`, `steps`, `dry_run`; `requests send ... --dry-run` instead describes scope and explicitly does not consult the pass. `authz compare ... --sessions NAMES --dry-run` offers its own count and ceiling comparison; it is not a general recipe planner. |
| Units left | `--project P --json pass show` → `pass.ceilings[]` with request `spent`, `left`, `unused` when a ceiling exists. Captured result is unbound with an empty array: it does not demonstrate a pass counter. |
| List jobs | `--project P --json jobs list --limit N` → `jobs[]`, bounded to 1000; use `--before ID` to page. Records include state, times, sent, units, reason and live. |
| Cancel | `--project P --json jobs stop ID` → `stopped.jobs[]`; observe again via jobs list. The capture uses `--all` with no running jobs; it does not establish in-flight cancellation. Ordinary synchronous request sends are not necessarily jobs and no per-send cancellation is established. |
| Edit surface | `--project P --json rules list`, `intercept status`, `intercept rules list`, `scripts list`, `sessions show NAME`, `config list` → respectively `rules`, `intercept`, `rules`, `scripts`, `session`, `settings`. Capture all at start and end, and investigate script hooks, CSRF and relogin; these reads alone do not prove no transformation occurred between snapshots. No bypass mode was established. |

On successful send the returned integer `sent.flow` is the usable lookup, and
each hop supplies a flow where captured; macro steps return their own IDs.
The API also makes flow nullable. This is not a caller-supplied durable
idempotency or correlation key: if the process loses its reply, the returned ID
cannot be relied on. `@last` or searching history cannot safely attribute a send
under concurrency. Unknown outcomes and missing capture require reconciliation;
do not retry a state-changing send as though it was absent. The capture does
not establish complete original HTTP wire bytes, a per-request ledger receipt,
or atomic edit-surface isolation. See [stack facts](stack-facts.md) for the
source-level accounting and pipeline qualifications. No evidence here qualifies
enforcement, pass limits, interrupted sends, concurrency or cancellation.

To reproduce, export the commit recorded in `fixtures/contracts/manifest.json`
and build Teapot with its lockfile offline. Run `python3 scripts/teapot-contracts.py
--binary /absolute/path/to/teapot` for schema equality and focused semantic checks;
`--capture` replaces the recorded fixtures. A different build digest is refused,
even if built from the same commit. The check is not a full JSON Schema validator
or M1.3 integration suite.

## Scourge invocation conformance

Run `SCOURGE_PINNED_TEAPOT=/absolute/path/to/teapot cargo test -p scourge-core
--test teapot_invocation --locked -- --ignored` with the binary from the
contract manifest. Use a short `TMPDIR` to leave room for Teapot's Unix
socket path. The test uses a disposable project, explicit Teapot directory
environment and an owned loopback HTTP fixture. It checks the captured
operations and both dry-run variants, including the `--before` jobs cursor.

Passive calls sent zero target requests. The explicit session check sent a
session probe and an anonymous control. The fixture checks that both omit
cookie, authorization, proxy-authorization and API-key headers. A bound-instance
mismatch prevented the session check from running. The test covers the live
unbound-pass result. Regular Rust tests cover missing executables, inconsistent
job pagination, subprocess cleanup and native or wrapper errors independently
of that pin.

`scourge_core::teapot` checks the bound project, instance and enforcement
state across separate native invocations. The CLI selects the engine from
the current project lock at each connection. It has no argument for an
expected instance, so the surrounding checks can detect observed changes
without making instance selection atomic with a session probe.

On Linux, each local subprocess has 120 seconds to exit and close both
output pipes. The transport drains both pipes together and caps each at
16 MiB plus one newline, enough for Teapot's maximum server frame rendered
as compact JSON. It discards capture on deadline or overflow, stops the
subprocess group and reaps the direct child. Operator-bound wrappers must
keep their helpers in the subprocess group. A deadline is
`TRANSPORT_UNAVAILABLE` and output overflow is `INVALID_NATIVE_OUTPUT`.
Both return `DEPENDENCY_UNAVAILABLE` with a redacted diagnostic that preserves
any observed native or wrapper exit. Timing out locally leaves engine-side
session probe dispatch unconfirmed.

## Accounting observations

`Teapot::begin_accounting` takes the declared run ID, request key, approved
pass ID and digest, and resolved absolute pass file. It reads one bounded
native jobs page, `pass show`, and the optional macro dry run.
`AccountingCapture::finish` takes new pass and jobs observations through the
same binding. Each read is bracketed by version probes for the configured
engine, project and pass file. The pass reads also check the approved digest,
pass state, lock and enforcement. These are separate observations. Teapot's
argv does not atomically pin an engine or establish what happened between
reads. A changed pass, observed instance change, decreasing spent counter,
increasing remaining counter, or changed counter ceiling fails closed.

The finished observation contains the frozen `scourge.accounting.v1` record
and its artifact originals. Each artifact carries the command phase, observed
time window, native and wrapper exit status, exact stdout bytes and their
SHA-256. The caller owns persistent evidence storage and the operation between
the snapshots. Partial artifacts stay available when a later read fails.
Native command failures retain the adapter's structured, redacted diagnostic.
A native count outside the immutable record's exact integer range keeps its
original artifact and refuses projection into the record.

`pass show` gives pass-level spent, left and unused values. Each missing
endpoint or individual value remains null, and continuity checks compare
only pairs of observed values. The macro estimate is the requested count,
and its reported `units_left` supplies the nullable dry-run ceiling. The
adapter's comparison is an estimate at observation time, with neither a
reservation nor a guarantee of admission. The preflight API returns
`BUDGET_REFUSED` for an estimate above the observed macro ceiling and
`ACCOUNTING_UNESTABLISHED` when capacity cannot be established or the caller
requires exact per-run costs.

The bounded job observations are useful context. This Teapot pin exposes
neither a job-to-Scourge-run correlation nor evidence covering other pass
spenders, so job IDs from the list stay in the original evidence and
attribution remains `unestablished`. The adapter is not given authenticated
run job receipts here. Run job IDs, admitted, observed sent and charged stay
unset. The proxy status schema does not type its health allocator fields, so
held units remain null. The raw jobs and counters support no per-run debit.
Accounting reads use only version, jobs list, pass show and macro dry-run
argv. The pinned disposable test seeds one job and an existing ledger
reservation through the fixture, then checks the accounting reads leave the
ledger, pass, macro, job and flow observations and target request count intact.

## Verifier edit and enforcement gate

The run coordinator can use `Teapot::with_verifier_admission` with its
named sessions and the engagement's required enforcement to take the
start snapshot before any target-capable work, including a session check.
It can use `Teapot::verifier_preflight` again for the final snapshot. Both
paths read `version`, `proxy status`, `pass show` and the six pinned
edit-surface commands. Every captured edit reading has a redacted
typed report when its decision fields can be decoded. Its digest
covers compact JSON of the native result, excluding envelope advice.
The pinned session operation is `sessions show`. An unexpected values
payload yields neither a typed report nor a digest for that session.

Each refusal carries the edit readings and enforcement facts observed
before it, along with native and wrapper exit evidence and any invocation
diagnostic. Unavailable readings remain absent. This allows the run to
retain an active final surface for its record. Keep native result digests
and the typed reports within verifier custody.

The gate uses the regular listener and a conservative configuration
profile. It admits recognized scope, pass and passive session settings,
corroborates the configured rules and intercept state, and refuses
unclassified configuration, active edits, request or response hooks, and
session relogin or CSRF behavior. An unavailable or inconsistent edit
surface yields `INSTRUMENT_EDITS_ACTIVE`. An unestablished engine identity
or enforcement state, or failure to meet required egress enforcement,
yields `ENFORCEMENT_UNAVAILABLE`. Native `pass-not-enforceable` retains
its refusal evidence. The gate checks the live pass and policy lock across
the pinned replies. The run's authority and accounting checks are separate.

The ignored `pinned_verifier_gate_refuses_before_target_traffic` test uses
the exact Teapot binary and a disposable loopback sink. It exercises the
Teapot startup refusal with a probe-only Playpen stand-in. A clean
admission calls a test dispatcher and the sink counts its request.
The same dispatcher sees zero invocations on the tested refusals.
The version checks around native invocations detect observed identity
changes. Separate snapshots leave room for changes between reads or
before external dispatch.
