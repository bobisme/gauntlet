# Scourge v1 cross-lane contracts

**Status** · Frozen at M0.7 for the surface, verifier and evidence lanes. The [wire registry](../contracts/scourge-v1.json), [Teapot argv registry](../contracts/teapot-argv-v1.json) and [examples](../../fixtures/contracts/scourge-v1) are part of this decision. `just cross-lane-check` exercises the static contract.

Every field in a registered shape is required. A type with `?` allows null, `[]` is an array, and `=` marks a literal string. Named types refer to the registered shapes or enums. Each versioned object is UTF-8 JSON with unique member names. Use nonempty strings without NUL, unsigned 64-bit integers for counts and sequences, UTC timestamps of the form `YYYY-MM-DDThh:mm:ss[.fraction]Z` with up to nine fractional digits, and 128-bit run nonces encoded as 32 lowercase hex digits. Probabilities are decimal strings in the closed interval from 0 to 1. The response may include command-specific fields. Other named shapes are closed. Breaking readers or changing persisted meaning requires a new version.

## Machine responses and exit codes

**Problem.** A shell result, an oracle observation and a finding status describe different outcomes. The worker needs a reliable route and a typed result even if a wrapper masks a native failure.

**Choice.** Every machine response uses `schema: "scourge.response.v1"`. `command` is the canonical space-separated command path (`status` for aliases and bare invocation) or null before resolution. `workspace` is the resolved absolute path, `engagement` the selected ID, and `request_key` the run key. An unavailable lookup carries null for the key and the run, including a key belonging to another engagement. `ok` indicates command completion. `result` is the command-specific result label or null on error. `run` carries its own state, flags, oracle result, reproduction and cleanup. A displayed finding carries both status and applicability and all badge dimensions. A read that finds a blocker sets `blockers`, leaves `error` null and exits 0. An unsuccessful effectful invocation sets `error` with an uppercase code, message and commit status. `commit_status` describes whether the command durably changed coordination state, including a persisted run declaration. `unknown` means commit durability was not established. `effects` separately describes external effects for the reported action or run.

| Exit | Meaning | Codes |
| --- | --- | --- |
| 0 | Command completed, including blocked reads and completed runs with oracle result `true`, `false` or `invalid`. | — |
| 2 | Invalid usage or schema | `USAGE_ERROR`, `SCHEMA_INVALID`, `SLOT_CONFLICT` |
| 3 | Missing or ambiguous scope, object or input | `WORKSPACE_UNBOUND`, `ENGAGEMENT_REQUIRED`, `OBJECT_NOT_FOUND`, `INPUT_REQUIRED`, `INPUT_AMBIGUOUS` |
| 4 | Conflict | `CONFLICTING_RUN`, `REVISION_CONFLICT`, `IDEMPOTENCY_KEY_REUSED` |
| 5 | Unmet obligation | `SLOTS_INCOMPLETE`, `IDENTITY_UNESTABLISHED`, `EVIDENCE_INCOMPLETE`, `ORACLE_UNAVAILABLE`, `CAPABILITY_UNAVAILABLE` |
| 6 | Integrity failure | `INTEGRITY_FAILURE` |
| 7 | Dependency, I/O or uncertain effect | `DEPENDENCY_UNAVAILABLE`, `EFFECT_UNKNOWN` |
| 8 | Refusal | `AUTHORITY_REQUIRED`, `SCOPE_REFUSED`, `BUDGET_REFUSED`, `ENFORCEMENT_UNAVAILABLE`, `CUSTODY_UNAVAILABLE`, `METHOD_REFUSED`, `INSTRUMENT_EDITS_ACTIVE`, `ACCOUNTING_UNESTABLISHED` |

Generate the runtime exit table from `error_exits`. Clients branch on `result` and `error.code`. Oracle reason codes live under a round's `reason_codes` or in command-specific projections, even when their spelling coincides with an error code. Native diagnostics use `diagnostics[].code` and carry the actual native exit and any wrapper exit as separate nullable integers.

**Guarantees.**

- Resolve `--format text|pretty|json` or its hidden `--json` alias before `FORMAT`, then use terminal detection (`pretty` on a terminal, `text` on a pipe). Ignore unsupported `FORMAT` values. Conflicting explicit formats are `USAGE_ERROR` rendered in JSON if any explicit selector asked for JSON. Detect machine mode before full argument validation, including flags placed after the command and before the `--` end-of-options delimiter. Machine mode emits one JSON object and a newline to stdout, including usage, help and refusals. It never prompts, pages or opens a browser. Progress and structured, redacted diagnostics go to stderr. Each `scourge.diagnostic.v1` stderr event names the nullable workspace, engagement, request key and run ID from the current context.
- `next` is an ordered array of complete argv actions, with the external effect class in `effects`. Include canonical `--format json` in machine-mode Scourge actions, plus the absolute `--workspace` and `--engagement` where resolution requires them. Preserve spaces within an argv element. Native actions use the pinned executable, format flag and binding. If there is no supported next action, use an empty array. Repairs that could weaken an authority, scope or custody gate are never suggested. A lost outcome offers read or reconciliation, never a replacement run.
- For M0-ADD-01, bound orientation exposes the usable operator-bound transport and a supported action in human and machine output. A transport or tool check uses the bound executable or channel and validates the expected structured response and peer identity. A known wrong peer produces `WRONG_LISTENER`. A missing executable produces `TOOL_UNAVAILABLE`. An invalid response without stronger evidence produces `INVALID_NATIVE_OUTPUT`. An explicit native failure produces `NATIVE_FAILURE` or the more specific code. A connection failure with no identified peer produces `TRANSPORT_UNAVAILABLE`. A zero wrapper exit cannot erase a typed diagnostic. A read presenting a diagnostic has `ok: true`, exit 0 and a matching blocker when work is blocked. An invocation that fails for that dependency has `ok: false`, exit 7 and `error.code: DEPENDENCY_UNAVAILABLE`, unless a send's outcome is unknown, which uses `EFFECT_UNKNOWN`.
- Render target content only in a bounded, delimited untrusted field. Keep secrets out of every output channel and keep target text out of generated argv. Shorten or withhold the claim before dropping a mandatory caveat.

**Limits.** The envelope describes the result; it provides no authenticity or authority. When a process is killed before it can respond, recover via the persisted run. Diagnostic examples are synthetic. The cold-worker execution and no-traffic tests belong to M1.2 and M1.9.

**Evidence.** Teapot has its own exits. Investigation provides the 2–7 alignment. [Plan §8.4–8.5](../../notes/plan.md#84-responses), [§11.4](../../notes/plan.md#114-dependencies-and-observability), [M0-ADD-01](baseline-taxonomy-decision.md#added-acceptance), [baseline setup friction](../../evals/baseline/FAILURE-TAXONOMY.md#setup-friction) and [Investigation exit semantics at the inventory source pin](../stack-facts.md#stack-fact-checks-m012).

**Revisit triggers.** A new transport or command shape needs a new projection, a runtime conformance failure exposes an ambiguous outcome, or an upstream exit class changes.

### Local coordination reads

An operator-bound `show`, `list` or `doctor` opens the workspace's existing coordination database and takes one SQLite read snapshot. Writer setup prepares the WAL and shared memory before returning, including when the writer stays idle. Scourge serializes that setup with readers. Snapshot acquisition retries a bounded set of SQLite contention and read-only WAL recovery results. Retry exhaustion reports `CONFLICTING_RUN`. Missing or structurally invalid sidecars on a WAL-mode database fail integrity.

Under ordinary shared-custody operation, these readers preserve the database, WAL and shared-memory files, including their identities and bytes. The reader takes SQLite locks and makes no application writes. The filesystem checks and advisory lock cover cooperating Scourge processes. A concurrent same-account actor who deletes or replaces SQLite files or changes journal mode can defeat that coordination.

## Request keys

**Problem.** The caller may lose the response after a run has been declared or a request dispatched. A tool lookup, actor change or retry must preserve the original execution identity.

**Choice.** The service mints an opaque `rk_` key for each new effectful command and durably inserts its identity, normalized request and run before calling an external dependency. A keyed resubmission accepts only an issued key scoped to the selected workspace binding and engagement. `run show --request-key KEY` is the read path, and `run reconcile RUN` is local recovery. A deliberate new test has no previous key. Persist normalized input as `scourge.request-input.v1` and compare typed values. Canonicalize commands and aliases, parse typed options, and apply stable CLI defaults. Compare records independent of JSON object member order. Preserve array order and string contents. Presentation flags, working-directory spelling after binding, actor attribution and the key itself are outside equality. Snapshot the effective lead and engagement revisions, pass and experimental bindings on first acceptance. Replays compare the caller's selectors and inputs against the stored normalized input before resolving mutable defaults or selectors again.

**Guarantees.**

The `verify` and `retest` normalized argument shapes are `verify_arguments` and `retest_arguments`. A null revision means the caller selected the current revision. Substitute the declared CLI defaults of two rounds for `verify` and `sequential` for retest mode before comparing inputs. A null retest round count means the verifier chooses the number with the frozen baseline and the retest template. Persist that choice with the run.

| Condition within the authorized binding | Result |
| --- | --- |
| Key exists, input matches | Return the same run and its current durable state. Once finalized, replay references that run's result. |
| Key exists, input differs | `IDEMPOTENCY_KEY_REUSED` / 4. Preserve the existing run. |
| Key absent, invalid for the scope or belonging to another engagement | `OBJECT_NOT_FOUND` / 3 with indistinguishable response. Never create a run using that key. |
| Original run declared, no step intent persisted | It may reopen under the same row and key after exclusive claiming and checking the persisted revisions and authority. Absence of step intent alone proves only that no recipe send began. Recover any accounting or other effects already separately recorded. |
| Step intent persisted and outcome unavailable | Reconcile from evidence tied to that run and step. Keep unknown effects and block conflicting runs until disposition. Never resend automatically. |

The key-to-run association is unique, inserted atomically and retained for the life of the engagement. Serialize resume with the same conflict claim. Preserve the key on a refused or failed run after declaration. A request key and actor string confer no authority. Each persisted step intent binds the step number, request digest, flow-ID floor and any instrument-known send reference. A nullable native reference remains null until established.

**Limits.** Local starts are idempotent. The instrument may dispatch or spend before its reply is lost. A flow ID only returned in the lost reply, matching request bytes, an idle engine and an empty flow search cannot prove absence or establish a match. Keep native job queries within their visibility.

**Evidence.** [Plan §7.5](../../notes/plan.md#75-run-lifecycle-and-recovery) and [§8.6](../../notes/plan.md#86-request-keys), [Investigation staging and same-key observations](evidence-contract.md#conformance-record), and [Teapot per-send reference request](../instrument-requests.md).

**Revisit triggers.** An upstream durable dispatch reference ships, key retention changes, or concurrency and crash tests uncover a second local start or input ambiguity.

## Verification record, chain and publication

**Problem.** A well-formed artifact in the evidence store can come from an import or an interrupted publication. Accepting either as trusted without durable verifier intent would let an import alter finding status.

**Choice.** Only the verifier publishes a `scourge.verification.v1` record. The chain accepts one immutable record per run. A run declaration alone establishes no record. The record binds the lead, engagement, property, policy, template, experiment and oracle versions. It records per-round canary digests, flow references and byte digests, completeness, identity observations and outcomes. It records the target, custody, enforcement, accounting, edit surface, effects, cleanup, tool identities, limitations and timestamps. Store any retest comparison under `retest`, with null for verify. A retest records the baseline record and digest, mode and the two independent results. For paired retests, record the freshly observed baseline target separately and label each round's target by phase. For intermittent comparisons, record the lower bound, planned and completed counts, miss threshold and achieved miss probability. Record references are stable identities plus digests. Oracle results are strings. Preserve round order and name the recipe step for every flow, including any instrument-generated login or retry. Preserve the complete versioned record bytes in Investigation. Status is computed on read from chain membership and original evidence.

The checkpoint shape is `{engagement, sequence, record_digest}`, with genesis sequence 0 and null digest. Every linked record has sequence predecessor sequence + 1 and `prev_record_digest` equal to the predecessor digest (null only at genesis). Each digest is SHA-256 over exact stored bytes, encoded as 64 lowercase hex digits with no prefix. A record has no self-digest member. Verify digests before decoding or following references. Reports and bundles pin the checkpoint and check the chain only through that checkpoint. Out-of-chain references, skipping or repeating a link, cross-engagement predecessors, and altered or missing canonical bytes are `INTEGRITY_FAILURE`.

**Guarantees.** Persist verifier-generated `scourge.publication-intent.v1` before storing any candidate record. Bind engagement, run ID, record ID, exact digest and expected head. Preserve the byte source for a recoverable pending write. Use the intent ID as the stable evidence-store write key in the engagement's verifier namespace. An acknowledged or recovered receipt binds that write key to the artifact ID. Verify the receipt, digest, run and predecessor. In one coordination transaction, compare the expected head, link the record with uniqueness on engagement and run, advance the head and mark the intent complete with the artifact ID. An identical finish returns the same receipt even if the head has advanced again. A moved head leaves the candidate unlinked. Mark the old intent superseded and rebuild from the same run's originals on the new head under fresh intent and record IDs. Recovery may complete only the persisted matching publication. It initiates no target effects. A durable record with no matching intent and chain entry remains unlinked and contributes nothing to status. Byte/artifact mismatch for an existing intent fails integrity.

Keep distinct record references from policy evidence and rule source on reads. The stored policy is the rule in force during acquisition or null. A subsequently admitted policy can change the finding projection without editing the record. Raw canaries and credentials stay out of the record. Retain role/subject identity observations as binding labels, digests and original evidence references.

**Limits.** The shared-custody chain detects missing or altered evidence relative to a checkpoint. A same-account forger can replace a locally trusted checkpoint. The evidence store and coordination store do not commit together. This static contract does not qualify persistence across power loss, retraction or isolated custody.

**Evidence.** [Plan §6.9](../../notes/plan.md#69-the-verification-record), [§9.3](../../notes/plan.md#93-chain-and-checkpoints), [custody decision](custody-topology.md), [evidence contract](evidence-contract.md) and [M0-ADD-02 on interrupted capture](baseline-taxonomy-decision.md#added-acceptance).

**Revisit triggers.** A storage or retention change alters acknowledgement, byte-preserving reads or digest semantics, or the crash matrix finds a recovery ambiguity.

## Accounting evidence

**Problem.** A pass debit may reserve units for several engine jobs, and pass-wide counters include spending outside the verifier. Counts are useful with their provenance.

**Choice.** Every record holds `scourge.accounting.v1` with pass ID and digest, job IDs, an observation window, a dry-run ceiling, before/after counter samples, and distinct evidence for requested, admitted, sent, charged and held units. Each scalar observation names value, unit, source, granularity, window and original evidence reference. An absent reading is null. An empty receipt list records zero located receipts, which establishes no charge amount. Ledger debits name their own observed granularity, ledger sequence and caller reference when present. `observed_sent` counts sends positively tied to the run, including retries and relogin. `charged` requires run-specific allocation evidence; even exclusive pass use does not attribute a previously reserved block to the run.

**Guarantees.** `exclusive` requires positive evidence covering every spender over the accounting window. `shared` requires evidence of a second spender. `unestablished` applies otherwise, including when the run holds a lock and the local job list is empty. Preserve disagreements between planned, admitted, observed and charged values. Use `ACCOUNTING_UNESTABLISHED` / 8 if the engagement requires exact per-run accounting and the instrument cannot substantiate it. Scourge records costs; the spender performs the debits.

**Limits.** A caller reference or sequence ties a debit to a ledger event. Allocation across runs needs separate evidence. The current Teapot pin does not expose the run-level proof required for exact accounting.

**Evidence.** [Plan §7.4](../../notes/plan.md#74-accounting-evidence), [stack accounting facts](../stack-facts.md), [two projects on one pass](../two-projects-pass.md) and [upstream accounting request](../instrument-requests.md).

**Revisit triggers.** A qualified instrument exposes run-scoped receipts, allocator allocation evidence, or a new counter or granularity.

## Teapot argv pins

**Problem.** The verifier and orientation surface need reproducible native actions. Command names, flags and JSON shape drift across instrument builds.

**Choice.** Use [the argv registry](../contracts/teapot-argv-v1.json) for the nine §7.2 operation groups. Every row is an argv vector with the executable supplied by the binding, `--project` and `--json` already placed, and one complete argument per placeholder. Optional groups keep their order and arity. Each row points to its captured schema and any exercised invocation. The observed binary SHA-256 and source object come from the [contract manifest](../../fixtures/contracts/manifest.json). The source object and historical installed digest are independently pinned in [inventory](../inventory.json).

**Guarantees.** Resolve the executable and project only from trusted bindings, invoke directly with a cleaned environment, and parse structured replies against the captured schema. Verify the responding engine identity before accepting describe. Preserve native response or failure evidence, including an inactive engine, missing flow, unbound pass or incomplete job cancellation. Evaluate edit surface at both ends. Treat every login or retry that actually sends as a separate flow. Status and plan use only the pin's read-only actions; the session check sends traffic. Follow the [custody topology](custody-topology.md) for which channel is exposed to workers.

**Limits.** The fixtures establish output for the captured loopback invocations. Schema-only options have no runtime qualification from this capture. A nullable flow ID provides no lost-response recovery. Windowed body capture and rendered heads do not establish complete wire bytes. Inactive cancellation, an unbound pass and end-point edit snapshots do not qualify active cancellation, exact accounting or edit isolation. Macro dry-run has a count; ordinary send dry-run does not consult the pass.

**Evidence.** [M0.1.3 contract and observations](../teapot-contracts.md), [verifier channel experiments](../teapot-channel-contracts.md), [upstream requests](../instrument-requests.md), and [plan §7.2](../../notes/plan.md#72-the-instrument-contract).

**Revisit triggers.** The instrument version, executable digest or any schema changes, or M1.3 observes new cancellation, body-capture, edit or accounting behavior. Re-run native conformance on the named replacement pin before changing the registry.
