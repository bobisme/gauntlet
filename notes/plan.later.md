# Gauntlet — later milestones (M3–M5) and deferred work

**Companion to** [`plan.md`](plan.md), revision 2 — 2026-11-21.

This file is written at lower resolution than the main plan on purpose. M0 to M2 will change what is worth building next, so each milestone here starts with a short design note that turns its section into work packages, written after the previous milestone's results are in. The invariants and fixtures of the main plan apply to everything here.

**Entry condition for M3.** The Tier 1 evaluation ([`plan.evaluation.md`](plan.evaluation.md) §6) shows that Gauntlet (condition C) produces fewer false promotions than written guidance alone (condition B) without losing discovery against the instruments alone (condition A). If it does not, find out why before adding breadth.

## 1. M3 — discovery

Verification without discovery is a tool that reports nothing. Published results point the same way: on BountyBench the best reported configurations reached 90% on patching and 67.5% on exploitation, and 12.5% on detection ([`plan.research.md`](plan.research.md) §4). Finding the issue is the harder half. M3 adds aids to exploration. It does not add control over it: the two-speed rule (D2) stands.

### 1.1 Surface map

`gauntlet map` builds a compact, durable picture of what could be tested. It is black-box only.

- **Inputs:** flows already in the instrument's store, a published API schema if one exists, and the engagement's principals and properties.
- **Output:** resource classes, the routes that reach them, which parameters carry object identifiers, and which principals have been seen on each.
- **Effects:** none by default. `gauntlet map --crawl` runs the instrument's own crawl under the pass and says so first.

It is not a threat model from source. That is Ward's work (§3). Scanner and schema imports create leads, never findings, and keep the producer's identity and original format.

### 1.2 Coverage

A coverage cell is a meaningful combination of resource class, operation and principal pair. The matrix is bounded and explicit, not a Cartesian product. Discovery may add cells, with a reason.

| State | Meaning |
|---|---|
| `untested` | Known and not yet examined. |
| `explored` | Seen in exploration. No valid test. |
| `tested_no_violation` | A valid `false` under stated conditions. |
| `tested_invalid` | Only invalid tests so far. |
| `violated` | A verified finding. |
| `blocked` | With a reason, including `model_refused`. |
| `not_applicable` | With a reason. |

Cells derive from leads and runs. A visited URL, a sent payload or a closed work item does not mark a cell tested, and an invalid test never does. Coverage is a disclosure of what was examined. It is not a completeness claim, and the report states what was never inventoried. Versioned OWASP identifiers may label cells; a label certifies nothing.

Cells live in Gauntlet's coordination store (`coverage_cells`).

### 1.3 Next-action ranking and stalls

M2's `next` uses a fixed order. M3 extends it, still read-only and still without a model call:

1. Unknown effects, owed cleanup, integrity problems.
2. Leads ready to verify.
3. Untested cells adjacent to a verified finding: same resource class with another operation, or another resource class on the same route pattern.
4. High-consequence untested cells.
5. A different method when repeated attempts have not changed what is known.

Progress means a new valid observation, a resolved prerequisite or an eliminated alternative. It does not mean more messages. After a configured number of attempts with no progress, `next` names the repeated blocker and suggests a different channel, a narrower claim or a stop. No invented probabilities. Learned scheduling stays deferred (§5).

The engagement may reserve part of its budget for verification and cleanup so that easy leads do not consume everything. The starting policy is one third, tuned from pilot data.

### 1.4 Out-of-band collector

The second observer. It establishes that a per-run token arrived somewhere only the target could have sent it. Candidate first classes: server-side request forgery and blind injection with a callback.

- A listener bound **outside the worker's network namespace**, at an address the operator provisions and the pass lists.
- The verifier mints a per-run token, places it in the stimulus, and reads interactions from the collector by token.
- Controls: a baseline request without the token produces no interaction; the interaction's source is neither the worker nor the verifier; a token from an earlier run is rejected.

Limits to state up front. In shared custody the agent can read the token from the instrument's store and call the collector itself, so an out-of-band finding in shared custody carries that caveat on its badge. Many lab targets cannot reach a local collector at all; the collector's reachability is checked before the run and its absence is `CAPABILITY_UNAVAILABLE`, not a negative.

### 1.5 Browser adapter

The third observer: the claimed effect fired in a victim's browser session. RECEIPT is the precedent ([`plan.research.md`](plan.research.md) §3). Its authors found that a naive "did JavaScript execute in a browser" check accepted 111 claims of which 10 were real, and that a clean replay with strict separation accepted none that were false. The parts to copy:

- A fresh environment per verification.
- The attacker's stimulus sent with attacker-only credentials.
- The victim in a real browser with victim-only credentials.
- A sentinel carrying a single-use token, installed by the verifier.
- A **fixed vocabulary** of victim actions (navigate, click a declared element, wait). No agent-written script runs in the victim's context.

Evaluate an existing browser automation CLI before taking a browser-automation library as a dependency. First class: stored cross-site scripting across principals. This oracle gets its own fixtures, mutation suite and red-team attempts before it is registered.

### 1.6 Parallel workers

Optional. Short-lived workers on disjoint slices of the surface map, each of which records leads and exits. Hub and spoke, not a council: the multi-agent failure literature finds coordination and verification failures, not benefits, from peer discussion.

- Vessel manages worker processes. A worker handoff holds an objective, an authority summary, bindings and the next valid action. A role prompt grants nothing.
- `rite` advisory claims coordinate files. Gauntlet's run lock still serializes verification per pass (INV-18), so workers explore in parallel and verify in turn.
- Bones gets coarse work items through `work_links`: one per surface slice or per finding to fix. Closing a work item never changes a finding. Gauntlet works with `bn` absent.
- An unavailable worker runtime blocks only managed workers.

### 1.7 Stateful recipes

Multi-step workflows such as checkout need a setup sequence before the treatment. Templates may declare one as instrument macros with producer and consumer bindings between steps, following the stateful API fuzzing literature. Business-logic claims wait for an observer that can state their violation deterministically. Until then they are leads.

### 1.8 M3 work packages and gate

| ID | Package | Acceptance evidence |
|---|---|---|
| M3.1 | Design note | Work packages re-cut from M2 results and the Tier 1 failure analysis. |
| M3.2 | `map` and coverage | Cells derive only from leads and runs. Invalid tests never mark coverage. Unknown denominators are shown. |
| M3.3 | `next` ranking and stall detection | Deterministic order with stated reasons. Fixtures for each rule. |
| M3.4 | Out-of-band collector and one template | Fixtures including a worker-generated callback and a replayed token. Mutation suite. Shared-custody caveat on the badge. |
| M3.5 | Browser adapter and one template | Fixtures including a marker reflected with no effect and a self-triggered sentinel. Mutation suite. |
| M3.6 | Workers and work links | Parallel exploration with serialized verification. Runs with `bn` and the worker runtime absent. |
| M3.7 | Stateful recipes | One multi-step template on the fixture's checkout flow. |
| M3.8 | Discovery evaluation | Held-out families at matched budget against condition A, with the preregistered margin. |

**Gate:** unassisted discovery is not worse than condition A by more than the margin, every new oracle passes its fixture and mutation gates, and the red-team track finds no promotion through the new observers.

## 2. M4 — protocol and cross-protocol

### 2.1 What exists

Read from Sippycup's source on 2026-11-21:

- It authorizes from its own approval window and counts calls in its own reserve-and-release ledger. It has no Hallpass integration.
- `sippycup assert` evaluates a capture against call-path expectations offline, with a three-state result.
- `sippycup go` shows where an engagement stands and prints the next step.
- It writes its own evidence packs and has its own journal.

### 2.2 Reuse, not rebuild

- Gauntlet binds the **Sippycup approval** by reference and digest, the way it binds a pass for HTTP. It never debits and never restates the approval.
- Where `assert` can state the violation, it is the observer. Gauntlet's template supplies the expectations and the controls around it.
- Evidence packs are imported into the evidence store with lineage. The native journal stays authoritative for native runs. No competing journal.
- Record what protocol evidence needs: native run identity, scenario version and parameters, Call-ID, dialog and transaction identity, SDP offers and answers, media endpoints, capture completeness, and the native oracle version.

### 2.3 What is missing

**A multi-tenant protocol target.** There is no SIP testbed with tenants, planted cross-tenant flaws and decoys. Build one before specifying any oracle (M4.1). Without it, an oracle specification is guesswork.

**A canary for media.** The HTTP canary is a random value in a body. The analog for media is specified in the M4 design note once the target exists; candidates are a per-run tone sequence or a signaled attribute. The rule carries over unchanged: the verifier mints it per run and a model cannot predict it.

### 2.4 Cross-protocol claims

Some findings have an HTTP stimulus and a SIP observation: a provisioning API change that alters where calls route. These need two instruments and two authorities in one experiment. The run lock spans both. Links between traces use explicit bindings (application principal to token to signaling principal to dialog to media stream). Timestamp proximity alone never establishes that two traces belong to one consequence.

### 2.5 Fixtures

| Situation | Required behavior |
|---|---|
| Signaling succeeds and media is not reachable. | Verify only the signaling property. |
| Media packets arrive and cannot be attributed or decoded. | No claim of content access. |
| Retransmissions appear as extra calls. | Counted once. Clock uncertainty stays visible. |
| Address translation makes two endpoints look like one. | Identity invalid, not a negative. |
| The capture drops packets or ends early. | `EVIDENCE_INCOMPLETE`. |
| The approval window expires mid-call. | Stop. Effects and cleanup recorded. |
| A chain's steps belong to different tenants or time windows. | No end-to-end finding. |

**Gate:** one complete live signaling and media experiment on the new target with the real runner, capture and cancellation, plus the fixtures above and a mutation suite for whatever oracle ships.

## 3. Source leads through Ward

Ward does static analysis and signs its evidence. Gauntlet consumes the result. This section ships only when a Ward import contract is qualified. It is not on the v1 release path, and M5 does not wait for it.

**Three separate facts,** never one boolean:

| Fact | Meaning |
|---|---|
| Presence | A `ward` binary is installed. |
| Qualification | Gauntlet's import contract tests pass against a named Ward version. |
| Eligibility | This engagement permits source access. |

**Import.** A Ward finding becomes a lead with origin `ward`, the artifact's identity, and the result of checking its signature under the operator's trust policy. A failed or absent signature leaves provenance `unestablished`; the lead is still a lead.

**Two outcomes:**

- A Ward lead that a runtime template verifies is an ordinary `runtime-controlled.v1` finding. No special profile.
- A Ward lead with no runtime path may reach `source-validated.v1`: a qualified import plus a reviewer who is not the lead's author. It displays as `Validated from source`, carries `validation: judged`, is counted apart from deterministic findings, and never says `reproduced`.

A runtime `false` under tested conditions limits a source claim. It does not refute it (INV-10): unreachable under these conditions is not the same as safe.

**Fixtures:** a source path that is unreachable at runtime; a broken signature; a finding from a different commit than the deployed build; several summaries of one Ward finding presented as independent confirmations (they are one acquisition).

## 4. M5 — release

- **Tier 2 evaluation** on the frozen candidate ([`plan.evaluation.md`](plan.evaluation.md) §6, §7).
- **Support matrix:** which instrument versions, which custody topologies on which hosts, which classes have an oracle. Generated from qualification records, not written by hand.
- **Documentation:** generated command reference, one guide per oracle in the published form, and a plain statement of what shared custody does not prevent.
- **Backup and restore** qualified: restore to an empty destination, start paused, no run resumed.
- **Migrations** tested from every released schema version. The oracle revocation path exercised end to end.
- **Packaging:** the `gauntlet` and `gauntlet-verify` binaries. Installation touches no global hooks or host trust settings.
- **Claims:** limited to what was measured, published with numerators and denominators.

**Exit:** the gates of [`plan.evaluation.md`](plan.evaluation.md) §7 are met on the frozen candidate, or the support claim is narrowed to the cells that passed.

## 5. Deferred work and triggers

| Item | Why it waits | Revisit when |
|---|---|---|
| Capture-only `gauntlet run -- CMD` | It cannot enforce a budget on this stack: Playpen confines egress and only the spender enforces ceilings. A wrapper that implied otherwise would be a false label. | The baseline or Tier 1 shows agents losing useful evidence from scripts run outside the instrument. Ship it labeled `egress_confined`, `budget_unenforced`. Its output is leads only. |
| `runtime-adjudicated.v1` | A reviewer-judged runtime verdict is what the product exists to avoid. | A class with real demand still has no deterministic observer after M3, and an adjudication protocol exists with measured reviewer agreement. It carries `validation: judged` and is counted apart. |
| Audience-projected reads | v1 is a single-operator tool. Bundles cover third parties. | A second audience with a different need-to-know uses a live workspace. |
| Mirroring findings into Investigation | Its conclusion records do not exist yet. | Investigation ships its Milestone A and a user wants findings in a casebook. One way, labeled as a projection, never read back. |
| Pack loader or plugin interface | One pack author. Extension points are unknown. | A second independently written pack exists. |
| MCP adapter | A second surface to keep honest, for no new capability. | A host that cannot run a CLI. It must share handlers and the envelope. |
| Learned scheduling | No data. | Tier 3 data shows the fixed order leaves measurable yield unused. |
| `authenticated_external` custody and multi-host work | Needs a signed channel and a trust policy. | A third-party verification service is required. |
| Exact per-run accounting | Needs an upstream change in Teapot. | Teapot sends caller references and exposes the ledger sequence. |
| SARIF and tracker exports | Lossy projections. | A consumer asks. Each export declares what it loses. |
| Sanitizer or fault observer | Needs build identity and usually source, outside the black-box default. | The Ward route is qualified and a memory-safety class is in demand. |
| Maintainer-decision study at scale | Expensive. | The M2 development pilot shows report design changes decisions. |
| Patch generation | Outside the product. | Not planned. |

## 6. Observer roadmap

A class is verifiable when an observer can state its violation deterministically. Until then its leads stay leads, and reports say so.

| Observer | Classes it opens | Needs | Milestone |
|---|---|---|---|
| Cross-principal canary | Private object read. Forbidden state change. Later templates on the same observer: list endpoints that leak another principal's object, nested resources, alternate routes, role-restricted functions, fields a principal should not be able to set. | Two principals and a writable or designated owner value. | M1, M2, then one template at a time. |
| Out-of-band interaction | Server-side request forgery. Blind injection with callback. | A collector the target can reach and the worker cannot. | M3 |
| Clean-browser victim | Stored and reflected cross-site scripting across principals. Cross-site request forgery, observed with the canary observer. | A real browser, separated credentials, a fixed action vocabulary. | M3 |
| Differential counterfactual | Fix verification. Later: claims that are only visible as a difference between builds or inputs. | Two builds, or a historical baseline under one measurement basis. | M2 for retests |
| Media canary | Cross-tenant call and media exposure. | The M4 target. | M4 |
| Sanitizer or fault | Memory safety on an identified build. | Build identity; usually source. | Not scheduled |

Adding a template to an existing observer is cheap and is the main way coverage grows. Adding an observer is expensive and gets its own fixtures, mutation suite, known misses and red-team attempts.

## 7. Fixtures for later milestones

Carried from revision 1 §16.4 where they apply beyond M2. The main plan's catalog (§14) holds the M0–M2 fixtures.

| Milestone | Situation | Required behavior |
|---|---|---|
| M3 | A marker is reflected with no effect. | A lead or a `false` predicate. Never proof of injection. |
| M3 | The worker generates the observer callback itself. | Cannot satisfy the target-caused obligation. |
| M3 | A callback token from an earlier run is replayed. | Rejected. |
| M3 | The state existed before the stimulus. | No causal attribution without a discriminating control. |
| M3 | A fixture administrator's write creates the alleged result. | Rejected as proof of attacker capability. |
| M3 | A dirty reset, or an unrelated concurrent worker. | Contamination flagged. Rerun under compatible state. |
| M3 | A worker is still alive after its lock expired. | Conflicting replacement blocked until reconciled. |
| M3 | Several agents summarize one source. | One acquisition. No invented independent confirmation. |
| M4 | See §2.5. | |
| Ward | See §3. | |
| Unscheduled | Wrong build, architecture or sanitizer. | Invalid applicability. The signal is kept as separate evidence. |
| Unscheduled | A reduced reproducer works and the original does not. | Simulation is distinguished from confirmation on the original target. |
