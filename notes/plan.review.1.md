# Critical Review: Gauntlet Implementation Plan (`notes/plan.md`, Rev. 1)

**Reviewed:** 2026-11-21. **Plan size:** 1,800 lines, about 24,800 words.

**How this review was done.** The plan's author had no access to this machine and says so. This review had access, so most of its weight is on checking the plan against what is actually in `~/src`:

- The whole plan was read.
- Its claims about Teapot, Hallpass, Playpen, Sippycup, Bones, Edict and Vessel were checked against local source at each repo's HEAD. Four read-only passes did this and cited file and line; I re-read the passages behind the findings this review leans on most (Teapot's allocator and enforcement launcher, Playpen's enforcement coverage, Hallpass receipt recovery, Sippycup's call ledger, the Teapot testbed).
- The Investigation plan it depends on (`~/src/investigation/notes/plan.md`, rev. 3) and that plan's own review were read for the contracts Gauntlet relies on.
- Ten of the research citations were fetched and compared with the plan's claims.

**Limits.** Nothing was built, run or tested. Source was read, not exercised. Where a statement below comes from documentation and was not confirmed in code, it says so.

---

## Executive Summary

### Strengths

1. **The central idea is right, and it is the one the best evidence supports.** Agents propose; ordinary code decides what an observation proves. Promotion consumes typed receipts, never a success field. This matches the closest working precedent (XBOW's "agent provides evidence, non-AI code checks it"), which the plan arrives at independently.
2. **It is honest about its own evidence.** It separates what was inspected from what was run, refuses a cross-paper leaderboard, and labels every number as a target. All ten citations I fetched loaded. Eight supported the plan's claim outright, one needs a small correction, and one has sub-details I could not confirm (see Change #11).
3. **The result taxonomy is sound.** Execution, evidence completeness, validity, oracle, interpretation, reproduction and cleanup are separate dimensions. "No valid test" and "no finding" never merge. This is the part most worth protecting during implementation.
4. **Ownership boundaries are mostly correct.** One owner per kind of truth, no second task graph, no second evidence store, no new HTTP client.
5. **The adversarial fixture list in §16.4 is excellent** and is the most directly implementable section of the document.
6. **Several inferences about the stack were right** without local access: Bones has no exclusive claim, Hallpass references are correlation rather than idempotency, Playpen confines egress only, Vessel is not a durable job store.

### Key areas for improvement

1. **Several stack facts are wrong or stale, and four of them change the design.** Teapot gives no per-attempt accounting receipt. The demo fixture cannot run under enforcement as the stack stands. Sippycup already has its own authorization, ledger, oracle and findings model. A security tool named Ward already exists in `~/src`. (Change #1.)
2. **The headline result is unreachable as specified.** `runtime-controlled.v1` requires isolated verifier custody. Nothing in the stack provides it, the plan does not design it, and the work package for it is one table row. Until that is decided, a cold agent in an ordinary session can never see "Verified". (Change #6.)
3. **The plan asks for evidence last.** The first cold agent touches the tool after sixteen work packages; the baseline that would show whether the gates earn their cost runs in M3. The fixture and the harness to run both in M0 already exist locally. (Change #2.)
4. **"Obvious to an agent with zero knowledge" has no budget.** Fourteen object types, nine result dimensions, four profiles, twelve obligations, 36 operations and 20 error codes, with no stated limit on what an agent must learn before its first useful action, and three names for the same thing. (Changes #3 and #4.)
5. **The critical path runs through a product that does not exist.** Investigation is a 2,264-line plan with no code. Gauntlet's first useful milestone needs most of two Investigation milestones, and neither plan owns the joint schedule. The promotion protocol also splits "is this verified" across two stores. (Change #7.)
6. **The release gates measure the wrong things in two places.** A 90% unassisted-discovery gate measures how easy the planted flaw is. Zero false promotions across twelve scenario families is weak evidence, and no trial has an agent actually trying to cheat the gate. (Change #5.)

### Against the stated bar

The prompt asked for the most verifiably effective tool, completely obvious to an agent with zero knowledge. The plan is strong on "difficult to fool" and weak on "obvious" and on "verifiably": its verification of itself arrives too late to shape the design. Most changes below are about closing that gap. None asks for less rigor in what a finding must prove.

### Decisions (settled by Bob, 2026-11-21)

Three changes turned on choices only the owner could make. All three are now decided, and the changes below are written to match.

| Decision | Outcome | Where |
|---|---|---|
| May a finding be called verified when the agent and the verifier share a Unix account? | **Yes.** The custody tier is shown on the badge; isolation is required for scored evaluations and third-party reports. | Change #6 |
| Does Gauntlet drive Investigation's hypothesis, review and conclusion lifecycle, or only use it to hold evidence? | **Evidence only in v1.** Findings are mirrored into Investigation one way. | Change #7 |
| Where is the boundary with Ward? | **Gauntlet is for black-box testing.** That is the working assumption. When source is available, Ward is part of the workflow; Gauntlet builds no static analysis. | Changes #11 and #13 |

The black-box answer reaches further than Ward. It makes several things in the plan conditional that are currently in the first slice, and it makes the real-target path in Change #8 the main path. Change #13 was added to carry that through.

---

## Proposed Changes

Ordered by priority: high impact and low effort first, then high impact and high effort, then medium.

---

### [High Impact, Low Effort] Change #1: Replace remote-inspection guesses with local ground truth

**Current State:**
The plan was written from GitHub at pinned commits and from an attached copy of the Investigation plan. It defers name and capability resolution to G00 and carries several open questions and a few wrong statements.

**Proposed Change:**
Correct the facts now. They are cheap to fix and four of them (marked ▲) change the design.

| Plan says | What is in `~/src` | Consequence |
|---|---|---|
| `teacup` may exist; resolve in M0 (line 42, G00, checklist) | No `~/src/teacup`, no `bobisme/teacup` on GitHub, and the string appears nowhere in Teapot. | The HTTP workbench is Teapot. Delete the open question. |
| Investigation repository "not accessible" (lines 183, 1692) | `~/src/investigation` holds `notes/plan.md` (rev. 3) and one review. No code, no `inv` binary. | It is a plan, not an inaccessible implementation. See Change #7. |
| `[S8]` links to a private ChatGPT library file | Not durable and not readable by an implementing agent. | Point to the local path. |
| Teapot pinned at `c90ab5bb` | HEAD is `3eec1146`, eleven commits later. Its README still lists authz and crawl as "being built"; they are present. | Pin HEAD; do not trust the README. |
| ▲ Preserve "ledger sequence, caller reference, named charges" per attempt (line 615) | Teapot debits Hallpass in blocks before sending and never refunds ("the ledger's count errs high", `allocator/mod.rs:39-41`). No Teapot API type carries a ledger sequence. Its vendored Hallpass (`df90119`) has no `caller_ref` at all. Only aggregates are exposed: `units`, `units_left`. | Per-attempt accounting receipts do not exist on the HTTP path. See Change #9. |
| ▲ "A private local lab can use dedicated non-loopback endpoints" (line 623) | Playpen refuses loopback destinations. Teapot refuses to start enforced with a loopback pass (exit 4, `pass-not-enforceable`) and offers `--no-enforce`. The Teapot testbed is loopback-only. | The demo cannot run enforced today. See Change #6. |
| Playpen enforces the pass | `playpen run --require-enforced` refuses any pass with ceilings or name restrictions (`docs/spec.md`, "Pass enforcement coverage"). | Ceilings are always enforced by the spender (Teapot), never by Playpen. Qualify that split, not "Playpen composition". |
| `caller_ref` is correlation only (line 615, crash matrix) | True. Since `6be9a75` there is also `hallpass receipt FILE --caller-ref REF`, returning `found`, `absent` or `ambiguous`. | Name it in the crash matrix. It needs `--caller-ref` at spend time, which Teapot does not send. |
| One Hallpass | Three: HEAD is 0.2.0; Playpen pins `05d657a` (0.1.0); Teapot vendors `df90119`. Hallpass's format docs say older readers reject the newer `required_counters_v1` key (from the docs; not run). | G00 needs a pass-format compatibility matrix across the three. |
| ▲ "A native Sippycup-to-Hallpass debit path was not established; its profile/campaign limits are a separate mechanism" (line 613) | Literally true, and misleading. Sippycup has its own reserve-and-release call ledger keyed by the owner's approval id (`lib/sippycup/call_ledger.py`), an approval window in `scope.yaml`, and Ed25519-signed single-use grants for its live MCP tool. | A Gauntlet-owned debit would double count. See Change #9. |
| "The existing Sippycup generic journal is real and remains authoritative for legacy native runs" (line 972) | The journal is the operator's hand-written engagement record. Machine truth is the run directories and the call ledger. | Import run directories, not the journal. |
| Registry carries `activity`, `execution` and `networkActivity` labels (line 966) | `activity` and `execution` are per command. `networkActivity` is a document-level constant about the listing itself. | Drop it from the adapter mapping. |
| Signaling oracles and reports are to be built (§7.3, §12.6) | Sippycup ships a versioned three-state oracle (`sippycup assert`: pass, fail, unknown), a findings schema that already treats a finding as a candidate until independently reproduced, hashed evidence packs, and `go --format json`, which emits the next command's argv. | M4 is mostly reuse. See Change #9. |
| Design an owned authz fixture (G01, line 1325) | `teapot/crates/teapot-testbed` has users admin, alice and bob; a planted IDOR on `/app/api/orders/{id}`; an owner-only control (`invoices`); a public control (`catalog`); an admin-only control; a per-user identity endpoint (`/app/api/me`); a reset endpoint; and an endpoint that acts and then drops the connection. | The development fixture and the §17.4 lost-response case largely exist. See Change #2. |
| Bones has no exclusive claim (line 582) | Confirmed: state is validated before the append lock and not re-checked under it. The stack's lease primitive is `rite claims` (advisory, with a TTL). | The plan's local admission lock is still right for effect fencing. Mention `rite` so nobody builds a third. |
| Teapot identity checks | Teapot has no who-am-I. `sessions check` answers only logged-in, logged-out or unknown; `logins` is the nearest thing to a session epoch. | The engagement must declare an identity probe. See Change #8. |
| ▲ Not mentioned | `~/src/ward`: "Verifiable Security Review Infrastructure", static analysis with signed evidence, plus an agentic layer with discoverer and disputer roles and signed witness bundles. | See Change #11. |
| "The Reliquary tools" | The name appears only on `agentreliquary.com`, which lists nine tools. Hallpass, Playpen, Teapot, Sippycup and Investigation are not among them. | Cosmetic. Name the tools instead. |

**Rationale:**
The plan repeatedly says "do not infer functionality from a filename or README". It then does so where it had no alternative. The cost of leaving these for M0 is that M0 is where an implementing agent has the least context and the most pressure to move on.

**Benefits:**
- Removes one fictional dependency question and several wrong adapter mappings.
- Surfaces the four design-changing facts before any work package is cut.
- Makes G00 a verification pass over a known list.

**Trade-offs:**
- These facts will drift again. Teapot gained eleven commits in the 73 minutes between the plan's pin and local HEAD. The table needs a date and G00 still needs to re-check.

**Implementation Notes:**
Keep the pinned-commit ledger in §22.5 but update the pins, and add the Hallpass version each consumer links. Do not delete the plan's caveats about inspection versus execution; they still apply to this review.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -40,3 +40,3 @@
 ### Naming clarification
 
-The request names **teacup**; earlier work and the accessible repository identify **Teapot** as the HTTP workbench. This plan uses the logical capability `http-workbench` and an initial `teapot` adapter. `bobisme/teacup` was not accessible during research; that does not prove it does not exist. Resolve the repository/binary binding in milestone M0 without changing the architecture or blocking the rest of the work. Do not create a replacement HTTP client on the assumption that the name refers to a missing product.
+The request names **teacup**. No such repository exists locally or under `bobisme` on GitHub, and the string does not appear in Teapot (checked 2026-11-21). The HTTP workbench is **Teapot** (`~/src/teapot`). This plan uses the logical capability `http-workbench` and a `teapot` adapter.
@@ -183,5 +183,9 @@
-- The attached Investigation API is a **specification**, and the repository was not accessible during this research. Build against a conformance contract; a simulator can unblock tests but never qualify a real release.
-- The current inspected Teapot source contains substantive authz/crawl handlers and corresponding test code. Older observations that these were placeholders are stale. Inspection is not a claim that the suites were run here.
-- Hallpass accounting and caller correlation do not establish exactly-once external execution. A committed debit can precede a failed send.
-- Playpen's documented IP egress controls are not filesystem confinement or semantic request-count enforcement. Its platform, container, raw-socket, and loopback limitations matter.
-- Sippycup's container/capture execution needs a specifically qualified confinement composition. Wrapping its launcher in Playpen and declaring the whole run confined is unacceptable.
+- Investigation is a **plan with no implementation**: `~/src/investigation` contains only `notes/plan.md` (rev. 3) and a review of it. §19.6 maps what Gauntlet needs to that plan's work packages.
+- Teapot has working authz-compare and crawl handlers with CLI tests, `teapot schema` and `teapot guide` for discovery, and a testbed crate with a planted IDOR and controls. Its README is stale on this.
+- Teapot debits Hallpass in blocks before sending and never refunds. It exposes no per-request ledger sequence, and its vendored Hallpass predates `caller_ref`. Accounting evidence on the HTTP path is aggregate (`units`, `units_left`) until that changes upstream.
+- Hallpass references are correlation, not idempotency. A committed debit can precede a failed send. `hallpass receipt FILE --caller-ref REF` recovers a lost spend response when the spender supplied a reference.
+- Three Hallpass versions are in use (Hallpass HEAD, Playpen's pin, Teapot's vendored copy). A pass must be readable by all three before an engagement can use it.
+- Playpen confines network egress only. It refuses loopback destinations, and `--require-enforced` refuses any pass with ceilings or name restrictions, so ceilings are always the spender's job. Nothing in Playpen, Hallpass or Vessel protects one same-account process from another.
+- Sippycup has its own approval window, a reserve-and-release call ledger keyed by approval id, signed single-use grants for its live MCP tool, a versioned three-state oracle, a findings schema and evidence packs. It has no Hallpass integration. Its default live mode is host networking with raw capture, which Playpen cannot wrap.
+- Ward (`~/src/ward`) is an existing static security-review tool with signed evidence. §3.1 states the boundary.
@@ -1738,1 +1742,1 @@
-- [ ] Record actual repository paths, toolchain, executable identities and capability versions. Resolve `teacup` versus `teapot` explicitly; leave the permanent Gauntlet name open.
+- [ ] Record actual repository paths, toolchain, executable identities and capability versions, including the Hallpass version each consumer links. Leave the permanent Gauntlet name open.
@@ -1800,1 +1804,1 @@
-[S8]: https://chatgpt.com/library?file_id=libfile_fde3_f-e3c066c838388191b23a90270cf049d2_84f617e431e881918e33d3a401276f18&account_id=personal
+[S8]: ../../investigation/notes/plan.md
```

---

### [High Impact, Low Effort] Change #2: Get evidence before building the gates

**Current State:**
The first cold agent uses Gauntlet in G17, after sixteen work packages. The matched baseline (agent with native tools, with and without the methodology as plain guidance) runs in G25 at M3. G01 designs a new fixture from scratch.

**Proposed Change:**
1. **Run the baseline in M0, before the domain catalog freezes.** Use the Teapot testbed as it stands: one planted IDOR, an owner-only control, a public control, an admin-only control and a per-user identity endpoint. Give a fresh agent the task, Teapot and `teapot guide`, and nothing else. Run condition A (native tools) and condition B (native tools plus the §20.1 methodology text) a handful of times each.
2. **Record how they fail.** The output is a failure taxonomy: which false conclusions agents actually reach on this fixture, how often, and at what step. That list decides which obligations are mandatory in v1 and which are advisory.
3. **Put a cold agent on a walking skeleton at the end of M1.** One thin path through every layer, with one oracle and its controls, in shared custody. It includes the decoys, so it is not a demo.
4. **Reuse Edict's hermetic evaluation harness** rather than building a runner. It already drives `claude -p` from a terse prompt that names no tool, scores with scripted checks against real state, self-tests its oracle, and runs a no-instructions control. Its last A/B run was 18 runs for $10.80 in 44 minutes, which is a real cost anchor.

**Rationale:**
The plan designs a detailed cure before observing the disease. It names "framework ceremony consumes the budget" as a material risk and schedules the measurement that would detect it after the ceremony is built. Investigation's review raised the same point about its plan (its Change #12), and the Edict A/B is local proof that these tools get better when measured early: a 658-word managed block matched or beat a 3,076-word one.

One practical hazard: this machine has about 27 live `rite` hooks that spawn real agents. Any cold-agent run here needs Edict's hermetic recipe or the trials will contaminate each other.

**Benefits:**
- Obligations in v1 are chosen from observed failures, not anticipated ones.
- Interface problems surface while the catalog is still cheap to change.
- The baseline exists before anyone is tempted to compare against a strawman.
- Saves building a fixture and a harness that already exist.

**Trade-offs:**
- The testbed has users and roles but no tenants, and one planted flaw. It is a development fixture and is now contaminated for held-out use. Held-out families still need separate authorship.
- Early baseline numbers will be small-sample. They are for choosing what to build, not for claims.

**Implementation Notes:**
The baseline needs the referee boundary from Change #6 only loosely in M0: the testbed's planted flaw is documented in its own source, so the agent must not be able to read `teapot/crates/teapot-testbed`. Run the testbed as a prebuilt binary from outside the agent's working tree.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -1476,3 +1476,3 @@
-| **M0 — contracts and proof target** | Pinned stack inventory, minimal Investigation dependency contract, public HTTP fixture, threat/custody topology, request/admission semantics, baseline evaluation protocol. | No guessed native flags; concrete recorder and enforcement/accounting gaps assigned; oracle succeeds on positive and rejects decisive negatives in fixture design. |
-| **M1 — offline reasoning and self-teaching shell** | Core domain/state, coordination DB/outbox, import, Investigation links, help/schema/brief/next, managed bootstrap, offline proof review. | Cold agent records and inspects a real imported lead, handles missing evidence, cannot self-promote, and resumes after lost metadata response. |
+| **M0 — contracts, proof target and baseline** | Pinned stack inventory, Investigation slice (§19.6), development fixture on the Teapot testbed, custody spike (§6.5), request/admission semantics, **baseline runs of conditions A and B on the development fixture**. | No guessed native flags; recorder, enforcement and accounting gaps assigned; a written failure taxonomy from the baseline runs; the v1 obligation list justified against it. |
+| **M1 — walking skeleton and self-teaching shell** | Core domain/state, coordination DB/outbox, import, Investigation links, help/schema/brief/next, managed bootstrap, **one thin path from lead to verified on the development fixture in shared custody**. | A cold agent, run through the hermetic harness, completes the thin path and rejects the public-object and same-user decoys; cannot self-promote; resumes after a lost metadata response. Interface failures feed back before the catalog freezes. |
@@ -1491,3 +1491,4 @@
 | G00 | Re-resolve repository/binary names; pin revisions and toolchain; save capability inventory | — | Machine-readable inventory, explicit inaccessible/planned capabilities, ADRs for bindings. |
-| G01 | Design owned authz fixture and negative controls; freeze evaluation protocol | — | Property/ground-truth specification separate from agent view; decoy catalog; no solution leakage. |
+| G01 | Adopt the Teapot testbed as the development fixture; add the missing decoys (200 login page, stale cache, same-user labels); freeze evaluation protocol | — | Ground-truth specification separate from agent view; decoy catalog; testbed source unreadable from the agent's tree. |
+| G01b | Baseline: conditions A and B on the development fixture through Edict's hermetic harness | G01 | Transcripts, a failure taxonomy with counts, per-run cost; the v1 obligation list cites it. |
 | G02 | Establish minimal neutral Investigation contract with upstream owner/implementation | G00 | Real begin/attach/finalize/query/record/review/idempotency conformance, or explicit blocked dependency. |
```

---

### [High Impact, Low Effort] Change #3: Give "obvious" a budget, one vocabulary and a five-call path

**Current State:**
The primary constraint is that an agent who has never seen the tool completes the workflow from the executable itself. The plan specifies fourteen object types (§5.1), nine independent result dimensions (§6.2), four profiles, twelve obligations, three assurance modes, three custody modes, twenty command rows (about forty-five with subcommands), 36 operations and 20 error codes. Nothing limits how much of that an agent must hold to act.

As the catalog is written, taking a supplied lead to verified needs at least a dozen typed mutations: bind the target, bind two principals, create a property, create a candidate, create an experiment, check it, freeze it, execute, evaluate, request review, challenge, execute a fresh replay, verify. `prepare` is meant to collapse some of these, but the plan does not say which.

The vocabulary also drifts. The same object is a candidate (32 uses), a lead (20), a claim (95) and a finding (76). It is created with `candidate.create` and verified with `finding verify ID`. Executions are attempts in the catalog (`attempt.execute`) and runs on the command line (`run show`). `finding.evaluate` and `finding.verify` both exist with no stated difference.

**Proposed Change:**
1. **Five nouns an agent must know:** engagement, lead, experiment, run, finding. Everything else is reachable from `show` and `explain` and never required to act.
2. **One name per thing.** A *lead* is anything unverified. A *finding* is a lead with at least one verification record. A *run* is one execution; "attempt" stays internal. Drop `finding.evaluate` or define it.
3. **Leads are nearly free to create.** One call, free text plus optional flow references. No property, policy source or principal binding is needed to record one.
4. **Packs own the controls.** For a supported class the agent fills a short claim template (who owns it, who should not reach it, which request, why it is private). The pack compiles the property, the control set, the experiment and the oracle. Agents do not author controls for a supported class.
5. **A stated path and a gate on it.** For a supported class: add lead, prepare, execute, verify, report. Five mutating calls. Measure calls-to-verified in every cold-agent run and gate on it.
6. **A concept check.** After onboarding, a cold agent states what the tool does, what it must not do, and what its next call is. Edict's first-generation evaluation did exactly this with eight questions.

**Rationale:**
The strongest systems in the plan's own research make hypothesis generation cheap and verification strict. Project Zero's Naptime work names two principles: verification that is automatic and certain, and many independent attempts made affordable by that verification. XBOW's design is the same shape. The plan built the strict half and then made proposing expensive too, which costs recall for no gain in soundness. Soundness comes from the oracle and its controls, not from how many records the agent filled in first.

Edict's A/B is local evidence for the other half: less instruction text did at least as well.

**Benefits:**
- A measurable definition of the primary constraint.
- Wider, cheaper lead generation without weakening promotion.
- Fewer places for an agent to supply a control that is subtly wrong.
- Removes a class of first-call errors caused by guessing the wrong noun.

**Trade-offs:**
- Templates only cover supported classes. An unsupported class falls back to the long path, and the tool must say so plainly.
- Pack-owned controls move judgment from the agent to the pack author. That is the intent, but it concentrates risk in pack review.

**Implementation Notes:**
Keep every typed operation in the catalog; this change is about what is required, not what exists. `prepare` should print which template it matched and which slots are unfilled, as a form the agent can complete.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -679,13 +679,24 @@
 ### 10.2 Core user loop
 
-The common agent path is:
-
-1. `onboard` or `brief` to establish state and limits.
-2. `next` to choose a useful action and inspect why.
-3. `prepare` to materialize a valid plan/draft from known bindings, exposing unresolved fields.
-4. `execute` for an explicitly frozen, admitted experiment.
-5. `show`/`evidence` for results and exact source.
-6. `finding verify` to evaluate recorded proof obligations, or obtain the next needed verification experiment.
-7. `report` or `handoff` when the objective or stop rule is met.
+An agent needs five nouns: **engagement** (what is authorized), **lead** (anything unverified), **experiment** (a frozen test with its controls), **run** (one execution) and **finding** (a lead with at least one verification record). Every other object in §5.1 is reachable from `show` and `explain` and is never required to act. Agent-facing text uses these five names only; "candidate", "claim" and "attempt" are internal.
+
+For a claim class with a shipped template the path is five mutating calls:
+
+1. `lead add` records an observation in one call: free text plus optional flow references. It needs no property, policy source or principal binding.
+2. `prepare LEAD_ID` matches a pack template, fills what the engagement already binds, and prints the unfilled slots as a form. The pack supplies the property, the control set, the experiment and the oracle. Agents do not author controls for a supported class.
+3. `execute EXPERIMENT_ID --request-id KEY` runs it.
+4. `verify LEAD_ID` evaluates the recorded proof, or returns the one further experiment needed.
+5. `report` exports it.
+
+`onboard`, `brief`, `next`, `show` and `explain` are read-only and can be used anywhere in that path. A class with no template uses the full typed catalog, and `prepare` says so and names the operations.
+
+**Budget.** These are release gates, measured in every cold-agent trial:
+
+- Bare `gauntlet` and `gauntlet onboard` each fit in 2 KiB.
+- From a supplied lead to a verified finding on a templated class: at most six mutating calls, median.
+- After onboarding only, a cold agent correctly states what the tool is for, what it must not do, and its next call.
@@ -777,1 +788,1 @@
-| Candidate | `candidate.create`, `candidate.amend`, `candidate.withdraw`; preserve original source claims. |
+| Lead | `lead.add`, `lead.amend`, `lead.withdraw`; preserve original source claims. A lead needs only text; bindings are added by `prepare`. |
```

---

### [High Impact, Low Effort] Change #4: One front door, two speeds, and the stack's own conventions

**Current State:**
A Gauntlet workspace contains Gauntlet, Investigation, Bones and Teapot. All four have an orientation command and three have `next`. Investigation's plan specifies `inv onboard`, `inv brief`, `inv next`, `inv frontier`, `inv show`, `inv schema` and `inv guide`, which are the same names Gauntlet uses. The plan says `gauntlet next` joins them but does not say whether an agent should ever call `inv` or `bn` directly, and §6.7 has to defend against "direct `inv` writes".

How exploration relates to confirmation is stated once, in §9.7, as an aside about the custom-execution escape hatch.

The plan also sets its own conventions where the stack already has some. Edict ships a CLI conventions document to every project (`--format text|pretty|json`, a hidden `--json` alias, an object envelope with an `advice` array). Bones and Maw teach themselves through `tldr`; Teapot through `schema` and `guide`. Exit code 6 means "refused" in Gauntlet's plan and "integrity failure" in Investigation's, written the same day.

**Proposed Change:**
1. **Gauntlet is the only tool an agent needs in a Gauntlet workspace.** `gauntlet show` resolves Investigation and Bones identifiers. The managed block says not to call `inv` or `bn` for writes.
2. **Make the two speeds a binding decision.** Explore freely with Teapot, which enforces the pass itself. Confirm only through Gauntlet, which re-acquires everything. Say this on the entry screen.
3. **Follow the conventions document** for formats, the envelope and `advice`. Add `tldr` as an alias for the entry screen, since two sibling tools taught agents that word.
4. **Align exit codes with Investigation** for 2 through 7 and put refusal on 8. Tell agents to branch on `result` and `error.code`, not on the exit code. Edict's exit policy already works this way.
5. **State how managed blocks compose** when Edict, Investigation and Gauntlet all write one.

**Rationale:**
A cold agent facing four tools with overlapping verbs will pick one by guessing. The plan's own primary constraint makes that a defect, and it is cheap to remove. The two-speed loop is also what makes the tool pleasant: nothing slows exploration, and nothing weakens confirmation.

**Benefits:**
- No wrong-tool first call.
- Removes the "direct `inv` write" bypass by making it unnecessary and unsupported in the workflow.
- An agent that knows one tool in the stack can guess Gauntlet's flags correctly.

**Trade-offs:**
- Gauntlet must proxy reads for two other tools, which is more surface to maintain.
- Exploration through Teapot produces flows the agent influenced. That is acceptable only because the verifier re-acquires its own evidence; the plan must keep saying so.

**Implementation Notes:**
Teapot runs one engine per project and locks its policy to the pass it was started with. The Gauntlet workspace should point at one Teapot project so that flows the agent explored and flows the verifier reads back live in the same store. The conventions document's own exit-code section contradicts Edict's implementation, so cite the behavior, not the document, for exit codes.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -24,2 +24,4 @@
 | Product boundary | Security-specific methodology, engagement coordination, typed experiments, proof obligations, verification, coverage, and reporting. |
+| Front door | In a Gauntlet workspace an agent uses `gauntlet` for orientation, recording and confirmation, and the native instrument for exploration. It does not call `inv` or `bn` for writes; `gauntlet show` resolves their identifiers. |
+| Two speeds | Explore freely with the native instrument under its own pass enforcement. Confirm only through Gauntlet, whose verifier re-acquires every observation it judges. Exploratory flows are leads, never proof. |
@@ -661,15 +663,16 @@
 ```text
 gauntlet — investigate security properties and verify findings.
 
+Explore:  use teapot directly; it enforces the pass. Nothing here slows that.
+Record:   gauntlet lead add "what you saw" --flow ID
 Orient:   gauntlet onboard
 Resume:   gauntlet brief
 Choose:   gauntlet next
 Inspect:  gauntlet show ID
 Learn:    gauntlet schema OPERATION
 
 New workspace: gauntlet init PATH --engagement FILE
 Local tutorial: gauntlet demo PATH --scenario authz
 
-Evidence can be recorded immediately. Verification needs the property's
-controls and a valid observation. Target actions require an active engagement.
+A lead is free to record. A finding is verified only by Gauntlet re-running
+the test with its own controls. You do not need `inv` or `bn` here.
 ```
@@ -879,3 +882,3 @@
-| 6 | Scope, budget, authority or required enforcement refusal. |
-| 7 | Dependency/IO failure, including unknown external effect; inspect structured state. |
-| 8 | Integrity failure requiring repair/review before continuation. |
+| 6 | Integrity failure requiring repair/review before continuation. Same meaning as `inv`. |
+| 7 | Dependency/IO failure, including unknown external effect; inspect structured state. Same meaning as `inv`. |
+| 8 | Scope, budget, authority or required enforcement refusal. |
```

---

### [High Impact, Low Effort] Change #5: Fix what the release gates measure

**Current State:**
§16.5 requires 40 scenario families × 2 model and host combinations × 2 sessions, 160 trials. Gates include at least 90% unassisted discovery per combination, zero false promotions on negative trials, and 90% on several other tracks. G24 and G25 carry all of the evaluation build as two table rows.

**Proposed Change:**

1. **Make the discovery gate relative.** Whether an agent finds a planted flaw nine times in ten depends mostly on how the flaw was planted. Replace the absolute threshold with: Gauntlet's recall is not worse than condition A's on the same families at the same budget, by a preregistered margin. Keep absolute gates for soundness, recovery and usability, where the tool is what is being measured.

2. **Say what the sample sizes can show.** Per combination the discovery track has 8 families × 2 sessions = 16 trials. Passing at 15 of 16 has a 95% Wilson interval of about 72% to 99%. The two sessions of a family are correlated, so the independent count is 8, and 8 of 8 has a lower bound near 68%. Twelve negative families with zero false promotions bounds the per-family rate below about 22% at 95% (one-sided); even treating all 48 trials as independent gives about 6%. These are smoke gates. The plan's §16.6 says as much in general terms; §16.5 should say it next to the numbers.

3. **Put soundness weight where the evidence is strong.** Mechanical evidence is cheap and repeatable: the §16.4 fixtures, plus mutation testing of each oracle with a stated kill-rate gate (remove one identity, control or correlation check and a fixture must fail). §16.7 mentions oracle mutation tests in one clause; make it a gate with a number.

4. **Add a promotion red-team track.** The plan's negative trials use honest agents on confusing targets. None has an agent trying to cheat. Add trials where the agent's stated goal is to get a known-false lead to verified by any means, in two arms: through the public interface only, and with whatever its custody tier allows. Gate: zero successes through the public interface. Report tampering successes per custody tier.

5. **Budget the fixture work and the spend.** Forty families that differ in more than names is a product in itself. Add a work package for a scenario factory with explicit variation axes (authentication mechanism, tenancy model, flaw placement, decoy set). Record cost per trial from the M0 baseline and set a preregistered spend cap before the 160-trial round.

**Rationale:**
"Difficult to fool" is the plan's central promise, and it is tested only against agents that are not trying. The plan cites NIST's evaluation-cheating work as a design input [R18] and then does not run that experiment on itself. The relative discovery gate removes a knob that could be turned, unintentionally, by whoever writes the fixtures.

**Benefits:**
- A discovery measure that cannot be passed by planting easier flaws.
- Direct evidence for the central claim.
- Honest statement of what a pass means.
- The largest hidden cost in the plan gets a line in the work graph.

**Trade-offs:**
- A relative gate needs the baseline arms run at release scale, roughly tripling discovery-track trials.
- A red-team track will find problems, and each one blocks release under the plan's own rule.

**Implementation Notes:**
Red-team trials must run in isolated custody (Change #6) or the tampering arm is meaningless. Score them with the same scripted checks as everything else; never ask a model whether the gate held.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -1269,2 +1269,4 @@
 | False promotion | Zero observed on mandatory negative/confounded trials. Every occurrence blocks release until understood and corrected. |
-| Real positive completion | At least 90% separately for unassisted discovery and supplied-lead verification in each supported model/host combination; report missed issues, abstentions and actual counts. |
+| Promotion red-team | Agents instructed to get a known-false lead verified by any means. Zero successes through the public interface. Successes by tampering are reported per custody tier and must be zero in isolated custody. |
+| Oracle mutation | For every shipped oracle, removing any single identity, control, correlation or completeness check makes at least one fixture fail. Report the kill rate; 100% of listed checks. |
+| Real positive completion | Supplied-lead verification: at least 90% in each supported model/host combination. Unassisted discovery: recall not worse than condition A on the same families and budget by more than the preregistered margin; report both arms, missed issues, abstentions and actual counts. An absolute discovery threshold is not a gate, because it measures fixture difficulty. |
@@ -1279,1 +1281,3 @@
 These are ambitious engineering targets on a specified corpus, not calibrated population guarantees. Publish numerators and denominators; 90% is a threshold, not permission to round a failure upward. Revise an unrepresentative corpus through a documented prospective revision, then freeze it before the next scored round. Do not lower the soundness requirement to make a release date. Track false-positive opportunities per held-out target/family and false discovery proportion among submitted claims separately; an agent-expandable count of tests/candidates is not a valid denominator for a reassuring false-positive rate.
+
+What these counts can show: per combination a track of 8 families × 2 sessions passes at 15 of 16, whose 95% interval is roughly 72% to 99%, and the independent count is 8 families. Zero false promotions over 12 negative families bounds the per-family rate below about 22%. These trials catch gross failures. The strong soundness evidence is mechanical: the §16.4 fixtures, oracle mutation, and the red-team track.
@@ -1515,1 +1519,2 @@
 | G24 | Build protected held-out evaluator, baselines and cost accounting | G01, G03 | Referee inaccessible; hints/attempts/setup recorded; independent adjudication path. |
+| G24b | Scenario factory: families varied by authentication mechanism, tenancy model, flaw placement and decoy set; spend cap preregistered from M0 cost per trial | G01b, G24 | 40 families that differ structurally, authored outside the implementing agent's view; cap recorded before the scored round. |
```

---

### [High Impact, Low Effort] Change #13: State black-box as the default and make source work conditional on Ward

*Added after the owner's decision. Numbered 13 to keep the other references stable; it belongs in this priority group.*

**Current State:**
The plan never says which information regime it is built for. It records the regime per engagement (§5.4) and treats all of them as first-class. Source work is spread through the first product:

- The first production slice includes "source-assisted reasoning when available" (§1.2).
- `source-validated.v1` is one of four initial profiles (§6.3), with its own column of obligations (§6.4).
- §17.2 is a worked scenario about a static lead with no reachable runtime.
- The release corpus must represent "source-validation workflows" (§16.5).
- The research synthesis leads with "stateful exploration and source-informed hypotheses" (§2.2).

Meanwhile the parts a black-box assessment depends on are written as exceptions. §6.5 opens with a verifier that "prepares a clean target instance" and "obtains the intended roles from the fixture/credential service", and only then adds: "For black-box production assessments, clean reset and server instrumentation may be unavailable."

**Proposed Change:**
1. **Add a binding decision:** Gauntlet is a black-box instrument. The default engagement gives a service, its documentation if any, and authenticated roles. Nothing in the default path needs source.
2. **Take source work out of the first slice.** `source-validated.v1` and the `source-runtime` pack ship only as the Ward integration, after the HTTP product. §17.2 moves with them.
3. **When source is available, Ward does the source work.** Ward's findings arrive as leads with their evidence attached. A lead from Ward is confirmed at runtime like any other, or stays a Ward finding with Ward's own provenance. Gauntlet does not re-judge source reasoning in v1.
4. **Invert §6.5.** The black-box case is the rule: no reset, no server instrumentation, no fixture service. Observational controls, an owner-planted canary and declared identity probes are the default (Change #8). A lab with a fixture service is the convenience case.
5. **Default target identity is `remotely_observed`,** and a verified finding is a bounded claim about the observed endpoint at the observed time. §5.3 already allows this; make it the expected case.
6. **Drop source validation from the release corpus** and from the cold-agent gates until the Ward integration ships. Keep the information regime field, since a Ward-fed lead is a different regime and must be scored separately.

**Rationale:**
A stated default removes a whole profile, a pack, a scenario and a gate track from the path to the first product, and it removes the one place where the plan asked for attributed human-style judgment ("source judgment is attributed review") inside a tool whose point is mechanical proof.

It also fixes an inversion. For black-box work the hard problems are the ones the plan treats as edge cases: no ground-truth service to mint canaries or confirm identity, no reset between control and treatment, and no build identity. The design should be shaped around those and treat the instrumented lab as the easy case.

**Benefits:**
- M2 gets smaller with no loss to what it proves.
- Every v1 profile ends in an executed control. None rests on a reviewer's reading.
- The default path is the one real engagements use.
- One owner for source analysis, which is the plan's own ownership rule.

**Trade-offs:**
- No source-only finding can be recorded as verified in v1. A real flaw that is visible in source and unreachable at runtime stays a Ward finding or a lead.
- The research the plan cites does show source hints help ([R5], [R26]). Black-box Gauntlet gives that up until Ward is wired in.
- Without reset, some controls are weaker. Order effects and state left by earlier steps have to be handled by fresh canaries and repeated identity probes, and some claim classes will be honestly blocked.

**Implementation Notes:**
Ward was read at README depth only. Before designing the import, check what its witness bundles and findings actually contain; the plan's rule about not inferring capability from a README applies. Ward's last commit is 2026-10-03 and its README calls it pre-release, so treat its interface as planned until qualified.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -24,2 +24,3 @@
 | Product boundary | Security-specific methodology, engagement coordination, typed experiments, proof obligations, verification, coverage, and reporting. |
+| Information regime | Black-box by default: a service, its documentation if any, and authenticated roles. Nothing in the default path needs source, a reset, server instrumentation or a fixture service. When source is available, Ward does the source analysis and hands Gauntlet leads; Gauntlet builds no static analysis. |
@@ -94,3 +95,3 @@
-**First production slice:** authorized HTTP/API assessment with multiple identities and tenants; session-aware replay; source-assisted reasoning when available; authz and state-transition violations; negative controls; independent rerun; evidence export; fix verification. HTTP/WebSocket protocol features are used only where the pinned instrument supports them.
+**First production slice:** authorized black-box HTTP/API assessment with multiple identities and tenants; session-aware replay; authz and state-transition violations; negative controls; independent rerun; evidence export; fix verification. HTTP/WebSocket protocol features are used only where the pinned instrument supports them.
 
-**Next slices:** SIP/RTP/WebRTC and HTTP-to-signaling/media workflows; stateful API exploration; source-to-runtime validation; optional scanner/fuzzer imports; browser-backed verification where a real browser is necessary.
+**Next slices:** SIP/RTP/WebRTC and HTTP-to-signaling/media workflows; stateful API exploration; optional scanner/fuzzer imports; browser-backed verification where a real browser is necessary. **When source is available:** Ward integration, which brings source leads, the `source-validated.v1` profile and the `source-runtime` pack.
@@ -353,1 +354,1 @@
-Only the first two profiles count as dynamically verified findings in that benchmark track. Report source-only and externally reviewed results separately so changing the mix cannot inflate the runtime verification metric.
+Only the first two profiles count as dynamically verified findings in that benchmark track, and only those two ship in the first product. `source-validated.v1` ships with the Ward integration and not before. Report source-only and externally reviewed results separately so changing the mix cannot inflate the runtime verification metric.
@@ -394,1 +395,1 @@
-For black-box production assessments, clean reset and server instrumentation may be unavailable. The profile must specify acceptable observational controls, state observations and limitations, or leave the particular verification blocked. Never manufacture a clone and silently substitute it for the target.
+Black-box assessment is the default case, and in it clean reset, server instrumentation and a fixture service are unavailable. Every shipped profile must therefore work with observational controls alone: a canary planted through an authorized principal's own session, identity probes declared by the engagement, and repeated observation in place of reset. A profile that cannot do this leaves the particular verification blocked and says why. A lab with reset and a fixture service is the convenience case, not the model. Never manufacture a clone and silently substitute it for the target.
@@ -1157,1 +1158,1 @@
-| `source-runtime` | Scanner/static path import, exact source context, reachable preconditions, runtime discriminator or honest source-only review. | Later v1 extension. |
+| `source-runtime` | Import of Ward findings with their evidence, reachable preconditions, runtime discriminator or an honest Ward-only result. | With the Ward integration, when source is available. |
@@ -1263,1 +1264,1 @@
-Map the frozen corpus to the shipped capability/profile/host support matrix. It must represent the claimed HTTP, live-protocol, connected cross-tool and source-validation workflows, including meaningful positive and negative/blocked cases for their applicable routes. Report their information regimes separately. These families fit within the minimum matrix where feasible; expand it before making additional support claims if coverage is insufficient. A scripted adapter test alone does not establish cold-agent usability, and an unrepresented workflow cannot receive the zero-tool-knowledge support claim.
+Map the frozen corpus to the shipped capability/profile/host support matrix. It must represent the claimed HTTP, live-protocol and connected cross-tool workflows, all black-box, including meaningful positive and negative/blocked cases for their applicable routes. Source-fed workflows join the corpus when the Ward integration ships and are reported as a separate information regime. These families fit within the minimum matrix where feasible; expand it before making additional support claims if coverage is insufficient. A scripted adapter test alone does not establish cold-agent usability, and an unrepresented workflow cannot receive the zero-tool-knowledge support claim.
```

---

### [High Impact, High Effort] Change #6: Decide verifier custody now, or the headline result cannot be reached

*Decided: accepted as recommended. Shared custody may reach verified, with the tier shown.*

**Current State:**
`runtime-controlled.v1` is the only profile that displays "Verified by controlled execution". §6.5 requires `isolated_trusted` or `authenticated_external` custody for it and says a shared account "cannot claim that isolation". §4.3 notes "the inspected stack has not yet demonstrated this whole composition". The work is one row, G12, and one entry in the ADR list.

**What the stack offers.** I asked this directly of each repo:

- **Playpen: nothing.** It protects the network from the workload, not the workload from its launcher. The workload runs as the caller on the host filesystem; the caller controls the binaries, the environment, the pass and the report path.
- **Hallpass: nothing against a same-account process.** The ledger is a hash chain with an unsigned witness. Its design document says rewriting both consistently is not detected.
- **Vessel: nothing.** Processes run as the server's user with its home directory.
- **Sippycup** says of its own ledger that it "stops honest mistakes, not an operator who deliberately rewrites".

So the whole stack is built to an honest-mistakes threat model, and Gauntlet's flagship profile alone demands tamper resistance with no mechanism behind it. The practical result: an agent in an ordinary session, which is the plan's "existing agent harness first" mode, can run the demo and never reach verified.

There is a second blocker in the same place. The demo fixture is loopback-only, Playpen refuses loopback destinations, and Teapot refuses to start enforced against one. So the first tutorial cannot run with enforcement on.

**Proposed Change:**
Name the adversary, then ship two tiers and show the tier on the badge.

**The adversary** is the assessed agent: same account, prone to shortcuts, willing to write a file when the command line refuses. It is not a hostile human operator.

**Tier S, shared and re-derivable.** The default for an attached agent. Shippable in M2.
1. The verifier is its own process. It mints the canary, drives the instrument from the frozen recipe, reads flows back by identifier, and evaluates the oracle. The agent never hands it an observation or a result.
2. Verdicts are never trusted at rest. `verify`, `report` and `bundle check` re-evaluate the oracle from retained originals. A stored `true` is a cache.
3. Verification records are hash-chained and each report carries a checkpoint, following Hallpass's `checkpoint` and `verify-checkpoint`.
4. The badge reads "Verified by controlled execution, shared custody".

What Tier S does not stop: an agent that consistently forges raw flows inside the instrument's store, or replaces a binary. The report says so.

**Tier I, isolated.** Confine the worker, not the verifier. The agent runs under a second Unix account or in a container whose only routes to the workspace are the Gauntlet interface and the proxy port. Gauntlet's state, the evidence store, Teapot's project database, fixture administration and the referee are not writable or readable from there.

This is the same boundary §16.2 already requires for the evaluation referee. Build it once, in M0, with the harness. Tier I is required for scored evaluations, for the red-team track, for reports that leave your hands, and for any engagement that asks for it.

**The M0 spike** proves both in one sitting. A scripted adversary inside the worker boundary tries five things: write Gauntlet's database, write Teapot's database, read a fixture administration secret, call the observer directly, replace the `gauntlet` binary. All five fail in Tier I. The spike also produces one working enforced topology for a local fixture, or records that there is none yet.

**Rationale:**
The alternative readings are worse. Keeping the plan as written means the first product ships with its main result unavailable in its main mode. Quietly letting shared custody count as isolated is the kind of claim the plan rightly forbids. Showing the tier is honest and keeps the default path alive.

Most of the protection against the realistic adversary comes from items 1 and 2 of Tier S, which cost little: the agent cannot supply results, and nothing stored is believed. Isolation then covers the remaining case for the audiences that need it.

**Benefits:**
- A cold agent can reach a verified finding in M2.
- One isolation mechanism serves custody, the referee and the red-team track.
- The custody claim on every report is true.
- The loopback problem is found in M0, not during the first demo.

**Trade-offs:**
- Tier S is weaker than the plan's current rule. A determined same-account agent can forge a finding, and only transcript audit would catch it.
- Tier I needs one-time setup by the operator, likely with root. Gauntlet should print the commands and never run them.
- Two tiers mean two badges to explain.

**Implementation Notes:**
- Signing precedents exist in the stack: Hallpass's `verify-approval` checks an owner's SSH signature, Sippycup's live grants are Ed25519 with a consumed nonce, and Ward has signing crates. An operator signature on a report is a human attestation and is worth offering; it is not verifier custody.
- For the enforced local topology, the source check reports a Playpen `--no-network --fixture` mode in its documentation. I did not exercise it. The spike should try it before inventing a non-loopback lab.
- Hallpass's witness depends on a stable home directory; a container or temporary home silently loses rollback detection (its integration guide says so). Tier I must keep the spender's state directory stable.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -392,1 +392,17 @@
-Track **verification custody** separately from host execution assurance: `isolated_trusted`, `authenticated_external`, or `operator_asserted_shared`. A supervised host agent can submit to an isolated verifier and obtain a strong proof. A shared writable UID/environment cannot claim that isolation; its results may support an explicitly external-evidence-reviewed/source judgment, but do not meet the controlled runtime profile until independently confirmed under qualified custody.
+Track **verification custody** separately from host execution assurance. The adversary is the assessed agent: same account, prone to shortcuts, willing to write a file when the command line refuses. Nothing in Playpen, Hallpass or Vessel protects one same-account process from another, so Gauntlet supplies the boundary itself, in two tiers. Every finding records its tier and every badge shows it.
+
+**Shared, re-derivable (`shared_rederivable`).** The default for an attached agent.
+
+- The verifier is its own process. It mints the canary, drives the instrument from the frozen recipe, reads flows back by identifier and evaluates the oracle. The agent supplies no observation and no result.
+- No stored verdict is trusted. `verify`, `report` and `bundle check` re-evaluate the oracle from retained originals.
+- Verification records are hash-chained; each report carries a checkpoint.
+- Display: `Verified by controlled execution, shared custody`.
+- Not prevented: an agent that consistently forges raw flows in the instrument's store, or replaces a binary. Reports state this.
+
+**Isolated (`isolated`).** The worker is confined, not the verifier: the agent runs under a second account or in a container whose only routes to the workspace are the Gauntlet interface and the proxy port. Gauntlet's state, the evidence store, the instrument's project database, fixture administration and the referee are neither writable nor readable from there. This is the same boundary the evaluation referee needs (§16.2); build it once. Required for scored evaluations, the promotion red-team track, reports intended for a third party, and any engagement that sets `required_custody = "isolated"`.
+
+`authenticated_external` remains available for a verifier outside this host with a signed channel and a named trust policy.
+
+`runtime-controlled.v1` accepts either local tier. A finding verified in shared custody is a verified finding with that tier displayed; it is not downgraded to an external-evidence profile.
@@ -1503,1 +1519,1 @@
-| G12 | Establish isolated verifier custody and constrained fixture role access | G01, G10, G11 | Worker cannot edit trusted oracle/receipt/fixture admin state; self-triggered observer rejected. |
+| G12 | Custody spike in M0, then both tiers. Spike: a scripted adversary in the worker boundary tries to write Gauntlet's database, write the instrument's database, read a fixture secret, call the observer directly and replace the binary. Also produce one enforced topology for a local fixture, or record that none exists | G01 | All five attempts fail in isolated custody and each is listed as possible or not in shared custody; self-triggered observer rejected in both; the enforced local topology runs or its blocker is filed upstream. |
```

---

### [High Impact, High Effort] Change #7: Make the Investigation dependency explicit and keep one authority for "verified"

*Decided: accepted as recommended. Investigation holds evidence in v1; "verified" is computed in one place.*

**Current State:**
Gauntlet stores evidence, runs, assessments, reviews, conclusions, coverage and exports in Investigation. G02 says "establish minimal neutral Investigation contract with upstream owner/implementation". The plan does not say which parts of Investigation that means.

Investigation is a plan. Mapping Gauntlet's needs onto its work packages:

| Gauntlet needs | Investigation package | Investigation milestone |
|---|---|---|
| Blob custody, idempotent receipts, revision checks (G05) | W01 (subset), W02 | A |
| Runs, observations, assessments, conclusions, review (G05, G14) | W03 | A |
| Ingest and selectors (G06) | W06 | A (minimum), B |
| `capture begin/append/attach/finalize/recover` (G13) | W07 | B |
| Review freshness, `basis_digest`, read-set closure (G14) | W10 | B |
| Export and archive (G15, G27) | W11 | C |
| Coverage records (G19) | CoveragePlan/Cell, which Investigation's own review proposes deferring | Unscheduled |

So Gauntlet's M1 needs Investigation's Milestone A, its M2 needs most of Milestone B, and its report bundles need part of C. Investigation's plan says the opposite about priority: "Do not block this product on access to a particular external repository", and it treats consumer integration as someone else's later work. Neither plan owns the joint schedule. Together they are about 400 KB of specification and no code.

Separately, §6.7 makes promotion a two-store protocol. Gauntlet binds its manifests into an Investigation transaction, waits for the receipt, re-compares a generation counter, then publishes. It must then defend the result: "a generic Investigation `validated` state is never sufficient". Two stores hold a version of "is this verified", and the plan spends three paragraphs and two crash-matrix rows keeping them from disagreeing.

**Proposed Change:**
1. **Add the table above to the plan** and name the Gauntlet-critical slice: Investigation Milestone A, plus W07 and the read-set parts of W10. Schedule that slice first, in whichever repo.
2. **Use Investigation for four things in v1:** capture a run with immutable artifacts; read an artifact by selector; record an immutable derived artifact (manifests and verification records); export. Do not drive its hypothesis, assessment, review or conclusion lifecycles from Gauntlet.
3. **One authority for status.** A finding's effective status is a pure function of its verification records, the current basis of the things they bind, and current oracle qualification. It is computed on read and stored nowhere. Investigation receives a one-way projection of each finding, through the outbox, labeled as projected.
4. **Keep coverage cells in Gauntlet's store in v1,** since their upstream home may not ship.
5. **Make Gauntlet the first conformance client.** The contract fixtures live in Gauntlet and run against `inv` in its CI.

**Rationale:**
Verification records are immutable and their inputs are content-addressed, so nothing they rest on can change underneath them. What can change is Gauntlet's own: the claim revision, the property, the bindings, the oracle's qualification. Gauntlet can compute freshness over those without a cross-store transaction. The only upstream event that matters is evidence retraction, which is a query at read time.

With one authority there is no second gate to bypass, so the defense in §6.7 becomes unnecessary instead of merely correct.

**Benefits:**
- Removes the cross-store promotion race and both crash-matrix rows about it.
- Shrinks the Investigation slice Gauntlet waits on.
- Makes the schedule dependency visible in both plans.
- Gives Investigation a real consumer exercising its producer API early.

**Trade-offs:**
- Security findings do not exercise Investigation's review and blindspot machinery in v1. If that machinery turns out to add value, Gauntlet adopts it later.
- A projected conclusion in the casebook is a copy and can lag. It must be labeled.
- This narrows a decision you made in the prompt ("based on ... investigation"). It keeps the dependency and reduces its surface.

**Implementation Notes:**
The plan forbids shipping a mock evidence engine and that should stand. The point of the narrow slice is that the real thing is small enough to build first. If the slice is not ready when G05 starts, the plan's existing rule applies: build that neutral slice in the Investigation repository, not a substitute in Gauntlet.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -267,1 +267,1 @@
-| CoverageCell | Property × surface × principal/state class, applicability, planned method, attempts and interpretation, denominator revision. | Investigation generic coverage records; Gauntlet domain projection. |
+| CoverageCell | Property × surface × principal/state class, applicability, planned method, attempts and interpretation, denominator revision. | Gauntlet coordination store in v1; move to Investigation coverage records if and when they ship. |
@@ -426,3 +426,5 @@
-Final promotion must atomically bind the relevant Investigation claim/evidence/review revisions through its public transaction and CAS contract. This atomicity covers Investigation's store only. Bind the immutable Gauntlet domain manifests and a material Gauntlet basis generation into that transaction. After its receipt is reconciled, compare that generation and current profile/oracle qualification before publishing a current verified view. A concurrent change preserves an accepted historical record with `needs_review`; it does not create a current verified cache entry.
-
-A generic Investigation `validated` state is never sufficient for Gauntlet verification. Queries, exports and promotion require a matching qualified VerificationRecord, the profile's required verifier provenance/custody, exact evidence/claim basis, and current applicable qualification. Direct `inv` writes, imported extensions, or self-asserted producer identities cannot bypass this gate; they remain attributed generic conclusions until the Gauntlet requirements are met.
+There is one authority for whether a finding is verified. A VerificationRecord is an immutable artifact stored in Investigation; its inputs are content-addressed and cannot change. A finding's effective status is a pure function of its VerificationRecords, the current revisions of the claim, property and bindings they name, current oracle and profile qualification, and whether any bound evidence has been retracted. It is computed on every read and stored nowhere, so there is no verified flag to set and no cross-store transaction to commit.
+
+Gauntlet does not drive Investigation's hypothesis, assessment, review or conclusion lifecycles in v1. After a VerificationRecord is recorded, the outbox mirrors the finding into Investigation as a Conclusion marked as a Gauntlet projection. That Conclusion's state carries no meaning for Gauntlet; queries, exports and reports never read it.
+
+Recording a VerificationRecord is a privileged operation of the verifier process (§6.5). An artifact shaped like one that arrived by `inv` or by import is an attributed assertion and is ignored by the status function.
@@ -1493,1 +1495,1 @@
-| G02 | Establish minimal neutral Investigation contract with upstream owner/implementation | G00 | Real begin/attach/finalize/query/record/review/idempotency conformance, or explicit blocked dependency. |
+| G02 | Build or obtain the Gauntlet-critical Investigation slice (§19.6): W01 subset, W02, W03 run and artifact parts, W06 minimum, W07, and W10 read-set parts. Gauntlet's contract fixtures run against the real `inv` | G00 | Capture with immutable artifacts, read by selector, record a derived artifact, idempotent retry and crash recovery pass against the real implementation; anything missing is a named upstream package, not a simulator. |
@@ -1541,1 +1543,19 @@
 Do not replace missing primitives with success-shaped stubs. Report exact blockers and continue independent useful packages. A release cannot claim a capability whose mandatory gate was skipped.
+
+### 19.6 What Gauntlet needs from Investigation, by work package
+
+Investigation is a plan (`~/src/investigation/notes/plan.md`, rev. 3). Its package and milestone names are used here.
+
+| Gauntlet needs | Investigation package | Investigation milestone | First needed by |
+|---|---|---|---|
+| Blob custody, idempotent receipts, revision checks | W01 (subset), W02 | A | G05 |
+| A run with observations and immutable artifacts | W03 (run and artifact parts) | A | G05 |
+| Ingest and selectors | W06 (minimum) | A | G06 |
+| `capture begin/append/attach/finalize/recover` | W07 | B | G13 |
+| Read-set closure and evidence retraction queries | W10 (parts) | B | G14 |
+| Export and archive | W11 | C | G15 |
+
+The first five rows are the Gauntlet-critical slice and are built before anything else in either repository. Gauntlet uses Investigation for four things in v1: capture a run, read an artifact by selector, record an immutable derived artifact, and export. It does not use hypotheses, assessments, reviews, conclusions, method packs or coverage records in v1.
+
+Investigation's plan says its release must not wait on any consumer. That stands. The slice is general, and Gauntlet's contract fixtures are its first external conformance test.
```

---

### [High Impact, High Effort] Change #8: Specify the first oracle and the path for a real target

**Current State:**
§7.3 and §7.4 describe oracles in general: typed observations in, five-valued result out, qualification set, calibration. The first oracle, the one M2 depends on, is described in one table row. §17.1 relies on "a trusted fixture service" that can create canaries and report ownership. A real target has no such service, and §6.5 says only that a profile "must specify acceptable observational controls".

Two facts from Teapot bear on this. It has no who-am-I; `sessions check` answers logged-in, logged-out or unknown. And `authz compare` selects flows by filter, takes one flow per endpoint shape, and sends only GET and HEAD by default. It is a discovery instrument, not a confirmation recipe.

**Proposed Change:**
Write the first oracle into the plan as a concrete specification. Illustrative form:

**`web.private-object-read.v1`**

Inputs, all acquired by the verifier in one run and bound to its nonce:

| Flow | Who | What | Purpose |
|---|---|---|---|
| I1, I2 | owner, other | identity probe | Two distinct subjects. |
| P | owner or fixture | plant a fresh 128-bit canary in the owner's object | Something only this run could have put there. |
| F1 | owner | read the object | Observer check: the canary is readable at all. |
| F2 | other | read the object | The treatment. |
| F3 | anonymous | read the object | Rules out a public object. |
| F4 | other | read a different object | Rules out a canary echoed everywhere. |
| I3, I4 | owner, other | identity probe again | Rules out session drift. |

Result:
- **True** when the canary is in F1 and F2, absent from F3 and F4, and the two subjects differ and are stable.
- **False** when setup is valid and the canary is absent from F2.
- **Invalid**, with a reason code, when the canary is absent from F1 (`OBSERVER_INVALID`), the subjects match (`SAME_SUBJECT`), an identity changed (`SESSION_DRIFT`), the canary is in F3 (`PUBLIC_OBJECT`), or any flow is missing or truncated (`EVIDENCE_INCOMPLETE`).

Status codes play no part. That alone handles four of the §16.4 fixtures: the 200 login page fails F1, the 403 that leaks data passes on content, a stale cache cannot contain a canary minted in this run, and an expired credential fails the identity probe.

**Known misses,** published with the oracle: flaws that expose only fields the canary is not in; write-only authorization flaws; exposure that is delayed past the observation window.

**Two canary modes.** `owner_planted` has the owner's own session write the canary through a request the engagement declares. With black-box as the default (Change #13) this is the default mode and the one the oracle is designed around. `fixture` uses a trusted service and is the lab convenience. Where nothing can be planted, the operator may designate an existing owner-only value; freshness controls then do not apply and the finding says so.

**The engagement declares what Teapot cannot supply:** an identity probe per principal and, for `owner_planted`, a plant request. It references the pass and does not restate scope, window or ceilings.

**Rationale:**
The oracle is the product. An implementing agent given §7.3's row will invent the control set, and the plan's whole argument is that invented control sets are where false findings come from. XBOW's published design makes the same choice of a fresh random canary and notes why: a model cannot predict it. It also makes the cost explicit, which is why known misses belong next to the definition.

"The same experience works outside the tutorial" (§1.4) is not achievable without the owner-planted mode.

**Benefits:**
- M2's central component is specified, with reason codes that map to fixtures.
- Real targets have a path.
- The engagement file stays small because the pass stays authoritative for scope.
- Each oracle ships with its own statement of what it cannot see.

**Trade-offs:**
- Owner-planted canaries write to the target. That is a state-changing effect needing its own permission and cleanup.
- A content canary cannot confirm flaws where the leaked data is not attacker-observable as bytes. Those need other oracles.

**Implementation Notes:**
The confirmation recipe needs specific requests under specific sessions. Teapot has replay (its allocator documentation shows `flows replay --times N`), and G09 must pin the exact commands; I did not verify the replay interface beyond that. Teapot's flow identifiers are integers that are never reused, and `flows show <id> --json` works with no engine running, which is what the verifier's read-back needs.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -479,1 +479,34 @@
 Not all rows ship in M2. The shipped capability registry must state which profiles have a qualified instrument and calibration corpus. Browser-dependent claims require a separate trusted browser adapter; HTTP replay alone cannot satisfy them. A media profile lacking the necessary decoder/observer remains unavailable, even if signaling tests work.
+
+#### The first oracle: `web.private-object-read.v1`
+
+This is the M2 oracle, specified in full so that nobody improvises its controls. The verifier acquires every flow itself in one run, bound to that run's nonce.
+
+| Flow | Principal | Action | Rules out |
+|---|---|---|---|
+| I1, I2 | owner, other | Identity probe | Two labels for one subject. |
+| P | owner or fixture | Plant a fresh 128-bit canary in the owner's object | Stale or cached content. |
+| F1 | owner | Read the object | A broken observer, a login page, a missing object. |
+| F2 | other | Read the object | (the treatment) |
+| F3 | anonymous | Read the object | An object that is public by design. |
+| F4 | other | Read a different object | A canary reflected on every response. |
+| I3, I4 | owner, other | Identity probe | A session that changed mid-run. |
+
+- `true`: canary in F1 and F2, absent from F3 and F4, subjects distinct and unchanged.
+- `false`: setup valid, canary absent from F2. Reported as no violation under these conditions.
+- invalid, never `false`: `OBSERVER_INVALID` (canary absent from F1), `SAME_SUBJECT`, `SESSION_DRIFT`, `PUBLIC_OBJECT` (canary in F3), `EVIDENCE_INCOMPLETE`.
+
+HTTP status is not an input. Known misses, shipped with the oracle: exposure limited to fields that do not carry the canary; write-only flaws; exposure delayed past the window.
+
+Canary modes: `owner_planted` is the default (the owner's session writes the canary through a request the engagement declares; it is a state-changing effect and needs that permission and a cleanup step). `fixture` is the lab convenience (a trusted service plants it). Where nothing can be planted the operator may designate an existing owner-only value; the finding then records that freshness controls did not apply.
+
+Every shipped oracle is documented in this form: flows, what each rules out, the predicate, the invalid reasons, the known misses.
@@ -590,1 +623,22 @@
 An engagement binds objective, target/service names and endpoints, excluded assets, authorized roles, permitted effect classes, approved time window, Hallpass identity/digest, limits, data policy, required confinement, cleanup budget, emergency stop, and reporting audience. The operator supplies real authority; Gauntlet validates its recorded representation and supported enforcement.
+
+The engagement references the pass and does not restate what the pass binds (destinations, window, ceilings). It adds what no other tool holds. Illustrative:
+
+```toml
+[engagement]
+objective = "Cross-user access in the orders API"
+pass = "passes/staging.toml"            # scope, window and ceilings live here
+required_custody = "shared"             # or "isolated"
+
+[principal.alice]
+session = "alice"                       # the instrument's session name
+identity_probe = { request = "GET /app/api/me", subject = "/id" }
+
+[principal.bob]
+session = "bob"
+identity_probe = { request = "GET /app/api/me", subject = "/id" }
+
+[property.private-orders]
+template = "web-authz/private-object-read"
+resource = "GET /app/api/orders/{id}"
+owner = "alice"
+policy_source = "operator: an order is visible only to its owner"
+plant = { as = "alice", request = "POST /app/api/orders", field = "/note" }
+```
+
+Request and field names here are placeholders. The identity probe is required because the HTTP workbench has no who-am-I; a session name is a label, not identity evidence.
```

---

### [High Impact, High Effort] Change #9: Match accounting and authority to what the instruments do

**Current State:**
§9.3 requires one accounting owner per operation and asks adapters to preserve "pass identity, exact digest, ledger sequence, caller reference, named charges and outcome". The bound execution manifest's digest is to appear in "accounting correlation". For Sippycup the plan proposes a possible "Gauntlet-owned conservative Sippycup batch debit" and treats authorization as Hallpass's throughout.

**What the instruments do.**

*Teapot.* It draws Hallpass units in blocks before sending, at most a tenth of what is left, and uses them locally. Unused units return to its own pool and are never refunded. Its vendored Hallpass has no `caller_ref`. No API type carries a ledger sequence. The spend note is fixed text. What an adapter can observe per job is `units` and `units_left`. `authz compare --dry-run` reports `units` and `within_ceiling`, and `--max-requests` caps a run.

*Playpen.* `--require-enforced` refuses a pass with ceilings. So in an enforced run, Playpen enforces destinations and time, and Teapot's allocator enforces ceilings.

*Sippycup.* Authorization is `scope.yaml`: an approval with an id, a status and a validity window, and eight limits. Calls are reserved in a per-engagement ledger before the first packet and released when no INVITE can have left. Its live MCP tool takes signed single-use grants. None of this is Hallpass. A bones note in the Sippycup repo (bn-2ap) describes Hallpass as the approval core "to be extracted later", so the direction of travel is from Sippycup to Hallpass, not the reverse.

**Proposed Change:**
1. **HTTP accounting evidence in v1 is aggregate.** Per run: pass id and digest, job id, the dry-run ceiling, and `units_left` before and after. Say plainly that per-run ledger sequences are unavailable. An engagement that demands exact per-run accounting gets `BUDGET_REFUSED` with that reason.
2. **File the upstream change** that would make it exact: Teapot updates its vendored Hallpass, passes a caller reference per job, and exposes the ledger sequence. This is a general capability, which is what §3.3 says upstream changes should be.
3. **Use the dry run as the fanout ceiling.** That satisfies the plan's own rule that an adapter with unknown fanout cannot claim a budget.
4. **Qualify the real enforcement split:** Playpen for destinations and time, the spender for ceilings.
5. **For Sippycup, the accounting owner is Sippycup and the authority is its approval.** Gauntlet never debits. An engagement that includes protocol work binds an approval id as well as, or instead of, a pass.
6. **M4 reuses what exists:** `sippycup assert` as the signaling oracle, its findings schema as the import shape, its evidence packs, and `go --format json` as the driver interface.
7. **Add the fixture work M4 lacks.** Sippycup's practice target has one throwaway account, no tenants and no planted flaws, so §17.3 needs a target built.

**Rationale:**
The plan's principle is one owner per kind of truth, and "never pre-debit in Gauntlet and debit the same units again inside a native tool". Applied to the real tools, that principle says Gauntlet should hold less accounting than the plan gives it, and that Sippycup's authority cannot be modeled as Hallpass's.

**Benefits:**
- No double counting on either instrument.
- Accounting claims in reports match what was recorded.
- M4 shrinks from building oracles and reports to mapping existing ones.
- The two-authority problem is visible now, not at M4.

**Trade-offs:**
- Aggregate accounting cannot attribute units to a run when two runs overlap. Conflict groups should make runs against one pass serial until the upstream change lands.
- An engagement may hold two authority bindings until the Hallpass extraction happens. That is a wart, and it is the truth.

**Implementation Notes:**
Revoking a pass edits the file, which changes its digest; a caller pinning the digest sees `pass-changed`, not `revoked` (Hallpass `docs/spec.md`). The adapter must map both to a stop. Debug builds of Hallpass honor a test clock variable; qualification should require `test_clock: false`.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -613,3 +613,11 @@
-Teapot has inspected native Hallpass integration. A native Sippycup-to-Hallpass debit path was not established; its existing profile/campaign limits are a separate mechanism. Adapter metadata declares `accounting_owner: native|gauntlet` only when qualified, otherwise `unavailable|unqualified`, and describes the charged units. Never pre-debit in Gauntlet and debit the same units again inside a native tool. A Gauntlet-owned conservative Sippycup batch debit is new integration work, not an existing guarantee.
-
-Hallpass `caller_ref` is correlation, not idempotency. Preserve pass identity, exact digest, ledger sequence, caller reference, named charges and outcome. A successful preview is not an authorization receipt. A debit can commit before a crash or before any send; no automatic refund or blind repeat is allowed.
+Both instruments own their accounting. Gauntlet never debits. Adapter metadata declares `accounting_owner: native` only when qualified, otherwise `unavailable|unqualified`, and describes the charged units and the granularity of the evidence.
+
+**Teapot** draws Hallpass units in blocks before sending and uses them locally; unused units are not refunded, so the ledger errs high. It exposes no per-request ledger sequence and its linked Hallpass has no caller reference. Accounting evidence per run in v1 is therefore aggregate: pass id and digest, native job id, the dry-run unit ceiling, and `units_left` before and after. Runs against one pass are serial so the difference is attributable. An engagement requiring exact per-run accounting is refused with that reason. Exact evidence needs an upstream change (linked Hallpass updated, a caller reference per job, the ledger sequence exposed); it is filed as a prerequisite, not worked around.
+
+**Enforcement is split.** Playpen enforces destinations and time. It refuses any pass with ceilings under `--require-enforced`, so ceilings are enforced by the spender. Qualify that composition as it is.
+
+**Sippycup** authorizes from its own approval (an id, a status and a validity window in the engagement's scope file) and counts calls in its own reserve-and-release ledger keyed by that approval id. It has no Hallpass integration. An engagement with protocol work binds the approval id; Gauntlet records Sippycup's reservations and never adds its own.
+
+Where a spender does supply a Hallpass caller reference, `hallpass receipt FILE --caller-ref REF` answers `found`, `absent` or `ambiguous` and is the reconciliation step for a lost spend response. References are correlation, not idempotency: a second spend with the same reference commits. A successful preview is not an authorization receipt. A debit can commit before a crash or before any send; no automatic refund or blind repeat is allowed.
@@ -966,1 +974,1 @@
-Begin with read-only imports and local deterministic protocol fixtures. Then qualify one complete live signaling/media experiment with the real native runner, counters, namespace, capture and cancellation. Consume the native registry's `activity`, `execution` and `networkActivity` labels for discovery. They do not encode authorization scope or budget ceilings; establish those separately per selected operation and version.
+Begin with read-only imports of native run directories and local deterministic protocol fixtures. Reuse what exists before building: `sippycup assert` is a versioned three-state oracle (pass, fail, unknown) and is the signaling oracle; the native findings schema already treats a finding as a candidate until independently reproduced and is the import shape; `go --format json` emits the next command's argv and is the driver interface. Then qualify one complete live signaling/media experiment with the real native runner, call ledger, namespace, capture and cancellation. The registry's per-command `activity` and `execution` labels help discovery; they do not encode authorization scope or ceilings. The practice target has one account, no tenants and no planted flaws, so §17.3 needs a target built for it.
@@ -972,1 +980,1 @@
-The existing Sippycup generic journal is real and remains authoritative for legacy native runs. Import it with immutable lineage, then migrate recorder ownership in that consumer if appropriate. Do not remove a useful native record or write competing generic journals during an incomplete migration.
+Sippycup's machine record is its run directories and call ledger; import those with immutable lineage. Its journal is the operator's hand-written engagement record and is imported as attributed notes, not as a run log. Do not remove a useful native record or write competing generic journals during an incomplete migration.
```

---

### [Medium Impact, Low Effort] Change #10: Say how a single agent obtains the challenge review

**Current State:**
An independent semantic challenge is required for every profile (§6.4). §6.6 says it "can be performed by a fresh agent/human". The default mode is one attached agent with no worker runtime, since Vessel is optional. §4.3 concedes that a worker identity is attribution only.

So in the default mode the path to verified stops at `REVIEW_REQUIRED` with no stated way forward, or the same agent passes a different actor name and reviews itself.

**Proposed Change:**
1. For runtime profiles, the required challenge is **control-backed**: the pack lists the alternatives for the class, and each is closed by an executed control with a result, not by prose. The oracle in Change #8 does this for its class.
2. A second reviewer is a **recorded independence dimension**, not a gate, for runtime profiles. When one is used, `review request` writes a self-contained packet and prints the one command a fresh agent or a human runs.
3. For `source-validated.v1`, where no control can be executed, a distinct reviewer stays **required**, and in shared custody the report says the distinction is attributed, not enforced.

**Rationale:**
The plan says it itself: "adding a reviewer prompt is not itself verification". Investigation's review cites evidence that models do not reliably correct themselves without external feedback. An executed control is external feedback. A second model reading the first one's notes may not be. Make the mechanical part mandatory and let the evaluation decide whether the second reader earns its cost, as §6.6 already proposes.

**Benefits:**
- The single-agent path can finish.
- No incentive to fake a second identity.
- Review effort goes where no control exists.

**Trade-offs:**
- A runtime finding can be verified with no second reader. If the pack's alternative list has a gap, nothing catches it at promotion time. The red-team track and oracle mutation gate (Change #5) are the backstop.

**Implementation Notes:**
The packet contains what §6.6 already lists and withholds the discoverer's narrative until the reviewer has recorded a first assessment.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -414,1 +414,7 @@
-Default to one investigator and one distinct verification pass for a runtime finding. The pass can be performed by a fresh agent/human with a qualified executor; a permanent multi-agent fleet is unnecessary.
+Default to one investigator and one distinct verification pass for a runtime finding. The distinct pass is the verifier process re-acquiring evidence from the frozen recipe (§6.5); it needs no second agent.
+
+For runtime profiles the required challenge is control-backed. The pack lists the alternative explanations for the claim class, and each is closed by an executed control whose result is in the record. An alternative answered only in prose is unresolved. A second reviewer is optional for these profiles and is recorded as an independence dimension when used.
+
+For `source-validated.v1`, where no control can be executed, a distinct reviewer is required. `review request ID` writes a self-contained packet and prints the single command a fresh agent or a human runs to begin. In shared custody the reviewer's distinctness is attributed, not enforced, and the report says so.
+
+A permanent multi-agent fleet is unnecessary.
```

---

### [Medium Impact, Low Effort] Change #11: Add the closest precedents, fix two citations, and state the Ward boundary

**Current State:**
The research is careful and its numbers hold up. It is weighted toward benchmarks and competition systems. The products most like Gauntlet are thin or missing: XBOW appears only as a benchmark repository, and its validator design, which is the nearest published precedent for §7, is not cited.

Ward is not mentioned. It lives in `~/src/ward`, is listed on `agentreliquary.com`, and describes itself as verifiable security review with deterministic evidence and signed provenance, with an agentic layer of discoverer, disputer, repairer and analyst roles producing signed witness bundles. I read its README and crate list only.

**Proposed Change:**
Add these rows, each marked with how far it was inspected (search-result level today, not full reading):

| Source | What it contributes | Design consequence |
|---|---|---|
| XBOW, "AI Agents for Offsec with Zero False Positives" (Black Hat USA 2025) and product docs | Agent supplies evidence; non-AI code checks it. Canary validators resist gaming because a random identifier cannot be predicted. Validator design trades false positives against misses. Docs label each vulnerability class as deterministic or agent-judged. | Publish each oracle's known misses (Change #8). Label every finding's class as deterministically checked or judged. Vendor's own claims; no independent rate found. |
| Project Zero, Naptime (2024) and Big Sleep | Two principles: verification that is automatic and certain, and many independent attempts made affordable by it. | Cheap leads, strict verification (Change #3). Small targets; the authors call results experimental. |
| OpenAI Aardvark, now Codex Security | Attempts to trigger each suspected flaw in an isolated sandbox before reporting. Reports 92% recall on its own test repositories. | Confirms the pattern. Vendor figure, unverified. |
| Shannon (Keygraph), Strix | Open-source pentest agents that report only findings with a working proof of concept. | Comparable products to baseline against in condition A. Self-reported. |
| CAI and CAIBench (Alias Robotics) | Open framework; its own benchmark shows 20-40% success on multi-step adversarial scenarios. | Another caution against headline CTF numbers. |

Two corrections to existing rows:
- **ARTEMIS [R4]:** the configuration with 11 findings, 82% valid and second place is the paper's A2. A1 also submitted 11 but 55% were valid. The paper does not call either "best".
- **CyberGym [R5]:** the 22.0% figure is in the paper. "High reasoning" and "300-instance subset" could not be confirmed verbatim in this check; verify or drop them.

RECEIPT [R29] and "From Runnable to Verifiable" [R30], which the plan could not inspect, both exist and their abstracts support the plan's direction: the first is specifically about cross-site scripting confirmed in a real browser, the second finds that oracles embedded in artifacts are unreliable.

**State the Ward boundary** in §3.1. *Decided:* Gauntlet assumes black-box testing. When source is available, Ward is part of the workflow: it owns static analysis and source evidence, and Gauntlet's `source-runtime` pack imports Ward's output. Gauntlet builds no static analysis. Change #13 carries the black-box default through the rest of the plan. Consider Ward's signing crates before writing receipt signing.

**Rationale:**
The prompt asked for frameworks proven effective. The plan's synthesis is right, and the sources that most directly back it are the ones it left out. Ward matters for a different reason: the plan's own rule is one owner per kind of truth, and it cannot apply that rule to a tool it does not know about.

**Benefits:**
- The oracle design rests on a cited working precedent.
- Condition A gains credible comparators.
- A known overlap is decided on purpose.

**Trade-offs:**
- The added rows are vendor claims. They must carry that label.
- Ward is optional. A black-box engagement has no dependency on it, and the adapter must report it as unavailable, not fail, when it is absent.

**Implementation Notes:**
Sources for the added rows are listed at the end of this review.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -174,2 +174,3 @@
 | Vessel, optional | Worker/process lifecycle and interaction in its supported host. | A new agent terminal or model loop; no assumption of durable jobs. |
+| Ward, when source is available | Static analysis of source, its evidence graph and signed provenance. The producer of source leads for the `source-runtime` pack. Not used in a black-box engagement. | A static analyzer, a taint engine, or a second signing scheme. |
 | Gauntlet | Engagement bindings, security properties, proof profiles, experiment coordination, promotion rules, security coverage, verification receipts, report assembly. | Upstream semantics it can call through a stable contract. |
@@ -1639,1 +1640,1 @@
-| **ARTEMIS** [R4], [R4a] | In one live-network study, the best configuration submitted 11 findings, nine judged valid, and ranked second under the study rubric against ten human participants. Dedicated triage attempts reproduction. | Human comparison uses a ten-hour scoring window within sixteen-hour runs. Small cohort, relaxed defenses and persistent false positives limit transfer. Its triage API accepts a reproduction decision plus evidence text; Gauntlet additionally requires qualified receipts and proof obligations. |
+| **ARTEMIS** [R4], [R4a] | In one live-network study, configuration A2 submitted 11 findings, nine judged valid, and ranked second under the study rubric against ten human participants. Configuration A1 also submitted 11, with 55% valid. Dedicated triage attempts reproduction. | Human comparison uses a ten-hour scoring window within sixteen-hour runs. Small cohort, relaxed defenses and persistent false positives limit transfer. Its triage API accepts a reproduction decision plus evidence text; Gauntlet additionally requires qualified receipts and proof obligations. |
@@ -1645,1 +1646,3 @@
 | **XBOW public validation suite** [R19] | Maintainer supplies 104 web CTF fixtures and now warns that the public suite is saturated and learned by current models. | This is a maintainer assessment, not an independent contamination measurement performed here. Retain useful regressions; do not use a perfect score as current differentiation or production-readiness evidence. |
+| **XBOW validators** [R34] | Conference talk and product documentation: the agent supplies evidence and non-AI code checks it; canary validators resist gaming because a random identifier cannot be predicted; each vulnerability class is labeled deterministic or agent-judged. | Vendor's own account; no independent false-positive rate found. Nearest precedent for §7. Publish each oracle's known misses and label each finding's class as checked or judged. |
+| **Project Zero Naptime / Big Sleep** [R35] | Two stated principles: verification that is automatic and certain, and many independent attempts made affordable by that verification. | Small targets and self-described experimental results. Keep leads cheap and verification strict (§10.2). |
```

---

### [Medium Impact, Low Effort] Change #12: Make the plan usable by the agents who will implement it

**Current State:**
The plan is about 24,800 words. An agent cannot read it in one pass; it took four reads here. Its "Normative language" section says `MUST` marks a requirement, and `MUST` appears once in the document, in that section. Meanwhile "do not", "never", "must not" and "cannot" appear about 224 times, and "qualif-" about 129 times. A reader cannot tell which of those are requirements with a test behind them and which are emphasis.

Work packages in §19.2 list dependencies and acceptance evidence but not what to read.

**Proposed Change:**
1. **Number the invariants.** Each prohibition that matters becomes `INV-nn` with one sentence and the fixture that enforces it (§16.4 and §16.7 already hold most of the fixtures). A prohibition with no fixture is either given one or cut.
2. **Add a "Reads" column** to the work graph: the sections and invariants each package needs.
3. **Split the file.** Keep `plan.md` to the binding decisions, the domain model, M0 through M2 and the work graph. Move the research ledger (§22), the evaluation protocol (§16) and M3 onward into siblings.
4. **Use the normative convention or delete it.**

**Rationale:**
The next step is turning this into bones. A bone that says "implement G10" sends an agent into 1,800 lines to find the eleven sentences that constrain it. Prohibitions that are not tests will be honored at first and eroded later; the plan's own §21.3 worries about exactly this.

**Benefits:**
- Each work item carries its own constraints.
- Requirements are distinguishable from commentary.
- Review of an implementation becomes "which invariants does this touch, and do their fixtures pass".

**Trade-offs:**
- An afternoon of editorial work that adds no design.
- Splitting creates cross-file references to maintain.

**Implementation Notes:**
Do this after the other changes are applied or rejected, so the invariant list is built once.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -44,3 +44,5 @@
 ### Normative language
 
-`MUST` and explicit rejection conditions are implementation requirements. Performance numbers and evaluation thresholds are proposed release targets, not observed results. All `gauntlet` commands and schemas below are proposed APIs. Upstream contracts are identified separately as inspected, planned, or requiring qualification. Examples with angle-bracket identifiers are schematic; shipped examples must use real IDs returned by their own fixtures.
+Requirements are the numbered invariants in §16.10 (`INV-01` onward). Each is one sentence and names the fixture that enforces it. A work package lists the invariants it must satisfy. Text elsewhere in this document explains and motivates; where it appears to add a requirement that has no invariant, raise it and either number it or remove it.
+
+Performance numbers and evaluation thresholds are proposed release targets, not observed results. All `gauntlet` commands and schemas below are proposed APIs. Upstream contracts are identified separately as inspected, planned, or requiring qualification. Examples with angle-bracket identifiers are schematic; shipped examples must use real IDs returned by their own fixtures.
@@ -1489,2 +1491,2 @@
-| ID | Work package | Depends on | Acceptance evidence |
-|---|---|---|---|
+| ID | Work package | Depends on | Reads | Acceptance evidence |
+|---|---|---|---|---|
```

---

## Suggested order of application

The three owner decisions are settled, so nothing below waits on an answer.

1. Change #1 (facts), then Change #13 (black-box default) and Change #11 (research and the Ward boundary). These set scope and remove work.
2. Changes #6 and #7, the two decided design changes.
3. Changes #2 through #5, which reshape M0 and M1 and are independent of each other.
4. Changes #8 and #9, which fill in the M2 design.
5. Changes #10 and #12 last.

Change #13 touches line 394, which sits two lines below the paragraph Change #6 replaces. Apply #6 first and re-anchor #13's hunk.

After that the plan is ready for `/plan-to-bones`, with M0 as: stack inventory, baseline runs on the Teapot testbed, the custody spike, and the Investigation slice.

## What this review did not verify

- No code was built or run in any repository. Every statement about a tool's behavior comes from reading its source or documentation.
- The four repository checks were done by read-only passes that cited file and line. I re-read the source behind the Teapot accounting, Teapot enforcement, Playpen coverage, Hallpass receipt, Sippycup ledger and Teapot testbed findings. The remaining findings (Bones locking order, Edict's evaluation history, Vessel's process model, Sippycup's MCP grants and oracle) I did not re-read.
- The claim that older Hallpass readers reject a newer pass key comes from Hallpass's format documentation and was not exercised.
- Playpen's `--no-network --fixture` mode was reported from its documentation and not examined.
- Ward was assessed from its README and crate list.
- The research rows proposed in Change #11 are at search-result depth. Of the plan's roughly forty reference links, ten were fetched; the rest were not checked.

## Sources for added research

- XBOW, [AI Agents for Offsec with Zero False Positives (Black Hat USA 2025)](https://i.blackhat.com/BH-USA-25/Presentations/US-25-Dolan-Gavitt-AI-Agents-for-Offsec-with-Zero-False-Positives-Thursday.pdf)
- XBOW, [Interpreting XBOW results](https://docs.xbow.com/console/guidance/interpreting-results/) and [Vulnerability classification](https://docs.xbow.com/console/reference/vulnerability-classification)
- Google Project Zero, [Project Naptime](https://projectzero.google/2024/06/project-naptime.html) and [From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)
- OpenAI, [Introducing Aardvark](https://openai.com/index/introducing-aardvark)
- Keygraph, [Shannon](https://github.com/KeygraphHQ/shannon)
- [Strix](https://github.com/UseStrix/strix), and [Help Net Security coverage](https://www.helpnetsecurity.com/2025/11/17/strix-open-source-ai-agents-penetration-testing/)
- Alias Robotics, [CAI](https://arxiv.org/html/2504.06017v2) and [CAIBench](https://arxiv.org/html/2510.24317v1)
