# Scourge implementation plan review

## Executive summary

**Keep the evidence model. Fix the release gates before treating the work graph as implementation-ready.** The plan gives a security finding a stronger basis than a scanner alert. It identifies the policy at issue, retains the original evidence, gives contradictory evidence a place, and checks that legitimate behavior survives a fix. The split between Investigation, Bones and the instruments is worth preserving. So is the comparison between native tools, written methodology and Scourge. That comparison can isolate the benefit of the software from the benefit of better instructions.

Three gaps change the decision to ship. A trial can find a real issue and also promote a false one outside the explicit zero-false-promotion gate. A blocked Investigation dependency can satisfy a work-package exit on paper. And a source-validation workflow is promised to cold agents without a required package that delivers it. I would start with two observable outcomes on an archived case. Can an unfamiliar agent find the decisive evidence from help alone? Can a maintainer make a defensible decision from its handoff? Both can be measured before committing to the full evaluation campaign.

I spot-checked the research that bears on this decision. DARPA reports 54 distinct synthetic vulnerabilities found and 43 patched across the finalists’ systems in 63 challenges. BountyBench reports results for different tasks and gives agents up to three attempts. Both support the plan’s care with denominators and task boundaries. Neither measures the marginal value of this proposed framework. [DARPA organizer results](https://www.darpa.mil/news/2025/aixcc-results) · [BountyBench, NeurIPS 2025](https://papers.nips.cc/paper_files/paper/2025/hash/faed4276b52ef762879db4142655c699-Abstract-Datasets_and_Benchmarks_Track.html)

I reviewed revision 1 (SHA-256 `f147fd467ee0cb7b75a63348e1f56463bc9c545499373387f6d31a11b0a75611`) against the sibling specifications, source and selected primary research. The diffs target that revision. For the conditional source route I used the black-box default and Ward ownership recorded in the adjacent review. Runtime qualification and measured effectiveness remain open. [Original plan](plan.md) · [Recorded design decisions](plan.review.1.md#decisions-settled-by-bob-2026-11-21)

## Proposed changes

The excerpts below are unified diffs for `notes/plan.md`. Each proposal includes an acceptance case and identifies the existing work package that can own it.

### 1. Make a false promotion fail the release on any scored case

*High impact / low effort · §§16.3–16.6 · G01, G24, G25*

**Current state**

The zero-false-promotion gate applies to mandatory negative and confounded trials. A positive trial can produce one correct finding and one false finding. The true finding can satisfy the completion gate, and the false one can miss the hard gate. Reporting a false discovery proportion later does not settle the release decision.

**Proposed change**

Adjudicate each submitted claim in every arm and each internal promotion in Scourge. Keep those as two score sheets. Apply the soundness gate to promotions on positive, mixed, negative, retest and recovery cases. Keep adjudication open for a credible issue missing from the answer key.

**Rationale**

A target can have both a real defect and a convincing benign observation. Independent evaluation has found cases where a grader credited the expected outcome for the wrong reason. The plan already anticipates that problem at the level of individual fixtures. The release rule should catch it across the whole corpus. [NIST CAISI evaluation audit](https://www.nist.gov/caissi/2-examples-cheating-caisis-agent-evaluations)

**Benefits**

One real finding still earns discovery credit. An unsound second promotion remains visible even if a later report omits or withdraws it.

**Trade-offs**

Mixed cases require claim-level adjudication. Reserve reviewer time and conceal arm identity where the evidence permits.

**Implementation notes**

Add one offline grading fixture with a supported finding, an unsupported promotion and a clearly labeled working hypothesis. Expect one credited finding, one blocking promotion and zero penalty for the hypothesis. A newly discovered issue goes to adjudication before a decision.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1253,2 +1253,3 @@
 | New real flaw absent from seeded ground truth | Independent adjudication; do not automatically mark it false because the label is missing. |
+| One correct finding and one unsupported promotion on the same case | Credit the correct claim, fail promotion integrity and retain both decisions if the second claim is later withdrawn. |
 
@@ -1268,3 +1269,3 @@
 | Unassisted valid completion | At least 90% within each promised track and each supported model/host combination; report every cell. An aggregate score cannot rescue a failed subgroup. Narrow support claims when a configuration does not qualify. |
-| False promotion | Zero observed on mandatory negative/confounded trials. Every occurrence blocks release until understood and corrected. |
+| False promotion | Zero adjudicated false or unsupported promotions on any mandatory scored trial, including a trial with a true finding. Grade each promotion against the evidence available at the time. An unresolved adjudication keeps the gate open. |
 | Real positive completion | At least 90% separately for unassisted discovery and supplied-lead verification in each supported model/host combination; report missed issues, abstentions and actual counts. |
@@ -1279,2 +1280,4 @@
 These are ambitious engineering targets on a specified corpus, not calibrated population guarantees. Publish numerators and denominators; 90% is a threshold, not permission to round a failure upward. Revise an unrepresentative corpus through a documented prospective revision, then freeze it before the next scored round. Do not lower the soundness requirement to make a release date. Track false-positive opportunities per held-out target/family and false discovery proportion among submitted claims separately; an agent-expandable count of tests/candidates is not a valid denominator for a reassuring false-positive rate.
+
+For A/B/C comparisons, score every intentionally submitted finding under the same rubric. For Scourge’s additional integrity gate, reconcile the full promotion history with those submissions, including superseded or withdrawn records. Report both counts and the disposition of claims absent from the answer key. Mark a proportion with zero submissions as undefined and report the completion and abstention counts.
 
```

### 2. Give each promised evidence route an owner and an exit gate

*High impact / low planning effort · §§3.2, 6.3, 12.3, 16.5, 19.2, 22.5 and 23 · G00, G02, G25*

**Current state**

G02 accepts a documented blocker as an exit, yet G05 depends on G02 for an actual recorder. The final handoff starts G03 before its stated G00/G01 prerequisites. Section 16.5 names source validation in the release corpus, while G19 delivers source leads and G25 has no named dependency that qualifies that route. Section 3.2 also mixes adapter presence and qualification in one list of states.

**Proposed change**

Pin the accessible Investigation specification, map each consuming path to actual evidence operations and leave a missing prerequisite blocked. Make the source route conditional on a qualified Ward artifact import. Keep a black-box release eligible without that route and qualify it separately before advertising it. [Scope and ownership choices recorded in review 1](plan.review.1.md#decisions-settled-by-bob-2026-11-21)

**Rationale**

The sibling Investigation document identifies itself as revision 3. W02/W03 cover durability and run records, W06/W07 cover ingestion and recording, and W10/W11 cover freshness and export. I found planning documents there and no `inv` executable on this shell’s PATH. Ward already documents a source review artifact and a verification interface. Scourge can test what such an artifact establishes without building another analyzer. [Investigation revision 3, §§10–11 and 19.2](../../investigation/notes/plan.md) · [Ward review artifacts](../../ward/README.md)

**Benefits**

A new implementer can locate the input without the originating chat, start independent design work immediately, and tell exactly which dependency blocks a shipping claim.

**Trade-offs**

The graph exposes an external dependency with real implementation cost. Making source support optional also means leaving that capability out of the release claim until its own gates pass.

**Implementation notes**

Three inspected local revisions differ from §22.5. Hallpass `261e74d5` documents `found`, `absent` and `ambiguous` receipt lookup against available history. Playpen `206190c7` distinguishes installed-binary and source-tree qualification. Teapot `8d6dab9a` adds `paused_evidence` flow IDs to its session view. The checkout advanced to `d89827cd` during review and I rechecked that field there. Edict, Bones, Sippycup and Vessel match the listed HEADs here. These are source comparisons. Installed versions and backend behavior still require their own evidence. [Hallpass accounting evidence](../../hallpass/docs/EVIDENCE.md) · [Playpen qualification](../../playpen/docs/spec.md#441-playpen-qualify) · [Teapot session response type](../../teapot/crates/teapot-api/src/commands/sessions.rs)

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -182,3 +182,3 @@
 
-- The attached Investigation API is a **specification**, and the repository was not accessible during this research. Build against a conformance contract; a simulator can unblock tests but never qualify a real release.
+- The Investigation input is an implementation specification. In the sibling checkout layout its revision 3 file has SHA-256 `4048bc54435855815b535d0179468e0ae75c2f9c2a222b00c0f346470b5b6d1d`. Accept an explicitly supplied copy in other layouts and record its digest. Track design conformance separately from actual recorder results. [Investigation revision 3](../../investigation/notes/plan.md)
 - The current inspected Teapot source contains substantive authz/crawl handlers and corresponding test code. Older observations that these were placeholders are stale. Inspection is not a claim that the suites were run here.
@@ -189,3 +189,5 @@
 
-Every adapter advertises `available`, `unsupported`, or `unqualified` per capability, with a reason and a concrete remediation route. Missing features must produce honest blocks, never fabricated evidence or silent fallback to an unrestricted command.
+Report presence, qualification for the selected composition, and engagement eligibility as separate fields per capability, with reasons and the evidence for each as in §12.1. An installed adapter can have an unqualified operation. An unsupported or unqualified operation stays unavailable for policies that require it.
+
+G00 records the research revision, candidate checkout revision, actual installed identity if available, contract differences and qualification evidence in separate fields. Record absence or ambiguity from a historical accounting lookup as such. Record which native checks exercised an installed binary and which exercised a checkout.
 
@@ -1156,3 +1158,3 @@
 | `cross-protocol` | Explicit HTTP-to-signaling/media capability binding and connected replay. | Protocol milestone exit. |
-| `source-runtime` | Scanner/static path import, exact source context, reachable preconditions, runtime discriminator or honest source-only review. | Later v1 extension. |
+| `source-runtime` | Import Ward’s source evidence with its producer and revision bound. Attribute conclusions to the qualified proof profile and disclose deployment applicability. | Conditional extension for engagements with source and a qualified evidence route. |
 | `browser-effects` | Clean attacker/victim roles and constrained real-browser proof with qualified observer. | Only after browser adapter qualification. |
@@ -1262,3 +1264,3 @@
 
-Map the frozen corpus to the shipped capability/profile/host support matrix. It must represent the claimed HTTP, live-protocol, connected cross-tool and source-validation workflows, including meaningful positive and negative/blocked cases for their applicable routes. Report their information regimes separately. These families fit within the minimum matrix where feasible; expand it before making additional support claims if coverage is insufficient. A scripted adapter test alone does not establish cold-agent usability, and an unrepresented workflow cannot receive the zero-tool-knowledge support claim.
+Map the frozen corpus to the capabilities, profiles and hosts claimed for this release. Cover the applicable HTTP, protocol and connected workflows, with meaningful positive and negative/blocked cases. The default assessment assumes black-box access. If the release claims source validation, qualify the Ward evidence route and add source-review families with their own information regime. Expand the matrix before adding an unsupported claim. Only represented and passed workflows earn the zero-tool-knowledge support claim.
 
@@ -1492,3 +1494,3 @@
 | G01 | Design owned authz fixture and negative controls; freeze evaluation protocol | — | Property/ground-truth specification separate from agent view; decoy catalog; no solution leakage. |
-| G02 | Establish minimal neutral Investigation contract with upstream owner/implementation | G00 | Real begin/attach/finalize/query/record/review/idempotency conformance, or explicit blocked dependency. |
+| G02 | Qualify the required neutral Investigation evidence contract with its upstream owner | G00 | Real recorder receipts for immutable ingestion, selectors, capture and durable retry, with the consuming package listed for each required operation. A missing required contract leaves the dependency blocked. Record the owner and continue independent development using labeled doubles. |
 | G03 | Define typed domain catalog, result dimensions and profile obligation matrix | G00, G01 | Generated schemas; positive/invalid/stale transition fixtures; no direct set-verified mutation. |
@@ -1515,3 +1517,4 @@
 | G24 | Build protected held-out evaluator, baselines and cost accounting | G01, G03 | Referee inaccessible; hints/attempts/setup recorded; independent adjudication path. |
-| G25 | Run release cold-agent trials and matched-budget/ablation study | G17, G19, G23, G24 | ≥160 trials, per-track/per-configuration gates and failures; no unsupported superiority claim. |
+| G24S | Qualify offline import and review of Ward evidence when source support is claimed | G06, G15 | Retained original and exact source/configuration, producer trust, independent challenge and deployment limits survive report and handoff. Demonstrate supported, contradicted and insufficient cases with live adapters absent. An import alone creates a lead. |
+| G25 | Run release cold-agent trials and matched-budget/ablation study | G17, G19, G23, G24, plus G24S for a source-support claim | ≥160 trials covering the shipped capabilities, per-track/per-configuration gates and adjudicated failures. Bound comparative claims to the measured effect. |
 | G26 | Optional MCP transport and selected extra capability | G17, G24 | CLI equivalence plus independent cold-agent transport evaluation; no surface explosion. |
@@ -1735,3 +1738,3 @@
 
-The implementing agent should begin with **G00, G01 and G03**, establish **G02**, and deliver the narrow complete HTTP slice before broadening the framework. This document contains the minimum integration/proof contracts; also consult the supplied Investigation revision 3 plan when implementing or changing its neutral substrate.
+Begin G00 and G01. G02 can start after G00. Start G03 when both G00 and G01 have supplied their inputs. Use Investigation W02/W03/W06/W07 to identify evidence dependencies. Map freshness and export requirements to the owners selected for the release. Continue independent domain and interface work while recording any blocked integration explicitly.
 
```

### 3. Keep workspace discovery from granting trust

*High impact / low effort if specified at bootstrap · §§4.3, 10.1, 11.5 and 12.1 · G00, G06, G08*

**Current state**

The CLI walks upward to the nearest `scourge.toml`. A security reviewer will routinely run it from inside someone else’s source tree. The plan says to trust installed binaries and protect configuration paths, but leaves open who decided that the *discovered* file may select an evidence root, credential provider, adapter binary or verifier socket.

**Proposed change**

Use an operator-provisioned binding outside the tree under review for trust-sensitive paths and identities. Let CWD discovery select an already bound workspace. In an unfamiliar directory, bare invocation can still explain the tool and show the local tutorial from its embedded catalog.

**Rationale**

Path validation answers where a file is. It cannot establish who authorized the settings inside. Native diagnostics also have their own effects. Playpen’s default `doctor` runs host probes, including local networking, and its qualification command can run tests from a selected checkout. Git’s protected configuration provides a precedent for keeping trust-sensitive settings outside repository control. [Playpen doctor and qualification contracts](../../playpen/docs/spec.md#44-playpen-doctor) · [Git protected configuration](https://git-scm.com/docs/git-config#SCOPES)

**Benefits**

Opening a new repository for review cannot redirect onboarding to an untrusted program or expose a different case. Previously provisioned workspaces still open directly.

**Trade-offs**

Initialization needs a trusted binding that can be provisioned headlessly. A directory move can require a new binding.

**Implementation notes**

Test bare help, onboarding, capabilities and doctor in a nested fixture with a conflicting config, a symlinked evidence root and a harmless sentinel adapter. Assert no adapter invocation, host probe, secret resolution or foreign case read. Repeat with the operator’s legitimate workspace selected from the same directory. A preconfigured assessment workspace outside the source tree can supply this binding. It requires no global trust prompt.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -886,3 +886,5 @@
 
-Discover the nearest `scourge.toml` upward from CWD, or use `--workspace`. Never scan the user's home directory to guess an engagement. If multiple engagements exist, require an explicit selection except a read-only listing. Workspace-local actor attribution is convenient but not authenticated authority.
+Discover the nearest `scourge.toml` or take `--workspace` as a location hint. Resolve trust-sensitive settings through an operator-provisioned binding outside the inspected content, tied to the workspace identity, root and material configuration. A copied workspace ID or a nested config cannot supply executable paths, service endpoints, credential sources, evidence roots or trust anchors. Explicit selection still checks the binding. Show embedded orientation and the binding status when it is absent or stale. Existing valid bindings work without another prompt.
+
+List accessible engagements when selection is ambiguous and require an explicit engagement for case-specific operations. Scope discovery to the selected root. Passive diagnostics report recorded check results and their age. Active native diagnostics have separately declared effects.
 
```

### 4. Make the first machine-readable answer usable from the caller’s directory

*High impact / low effort · §§10.1–10.4, 11.2–11.5 and 16.5 · G06, G08*

**Current state**

The tutorial selects a workspace explicitly, then the specimen response emits `scourge run show …` without carrying the selection forward. A stateless caller in another directory or a workspace with two engagements loses the binding. `schema` also promises a runnable instance when there may be no fixture. The first-action timer starts after onboarding, so a long orientation can still pass.

**Proposed change**

Generate local next-action argument arrays with enough selection information to execute them from the caller’s actual directory. Mark structural examples and unavailable inputs explicitly. Support the ecosystem’s `--json` alias, including machine-readable help and parse failures, and count calls from first invocation.

**Rationale**

This is a hypothesis about how agents use the executable and can be tested cheaply on offline evidence. The Bones conventions document the guessed alias. The SWE-agent interface study gives evidence that the interface affects agent behavior on coding tasks. Its published result cannot predict Scourge’s completion rate. [Bones CLI conventions](../../bones/.agents/edict/design/cli-conventions.md) · [SWE-agent interface study](https://arxiv.org/abs/2405.15793)

**Benefits**

A replacement agent can follow the returned action verbatim, select the right case and reach an evidence-based answer without a private prompt or working-directory guess.

**Trade-offs**

The CLI must handle early help and parser exits in machine mode. Local selection paths belong in authorized local responses and must be removed or rebound in portable exports.

**Implementation notes**

Use a supplied offline case with a missing policy record. Start in an unrelated directory, select a workspace whose path contains spaces and give it two engagements. After the first response, allow only its returned argument arrays or embedded help. The first useful result names the missing record and the retained evidence supporting that diagnosis. Also run the no-workspace path with a pipe instead of a TTY.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -678,2 +678,4 @@
 
+Outside a bound workspace, machine-readable help and schema return the static contract, the inputs the caller still needs, and a local creation or selection route. A fixture-bound example declares itself runnable and uses bindings from that fixture. Accept `--json` as an alias for `--format json` on help, reads and mutations. When machine mode is requested, usage and validation failures emit one parseable error object on stdout, including failures before a workspace or request ID exists. Use null for unavailable envelope identifiers.
+
 ### 10.2 Core user loop
@@ -725,2 +727,4 @@
 
+For each local action, emit the selected workspace and engagement as explicit argv elements when resolution depends on them. Generate the `--engagement ID` selector from the catalog. Keep whitespace inside one argument. Local responses can carry authorized absolute paths. Portable handoffs resolve workspace-local bindings at the recipient before offering a runnable action.
+
 `next --explain ACTION_ID` shows the deterministic rule and selected inputs. Recommendations derived from untrusted source text may quote that text only as evidence; the trusted operation and its arguments come from the command registry and validated bindings.
@@ -835,3 +839,3 @@
   "next": [
-    {"effects": "none", "argv": ["scourge", "run", "show", "<real-attempt-id>", "--format", "json"]}
+    {"effects": "none", "argv": ["scourge", "--workspace", "<selected-local-workspace>", "--engagement", "<selected-engagement-id>", "run", "show", "<real-attempt-id>", "--format", "json"]}
   ]
@@ -1266,3 +1270,3 @@
 |---|---|
-| Useful first action | Within three task-relevant calls after onboarding/initialization on the simple path; count schema/repair calls and report distribution. |
+| Useful first action | On a preconfigured offline case, reach a cited observation or the correct material blocker within three calls from first invocation, including help, orientation and repair. Record every call and elapsed time. Retain the post-onboarding three-call gate on the simple path and publish clean-init, missing-capability and never-reached results separately. |
 | Unassisted valid completion | At least 90% within each promised track and each supported model/host combination; report every cell. An aggregate score cannot rescue a failed subgroup. Narrow support claims when a configuration does not qualify. |
```

### 5. Require evidence for refuting a finding

*High impact / low effort · §§6.1, 6.7, 11.1 and 14.3 · G03, G14*

**Current state**

The lifecycle distinguishes withdrawal from refutation, and the positive proof profiles have extensive obligations. `finding.disposition` has no equivalent decision rule for `refuted`. Refuted or withdrawn leads can disappear from the summary “where useful.” A missing artifact or a later successful fix could be recorded as a refutation of an earlier true claim.

**Proposed change**

Define refutation against a specific proposition and basis. Require an inspectable contradiction of a necessary premise. Make withdrawal, duplication, deferral and inconclusive evidence cheap, attributed dispositions that retain independent support and objections.

**Rationale**

The proposition “the object was private in revision A” can be contradicted by the policy for revision A. A public-object policy introduced in revision B answers a different question. The same distinction protects findings when old evidence has expired.

**Benefits**

Negative outcomes become auditable without forcing every abandoned lead through a verification ceremony.

**Trade-offs**

A reviewer who wants to close a claim as refuted must identify the contradicted premise. Cases with unavailable evidence may remain inconclusive.

**Implementation notes**

Exercise the transition with three offline records. A same-revision policy contradiction permits refutation. A later policy change limits current applicability. A missing policy document leaves the premise unresolved. Include a case where another reviewer still has material evidence.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -322,2 +322,4 @@
 The implementation stores lifecycle history and computes effective status. `NeedsReview` is a freshness overlay, not an erasure of historical verification. Findings can also be `disputed` when a material objection is unresolved. Rejected reproduction, refused execution, and withdrawn claim are different events.
+
+`finding.disposition(refuted)` requires the exact proposition and basis, the necessary premise contradicted, the cited contrary evidence for that basis, and an attributed review of material supporting evidence. A failed observation, missing artifact, later fix or budget stop can leave a claim inconclusive. Withdrawal ends the author’s assertion. Grouping duplicates preserves their evidence. A new material objection or supporting acquisition reopens review of the disposition.
 
@@ -1108,3 +1110,3 @@
 - Candidates and conditional consequences requiring more work.
-- Refuted/withdrawn leads where useful to prevent repeated work.
+- Counts and drill-down for refuted, withdrawn, duplicate and deferred leads. Preserve their distinct reasons, historical bases and outstanding disagreements in the selected audience’s view.
 - Coverage, blocks, unexamined areas, operational incidents, cleanup and limits.
```

### 6. Apply the reader’s current disclosure rights to receipts, briefs and handoffs

*High impact / high effort across readers · §§9.5, 10.5, 10.8, 11.2 and 18.5 · G04–G06, G15*

**Current state**

Request IDs are workspace-wide. Section 11.2 promises the original receipt to a replacement actor, while audience rules focus on report bundles and raw evidence. A caller who knows a key could receive old restricted fields or learn about another engagement from a mismatch error. A model-hosted CLI can also send a supposedly local brief into a provider transcript.

**Proposed change**

Deduplicate against the original committed operation. Authorize the reader and project the response for the current audience before disclosing existence, receipt details, searches, errors or actions. Apply the same rule to evidence returned through a model host and to stored handoffs.

**Rationale**

Action authority, attribution and permission to read evidence are different decisions. A read-only call can disclose private evidence even when it makes no network call itself. Investigation rev. 3 already specifies classification propagation and positive inclusion across views. Scourge can inherit that policy for the fields it adds. [Investigation evidence sensitivity and export selection](../../investigation/notes/plan.md#162-sensitivity-and-views)

**Benefits**

A replacement agent recovers permitted facts about completed work. A narrower audience cannot obtain a previous caller’s data by retrying an ID, changing `actor`, asking for JSON, or using a different transport.

**Trade-offs**

Audience-aware reads require a principal bound to a trustworthy local channel. A shared unrestricted UID can only support the disclosure boundary the operator actually provides.

**Implementation notes**

Seed a private marker in a title, native receipt and derived note. Exercise lookup, retry with changed input, `brief --since`, errors, handoff, report and MCP for two permitted audiences and one unrelated reader. Also verify that a hidden material caveat downgrades or suppresses the visible claim. For a remote model host, test what can reach its input stream.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -810,2 +810,4 @@
 Canonical request hashing excludes transport formatting, input-file path and retrying-actor attribution, includes all semantic authority/plan/input bindings, and uses a versioned algorithm. An authorized retry cannot change the original executing capability. Unknown fields in Scourge-owned schemas are rejected with paths. Unknown bounded external metadata may be preserved opaquely in the imported source, but never used as control fields.
+
+A request key locates a committed operation. Authorize access to its engagement and receipt before revealing its existence, comparing semantic input for the caller, or rendering any payload. An authorized retry returns the same operation identity and commit outcome with fields permitted to the current reader. An unrelated reader receives the same public response as for an unknown key. Bind access to a trusted caller context. The request’s `actor` string provides attribution only.
 
@@ -1466,2 +1468,4 @@
 Enable local diagnostic export with explicit selection/redaction. No mandatory telemetry service, external upload, model provider or Internet connectivity for local reads, stored proof evaluation or reports.
+
+Treat a model host, worker transcript and diagnostic consumer as evidence recipients under the engagement policy. Filter before bytes enter their input stream. Inherit Investigation classifications for derived labels, snippets, arguments, errors, receipts and indexes. If a required caveat is withheld, withhold the corresponding claim or state its review limit. In supervised mode disclose the limits of controlling other host reads. A restricted audience needs a mediated view or an isolated export to obtain an enforceable boundary.
 
```

### 7. Define which evidence snapshot a current report describes

*High impact / high integration effort · §§6.7, 10.5, 11.3 and 14.3 · G05, G14, G15*

**Current state**

Promotion checks its read-set. Later, `brief`, `report`, pagination and `brief --since` promise a consistent view assembled from different stores. The example response has a single control snapshot. After Investigation retracts evidence, a cached positive result and a newer objections list can each be authentic while describing states that never belonged together.

**Proposed change**

Define a report snapshot in terms of the contributing owners, their workspace identities, immutable checkpoints and material dependencies. Give historical inspection and a request for current status distinct behavior when an owner is missing, behind or changing.

**Rationale**

A local SQLite read transaction gives one reader a stable view of that database. It cannot freeze Investigation’s journal or the qualifications used to decide whether the finding still stands. Even if Scourge alone owns the verdict, a withdrawal in the evidence store still matters. Investigation already specifies a canonical read-set and distinguishes its projection head from its committed state. [SQLite isolation](https://www.sqlite.org/isolation.html) · [Investigation concurrency contract](../../investigation/notes/plan.md#103-revisions-and-concurrent-agents)

**Benefits**

A report can show when a finding was supported, which evidence later changed, and whether the reviewer can establish its present status. Unavailable work-item metadata need not hide valid evidence.

**Trade-offs**

Establishing a common view can require another read. Under contention, a bounded historical answer or explicit freshness error is preferable to an unbounded retry.

**Implementation notes**

Have a reader pause between reading the control state and the evidence state. Retract the supporting record, finish the report, and check its exact basis. Repeat with an unrelated Bones update, an unavailable evidence owner and a page token reused under another audience. Require one immutable historical view or an explicit stale/unknown result.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -734,2 +734,4 @@
 `brief --since RECEIPT` returns meaningful changes and newly stale results. Lists use snapshot-bound pagination. JSON output is valid even when truncated by a deliberate item budget; raw byte truncation is not allowed. Binary captures remain files. Raw source is opt-in, bounded, inert and marked untrusted.
+
+Bind page and delta tokens to the workspace, engagement, audience, filters and contributing checkpoints. Recheck current read access on use. An expired or unavailable snapshot returns an explicit restart route. A delta reports evidence withdrawals and qualification changes that affect the selected findings.
 
@@ -1102,2 +1104,4 @@
 ### 14.3 Report semantics
+
+A report snapshot names the engagement, selection and audience, the Scourge material generation, Investigation workspace, storage epoch and committed checkpoint, profile/qualification revisions, and the Bones checkpoint when work data is shown. Include the availability and freshness of each contributing projection. Read immutable records at the selected checkpoints and verify dependency closure. For a current view, use a coordinator-supplied consistent cut or read the material revisions before and after collection and require an overlapping stable interval. Bound retries. A current verified label requires compatible material dependencies at a common point during the read. If that cannot be established, return the identified historical basis with current status unknown or a repairable stale response. Work-link lag affects the work section only unless the work data is a declared dependency.
 
```

### 8. Say what a recipient can verify from a redacted bundle

*High impact / moderate effort · §§9.5, 13.7, 14.1–14.3 · G15, G27*

**Current state**

A default export may omit the only original bytes supporting a claim. `bundle check` checks digests, declared missing entries and internal consistency, but its contract gives no concrete result for an intact bundle with withheld evidence. A recipient can also replace both a file and its manifest digest and still produce a self-consistent archive.

**Proposed change**

Report byte integrity, independently established provenance, and inspectability of each required obligation as distinct results. Specify how a withheld original, a reviewed derivative, an intentionally removed original and an unexpectedly missing file change those results.

**Rationale**

The exporting investigator may have seen the original. A different recipient may have only a redacted artifact. Both accounts can be accurate if the report names the audience and the snapshot. Investigation already defines loss of inspectability after retention removes a blob. [Investigation retention contract](../../investigation/notes/plan.md#165-retention-withdrawal-and-actual-deletion)

**Benefits**

A clean-machine reviewer can tell whether a file was damaged, deliberately excluded, or never authenticated. Redaction does not manufacture independent support or disclose a sensitive digest by accident.

**Trade-offs**

The manifest needs per-obligation availability and safe lineage. Portable authentication requires a trust reference supplied independently by the recipient when that assurance is claimed. An unsigned internal bundle can still be useful.

**Implementation notes**

Qualify three offline copies of the same case. One is complete. One omits a required channel under policy. In the third, the manifest advertises a file that is absent. Check that each produces a different explanation. Then replace both a file and its digest in an unsigned copy and confirm that provenance stays unestablished. No bundled program needs to run.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1097,3 +1097,7 @@
 
+Return separate results for integrity of included files, producer authentication under the recipient’s trust policy, and the evidence available to inspect each required obligation. A present file with the wrong digest or an unexpectedly missing promised file is an integrity failure. A declared policy omission can leave the bundle internally intact and an obligation uncheckable. Mark approved derivatives with their own selectors and digests. Expose original identifiers and digests only where the audience policy permits. A manifest and a verification key supplied solely by the bundle cannot authenticate its producer.
+
 Live replay starts a new attempt in a new or rebound engagement. The bundle's historical Hallpass receipt is evidence of prior admission, not current authorization. Require current credentials and target identity. If only offline inspection is possible, report that limit without corrupting the historical result.
+
+Record the historical verification decision at its named snapshot and the checks this recipient could perform. Propagate Investigation’s `intentionally_removed` state into new exports. Preserve previously produced bundles as historical artifacts and account for copies outside local retention control. Offline checking makes an as-of statement about the supplied material.
 
```

### 9. Budget the cold-agent gate separately from the effectiveness study

*High impact / low planning effort · §§16.2–16.6 and 19.1–19.2 · G01, G24, G25*

**Current state**

Forty families × two model/host combinations × two sessions costs 160 Scourge sessions. The design separately requires A/B/C and one-feature ablations. It gives no total campaign budget or allocation decision. M3 begins the 160-trial qualification even though M4 can change the candidate and the release claims. A 95% recovery gate can also have zero eligible errors if the agent never encounters one.

**Proposed change**

Use development-only pilots for sizing. Freeze the release candidate and scorecard before confirmatory trials, schedule explicit repair and handoff opportunities, and budget the comparator study by its paired estimand. Specify when a trial can count for both purposes.

**Rationale**

With six families and two sessions, a given host has twelve observations in that track. A 90% gate needs eleven successes, and a 95% gate needs all twelve if all are eligible. Twelve negative families across hosts and sessions yield 48 runs but only twelve families. Even under an independent, representative, binary family-failure model, zero out of twelve gives a one-sided 95% upper bound of about 22%. A hand-picked family set does not justify that population bound.

**Benefits**

The operator can price a credible release, see the coarseness of small cells, and decide whether the data warrant a comparative claim. Skipping a repair opportunity cannot produce a passing recovery score.

**Trade-offs**

A matched three-arm study at the same full allocation would cost 480 sessions before pilots or ablations. A smaller preregistered comparison may be appropriate, with correspondingly narrower conclusions.

**Implementation notes**

For example, reserve a repair opportunity for each designated recovery trial before the session begins and grade all assigned trials, including failures to reach the step. Record natural-error incidence separately. Make budget arithmetic visible in agent sessions, independent reviewer-hours and elapsed time. Record development use of any inspected family.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1286,2 +1286,4 @@
 
+Freeze a trial ledger by release fingerprint, family, track, model/host, arm and assigned opportunity. Designate repair and handoff opportunities prospectively. Count every assigned trial in its relevant completion denominator and report whether each step was reached. A gate with zero assigned opportunities is unmeasured. Show required integer successes, actual outcomes and family counts for each release cell.
+
 Track per-attempt and all-in model cost/tokens, wall time, target operations, bytes, instrument/runtime compute, verification overhead, setup/reconstruction time and human interventions. Report success-at-one and the empirical outcome of all repeated attempts separately; do not advertise a best-of-many result as reliable first-run performance [R24].
@@ -1289,2 +1291,4 @@
 A superiority claim requires a powered matched comparison and a useful effect size, not a higher point estimate on a dozen tasks. Preregister the primary paired estimand and minimum useful effect. Evaluate uncertainty for the family-level paired difference against zero and that useful-effect threshold; overlap between separate arm-level confidence intervals is not the decision rule. Treat an imprecise difference as an unestablished benefit. Label multiple ablations exploratory or confirm selected improvements on untouched data. Release correctness can be demonstrated before claiming global superiority.
+
+Budget the 160 Scourge qualification sessions separately from A/B/C, pilots and ablations. A fully crossed study of equal size in all three arms requires 480 sessions before extras. Reuse a Scourge session in both analyses only when the frozen candidate, cases, rubric, allocation and budget meet both protocols. Use pilot timings and adjudication costs to choose and fund the paired comparison before opening the confirmatory corpus.
 
@@ -1478,3 +1482,3 @@
 | **M2 — complete HTTP verification** | Actual qualified Teapot execution, identities, controls, custody, accounting, capture, local admission, independent replay, report and paired fix verification. | Full §17.1 workflow on real binaries, required adversarial controls and §13 crash matrix; twelve pilot cold-agent runs reviewed. This is the first useful end-to-end product. |
-| **M3 — realistic discovery and durable coordination** | Coverage, bounded prioritization, stateful recipes, Bones links, complete handoff/reconciliation, source leads, optional qualified workers. | Matched-budget baselines and held-out HTTP cases; concurrency/cancel/unknown-effect gates; 160-trial cold-agent qualification begins. |
+| **M3 — realistic discovery and durable coordination** | Coverage, bounded prioritization, stateful recipes, Bones links, complete handoff/reconciliation, source leads, optional qualified workers. | Matched-budget development comparisons, HTTP cases reserved for the scoped candidate, and concurrency/cancel/unknown-effect gates. Freeze the complete supported candidate before its scored release trials. |
 | **M4 — protocol and cross-protocol verification** | Sippycup import/live adapter, qualified runner and accounting composition, signaling/media profiles, connected cross-tool replay. | §17.3 plus incompatible-chain and missing-media-observer controls; no enforcement downgrade. |
```

### 10. Test whether maintainers can act on the report

*High impact / moderate pilot effort · §§1.3, 16.3 and 16.9 · G06, G15, G24*

**Current state**

The human review gate measures navigation and comprehension. The benchmark measures technical correctness and agent cost. Neither specifies how to find out whether a maintainer can actually decide to fix, close, request evidence or defer a supplied report faster and as accurately as with the native evidence.

**Proposed change**

Use a small panel of previously resolved, permission-cleared cases as a development pilot. Compare native evidence, the same written guidance, and the Scourge review on the same inputs. Test the handoff with a maintainer who has no access to the original investigator. Keep hidden outcomes with the adjudicator. Use correct evidence-supported dispositions by a fixed cutoff as the primary outcome and reviewer minutes per case as the cost measure.

**Rationale**

Tricorder’s authors evaluated a program-analysis platform inside a real engineering workflow. In a separate 20-interview study of software composition analysis, practitioners reported that tool output often lacked the deployment context needed for triage. These findings motivate measuring downstream decisions directly. They do not supply a numerical benefit for Scourge. [Tricorder field evaluation](https://research.google/pubs/tricorder-building-a-program-analysis-ecosystem/) · [Lin et al., USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/lin-elizabeth)

**Benefits**

The team learns whether the report saves engineering time, preserves uncertainty and avoids unnecessary investigations. Plain guidance can earn full credit where it delivers the same result.

**Trade-offs**

Historical outcomes can be wrong and a reviewer who recognizes a case can bias the result. A blinded second judgment for disputed cases costs time.

**Implementation notes**

Use independent reviewers or disjoint assignments so nobody sees the same case twice. Hide later patches and original decisions during review. Score correctness against the available evidence, allow justified uncertainty and adjudicate disagreement with the historical resolution. Use a small development panel to revise the report before spending the sealed evaluation budget.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1319,2 +1319,4 @@
 A reviewer unfamiliar with the case must be able to find the current bounded claim, identify its validation route and strongest caveat, traverse exact evidence, distinguish invalid test from valid negative, identify residual side effects, and prepare a replay or retest without a narrated tour. Retain the observations and fix misleading status labels or navigation. Visual polish is secondary to honest comprehension.
+
+At M1, try the offline evidence view on permission-cleared archived cases, including a benign alert and a case where the available evidence cannot settle deployment applicability. Repeat when the G15 report exists. Compare native evidence, the same guidance and Scourge with equal access and time. Balance reviewers across arms, assign each case to a different reviewer per arm, and blind outcome adjudication to the arm where feasible. Preregister the fraction of cases with an evidence-supported disposition by the time limit. Record each disposition, cited decisive evidence, requests for missing context, active review minutes, unresolved cases and adjudicated errors. Count preparation and authoring time. Use this pilot to choose report changes. A comparative effectiveness claim uses the preregistered, held-out design in §16.6.
 
```

### 11. Test durable acknowledgments under storage faults and concurrent reads

*Medium impact for the preview / moderate qualification effort · §§13.1, 13.6–13.7 and 16.8 · G04, G27*

**Current state**

The plan asks for tested durability and includes `fsync` in the latency target. Its crash matrix mostly kills processes at API boundaries. That can pass with a SQLite configuration that loses an acknowledged commit on power loss. The warm p95 target also leaves the number of concurrent readers and capture size unspecified.

**Proposed change**

State which failures an acknowledgment survives on the supported local storage profile. Test that guarantee on offline receipt and evidence-reference writes. Add a slow export reader and a large, documented capture to the existing latency and bounded-memory benchmark.

**Rationale**

In SQLite WAL mode, `synchronous=NORMAL` can survive application termination and still lose a committed transaction after loss of power. Long readers can prevent a checkpoint from resetting the WAL. Measuring only a warm, idle query misses both costs. [SQLite synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous) · [SQLite WAL checkpoint behavior](https://www.sqlite.org/wal.html#avoiding_excessively_large_wal_files)

**Benefits**

A durable receipt has a testable meaning. The team can see whether a report export exhausts disk headroom or breaks the latency target before choosing an index or cache.

**Trade-offs**

A credible storage-fault test needs a disposable database and a storage fault harness or VM that can model loss of unsynced writes. A process-kill test alone has a narrower evidence claim.

**Implementation notes**

Use a synthetic metadata import, acknowledge it, interrupt at the chosen storage boundary and recover the receipt and its immutable references. Account for unavailable bytes explicitly. Record the filesystem, effective writer settings, capture size, RSS, disk peak, contention and tail latency. Keep large storage tests outside the quick unit-test path.

**Git diff**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1000,2 +1000,4 @@
 Use SQLite with transactions, foreign keys, explicit migrations and tested local durability settings for the small canonical coordination state. Initial supported writes are on a local Linux filesystem, not a synchronized folder or network share. Back up consistently; do not copy a live WAL database as if it were a complete archive.
+
+Define the failure model for an acknowledged control commit. For a local WAL profile promising host-crash durability on storage that honors flushes, require `synchronous=FULL` on every writer and verify the effective settings. Qualify another journal/storage profile against its own durability contract. Exercise a disposable offline import under process termination, loss of unsynced writes and failed sync. Verify acknowledged request identity and cross-references after recovery, and surface uncertain commit outcomes.
 
@@ -1315,2 +1317,4 @@
 Document end-to-end latency separately from native instrument time and model latency. An efficient controller that causes many extra agent calls is not an efficient workflow. Profile before introducing caches or parallelism; cached guidance always carries its basis and is revalidated before effects/promotion.
+
+Repeat the benchmark with a slow snapshot export and concurrent local metadata updates. Name the workload, reader count, input sizes and memory/disk budgets in the benchmark manifest. Measure p95 and worst observed latency, peak resident memory, WAL/spool high-water marks and recovery after the reader exits. Bound snapshot lifetimes or materialize immutable reference lists before long streaming renders when measurement shows checkpoint pressure.
 
```
