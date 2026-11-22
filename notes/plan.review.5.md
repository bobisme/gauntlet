# Scourge implementation plan review 5

## Executive summary

Keep the computed finding status, the independent evidence store, and the comparison between native tools, written guidance and Scourge. They give a maintainer a way to ask what happened, what the evidence proves, and whether the software helped. **Revise the evidence and recovery contracts before M0.7 freezes them.** Teapot can send a request without saving a flow. The proposed recovery rule would tell a successor that the request was never sent.

Two other decisions deserve attention before the HTTP preview. The plan permits use of an existing object but describes cleanup as deleting the object. And its evaluation can give an “unassisted” agent a property declaration that identifies the case to investigate. The first risks changing someone’s data. The second can make operator preparation look like agent performance.

RECEIPT’s authors report 24 previously unknown findings in their study of cross-site scripting with source access. Chen’s independent artifact audit found that 20 of 30 patched cases still produced the claimed signal. Neither supplies an effectiveness estimate for Scourge’s black-box HTTP product. The maintainer pilot in E§14 is worth keeping alongside the mechanical tests. Tricorder evaluated developer use in situ, and Lin et al.’s 20 developer interviews document why missing deployment context matters to people making remediation decisions. [RECEIPT](https://arxiv.org/abs/2607.18575) · [Artifact reproducibility study](https://arxiv.org/abs/2608.09567) · [Tricorder](https://research.google/pubs/tricorder-building-a-program-analysis-ecosystem/) · [Lin et al.](https://www.usenix.org/conference/usenixsecurity25/presentation/lin-elizabeth)

**Review basis.** Revision 2 at `9d7ef0b` and its evaluation, research and later-milestone companions. Reviews 1–3 address the archived revision. Review 4 appeared during this pass and independently identifies the risks from case hints, managed instructions and chain scope. The proposals here also address missing captures, pre-existing objects and the evidence available to a report recipient. Priorities below refer to implementation risk and effort. The line references point into the original revision. This review used static source inspection and primary publications. Product behavior, agent success rates and release readiness still require measurements.

## Proposed changes

### 1. Keep an interrupted action unknown when capture is missing

**P0 · High impact, low effort**

**Current state.** The recovery table treats an idle engine plus an empty capture search as “not sent.” It also treats a matching request digest above a flow-ID floor as the outcome. Two callers can submit the same bytes. Teapot explicitly represents a sent request whose flow ID is absent, and its capture pipeline can lose capture while relay continues. Hallpass’s receipt documents the debit only. [Plan §7.5, line 616](plan.md#75-run-lifecycle-and-recovery) · [Teapot’s recorded hop](https://github.com/bobisme/teapot/blob/a4ee40519d7c37452d3eade48eebf975708ea7bc/crates/teapot-engine/src/replay/outcome.rs#L68-L86) · [Capture failure behavior](https://github.com/bobisme/teapot/blob/a4ee40519d7c37452d3eade48eebf975708ea7bc/crates/teapot-engine/src/pipeline/capture.rs#L13-L37) · [Hallpass receipts](https://github.com/bobisme/hallpass/blob/f6ebf2f4c9e937cd43e700917ea66048a8f76c46/docs/EVIDENCE.md#L7-L22)

**Proposed change.** Require positive, step-specific evidence for any claim about dispatch. A durable refusal before dispatch can establish that nothing was sent. Delivery and application of the intended change remain separate questions.

**Rationale and benefit.** A successor can safely stop even when the instrument will never recover the missing evidence. This also respects HTTP’s rule for retries when the outcome of a non-idempotent request is unknown. [RFC 9110 §9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2)

**Trade-off.** Some runs will remain unresolved and need the operator’s named disposition. That is a legitimate outcome of M1.7.

**Implementation and acceptance.** Give recovery a saved pre-dispatch refusal, a sent request with no retained flow, and two matching candidates with different run identities. Require the same run ID after reconciliation, no second dispatch, and uncertainty for the last two whenever the effect cannot be established.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -613,5 +613,5 @@
 | Before the run row | Nothing happened. | A new command is safe. |
-| Run declared, no step sent | No effect. | The same request key resumes. |
+| Run declared, no durable dispatch intent | No step could have started under the write-ahead rule. | Reopen the existing run by its key. |
 | During the instrument's budget draw | A charge may have committed. | Record `units_left` when readable. No refund is assumed (F-13). |
-| Step sent, response lost | The request may have reached the target. | Read flows above the recorded floor and match the step's request digest. A match gives the outcome. No match with an idle engine means not sent. Otherwise effects are `unknown`, conflicting runs are blocked, and nothing is repeated automatically (INV-14, F-12). |
+| Dispatch intent persisted, response unavailable | The action may have reached the target. An idle engine, a missing flow and a matching payload digest are each insufficient to settle the effect. | Reconcile locally from durable evidence bound to this run and step. Report only the observed stage. Record `observed` for an established effect and `none` for an established absence of effects. If neither can be established, keep `unknown`, retain the conflict block and suppress automatic repetition (INV-14, F-12). |
 | Verifier killed mid-run | The instrument's job may continue. | Query the job. Finalize with what was captured. Cleanup remains owed. |
@@ -622,3 +622,3 @@
 
-A lost response is recovered with `scourge`, which lists the run, or `scourge run show --request-key KEY`. A deliberate new verification is a new run with a new key. Lock expiry alone never proves the earlier run stopped.
+Recover a lost response through the existing run listed by `scourge` or by request key. Reconciliation may finish its inspection with effects still unknown. A deliberate new verification has its own run and key. Lock expiry alone never establishes termination.
 
@@ -1059,3 +1059,3 @@
 | F-11 | A flow is missing or truncated. | `EVIDENCE_INCOMPLETE`. Partial originals kept. |
-| F-12 | An action commits and the response is dropped. | Effects `unknown`. Reconcile. No repeat. |
+| F-12 | An action may have committed. The response is lost, with either no stored flow on an idle engine or several matching digests. A separate history contains a durable pre-dispatch refusal. | The first two histories retain `unknown` without step-specific evidence. The refusal establishes no dispatch. Every lookup retains the original run and makes zero sends. |
 | F-13 | Budget is drawn and the send fails. | Charge preserved. Not-started evidence. No refund assumed. |
````

</details>

### 2. Protect existing objects from cleanup and stale proof

**P0 · High impact, low effort**

**Current state.** Section 6.5 admits `update` on a pre-existing object and `designated` on an existing value. The same table specifies removal during cleanup. Section 7.7 assumes Scourge created the object, and §5.3 assumes each round has a fresh one. A designated value could therefore produce a fresh-looking badge, or cleanup could delete an object the operator already owned. Scored trials exercise only `create`, so passing them would say nothing about the other two modes. [Plant modes, line 491](plan.md#65-the-first-oracle-webprivate-object-readv1) · [Cleanup](plan.md#77-cancellation-and-cleanup)

**Proposed change.** Limit the initial verified profile to objects whose creation by this run is established. Keep the other modes available for recording leads. A preview of an unsupported mode should explain the limitation before any target action.

**Rationale and benefit.** The product can keep its freshness promise and tell the operator exactly which data it may remove. This narrows two product modes while preserving the chosen black-box scope.

**Trade-off.** Read-only engagements can preserve evidence as leads. Their first verified badge would have to wait for a separately qualified profile. Supporting an existing object later needs its own restoration and evidence rules.

**Implementation and acceptance.** In a fixture with an existing object, preserve its bytes, identity and existence across both refusal and cleanup. An ambiguous creation receipt leaves cleanup owed. Test both custody tiers because custody does not establish object ownership.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -490,3 +490,3 @@
 
-**Plant modes.** `create` is the default and is required for scored evaluations: the object did not exist before the run, so nobody could have shared it in advance. `update` writes the canary into an existing owner object where creation is impossible; the record carries `object_preexisting`. `designated` uses an existing owner-only value named by the operator where nothing can be written; freshness controls do not apply and the record says so. Planting changes target state, so the engagement must allow the `plant` effect.
+**Plant modes.** M0–M2 qualify `create` only. Cleanup may remove only an object unambiguously identified as created by this run. An ambiguous owner or object ID leaves cleanup unresolved. `update` and `designated` can be recorded as leads. Their previews explain the unsupported mode and verification refuses before any target action. Qualifying either mode requires separate freshness, ownership, restoration and disclosure fixtures.
 
@@ -638,3 +638,3 @@
 | `observe` | Identity probes and reads | An active engagement and a valid pass. |
-| `plant` | Creating, updating and removing the verifier's own object | `allow_effects` includes `plant`. |
+| `plant` | Creating an object for this run and removing that same object after its creation is established | `allow_effects` includes `plant`. |
 | `mutate` | The treatment write in the state-change oracle | `allow_effects` includes `mutate`. |
@@ -1025,3 +1025,3 @@
 | INV-19 | Cleanup outcome is recorded per run, and an engagement cannot close with unresolved effects or cleanup unless the operator accepts them by name. | F-27. |
-| INV-20 | Canaries are 128-bit random, minted by the verifier per round, and never reused across rounds or runs. | Unit test; F-09. |
+| INV-20 | For the initial controlled and intermittent HTTP profiles, each round requires a fresh run-created object and a verifier-generated random 128-bit canary never reused across rounds or runs. Cleanup requires evidence that this run created the exact object. | Unit test, F-09 and F-27. |
 | INV-21 | Executable paths, evidence roots, credential sources and sockets come only from the operator binding outside the inspected tree. | F-28. |
@@ -1074,3 +1074,3 @@
 | F-26 | Enforcement is required and the instrument cannot enforce the pass. | Refused. No downgrade offered. |
-| F-27 | Cleanup fails. | The finding may verify. The engagement cannot close. |
+| F-27 | Cleanup fails, creation is ambiguous, or the property names an existing object. | An existing object remains intact. Uncertain ownership produces no deletion. An owed cleanup blocks closure until resolved or explicitly accepted under INV-19. A supported finding retains its cleanup caveat. |
 | F-28 | A nested `scourge.toml` names a sentinel adapter and a symlinked evidence root. | No adapter invocation, host probe, secret resolution or foreign read. |
--- a/notes/plan.later.md
+++ b/notes/plan.later.md
@@ -205,3 +205,3 @@
 |---|---|---|---|
-| Cross-principal canary | Private object read. Forbidden state change. Later templates on the same observer: list endpoints that leak another principal's object, nested resources, alternate routes, role-restricted functions, fields a principal should not be able to set. | Two principals and a writable or designated owner value. | M1, M2, then one template at a time. |
+| Cross-principal canary | Private object read. Forbidden state change. Later templates on the same observer: list endpoints that leak another principal's object, nested resources, alternate routes, role-restricted functions, fields a principal should not be able to set. | Two principals and an object created by the run for M0–M2. Existing-object modes require separate qualification under plan §6.5. | M1, M2, then one template at a time. |
 | Out-of-band interaction | Server-side request forgery. Blind injection with callback. | A collector the target can reach and the worker cannot. | M3 |
````

</details>

### 3. Give the policy behind a verified finding an accountable source

**P0 · High impact, high effort**

**Current state.** A property may come from a lead. A document with an artifact ID and selector can supply a verification-grade policy basis. The plan never says who establishes that the selected text imposes this restriction on these principals and this release. A digest of a real manual for a different edition would satisfy the stated representation. Also, the controlled profile requires a non-inferred policy before the predicate can be true, while F-04 expects a true observation with inferred policy to reach `conditional`. [Property and policy, lines 268 and 299](plan.md#45-policy-basis) · [Controlled profile](plan.md#53-profiles) · [F-04](plan.md#14-fixture-catalog)

**Proposed change.** Let leads propose policy citations freely. Admit a document-backed rule once per applicable scope through the operator’s policy binding. Keep the measured predicate independent of that decision. Where policy depends on mutable target state, protecting local stores alone cannot establish the applicable restriction. Preserve the owner’s decision to accept attributed operator statements in shared custody.

**Rationale and benefit.** A maintainer can accept what the evidence shows and still challenge the interpretation of the rule. The same approved rule can support multiple leads. The agent cannot confer policy authority by changing a source label.

**Trade-off.** An uncatalogued policy may require one operator judgment before a conditional result can become verified. No general-purpose policy language is needed.

**Implementation and acceptance.** Use the same saved observation in four cases. Supply a matching approved rule, an unreviewed citation, a genuine rule for a different version, and an applicable rule allowing the behavior. Only the first can support a verified policy violation. A custody badge alone cannot resolve a material uncertainty about sharing state. Keep the identity and provenance of the decision in the snapshot.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -231,3 +231,3 @@
 | What protects the verdict | The verifier is a separate process and takes no observation or result from the agent. No stored verdict is trusted: `report`, `bundle check` and `retest` re-evaluate the oracle from retained originals. Verification records are hash-chained and each report carries the chain checkpoint. | All of the above, and the coordination store, evidence store, instrument project, verifier binary and fixture administration are neither writable nor readable from inside the boundary. |
-| Not prevented | An agent that forges raw flows inside the instrument's store, replaces a binary, or uses a test identity to change target state during a run. Reports say so. | Anything outside the documented boundary. The qualification record lists what was tested. |
+| Limits of the boundary | A same-account process can change files, processes or target state available to its test identity. | Qualification states which local stores and channels are protected. Target-side policy or sharing state can still change through authorized clients. A claim that depends on unestablished policy state stays conditional or disputed in either tier. |
 | Badge | `Verified by controlled execution · shared custody` | `Verified by controlled execution · isolated custody` |
@@ -298,3 +298,3 @@
 | `engagement` | The operator declared the property in the engagement file. | Can verify. |
-| `document` | A retained artifact (API documentation, specification) with a selector. | Can verify. |
+| `document` | An operator-admitted rule binds a retained document digest and selector to the asserted restriction, its scope and applicable version. A lead can suggest a citation. | Can verify within that binding. An unadmitted or out-of-scope citation has the status effect of `inferred`. |
 | `operator` | An operator statement recorded during the engagement. In shared custody this is attributed, not authenticated, and the record says so. | Can verify. |
@@ -356,4 +356,4 @@
      r depends on, or evidence r cites is retracted → needs_review
-  if a material objection is unresolved            → disputed
-  if r.policy_basis = inferred                     → conditional
+  if a material objection or applicable contrary policy stands → disputed
+  if no admitted applicable policy supports the restriction   → conditional
   else                                             → verified
@@ -387,3 +387,3 @@
 |---|---|---|---|
-| `runtime-controlled.v1` | Every round of the experiment true with all controls valid, policy basis not inferred, no unresolved objection. | `Verified by controlled execution` plus custody, policy basis and scope. | M1 |
+| `runtime-controlled.v1` | Every declared round is true with all controls valid. This determines the measurement. Section 5.1 separately applies policy, objections and freshness to the finding. | A verified badge requires all §5.1 conditions and shows custody, policy basis and scope. | M1 |
 | `runtime-intermittent.v1` | A number of rounds declared before the run with no early stop, every round's controls valid, at least two rounds true, all rounds retained. | `Verified intermittent behavior, k of n rounds`. Never implies reliable exploitation. | M2 |
@@ -1011,3 +1011,3 @@
 | INV-05 | Every record and badge carries profile, oracle version, custody tier, enforcement, policy basis and validation kind. | Report snapshot tests. |
-| INV-06 | A true predicate with an inferred policy basis yields `conditional`, never `verified`. | F-04. |
+| INV-06 | A true observation with an inferred or inapplicable policy basis yields at most `conditional`. Each verification-grade policy binding identifies its authority, proposition and scope. An applicable rule permitting the observed behavior precludes a verified violation of that rule. | F-04 and F-25. |
 | INV-07 | An invalid setup or measurement yields `invalid` with a reason code, never `false` and never `true`. | F-01–F-08; F-11. |
@@ -1051,3 +1051,3 @@
 | F-03 | A login or error page returns 200. | `OBSERVER_INVALID` or a failed identity probe. Not a successful read. |
-| F-04 | Every authenticated user may read the object by design. | Predicate true. Without a non-inferred policy basis the status is `conditional`. |
+| F-04 | One saved true observation is paired in turn with an admitted applicable prohibition, an unadmitted citation, a citation for a different version, and an applicable permission. | Only the prohibition supports `verified`. The middle cases are `conditional`. The permission is contrary evidence for §5.6. The observation itself is unchanged. |
 | F-05 | A 403 body contains the canary. | `true`. Content decides, not status. |
````

</details>

### 4. A historical finding needs a separate answer about current applicability

**P0 · High impact, high effort**

**Current state.** The status function selects the latest *true* record. An older positive stays selected after a later retest reports a bounded fix. A report can therefore put the earlier finding in its verified section without telling the maintainer what the later test established about the deployment. Its stability check can also miss an objection committed during rendering. An objection changes `lead_events` without moving the verification chain head, the engagement revision or the evidence checkpoint. The early return for refutation can conceal a broken chain. [Status algorithm, lines 344–359](plan.md#51-status-is-computed) · [Report checkpoints, lines 872–875](plan.md#103-report-semantics)

**Proposed change.** Keep the historical finding and identify the basis to which it applies. Display the latest relevant retest and target applicability separately. Read all local metadata from one revision that includes lead events. Compare it with the evidence revision and registry used by the read. If the read never produced a coherent snapshot, return an indeterminate result.

**Rationale and benefit.** A maintainer can see both “verified on the earlier release” and “no violation within the retested scope on the later release.” A plain negative or broken retest cannot erase the original evidence. SQLite WAL gives a reader a consistent view of one database while writers proceed. A second store still needs its own identifiable snapshot. [SQLite isolation](https://www.sqlite.org/isolation.html)

**Trade-off.** Status and reports carry an extra revision and an applicability field. A busy workspace may temporarily lack a current report.

**Implementation and acceptance.** Use recorded histories for a bounded fix, an inconclusive retest and a later valid negative. Commit a material objection while a slow export is collecting evidence. The result must name one coherent state or say it could not establish one. Include this case in the existing concurrent-reader benchmark. A discarded cache entry may cost time but must never affect a badge.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -344,10 +344,9 @@
 status(lead) =
-  let R = verification records on the chain that name this lead
-  if a `refuted` disposition stands                → refuted
-  if R has no record with predicate = true         → lead
-       (open | withdrawn | duplicate | deferred | blocked,
-        with the last run's outcome: false | invalid | none)
-  let r = latest record in R with predicate = true
-  if chain broken, or originals missing, or
-     re-evaluation over originals ≠ r.result       → integrity_failure
+  let R = on-chain records for this lead at the selected snapshot
+  if the chain fails its integrity check             → integrity_failure
+  if a supported refutation stands at this snapshot → refuted
+  let r = latest kind=verify record in R with a true measurement
+  if no such r                                      → lead with disposition and last outcome
+  if required originals are missing, or
+     re-evaluation differs from r.result             → integrity_failure
   if r.oracle version is revoked in the registry   → needs_review
@@ -365,3 +364,3 @@
 
-`needs_review` does not erase history: the record still shows what was verified, against which basis, and what changed. A revoked engagement stops new runs and does not make a correctly observed historical violation false. A new deployment leaves the old finding historically valid and its applicability to the new deployment unestablished.
+`needs_review` preserves the earlier record and basis. Alongside historical status, compute applicability to the named target revision from the full dated evidence, including later results. A qualifying fix shows the earlier verified finding and the bounded retest outcome together. A later valid negative on the same basis exposes the conflicting evidence. A different deployment or an inconclusive retest leaves present applicability unestablished. An expired or revoked pass stops future activity. It does not erase the historical finding.
 
@@ -871,7 +870,7 @@
 
-A report names its snapshot: engagement and revision, selection and audience, the chain checkpoint, the oracle registry version, and the evidence store's checkpoint. It recomputes status and re-evaluates oracles (INV-04).
-
-- A `current` label requires that the material inputs were stable across the read: the generator reads the checkpoints before and after collecting, and retries a bounded number of times. If stability cannot be established, the report presents the identified historical basis with current status unknown.
-- Sections are separate: verified findings (by profile, with custody and policy basis); conditional findings; leads with their last outcome; refuted, withdrawn, duplicate and deferred leads with counts and reasons; runs with unknown effects; cleanup; limits.
-- Each finding shows its strongest caveat and direct evidence navigation.
+A report names the engagement, selection, audience, chain head, registry digest and evidence snapshot. Its coordination revision covers lead revisions, dispositions, objections, runs and cleanup as well as the verification index. Compute findings from one SQLite read snapshot and an identified evidence snapshot. Include both revisions in the report.
+
+- Label the report current as of a recorded observation only when both stores and the registry agree with the selected basis across collection. Test stability from fresh reads outside the original read transaction. After bounded retries, return the last complete, named historical snapshot if available. Otherwise state that no coherent report could be assembled. A mixed read cannot be presented as history.
+- Report verified history with its profile, custody and policy basis. Show current applicability and the latest pertinent retest beside it. Count conditional, disputed and needs-review items explicitly. Include lead outcomes and dispositions, unknown effects, cleanup and limits.
+- Each finding shows its strongest caveat, the named target basis and direct evidence navigation. An earlier verification cannot be counted as a currently established violation on a later deployment solely because it is the most recent positive.
 - "No verified findings" never becomes "secure" (F-35). "No violation observed" is bound to the conditions tested.
@@ -1007,3 +1006,3 @@
 | INV-01 | No command, file, import or API accepts a verdict, an oracle result or a verification record from a caller; only the verifier writes records. | Catalog schema test; F-20; red-team public arm. |
-| INV-02 | A finding's status is computed on every read from records, current revisions, the oracle registry and evidence availability, and is stored nowhere. | Status property tests; F-21; F-22. |
+| INV-02 | Historical finding status and applicability to a named target are computed on read at one identified coordination, evidence and registry snapshot. A memoized predicate cannot conceal a later retest, material edit, objection or loss of evidence. | Status property tests, F-21, F-22 and the concurrent report test. |
 | INV-03 | An oracle judges only flows the verifier itself sent in that run; flows from exploration or earlier runs are never inputs. | F-09; F-10. |
@@ -1069,3 +1068,3 @@
 | F-21 | The oracle version is revoked. | `needs_review`. |
-| F-22 | The lead's class, slots or policy basis change after verification; separately, its text changes. | `needs_review` for the first. No change for the second. |
+| F-22 | Change material slots or wording only, then exercise a later retest and a material objection during a report read. | The material change needs review. Wording alone leaves the judgment intact. The retest remains visible beside the historical basis. An objection cannot disappear from a report claiming the newer snapshot. |
 | F-23 | A stored verdict or memo is edited. | Re-evaluation disagrees. `INTEGRITY_FAILURE`. |
````

</details>

### 5. Make recovery prove who published a record

**P1 · High impact, high effort**

**Current state.** An imported record-shaped artifact is ignored under INV-01. Yet the recovery table lets reconciliation put an orphan artifact on the chain after re-evaluation. Recalculating a result authenticates neither the writer nor the membership of the inputs in the original run. Two reconcilers can also read the same chain head. The lock for a pass does not specify who serializes record publication or repairs. [Crash matrix, line 620](plan.md#75-run-lifecycle-and-recovery) · [Chain and checkpoints](plan.md#93-chain-and-checkpoints)

**Proposed change.** Scope each chain to its engagement. Before publication can become ambiguous, persist a verifier-authored local intent binding the run, record digest and predecessor. Reconciliation can finish only that publication. Make linking the record, advancing the expected head and recording completion one conditional SQLite transaction.

**Rationale and benefit.** Crash recovery then preserves the same admission boundary as normal publication. A duplicate reconciliation can return the original receipt without forking the chain or running an experiment.

**Trade-off.** A head conflict or lost publication intent can leave valid evidence unlinked until a trusted local finalization resolves it. Same-account custody keeps its documented limits.

**Implementation and acceptance.** Start from saved artifacts. Exercise an authentic pending publication, an otherwise identical artifact with no matching intent, and two simultaneous reconciliations. Require one linked record for the first case, none for the second and one head after the race. Fail closed on a conflicting predecessor. Use the existing coordination and evidence stores.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -619,3 +619,3 @@
 | Evidence stored, acknowledgment lost | The artifact may exist. | Retry with the same ID. |
-| Record stored, chain head not advanced | An orphan artifact. | It is ignored. `scourge run reconcile` re-evaluates from originals and appends. |
+| Record stored, chain head not advanced | An artifact may belong to an interrupted verifier publication. | Match its digest, run and predecessor to the verifier's durable publication intent. Only that exact publication is eligible to finish. Unmatched artifacts remain unlinked. Reconciliation performs no target action. |
 | Report render failed | Evidence intact. | Render again. |
@@ -833,3 +833,5 @@
 
-Each verification record contains the digest of the previous one. The coordination store holds the head. Reports and bundles carry the head as a checkpoint, following Hallpass's checkpoint precedent. A broken chain, or a record cited by a report that is not on the chain, is `INTEGRITY_FAILURE` (INV-28). In shared custody the chain detects accidents and casual edits. It does not stop a determined same-account forger, and reports say that.
+Each engagement has its own chain. Serialize final publication per engagement. Before writing its immutable record artifact, the verifier reserves the next head and persists one pending publication containing the engagement, run ID, record digest and expected predecessor. In one coordination transaction, link the record once per run, compare and advance the expected head, and mark the intent complete. Concurrent completion of the same publication returns the original result. A conflicting predecessor leaves publication pending for trusted local finalization. An import cannot create an intent.
+
+Reports and bundles carry the applicable head. A broken chain or an off-chain record presented as a member is `INTEGRITY_FAILURE` (INV-28). In shared custody this check detects internal inconsistencies relative to the retained head. The same-account trust limit appears in the report.
 
@@ -1033,3 +1035,3 @@
 | INV-27 | Evidence originals are immutable; redaction creates a derivative with its own digest and lineage. | Evidence contract tests. |
-| INV-28 | Verification records are hash-chained, reports carry the checkpoint, and a broken chain is an integrity failure. | Chain tests. |
+| INV-28 | A per-engagement chain admits only a verifier-bound publication, once per run. Head advance and completion are atomic. Reports carry the checkpoint and broken links fail integrity. | Chain and concurrent-reconciliation tests, F-20. |
 | INV-29 | The coordination store holds no evidence blobs, no copy of Bones state and no Investigation lifecycle state. | Schema test. |
@@ -1067,3 +1069,3 @@
 | F-19 | The oracle or experiment changed between baseline and retest. | Comparison invalid. `inconclusive`. |
-| F-20 | A record-shaped artifact is imported or written to the evidence store directly. | Ignored by status. |
+| F-20 | Normal import, reconciliation of an unlinked lookalike, and two recoveries of one genuine pending publication. | Only the genuine digest bound by the verifier can be linked. Both recoveries agree on the single record and head. |
 | F-21 | The oracle version is revoked. | `needs_review`. |
````

</details>

### 6. Say exactly what a recipient can check in a redacted bundle

**P1 · High impact, low effort**

**Current state.** INV-04 mandates an integrity failure for missing originals in *every* bundle. Section 10.2 explicitly allows policy omissions. Both rules apply to a normal credential-bearing capture exported under INV-23. The checker also needs the historical oracle implementation, while the plan only promises the registry compiled into the installed executable. Finally, D5 requires isolated custody for third-party reports, but the export section never checks the custody of each contributing record. [INV-04](plan.md#13-invariants) · [Export and checking, lines 842–868](plan.md#10-reports-and-bundles)

**Proposed change.** Make the manifest declare which materials are included and which obligations those materials can support. Grade file integrity, producer provenance and recipient inspectability independently. Qualify third-party verified claims against the original records’ custody.

**Rationale and benefit.** A secret can stay withheld without accusing the producer of corrupting the archive. Conversely, a redacted derivative with a matching hash cannot earn an “independently rederived” badge for facts that required the omitted bytes. Isolation during export cannot retrospectively strengthen custody during acquisition. Investigation already plans separate review and recovery exports with explicit omissions. [Investigation export design, §16](../../investigation/notes/plan.md)

**Trade-off.** Some third-party reports will carry a historical assertion the recipient can only partially inspect. Keeping old trusted readers available is a separate compatibility cost.

**Implementation and acceptance.** On a clean machine, check a complete bundle, a declared omission, a missing promised file and an altered file. Then check the complete bundle with the matching reader unavailable. Record the affected obligation as uncheckable in the omission and missing-reader cases. Require an integrity failure for the missing or altered promised file. Also try exporting a mixed-custody selection for a third party. Check the status of each item and the exclusion counts. No checker loads executable code from a bundle.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -363,3 +363,3 @@
 
-Status is computed on every read and stored nowhere (INV-02). `report`, `bundle check` and `retest` always re-evaluate the oracle from original bytes (INV-04). Other reads may memoize by record, oracle and basis digests; the memo is a cache and never an input. Investigation holds the evidence and has no opinion on status, so there is no second gate to bypass and no cross-store transaction to commit.
+Status is computed on every read (INV-02). Local `report` and `retest` re-evaluate the cited measurement over its retained originals. An offline `bundle check` verifies the promised contents and re-evaluates each independently checkable obligation under §10.2 and INV-04. A memo may cache computation only. Investigation holds the evidence and the status remains Scourge's.
 
@@ -855,3 +855,3 @@
 
-Default exports redact secrets and unneeded personal data. A canary proves the boundary without collecting real records. Redaction creates a derivative with its own digest and lineage and never overwrites an original (INV-27).
+Default exports admit only material appropriate for the recipient. Record each omitted evidence channel and the obligations it affects without disclosing the omitted data. Each redacted derivative carries its own digest and lineage (INV-27). For a third-party report, each claim presented as verified requires isolated custody in its supporting acquisition record (D5). Count and identify ineligible claims within the audience policy. Packaging a shared record in isolation preserves its original tier.
 
@@ -865,3 +865,3 @@
 | Provenance | Is the producer authenticated under the recipient's own trust policy? | A key or manifest supplied only by the bundle cannot authenticate it. An unsigned bundle is `unestablished`, and can still be useful. |
-| Inspectability | For each obligation, is the evidence present to re-check it? | A declared policy omission leaves an obligation `uncheckable` without being an integrity failure. Where originals are present, the oracle is re-evaluated. |
+| Inspectability | Which obligations can this recipient re-evaluate? | Re-evaluate from permitted originals with a locally trusted implementation matching the recorded oracle digest. Mark an obligation `uncheckable` for declared omitted inputs or an unavailable implementation. A historical assertion, derivative digest or bundled executable cannot satisfy that obligation. |
 
@@ -1009,3 +1009,3 @@
 | INV-03 | An oracle judges only flows the verifier itself sent in that run; flows from exploration or earlier runs are never inputs. | F-09; F-10. |
-| INV-04 | `report`, `bundle check` and `retest` re-evaluate the oracle from retained original bytes and fail with `INTEGRITY_FAILURE` on mismatch or missing originals. | F-23; F-24. |
+| INV-04 | Required local originals missing or inconsistent with the recorded result fail integrity during local report or retest. The offline checker fails integrity for a promised file missing, digest mismatch or re-evaluation disagreement. A declared omission or unavailable matching reader leaves the affected obligation uncheckable. | F-23, F-24 and M2.5 bundle matrix. |
 | INV-05 | Every record and badge carries profile, oracle version, custody tier, enforcement, policy basis and validation kind. | Report snapshot tests. |
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -104,3 +104,3 @@
 | Entry size and concept check | Bare `scourge` and default `status` fit in 2 KiB. After the entry screen only, the agent states what the tool is for, what it must not do, and its next call. |
-| Reports | Every finding in a report resolves to complete required evidence and a current registered oracle. No lead appears as verified. |
+| Reports | At the producer, every current verified claim resolves to complete required evidence and a qualified oracle. At the recipient, report integrity, provenance and per-obligation inspectability independently. Only originally isolated records qualify for third-party verified claims. |
 
````

</details>

### 7. Keep operator-supplied answers out of the discovery score

**P1 · High impact, low effort**

**Current state.** E§2 requires the same information in all three arms. But the example engagement already identifies the property, principal pair, resource and claim class. Supplying it to C alone gives C a location hint. Supplying it to everyone still turns an unassisted case into a supplied one. Separately, M3 requires “fewer false promotions” than B, although B has no promotion operation. If B and C submit zero unsupported claims, the study cannot distinguish them on that measure. [Example engagement](plan.md#46-the-engagement-file) · [Evaluation conditions](plan.evaluation.md#2-conditions) · [M3 entry condition](plan.later.md)

**Proposed change.** Freeze the information each arm can see, including its prepared workspace and first screen. Distinguish the shared outcome a reviewer can score in every arm from C’s internal promotion gate. Predeclare what constitutes enough evidence to proceed and what counts as inconclusive.

**Rationale and benefit.** A team can tell whether a reported improvement came from software, written guidance or operator labor. Passing the mutation gate establishes that the fixtures detect removal of the listed checks. It leaves any unlisted missing obligation unmeasured. The independent scoring track still has work to do. NIST’s evaluation work illustrates the value of inspecting what an assessed agent could actually see. [NIST evaluation practices](https://www.nist.gov/caissi/4-practices-detecting-and-preventing-evaluation-cheating)

**Trade-off.** Some already-prepared cases will count only as supplied-lead cases. Tied or small cells can leave the comparative question open. The owner’s 20-family release floor still applies.

**Implementation and acceptance.** Have the referee inspect the *agent-visible* input package for each condition before scoring. Grade the published decision rule on three artificial score sheets covering a tie, abstention on every positive case, and a correct submission accompanied by an unsupported one. Under the starting Tier 2 allocation, the release already needs 80 C sessions and 16 matched A discovery sessions before extras. The existing maintainer pilot can also measure how much incoming work the two-class preview covers by keeping unsupported historical cases in its intake count.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -32,3 +32,3 @@
 
-A versus B shows what better instructions buy. B versus C shows what the software buys. Count every worker, failed attempt, setup step and recovery toward the budget. Reset or clone the environment between conditions and randomize order within matched groups.
+A versus B estimates the effect of written instructions. B versus C estimates the effect of software on the externally adjudicated submissions. Freeze each arm's visible inputs, including report templates, property declarations, workspace files, examples and initial screen. Give the same task facts in a usable form in every arm. An input that identifies the case-specific candidate counts as a supplied hint in every arm that receives it. A neutral policy can remain available in discovery cases. Have the referee attest hint parity before scoring. Count operator preparation and all worker and recovery costs. Randomize order within matched groups and reset between conditions.
 
@@ -92,3 +92,3 @@
 |---|---|
-| False promotion | Zero adjudicated false or unsupported promotions on **any** scored trial, including a trial that also contains a true finding. Grade each promotion against the evidence available at the time, using the full promotion history including superseded and withdrawn records. An unresolved adjudication keeps the gate open. |
+| False promotion | Zero adjudicated false or unsupported promotions by C on any scored case, including mixed cases and later withdrawals. Grade against evidence available at the time. Open adjudication keeps the gate open. For comparisons across A, B and C, grade unsupported submitted claims under the same external rubric (§10). |
 | Promotion red-team | Zero successes through the public interface. Tampering successes reported per custody tier and zero in isolated custody (§8). |
@@ -147,3 +147,3 @@
 
-**Comparative claims.** Preregister the primary paired estimand and the minimum useful effect. Use family-level paired differences and resampling; repeated sessions of one family are not independent samples. Overlap between separate arm intervals is not the decision rule. An imprecise difference is an unestablished benefit. Label multiple ablations exploratory or confirm them on untouched data. Release correctness can be shown before any superiority claim, and no superiority claim is made without a powered matched comparison.
+**Comparative claims.** Preregister the family-level paired estimand, minimum useful effect, noninferiority margin where relevant, and decision rule. Report externally adjudicated unsupported submissions per assigned trial alongside supported yield, abstentions and cost. Use family-level paired differences and resampling. Multiple sessions per family are correlated. Use the interval on the paired difference for the decision. Label additional ablations exploratory until confirmed on untouched cases. Equal zero unsupported submissions supplies no evidence that C reduced them. Zero supported yield in both arms leaves useful discovery unestablished. Classify imprecise differences as inconclusive. Tier 1 guides investment. A superiority claim requires a powered matched comparison on untouched cases.
 
@@ -182,3 +182,5 @@
 
-**Maintainer-decision pilot (development only, at M2).** On a small panel of previously resolved, permission-cleared cases, compare native evidence, the same written guidance, and the Scourge report with equal access and time. Primary outcome: the fraction of cases with an evidence-supported disposition (fix, close, request evidence, defer) by a fixed cutoff. Cost measure: reviewer minutes per case. Use different reviewers per arm for each case and hide later patches and original decisions. This pilot chooses report changes. It supports no comparative claim.
+**Maintainer-decision pilot (development only, at M2).** On a small panel of previously resolved, permission-cleared cases, compare native evidence, the same written guidance and the Scourge report with equal access and time. Measure the fraction reaching an evidence-supported disposition (fix, close, request evidence, defer) by a fixed cutoff and reviewer minutes per case. Use different reviewers per arm for each case and hide later patches and original decisions. Use the pilot to improve reports.
+
+For claims about usefulness across incoming reports, record how the panel was selected. If a consecutive, permission-cleared intake is available, show the full count, the count with a supported class and prerequisites, and the count with an actionable disposition. Report the result within supported cases alongside its fraction of all incoming cases. A panel selected only for supported classes establishes no intake-wide rate.
 
--- a/notes/plan.later.md
+++ b/notes/plan.later.md
@@ -6,3 +6,3 @@
 
-**Entry condition for M3.** The Tier 1 evaluation ([`plan.evaluation.md`](plan.evaluation.md) §6) shows that Scourge (condition C) produces fewer false promotions than written guidance alone (condition B) without losing discovery against the instruments alone (condition A). If it does not, find out why before adding breadth.
+**Entry condition for M3.** Apply the frozen Tier 1 decision rule in E§7 and E§11. Compare externally adjudicated unsupported submissions in C and B and supported yield in C and A at matched budget. C's internal promotion gate must pass independently. A tie at zero, insufficient precision, or zero supported yield in both discovery arms leaves the proposed benefit unestablished. Diagnose the result before adding breadth.
 
````

</details>

### 8. Prove budget attribution before assigning a cost to one run

**P1 · High impact, low effort**

**Current state.** Section 7.4 offers only `exclusive` or `shared`. Its default inference of exclusivity relies on serializing Scourge runs and inspecting that engine’s job list. Native clients remain permitted, and Teapot’s own accounting type expressly includes spending outside Teapot. Units left can also be unknown. A block drawn during one run can fund later work. Even a caller reference on that block identifies a debit at block granularity. [Accounting, line 603](plan.md#74-accounting-evidence) · [Teapot’s accounting fields](https://github.com/bobisme/teapot/blob/a4ee40519d7c37452d3eade48eebf975708ea7bc/crates/teapot-engine/src/allocator/mod.rs#L340-L385)

**Proposed change.** Add `unestablished` attribution. Keep engine activity, pass-wide totals and run-specific charges distinct. Publish estimates only at the granularity the evidence supports.

**Rationale and benefit.** An evaluation cannot accidentally count another consumer’s spend against Scourge, or report zero cost for work paid from a previously drawn block. This preserves the instrument’s ownership of accounting.

**Trade-off.** More cost-per-finding cells will lack an exact number. Known aggregate cost and its observation window remain useful.

**Implementation and acceptance.** Give the adapter two saved observations with identical visible job lists and counter deltas. In one history another consumer contributed to the change. Without independent evidence of exclusivity both histories must produce the same conservative label. Include a null counter and a block spanning two jobs.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -591,3 +591,3 @@
 | Units left | Before and after a run. |
-| List jobs | To see whether anything else spent from the pass during the window. |
+| List jobs | Identify activity visible to this engine in the interval. Other consumers of the pass may be outside that view. |
 | Cancel | Request, then observe. |
@@ -602,3 +602,5 @@
 
-Per run, the record holds: pass ID and digest, instrument job IDs, the dry-run request ceiling, `units_left` before and after, and `attribution: exclusive | shared`. Runs against one pass are serialized so the difference is attributable. If the job list shows another spender in the window, attribution is `shared` and the report says so. Because Teapot draws in blocks and does not refund, the ledger errs high; the record states the granularity. An engagement that demands exact per-run accounting is refused with that reason until the upstream change lands: Teapot linking a Hallpass with caller references, sending one per job, and exposing the ledger sequence. Then `hallpass receipt --caller-ref` becomes the reconciliation step (INV-16).
+Record the pass ID and digest, job IDs, dry-run ceiling, counter source, granularity, window and nullable counter values before and after each run. Attribution is `exclusive` only with positive evidence covering all consumers of the pass for that window, `shared` when another spender is observed, and `unestablished` otherwise. A local run lock and an empty job list cannot establish exclusivity. Keep ledger debits, units held by the engine and observed run work in separate fields.
+
+Refuse exact per-run accounting unless the instrument can attribute the required units to that run. A caller reference and sequence identify a debit at its recorded granularity. A block spanning jobs needs evidence of how the units were assigned before individual charges can be claimed (INV-16).
 
@@ -1021,3 +1023,3 @@
 | INV-15 | Status, help, `show`, `next`, `--plan`, `doctor`, `report` and `bundle check` send no target traffic. | Network-sink test over the whole read-only surface. |
-| INV-16 | Scourge never debits a budget; accounting evidence is recorded as observed, with its granularity and attribution. | Adapter contract test; F-13. |
+| INV-16 | Scourge never debits a budget. Every reported cost retains its source, granularity, scope and attribution. Unavailable counts stay unknown, and a pass-wide delta alone cannot establish a run's charge. | Adapter contract test, F-13 and M2.7. |
 | INV-17 | When a required enforcement or custody tier is unavailable the run is refused; no flag or retry downgrades it. | F-26. |
--- a/notes/plan.later.md
+++ b/notes/plan.later.md
@@ -193,3 +193,3 @@
 | `authenticated_external` custody and multi-host work | Needs a signed channel and a trust policy. | A third-party verification service is required. |
-| Exact per-run accounting | Needs an upstream change in Teapot. | Teapot sends caller references and exposes the ledger sequence. |
+| Exact per-run accounting | Job references alone may identify a block shared across runs. | The instrument demonstrates run-bound attribution at the granularity the engagement requires. |
 | SARIF and tracker exports | Lossy projections. | A consumer asks. Each export declares what it loses. |
````

</details>

### 9. Test the exact handoff a first-time agent receives

**P1 · High impact, low effort**

**Current state.** The JSON example’s suggested command omits an output-format flag. With a fresh shell and no `FORMAT`, the stack’s documented pipe default is text. A client following that argv can lose its JSON contract on the very next call. The example badge also omits oracle version, enforcement and validation kind despite INV-05. Section 8.2 counts three mutating calls, although its path through the first verdict contains only `lead add` and `verify` as mutations. Section 6.1 also says only verification sends traffic while the command catalog gives retest the same effects. [Response example, lines 706–726](plan.md#84-responses) · [Bones CLI conventions, lines 24–61](../../bones/.agents/edict/design/cli-conventions.md)

**Proposed change.** Carry machine format into machine-generated suggestions and show all mandatory qualifiers in the example. Score executable-only orientation independently of managed instructions. Define exactly where the first-result clock starts and what evidence stops it.

**Rationale and benefit.** This tests whether an agent can use the first answer safely from another directory, without a remembered environment or help from the bootstrap author. Edict’s harness deliberately probes whether its managed instructions loaded. SWE-agent’s interface ablations motivate an interface comparison, but their coding results supply no Scourge success rate. [Edict evaluation harness](https://github.com/bobisme/edict/blob/3f882a4d70bb948e059a2458c2d5047072e1cbf0/evals/README.md#L43-L74) · [SWE-agent §5.1](https://arxiv.org/html/2405.15793v3#S5.SS1)

**Trade-off.** Suggested argv grows by two arguments. Reporting the executable-only and managed starts separately may reveal a dependency on the managed block.

**Implementation and acceptance.** Give a fresh agent the tool name and a prepared, offline case. Ask it to identify the strongest caveat and cite the evidence or the case’s actual blocker within three calls. Repeat from an unrelated directory with spaces, no inherited format setting and two engagements. Run each suggested read literally and parse the reply as one JSON object. Record failure to reach the result in the denominator.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -118,3 +118,3 @@
 - A useful result (a cited observation or the correct blocker) within three calls from first invocation, counting help and repair calls.
-- From a supplied lead to a verified finding on a supported class: at most six mutating calls, median. The designed path is three (§8.2).
+- From a supplied lead to a verified finding on a supported class, at most six mutating calls, median. Count from the stated starting condition through the first verdict (§8.2).
 - After reading only the entry screen, the agent can state what the tool is for, what it must not do, and its next call.
@@ -441,3 +441,3 @@
 
-A run that sends target traffic is explicit: `verify` says what it will do and `--plan` shows it first. Nothing else in the porcelain sends target traffic (INV-15).
+Both `verify` and `retest` can send target traffic. Their `--plan` forms send none (INV-15). The command catalog names local writes separately from target effects so readers can tell what the suggested action changes.
 
@@ -679,3 +679,3 @@
 
-Three mutating calls. For a class with no template, `verify --plan` returns `ORACLE_UNAVAILABLE`, lists the supported classes, and says the lead stays a lead.
+From supplied lead details through the first verdict this sequence has three calls, of which two mutate state. If the lead is already recorded, only one mutation is needed. Report export comes after that measurement. For a class without a template, `verify --plan` returns `ORACLE_UNAVAILABLE`, lists supported classes and preserves the lead.
 
@@ -693,4 +693,4 @@
 | `finding object ID`, `finding refute ID` | local | §5.5, §5.6. |
-| `run show`, `run cancel`, `run reconcile` | cancel: requests cancellation. Others none. | §7.5. Never starts a new run. |
-| `report [--kind review\|reproduction\|summary]`, `bundle check PATH` | none | §10. |
+| `run show`, `run cancel`, `run reconcile` | `show` reads, `cancel` requests cancellation, `reconcile` may commit local recovery metadata. | §7.5. A local reconciliation never starts a new run. |
+| `report [--kind review\|reproduction\|summary]`, `bundle check PATH` | Both are offline. A report export writes local output. Checking a bundle is read-only. | §10. |
 | `handoff` | none | Bounded continuation context: target, findings with strongest caveat, unknown effects, cleanup, next action. Default 16 KiB. |
@@ -714,3 +714,4 @@
   "finding": {"id": "L-1", "status": "verified", "profile": "runtime-controlled.v1",
-              "custody": "shared", "policy_basis": "engagement"},
+              "custody": "shared", "enforcement": "unenforced", "policy_basis": "engagement",
+              "oracle_version": "web.private-object-read.v1", "validation": "deterministic"},
   "run": {"id": "R-4", "cleanup": "complete"},
@@ -719,3 +720,3 @@
     {"effects": "none",
-     "argv": ["scourge", "--workspace", "/work/orders", "--engagement", "orders-api", "report"]}
+     "argv": ["scourge", "--format", "json", "--workspace", "/work/orders", "--engagement", "orders-api", "report"]}
   ]
@@ -1036,3 +1037,3 @@
 | INV-30 | Bare `scourge` and default `status` each fit in 2 KiB, with omission counts and drill-down routes. | Size tests. |
-| INV-31 | Every suggested action is a complete argv that runs from the caller's directory. | M1.2 tests. |
+| INV-31 | Each suggested action has a complete argv for the caller's directory. A Scourge action suggested in machine mode explicitly selects JSON and carries its workspace and engagement when needed. | M1.2 launches suggestions in a fresh process with `FORMAT` unset. |
 | INV-32 | In machine mode every outcome, including usage errors, is one JSON object on stdout, and `--json` equals `--format json`. | CLI tests. |
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -49,3 +49,5 @@
 
-**A cold agent receives:** the executable on its PATH, the task objective, a prepared engagement with the needed credentials, and permission to use normal tool help. No system prompt with the command sequence, no coaching, no warm-up. Relevant security skill is assumed; tool knowledge is not.
+**Cold starts.** Record exactly what the host loaded. In the executable-only orientation cell the agent is given the executable name, a prepared workspace and the objective. Omit managed instructions and coaching. In the managed cell the ordinary owned block is present. Score discovery of the tool name separately if the prompt omits it. All cells retain their original assigned denominator.
+
+For the read-only orientation task, start counting at the first invocation, including help and repairs. Give credit only for a correct case-specific evidence reference and caveat, or a blocker that the referee independently confirms applies. Count an unreached result explicitly. Exercise machine suggestions with an empty format environment in a new process and an unrelated working directory.
 
````

</details>

### 10. Put the real prerequisites on the milestone graph

**P2 · Medium impact, low effort**

**Current state.** The handoff starts M0.6 alongside M0.1 even though M0.6 depends on M0.1. M0.6 also promises a recording-API crash/recovery check while the table first assigns W07 to M1.4 and M2.3. M1.6 promises status on retraction, but the first scheduled W10 query is M2.6. M2.5 needs W11 export, which appears in the prose and is missing from its dependency column. E§3 places the referee boundary in M0.5, while M0.4 can start from M0.3 alone. [Package table](plan.md#122-work-packages) · [Evidence bridge](plan.md#92-evidence-store) · [Investigation’s W07, W10 and W11](../../investigation/notes/plan.md)

**Proposed change.** Name upstream capabilities at the *first acceptance test that consumes them*. Distinguish unscored harness development from a baseline with a qualified referee. Keep the owner’s Investigation-first order and use its shipped public interface.

**Rationale and benefit.** A maintainer can tell which work can start and whether a milestone is genuinely complete. A local double or a package name can no longer stand in for an observed upstream capability.

**Trade-off.** An upstream delay becomes visible earlier. Inventory, fixture work and unscored harness development can still proceed.

**Implementation and acceptance.** Walk the graph once with W07, W10 and W11 independently unavailable. The corresponding acceptance checks must show a named unmet dependency. A later implementation of the dependency can satisfy the same check without changing the plan or introducing a second store.

<details>
<summary>Proposed plan edits</summary>

````diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -825,5 +825,5 @@
 | Ingest and selectors | W06 (minimum) | A | M1.4 |
-| Recording API: begin, append, attach, finalize, recover | W07 | B | M1.4 for begin, attach, finalize; M2.3 for recover |
-| Retraction queries | W10 (part) | B | M2.6 |
-| Export and archive | W11 | C | M2.5 |
+| Recording API: begin, append, attach, finalize, recover | W07 | B | M0.6 public contract conformance, M1.4 integration and M2.3 recovery with the instrument. |
+| Retraction queries | W10 (part) | B | M1.6 status freshness and M2.6 disposition handling. |
+| Export and archive | W11 | C | M2.5 bundle export. |
 
@@ -953,3 +953,3 @@
 
-**Prerequisite.** Investigation is built first (§15.2). M1.4 needs its packages W01 to W03, the minimum of W06, and the W07 recording API. M2.5 and M2.6 need W11's export and W10's retraction queries. M0.1 to M0.5 need none of it.
+**Prerequisite.** Investigation is built first (§15.2). M0.1–M0.5 do not consume its API. M0.6 qualifies the shipped W07 recording surface over W01–W03 and minimum W06. M1.4 integrates that surface. M1.6's retraction-aware status requires the W10 query. M2.5 needs W11 export and M2.6 uses the W10 retraction query. Each consumer records the actual upstream version and result.
 
@@ -964,5 +964,5 @@
 | M0.3 | Evaluation harness | M0.2 | E§3 | Edict's harness adapted and hermetic. Scripted checks against real state. A scripted correct agent scores 100% and a scripted cheating agent fails. A no-instructions control. Cost per run recorded. |
-| M0.4 | Baseline A and B | M0.3 | E§2, E§4 | At least five runs per condition. Transcripts. A failure taxonomy with counts. An ADR that keeps, cuts or adds obligations and fixtures against it. |
+| M0.4 | Baseline A and B | M0.3, referee boundary from M0.5 | E§2, E§4 | At least five runs per condition with comparable inputs and a qualified referee boundary. Record transcripts, costs and the failure taxonomy for the design ADR. Earlier unscored rehearsals may guide the harness. |
 | M0.5 | Custody spike | M0.2 | §3.4, §7.3, F-32 | The worker boundary built. Five tamper attempts scripted: all fail in isolated, each listed for shared. The confined-exploration route chosen. One enforced local topology running, or its blocker filed upstream with a reproduction. ADR. |
-| M0.6 | Investigation conformance | M0.1 | §9.2, §15.2 | Scourge's contract fixtures for capture, read, record, idempotent retry and crash recovery pass against the shipped Investigation. Anything missing is a named upstream package. A documented blocker does not satisfy this package. |
+| M0.6 | Investigation conformance | M0.1, shipped Investigation W07 and prerequisites | §9.2, §15.2 | Capture, read, record, idempotent retry and crash/recovery contract fixtures pass through the shipped public interface. Record unsupported capabilities as blockers. |
 | M0.7 | Contract freeze | M0.4, M0.5 | §4–§8, §13 | ADRs freezing the engagement schema, template schema, envelope, error and exit codes, record format and the two oracle specifications, written after the baseline. Upstream requests filed: Teapot caller reference and ledger sequence; loopback enforcement. |
@@ -973,3 +973,3 @@
 | M1.5 | Verifier and first oracle | M0.2, M1.3, M1.4 | §6.1–§6.5, §6.7, INV-01, 03, 07–09, F-01–F-11, F-14 | Every listed fixture passes. Mutation suite kills every listed check. |
-| M1.6 | `lead add`, `verify`, status, chain | M1.5 | §5, §6.9, §9.3, INV-02, 04–06, 28, F-20–F-24 | Status property tests. No command accepts a verdict. Tampered cache and missing original are caught. |
+| M1.6 | `lead add`, `verify`, status, chain | M1.5, shipped W10 retraction query | §5, §6.9, §9.3, INV-02, 04–06, 28, F-20–F-24 | Status property tests cover evidence retraction, changed cache and missing originals. No command accepts a verdict. |
 | M1.7 | Lost-response recovery | M1.6 | §7.5, INV-14, F-12 | On the testbed's act-then-drop route: effects unknown, nothing repeated, reconcile reaches an outcome backed by evidence. |
@@ -981,3 +981,3 @@
 | M2.4 | Isolated tier | M0.5, M1.6 | §3.2, §3.4, INV-17, F-32 | Broker and worker boundary. Setup commands printed, not run. Qualification record produced. Tamper attempts fail. Badge shows the tier. |
-| M2.5 | Report, bundle, `bundle check` | M1.6, M0.6 | §10, INV-04, 05, 23, 27, 35 | Clean-machine check of three bundles: complete, policy-omitted channel, and missing promised file. Replaced file plus digest in an unsigned copy leaves provenance unestablished. Seeded secret appears nowhere. |
+| M2.5 | Report, bundle, `bundle check` | M1.6, M0.6, shipped W11 export | §10, INV-04, 05, 23, 27, 35 | Clean-machine checks for complete, omitted, missing promised and altered materials. Repeat a complete check without its historical oracle. Confirm provenance is unestablished when material and its digest are replaced in an unsigned copy. Seeded secrets are absent from exports. |
 | M2.6 | Dispositions, objections, `next`, `handoff` | M1.6 | §5.5, §5.6, §8.3, INV-10, F-25 | The refutation trio. A successor agent given only the handoff names the claim, caveat, unknown effects and next action. |
@@ -1185,3 +1185,3 @@
 
-Investigation comes first (§15.2). In Scourge, start with M0.1, M0.2 and M0.6 in parallel, then M0.3 to M0.5, then M0.7. Do not write the domain catalog before the baseline taxonomy exists.
+Investigation comes first (§15.2). Scourge inventory and fixture work (M0.1 and M0.2) can start together. M0.3 and M0.5 follow the fixture. M0.4 uses the harness and its qualified referee boundary. M0.6 starts after inventory and availability of the shipped recording API. Freeze the domain catalog only after the baseline taxonomy exists.
 
````

</details>

All ten diffs passed `git apply --check` independently against revision 2. Applying them in order to a disposable copy also produced the intended documents.
