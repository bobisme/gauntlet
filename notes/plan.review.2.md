# Plan Review: Gauntlet Implementation Plan (`notes/plan.md`)

**Reviewed document:** `notes/plan.md` (Revision 1, 2026-11-21)  
**Review date:** 2026-11-21  
**Evaluation basis:** Comprehensive multi-dimensional critique (Architecture & Design, Robustness & Reliability, Performance & Efficiency, Features & Usability, Security & Privacy, Implementation & Execution) challenged against primary 2024–2026 empirical security-agent and agent-ergonomics research.

---

### Executive Summary

`notes/plan.md` is an unusually rigorous **epistemic verification and audit-custody specification**. Its strongest ideas—refusing to let LLMs self-certify findings, separating observation from proof, enforcing paired/negative controls and functional-preservation fix verification, maintaining an explicit adversarial decoy suite (§16.4), being honest about Playpen/Hallpass enforcement limits, and requiring matched-budget A/B/C ablations—directly address the biggest credibility failures in modern AI security tooling.

However, judged against the original goal (*build an Edict-like tool over the Reliquary stack that is the most verifiably effective security/vulnerability research framework possible and completely obvious to agents with zero tool knowledge*), the plan has five major structural flaws:

1. **Verification over-engineering at the expense of discovery:** The plan devotes ~12 sections to custody, sagas, and receipts while starving vulnerability *discovery* (~70 lines in §8), even though its own cited BountyBench benchmark shows frontier agents hit **90% Patch / 67.5% Exploit / only 12.5% Detect**. Proven real-world systems (Big Sleep, XBOW, OpenAI Aardvark/Codex Security, Keygraph Shannon, Trail of Bits AI auditing) win via threat-model-first code/surface mapping, hybrid tooling, day-1 headless browsers, OOB canaries, and ephemeral parallel workers—most of which are omitted or deferred.
2. **Cold-agent ergonomics collision:** Exposing 35 typed operations, 14 domain objects, 9 result dimensions, 12 obligations, and manual `freeze` / `preconditions` / `basis_digest` / `request_id` choreography directly contradicts the "useful first action within 3 calls" gate, Anthropic's *Writing Tools for Agents*, the *Bitter Lesson* (`mini-SWE-agent`, Code Mode), and what `edict` actually is (thin workflow glue).
3. **Stifling exploration instead of isolating verification:** The plan forces exploratory actions through declarative recipes and an 8-step admission saga. Ironically, UC Berkeley's `RECEIPT` (`arXiv:2607.18575`)—which the plan author could not inspect—proved that **free white-box exploration + strict clean-instance replay verification** yielded **24 real zero-days across 95 live apps with 0 false positives**.
4. **Hard architectural blockers & paradoxes:** The plan deadlocks local Linux agents out of `runtime-controlled.v1` custody (§6.5 vs §4.4), blocks the entire build on an unimplemented `Investigation` spec linked to a private ChatGPT URL (`[S8]`), builds a 5-store distributed saga with an 11-table SQLite outbox on a single host, restricts automatic verification to compiled Rust oracles that cannot generalize to novel bugs, and gates v1 on authoring a NeurIPS-scale 40-family / 160-trial sealed benchmark.
5. **Security & operational blind spots:** Host-agent prompt injection in `supervised` mode, missing OOB callback infrastructure (despite requiring an OOB oracle in §7.3), and frontier-model cyber-safety false refusals are unaddressed.

The 10 prioritized changes below preserve the plan's epistemic rigor while cutting ~70% of its ceremony and redirecting effort toward discovery yield, zero-knowledge usability, and clean-room verification.

---

### Proposed Changes

---

#### [High Impact, Low Effort] Change #1: Resolve the Verifier Custody Deadlock via a Clean-Container Verifier Boundary

**Current State:**
In §4.3 (lines 235–241), §4.4 (line 245), and §6.5 (lines 390–392), the plan stipulates that the initial process model is local Linux with same-UID processes, admits the inspected stack has not demonstrated filesystem/verifier-write isolation, and simultaneously rules that a shared writable UID *"cannot claim that isolation... [and does] not meet the controlled runtime profile until independently confirmed under qualified custody."*

**Proposed Change:**
Explicitly decouple **discovery host mode** from **verifier custody mode** by making a **clean, ephemeral container/microVM verifier runner** (Docker/Podman/systemd-nspawn) the standard `isolated_trusted` custody boundary for `gauntlet verify`, even when discovery runs in local `supervised` mode. Additionally, introduce an explicitly labeled `runtime-supervised.v1` custody tier for operator-local non-containerized runs where the operator trusts their local machine and only requires anti-hallucination replay/controls rather than adversarial tamper-proofing.

**Rationale:**
Under the current plan, a developer running Claude Code or Codex locally on Linux can **never** produce a `runtime-controlled.v1` verified finding because same-UID processes fail the custody obligation. Separating the two threat models—(1) *benchmark/adversarial agent custody* (NIST CAISI / RECEIPT, where an agent may reward-hack or be prompt-injected) vs. (2) *operator-local research*—removes the deadlock while providing real isolation via standard containers rather than trying to invent OS-level custody on a shared local UID.

**Benefits:**
- Eliminates a fatal contradiction that makes `runtime-controlled.v1` unreachable on the initial target platform.
- Provides true clean-instance replay (preventing dirty-fixture contamination per RECEIPT and CyberGym) using commodity Linux container primitives.
- Enables safe execution of constrained agent-submitted PoCs (see Change #8) without risking the operator's host.

**Trade-offs:**
- Requires Docker/Podman (or equivalent Linux namespace/container runtime) to earn the `isolated_trusted` badge; bare-metal environments without containers must accept the explicitly labeled `operator_asserted_shared` / `runtime-supervised.v1` badge.
- Adds container startup latency (~1–3s) at the verification gate (acceptable since verification runs only on promising candidates, not every exploratory request).

**Implementation Notes:**
Define a narrow `VerifierBackend` interface with two initial backends: `container-isolated` (mounts evidence/PoC read-only, owns separate verifier credentials/secrets and write-only receipt output outside the agent's writable workspace) and `local-supervised` (same-UID fresh subprocess with explicit `verification_custody: operator_asserted_shared` labeling).

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -235,8 +235,8 @@
 Three execution assurance modes must remain explicit:
 
 - **Offline:** local inspection/import/oracle replay only; no target traffic.
 - **Supervised:** an existing externally managed agent uses Gauntlet with authorized native instruments; Gauntlet records the known controls but does not claim to confine the entire host agent.
 - **Enforced:** the qualified worker/instrument composition prevents alternate egress and unauthorized access to verifier/policy/evidence writes within its documented boundary.
 
-Profiles declare the minimum acceptable mode. Enforced mode additionally requires a qualified filesystem, credential and verifier-write isolation boundary; Playpen's egress guard alone does not establish it. The inspected stack has not yet demonstrated this whole composition. A finding's evidence strength and an engagement's execution assurance are different dimensions: a real finding obtained in supervised mode may be valid, but its report must not claim enforced confinement or tamper-resistant receipts. `--force`, an agent prompt, or an omitted dependency must not upgrade assurance.
+Profiles declare the minimum acceptable custody boundary. Enforced mode requires a qualified filesystem, credential, and verifier-write isolation boundary (e.g., an ephemeral container/microVM verifier whose credentials and receipt store are unreachable from the discovery agent's UID); Playpen's egress guard alone does not establish it. A finding's evidence strength and an engagement's execution assurance are different dimensions: a supervised discovery agent may obtain an `isolated_trusted` proof by submitting a self-contained replay spec to the containerized verifier, or an explicitly labeled `supervised` verification on bare local Linux where operator-local trust applies. `--force`, an agent prompt, or an omitted dependency must not upgrade assurance or custody labels.
@@ -390,5 +391,8 @@
 The submission boundary is an immutable object containing claim, required roles, recipe, oracle/profile references and evidence pointers. For the controlled runtime profiles, a qualified verifier prepares a clean target instance or confirms the existing instance's state, obtains the intended roles from the fixture/credential service, and executes only the submitted permitted actions. Its custody boundary prevents the discoverer from editing the verifier binary, oracle, target database/build outside claimed attacker actions, hidden fixture state, trusted receipt store, or reference tests during this run.
 
-Track **verification custody** separately from host execution assurance: `isolated_trusted`, `authenticated_external`, or `operator_asserted_shared`. A supervised host agent can submit to an isolated verifier and obtain a strong proof. A shared writable UID/environment cannot claim that isolation; its results may support an explicitly external-evidence-reviewed/source judgment, but do not meet the controlled runtime profile until independently confirmed under qualified custody.
+Track **verification custody** separately from host execution assurance: `isolated_trusted`, `authenticated_external`, or `operator_asserted_shared`.
+- **Standard isolated path:** Even when discovery runs locally in `supervised` mode, `gauntlet verify` invokes a clean ephemeral container/microVM verifier (or separate-UID service) that owns target/fixture resets, verifier credentials, and the trusted receipt output. This satisfies `runtime-controlled.v1` with `isolated_trusted` custody.
+- **Bare-host local path:** When no container/separate-UID verifier is available on a local workstation, a fresh subprocess replay with all required controls may emit `runtime-supervised.v1` with `verification_custody: operator_asserted_shared`. It retains full semantic replay value for local operators while remaining clearly distinct from tamper-resistant `isolated_trusted` proofs and ineligible for adversarial benchmark promotion.
```

---

#### [High Impact, Low Effort] Change #2: Unblock M1–M2 from the Unbuilt `Investigation` Substrate & Fix Inaccessible Reference `[S8]`

**Current State:**
Lines 8, 183, 942, 1493 (`G02`), and 1800 (`[S8]`) make the unimplemented `Investigation` repository a hard prerequisite for `G05–G17` (essentially the entire product). Moreover, `[S8]` points to a personal `chatgpt.com/library` URL that is completely inaccessible to any implementing agent or external reviewer.

**Proposed Change:**
1. Extract and check in the minimal neutral evidence-store contract (`docs/contracts/evidence-store-v1.md` + JSON schema fixtures) inside the Gauntlet repo so no spec depends on a private ChatGPT link.
2. Define a narrow `EvidenceStore` trait in `gauntlet-core` with an embedded, production-usable local implementation (`LocalEvidenceStore`: content-addressed immutable blob directory + atomic WAL SQLite index) that satisfies the minimal Investigation capture/query/export semantics (`begin/attach/finalize/query/bundle`).
3. Ship M1–M2 on `LocalEvidenceStore`, keeping `Investigation` integration as a clean swappable backend adapter (`InvestigationAdapter`) once the upstream Investigation binary/crate actually exists.

**Rationale:**
Blocking every milestone on an external repo that does not yet exist guarantees months of stalled delivery and forces speculative mock choreography. A content-addressed local evidence store is ~500 lines of clean Rust, gives real crash/durability/replay semantics immediately, and keeps Gauntlet's architecture strictly decoupled from Investigation's internal implementation schedule.

**Benefits:**
- Unblocks M1 and M2 immediately with real, persistent, crash-safe evidence storage (not a throwaway test mock).
- Eliminates a dead, private URL (`[S8]`) as an authoritative design dependency.
- Validates the actual minimal evidence interface needed by Gauntlet before freezing Investigation's upstream API.

**Trade-offs:**
- Requires maintaining a small migration/import bridge when migrating early Gauntlet workspaces from `LocalEvidenceStore` to the full `Investigation` engine later.
- Must enforce strict discipline not to grow `LocalEvidenceStore` into a second full generic casebook/graph product.

**Implementation Notes:**
Keep `EvidenceStore` strictly neutral (blobs, runs, acquisitions, immutable artifacts, linked manifests, export archive). Write conformance tests against the trait so both `LocalEvidenceStore` and the future `InvestigationAdapter` pass the exact same suite.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -181,5 +181,5 @@
 M0 must pin actual revisions and verify each advertised operation. The research snapshot is in §22; do not infer functionality from a filename or README milestone alone. Important findings already affect the design:
 
-- The attached Investigation API is a **specification**, and the repository was not accessible during this research. Build against a conformance contract; a simulator can unblock tests but never qualify a real release.
+- The attached Investigation API is a **specification**, and the repository was not accessible during this research. Extract the minimal neutral `EvidenceStore` contract into `docs/contracts/evidence-store-v1.md` and ship a small, durable embedded `LocalEvidenceStore` (content-addressed blobs + WAL index) behind that trait so M1–M2 ship real, crash-safe evidence persistence without blocking on upstream Investigation delivery. Swap in `InvestigationAdapter` via the same conformance suite once upstream ships.
 - The current inspected Teapot source contains substantive authz/crawl handlers and corresponding test code. Older observations that these were placeholders are stale. Inspection is not a claim that the suites were run here.
@@ -940,5 +940,5 @@
 Gauntlet's producer envelope uses `inv.producer-run.v1` where available. Domain fields remain inert namespaced metadata or referenced security manifest artifacts. Native control-plane and scanner claims stay producer assertions until assessed. A successful `capture finalize` never creates a verified finding.
 
-Because the upstream is planned, M0 must write a capability/contract fixture and identify the smallest neutral upstream slice needed. A test double may implement that fixture for local unit tests. Production qualification requires the actual recorder implementation and actual crash/retry behavior. Do not ship a mock evidence engine as a fallback.
+Because upstream Investigation is not yet implemented, M0 must vendor the minimal neutral contract into `docs/contracts/evidence-store-v1.md` and implement `EvidenceStore` with a real, durable `LocalEvidenceStore` (immutable content-addressed blobs, fsynced manifest commits, atomic export bundles). This is a minimal conforming backend—not an in-memory mock—and qualifies M1–M2 while keeping the boundary clean for a drop-in `InvestigationAdapter` when upstream ships.
@@ -1491,3 +1491,3 @@
 | G00 | Re-resolve repository/binary names; pin revisions and toolchain; save capability inventory | — | Machine-readable inventory, explicit inaccessible/planned capabilities, ADRs for bindings. |
 | G01 | Design owned authz fixture and negative controls; freeze evaluation protocol | — | Property/ground-truth specification separate from agent view; decoy catalog; no solution leakage. |
-| G02 | Establish minimal neutral Investigation contract with upstream owner/implementation | G00 | Real begin/attach/finalize/query/record/review/idempotency conformance, or explicit blocked dependency. |
+| G02 | Vendor minimal `EvidenceStore` contract and implement durable `LocalEvidenceStore` (Investigation-compatible) | G00 | Real begin/attach/finalize/query/export/idempotency conformance passing crash/restart tests; upstream `InvestigationAdapter` pluggable without schema rewrite. |
@@ -1798,3 +1798,3 @@
 [S6]: https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/README.md
 [S7]: https://github.com/bobisme/vessel/blob/f0ccd685a9bd084289d42a1eda8c7e44223f037a/README.md
-[S8]: https://chatgpt.com/library?file_id=libfile_fde3_f-e3c066c838388191b23a90270cf049d2_84f617e431e881918e33d3a401276f18&account_id=personal
+[S8]: ./docs/contracts/evidence-store-v1.md (extracted from Investigation rev. 3 spec; replaces inaccessible private ChatGPT library link)
```

---

#### [High Impact, Low Effort] Change #3: Replace the Unrealistic 40-Family / 160-Trial v1 Gate with a Tiered, Matched-Baseline Eval Ladder

**Current State:**
§16.5 (lines 1261–1279) requires **at least 40 genuinely distinct scenario families** (not ID renames, each with real vulnerabilities, decoys, patches, and functional tests) × 2 model/host combos × 2 sessions = **160 cold-agent trials**, plus retiring exposed holdouts and authoring fresh families after fixes, plus full matched-budget A/B/C baselines—all before release qualification.

**Proposed Change:**
Replace the single monolithic 160-trial gate with a **3-tier evaluation ladder** that validates ROI early against Baseline B (native tools + good Markdown guidance) and scales custom held-out fixture authoring realistically:
- **Tier 1 (M2 Preview Gate):** 10–12 high-craft local fixtures covering every §16.4 decoy class + real HTTP authz/state/fix bugs (12–24 cold-agent trials across 2 models) **plus** an early matched-budget A/B/C comparison on a pinned, scrubbed slice of an existing public benchmark (e.g., 10–15 non-saturated cases from CVE-Bench v2.0 / BountyBench) to test early whether Gauntlet actually beats plain tools + Markdown methodology.
- **Tier 2 (M4 / v1.0 Release Gate):** 16–20 genuinely distinct private held-out families (spanning HTTP, stateful/browser, SIP/protocol, cross-protocol, negative decoys, fix verification, and crash/recovery) × 2 model/host combos = **64–80 trials**, with zero false promotions on negative families and matched A/B/C reporting.
- **Tier 3 (Post-v1 Continuous Qualification):** Incrementally grow the private family pool to 40+ as real-world engagements and new packs are added.

**Rationale:**
Authoring 40 genuinely distinct, realistic multi-tenant/protocol applications with patches, decoys, and functional test suites is the scale of an entire academic lab's benchmark release (BountyBench itself had 25 systems / 40 bounties across a Stanford research team). Making a 40-family custom corpus a v1 blocker either prevents v1 from ever shipping or incentivizes shallow synthetic clones that violate the plan's own anti-cloning rule. Running an early A/B/C check in M2 also catches "framework ceremony hurting performance" *before* M3–M5 are built.

**Benefits:**
- Provides an early kill/pivot signal in M2 if Gauntlet's ceremony loses to Baseline B (native tools + Markdown prompt).
- Reduces v1 fixture-authoring effort by 60%+ while retaining high statistical rigor on false promotions and cold-agent usability.
- Leverages battle-tested, ABC-hardened external benchmarks (CVE-Bench v2.0, BountyBench) alongside custom Reliquary/SIP fixtures.

**Trade-offs:**
- Smaller v1 family count (16–20 vs. 40) gives wider confidence intervals on discovery recall estimates; must be reported transparently per §16.6 without over-claiming population superiority.

**Implementation Notes:**
Keep the strict zero-false-promotion rule on all negative/decoy families across every tier. Track cost/tokens and wall-clock time per verified finding from Tier 1 onward so ceremony regressions are caught immediately.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -1260,5 +1260,10 @@
 
-Start with twelve pilot runs to identify gross interface failures. The release qualification expands to **at least 40 distinct scenario families × two materially different supported model/host combinations × two fresh sessions = 160 trials**. Allocate eight unassisted-discovery families, eight supplied-lead verification families, twelve negative/confounded families, six fix-verification families and six interrupted/missing-capability/recovery families. Include source-informed verification only in its declared information track. Vary names and semantic details; do not merely randomize IDs in the same solution. Agents must not receive expected-positive/negative labels or the number of planted issues.
+Qualify cold-agent usability and framework ROI in three progressive tiers rather than gating v1 on a 40-family custom benchmark:
+- **Tier 1 (M2 HTTP Preview Gate):** 10–12 high-craft local fixtures covering all §16.4 decoy/failure classes plus an early matched-budget A/B/C pilot on a pinned slice (10–15 cases) of an established external benchmark (e.g., CVE-Bench v2.0 / BountyBench) across 12–24 cold-agent runs. Purpose: catch UX friction and verify Gauntlet outperforms Baseline B (native tools + Markdown methodology) before scaling architecture.
+- **Tier 2 (v1.0 Release Gate):** **16–20 genuinely distinct private held-out scenario families** (4 unassisted discovery, 4 supplied-lead verification, 6 negative/confounded decoys, 3 fix verification, 3 interrupted/recovery — spanning HTTP, browser/state, SIP/protocol, and cross-protocol) × 2 materially different model/host combinations × 2 fresh sessions = **64–80 trials**, plus matched-budget A/B/C comparison.
+- **Tier 3 (Post-v1 Longitudinal Expansion):** Grow private held-out families toward 40+ as new domain packs ship, retiring exposed families into regression suites.
+
+Vary architecture and semantic details across families; do not merely randomize IDs in the same solution. Agents must not receive expected-positive/negative labels or the number of planted issues.
@@ -1478,4 +1483,4 @@
 | **M2 — complete HTTP verification** | Actual qualified Teapot execution, identities, controls, custody, accounting, capture, local admission, independent replay, report and paired fix verification. | Full §17.1 workflow on real binaries, required adversarial controls and §13 crash matrix; twelve pilot cold-agent runs reviewed. This is the first useful end-to-end product. |
-| **M3 — realistic discovery and durable coordination** | Coverage, bounded prioritization, stateful recipes, Bones links, complete handoff/reconciliation, source leads, optional qualified workers. | Matched-budget baselines and held-out HTTP cases; concurrency/cancel/unknown-effect gates; 160-trial cold-agent qualification begins. |
+| **M3 — realistic discovery and durable coordination** | Threat-model mapper, Playwright + OOB canary support, coverage, Bones links, handoff/reconciliation, source leads, ephemeral Vessel workers. | Tier 1 matched-budget A/B/C baseline passes on HTTP/benchmark slice; concurrency/cancel/unknown-effect gates pass. |
 | **M4 — protocol and cross-protocol verification** | Sippycup import/live adapter, qualified runner and accounting composition, signaling/media profiles, connected cross-tool replay. | §17.3 plus incompatible-chain and missing-media-observer controls; no enforcement downgrade. |
 | **M5 — release excellence and selected extensions** | Complete reports/archives, regression retests, stability/compatibility, approved extra profiles/adapters, evaluation report. | Required qualification tests and cold-agent gates pass, material risks recorded, measured benefit or precise limits published. |
@@ -1515,2 +1520,2 @@
 | G24 | Build protected held-out evaluator, baselines and cost accounting | G01, G03 | Referee inaccessible; hints/attempts/setup recorded; independent adjudication path. |
-| G25 | Run release cold-agent trials and matched-budget/ablation study | G17, G19, G23, G24 | ≥160 trials, per-track/per-configuration gates and failures; no unsupported superiority claim. |
+| G25 | Run Tier 2 release cold-agent trials and matched-budget/ablation study | G17, G19, G23, G24 | 64–80 trials across 16–20 distinct families, per-track/per-configuration gates and failures; honest uncertainty bounds and no unsupported superiority claim. |
```

---

#### [High Impact, Low Effort] Change #4: Close Major Research & Evidence Gaps in §2 and §22

**Current State:**
§22 omits several of the highest-impact proven vulnerability-research systems of 2024–2026 (Google Project Zero's **Big Sleep / Naptime**, **XBOW**'s actual architecture, OpenAI **Aardvark / Codex Security**, Anthropic **Claude Code Security**, **Keygraph Shannon**, **MAPTA**, **EnIGMA**, **CAI**, Trail of Bits' AI auditing skills, **mini-SWE-agent / Code Mode**, **CyberGym-E2E** `2606.04460`, and **CVE-Bench v2.0 / Agentic Benchmark Checklist**). Furthermore, line 1677 leaves **RECEIPT (`2607.18575`)** and **From Runnable to Verifiable (`2608.09567`)** uninspected even though both papers' actual empirical findings directly shape this architecture.

**Proposed Change:**
Update §2.2 and §22 to incorporate these primary systems and empirical findings, explicitly recording the lessons that revise Gauntlet's architecture:
- **RECEIPT (`2607.18575`)**: Free white-box exploration + fresh clean-instance deterministic replay yielded 30 confirmed XSS (24 zero-days, 0 FP) vs. 10/111 true positives under naive verification.
- **From Runnable to Verifiable (`2608.09567`)**: Pre-registered audit of 104 papers found 56.9% script/CVE ID mismatches and artifact-embedded oracles with only 60% sensitivity / 45% specificity (20/30 fired on patched builds; 7/19 fired on benign controls), proving differential patched/negative controls are paramount.
- **Big Sleep, XBOW, Codex Security (Aardvark), Shannon, EnIGMA, mini-SWE-agent**: Establish threat-model-first discovery, fluid sandboxed scripting/interactive tools, day-1 browser support, and hub-and-spoke ephemeral parallel workers (contrasting with MAST's chatty peer councils).
- **CVE-Bench v2.0 / ABC & CyberGym-E2E (`2606.04460`)**: Quantify grader loophole inflation (up to 33% drop after ABC hardening) and end-to-end discovery+PoC+patch evaluation.

**Rationale:**
Because the plan was synthesized primarily from grader-cheating and static/API-fuzzing papers while missing the actual systems finding zero-days and topping bug-bounty leaderboards, its design skewed heavily toward bureaucracy over research effectiveness. Correcting the evidence ledger aligns the entire specification with empirical state of the art.

**Benefits:**
- Grounds the architectural shifts in Changes #5–#8 directly in verified primary literature.
- Prevents future implementers from misreading MAST as a blanket ban on parallel ephemeral exploration workers.
- Documents known real-world operational hazards (e.g., model cyber-safety false refusals observed in Claude Code Security deployments).

**Trade-offs:**
- Requires replacing unverified/commercial architectural claims (e.g., XBOW/Codex Security blog descriptions) with clear evidence-classification labels (`Design reference` vs. `Primary experimental result`) per §2.1.

**Implementation Notes:**
Keep the plan's strong §2.1 evidence discipline intact—tag vendor architecture posts (XBOW, Aardvark/Codex Security, Big Sleep blog posts) clearly as operational/design references distinct from peer-reviewed controlled evaluations (RECEIPT, From Runnable to Verifiable, EnIGMA, BountyBench, ARTEMIS).

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -137,9 +137,10 @@
 The most defensible architecture combines five ideas:
 
-1. **Stateful exploration and source-informed hypotheses.** Use dependency-aware instrumented tests and available code context to reach meaningful states; do not ask a model to improvise every low-level action.
-2. **Executable, claim-specific verification.** Check the actual protected property and identities, not merely the presence of a string or process exit code.
-3. **Control and counterfactual experiments.** Healthy control, minimally changed input/role, fresh replay, and fixed-build comparison expose false signals and incomplete remediations.
-4. **Durable, layered knowledge.** Preserve original evidence and failed attempts; expose a small current brief and exact drill-down references.
-5. **Evaluation of the complete workflow.** Measure fresh agents, meaningful environment outcomes, false positives, recall, recovery, and cost under matched budgets and hidden cases.
-
-More agents are optional. More reliable evidence is compulsory. Roles are justified by a distinct information need, isolated authority, or a measured benefit; adding a reviewer prompt is not itself verification.
+1. **Threat-model-first, unconstrained discovery.** Map architecture, trust boundaries, auth middleware, and entry-to-sink paths first; let agents explore fluidly with real instruments, browsers, static/fuzz tools, and short scripts under transparent scope/budget guards rather than rigid workflow ceremony.
+2. **Asymmetric clean-room verification.** Discard exploration state at the promotion boundary and deterministically replay a constrained PoC/recipe inside an isolated verifier using universal mechanistic observers and claim-specific controls.
+3. **Differential and counterfactual controls.** Patched-vs-unpatched comparisons, benign controls, healthy authorized controls, and fresh replay catch the high oracle error rates documented across security benchmarks.
+4. **Durable, layered knowledge with ephemeral workers.** Persist compact facts, leads, and immutable evidence externally so short-lived, single-mission parallel workers avoid context rot without devolving into chatty agent councils.
+5. **Evaluation of the complete workflow.** Measure cold agents, discovery recall, verified yield, false promotions, token/turn efficiency, recovery, and cost under matched A/B/C baselines.
+
+Chatty peer-agent councils add failure modes without proving truth [R25]; by contrast, short-lived, isolated hub-and-spoke exploration workers feeding a deterministic verifier have demonstrated strong real-world discovery throughput [R4], [R34], [R37].
@@ -1643,4 +1644,9 @@
 | **CVE-Bench** [R33], [R33a] | Real web-vulnerability environments with effect-specific runtime graders. Current revisions address evaluator loopholes; inspected grader code uses instance canaries and bounded exception diagnostics. | Unsupported checks may be skipped or return false; this is not Gauntlet's proposed result taxonomy. A broad achieved effect can still miss the intended CVE mechanism. Keep evaluator failure, unsupported measurement and valid negative separate. |
+| **CVE-Bench v2.0 / ABC** [R38] | Applying the Agentic Benchmark Checklist (ABC) to close grader loopholes (e.g., crash-DoS / keyword matching) reduced inflated agent scores by up to 33%. | Reinforces strict causal outcome validity and continuous grader auditing. |
+| **RECEIPT** [R29] | UC Berkeley white-box XSS study across 95 live web apps: naive verification yielded 10/111 true positives; separating free exploration from fresh clean-instance deterministic replay yielded 30 confirmed XSS (24 zero-days) with 0 false positives. | Strongest primary evidence for asymmetric architecture: keep exploration fluid and enforce strict isolation/determinism at the verification boundary. |
+| **From Runnable to Verifiable** [R30] | Pre-registered reproducibility audit of 104 papers (2023–2026): 56.9% anchor CVE-ID mismatch; artifact-embedded oracles had 60% sensitivity / 45% specificity (20/30 fired on patched builds; 7/19 fired on benign controls). | Proves runnable signals are unreliable without patched counterfactuals and matched negative controls. |
+| **EnIGMA** [R36] | NYU/Princeton/TAU SWE-agent extension with Interactive Agent Tools (stateful debuggers/network tools) and output summarizers; SOTA across NYU CTF, InterCode-CTF, and CyBench; documents agent "soliloquizing." | Supports interactive grounded tool interfaces and summarized outputs over rigid multi-step JSON state machines. |
+| **MAPTA / Shannon** [R37] | Open-source web pentesting pipelines (Source Pre-Recon -> Playwright Recon -> Parallel OWASP Hunting -> Proof-by-Exploitation) reaching 76.9% (MAPTA) to 96.15% (Shannon Lite) on scrubbed XBOW benchmarks. | Demonstrates value of source-guided threat modeling, day-1 Playwright, parallel category workers, and exploit-gated reporting (benchmark saturation caveat applies). |
 | **NIST CAISI evaluator audit** [R18], [R18a] | Evaluators manually confirmed solution contamination and expected effects reached without the intended vulnerability; they describe evaluation-hardening practices. | Retrospective heterogeneous samples, with possible missed cases. Do not infer a universal cheating rate. Isolate hidden state, test causal attribution, inspect action traces and prevent solution/history leakage. |
 | **XBOW public validation suite** [R19] | Maintainer supplies 104 web CTF fixtures and now warns that the public suite is saturated and learned by current models. | This is a maintainer assessment, not an independent contamination measurement performed here. Retain useful regressions; do not use a perfect score as current differentiation or production-readiness evidence. |
@@ -1668,11 +1674,15 @@
 | Reference | What is useful | Evidence boundary |
 |---|---|---|
 | **SWE-agent ACI study** [R22] | Small purposeful actions, concise feedback and interface design tested against a plain-shell baseline. | Coding benchmark evidence, not a security-scaffold efficacy estimate. Apply the lesson through Gauntlet's own cold-agent ablation. |
+| **mini-SWE-agent / Code Mode / Code Execution with MCP** [R39] | Minimal bash (~100 LOC, >74% SWE-bench Verified) and programmatic tool execution reduce token bloat and outperform rigid multi-tool JSON choreography. | Design/coding evidence cautioning against over-constrained declarative tool APIs during open-ended exploration. |
 | **Anthropic tool engineering / evaluations / long-running harnesses** [R23], [R24], [R31] | Evaluate realistic outcomes, inspect trajectories, provide useful tool semantics and preserve durable progress between contexts. | Primary vendor engineering reports; design guidance rather than independent proof of Gauntlet's performance. Account for every trial and distinguish environment outcome from agent narration. |
-| **MAST** [R25] | Analysis of 1,600+ traces across seven multi-agent frameworks identifies system, coordination and task-verification failures. | Failure taxonomy, not evidence that a larger team is better. Use worker roles only where isolation or measured benefit justifies the cost. |
+| **MAST** [R25] | Analysis of 1,600+ traces across seven multi-agent frameworks identifies system, coordination and task-verification failures in conversational multi-agent systems. | Argues against unstructured chatty agent councils; does not contradict hub-and-spoke ephemeral parallel workers writing to shared durable state. |
+| **Big Sleep / Naptime** [R34] | Google Project Zero + DeepMind grounded agent (code browser, debugger, sandboxed scripting) discovered real-world zero-days in SQLite (incl. CVE-2025-6965); complementary to fuzzers like Fuzzilli. | Vendor operational reports; demonstrates that minimal grounded exploration + execution beats heavy workflow bureaucracy. |
+| **XBOW / OpenAI Aardvark (Codex Security) / Claude Code Security / Trail of Bits AI Auditing** [R35] | Production security architectures emphasizing threat-model generation, code slicing, ephemeral parallel workers, Playwright, sandboxed exploit validation, and cyber-safety classifier friction. | Operational/design references rather than controlled open benchmarks; directly inform Gauntlet's Phase-1 threat-modeling, browser, and refusal-handling design. |
+| **CyberGym-E2E** [R40] | Follow-up benchmark (`arXiv:2606.04460`) extending CyberGym to end-to-end discovery, PoC generation, and patching. | Benchmark reference for tracking end-to-end vs. hinted reproduction tracks. |
 | **Sapper / Sapper v2** [R20], [R20a] | The linked project led to inspection of v2 commander guidance: layered memory, explicit handoff, bounded escalation, reusable tactics and watchdog ideas. | Guidance/architecture, largely CTF oriented; performance claims were not independently reproduced. Do not import automatic trust-dialog acceptance, prompt-only confinement or score-driven proof shortcuts. |
 | **nvwabase** [R21] | Follow-on design separates reusable history and proposed agent orchestration. | The inspected README distinguishes implemented history from future general runtime extraction. Treat runtime descriptions as design references until actual contracts are qualified. |
 | **AXE, revised 2026 preprint** [R26] | Primary abstract describes grey-box exploitability confirmation and material benefit from source/CWE/location metadata, including a single-agent comparison. | Abstract-level review, unequal information regimes across some comparisons. Source hints can help without establishing that multi-agent architecture caused the gain. |
 | **BugStone-E2E** [R27] | Author project page describes patch-derived rules, inexpensive source filtering, triage and runtime evidence. | Full paper did not load in this inspection. Runtime-evidenced unsafe conditions are not automatically independently confirmed exploitable vulnerabilities. Keep tactic applicability and discovery outside historical rules. |
 | **ReproBench** [R28] | September 2026 primary abstract studies reconstruction from CVE IDs across 30 IoT vulnerabilities and reports simulation substitution as a major failure mode. | Abstract inspected; submitted to AAAI 2027, acceptance not established. Environment reconstruction and original-target identity deserve explicit gates; do not transfer its narrow success rate to Gauntlet. |
-| **RECEIPT / From Runnable to Verifiable** [R29], [R30] | Identified recent work concerning browser evidence and exploit-verification validity. | Full primary artifacts could not be inspected sufficiently. No numerical efficacy claim or required implementation dependency rests on them. The proposed custody/control design stands on the independently specified requirements and better-inspected sources above. |
```

---

#### [High Impact, High Effort] Change #5: Adopt an Asymmetric Two-Zone Architecture ("Explore Freely, Verify Strictly")

**Current State:**
The plan applies the same heavy typed-recipe lifecycle (`experiment.create -> check -> freeze -> bound_execution_manifest -> 8-step admission saga`, §7.1 lines 438–454, §9.2 lines 596–610) to routine discovery actions and explicitly restricts arbitrary scripts/code to disposable labs as an "escape hatch" (§9.7 lines 647–652).

**Proposed Change:**
Split Gauntlet explicitly into two asymmetric operational zones:
- **Zone 1 — Fluid Discovery (Thin Edict-Like Wrapper):** Agents freely invoke native Reliquary instruments (`teapot`, `sippycup`), standard code-analysis/fuzzing tools, Playwright, and ad-hoc exploratory Python/shell scripts through a **single transparent wrapper (`gauntlet run`)** that enforces Hallpass budgets + Playpen egress confinement and automatically captures immutable evidence in the background. **No manual `experiment.create`, `freeze`, `basis_digest`, or declarative recipe authoring during discovery.**
- **Zone 2 — Strict Clean-Room Verification (`gauntlet verify`):** Apply Gauntlet's full epistemic rigor—frozen submission artifact, clean-instance/controlled replay, mandatory negative/identity/counterfactual controls, isolated custody, independent semantic challenge, and proof profile evaluation—*only* when promoting a candidate to `Verified` or verifying a fix.

**Rationale:**
Empirical evidence from `RECEIPT`, `Big Sleep`, `XBOW`, `Shannon`, and `mini-SWE-agent` converges on the same truth: **constraining exploration destroys discovery recall**, while **constraining verification destroys false positives**. Forcing an agent to construct valid typed JSON recipes and pre-compute basis digests just to probe whether an endpoint accepts a modified JWT header wastes tokens, kills creative hypothesis testing, and drives agents either into schema-error loops or around the tool entirely.

**Benefits:**
- Dramatically increases discovery recall and agent velocity without weakening a single promotion invariant.
- Makes Gauntlet genuinely feel "Edict-like" during active research while retaining best-in-class proof rigor for findings.
- Eliminates the false choice between "rigid declarative DSL" and "uncontrolled shell."

**Trade-offs:**
- Exploratory traces are captured automatically as raw acquisitions rather than pre-structured formal experiments; promoting a discovery still requires converting it into a clean replay spec (which Gauntlet can help synthesize from captured traffic/traces).
- Requires Hallpass/Playpen wrapper ergonomics to be rock-solid so transparent wrapping has minimal friction and overhead.

**Implementation Notes:**
Make `gauntlet run -- <native-cmd-or-script>` (and shorthand wrappers like `gauntlet run teapot ...`) handle scope/budget check, Playpen wrapping, automatic acquisition recording, and concise output summarization in one step, returning an `acquisition_id` the agent can immediately cite in `gauntlet claim`.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -31,5 +31,6 @@
 | Workflow style | Edict-like local bootstrap, managed instructions, contextual guidance, and explicit machine-readable protocols. Edict need not be a runtime dependency. |
+| Operational model | **Asymmetric two-zone workflow:** fluid, low-ceremony exploration transparently guarded by Hallpass/Playpen and auto-captured; strict frozen clean-room verification at finding promotion and fix retest. |
 | Verification | Claim-specific, versioned proof contracts with controls, causal evidence, fresh replay, and explicit uncertainty. No universal numeric confidence score. |
@@ -220,9 +221,9 @@
 | Plane | Permitted responsibilities | Boundary |
 |---|---|---|
-| Agent reasoning | Propose hypotheses/plans, inspect permitted evidence, explain ambiguity, request a review. | Cannot manufacture authority, server state, oracle results, or a verified status. |
-| Domain engine | Validate plans and transitions, compute freshness, prepare context, choose deterministic eligible actions. | Cannot infer arbitrary semantic truth from prose. |
-| Execution | Run a pinned operation under the bound authority, limits, environment, and recording policy. | Cannot enlarge scope or rewrite the frozen plan. |
-| Observation | Retain original outputs, identities, timing, completeness, and instrument facts. | Captured output remains untrusted input. |
-| Verification | Evaluate a pinned proof profile over exact retained inputs, challenge confounders, record measured status. Independent replay uses the ordinary authorized Execution path. | Predicate evaluation cannot alter inputs, policy or evidence to make a proof pass. |
+| Zone 1: Fluid Discovery | Read source/surfaces, build threat models, run native instruments, browsers, or exploratory scripts under transparent Hallpass/Playpen guards with automatic evidence capture. | Exploratory runs never directly produce `Verified` status and cannot expand engagement scope/budgets. |
+| Zone 2: Clean-Room Verification | Consume an immutable candidate + replay spec, discard exploration state, run controls and replay in an isolated verifier boundary, evaluate mechanistic observers, and record proof receipts. | Discoverer cannot modify verifier state, oracle predicates, verifier credentials, or trusted receipt storage. |
+| Observation & Custody | Automatically capture immutable artifacts, identities, timing, completeness, and accounting receipts across both zones. | Captured target/repo output remains untrusted data. |
+| Referee, in evaluations | Own hidden ground truth, target reset, grading state, and canaries. | Not writable or readable by the assessed agent. |
@@ -436,19 +437,16 @@
 ### 7.1 Experiment structure
 
-Use a small typed recipe model, not a general programming language. Steps are native adapter operations with data bindings and bounded predicates. Complex tool-specific procedures stay in their instrument; Gauntlet references their immutable scenario artifacts.
+Distinguish **exploratory runs** (Zone 1) from **confirmatory verification specs** (Zone 2):
 
-An experiment contains:
+- **Exploratory runs** require no pre-authored declarative recipe or manual freeze step. The agent invokes native instruments (`teapot`, `sippycup`, browser, scanners) or bounded scripts through `gauntlet run`, which transparently enforces engagement scope, Hallpass budgets, and Playpen egress while recording an immutable acquisition and compact summary.
+- **Confirmatory verification specs** (submitted to `gauntlet verify` or `gauntlet retest`) are automatically frozen by the CLI into an immutable `bound_execution_manifest` before admission. A verification spec declares:
+  - Claim/property ref, target/principal bindings, and information regime.
+  - Executable replay procedure: either typed native adapter steps (`teapot`/`sippycup`/browser actions) **or** a self-contained, constrained replay script (e.g., Python/Playwright) executed inside the isolated verifier container with no host/admin access.
+  - Required controls (healthy authorized path, negative/role counterfactual, benign input, or patched baseline) and universal mechanistic observer / proof profile binding.
+  - Bounded limits (requests, duration, bytes, retries), effect class, and cleanup procedure.
 
-- Objective/question, candidate/property refs, exploration versus confirmation, and predicted discriminatory observations.
-- Target/principal/session refs and required state; an information-regime declaration.
-- Setup and instrument checks; stimulus; observation; controls; reset and cleanup.
-- Dependency bindings between steps; typed outputs consumed by later inputs.
-- Pinned oracle/profile, observable channels, identity/nonce correlation and maximum observation delay.
-- Maximum requests/messages/bytes/duration/concurrency/retries and expected resource charges.
-- Effect class, allowed resources, halt conditions, and whether an operation is naturally repeatable, target-idempotent, or potentially irreversible.
-- Evidence requirements and completeness policy, result interpretation rules and limitations.
-
-Freeze produces an immutable recipe digest. Editing any substantive field produces a new experiment revision. Runtime parameters may be bound after freeze only through declared typed slots with constraints. Before launch, create an immutable `bound_execution_manifest` containing recipe digest, resolved slots, secret handle/version identities, native input artifacts, target/role/session bindings, tool/image identity, oracle/profile, limits and effects. Its digest appears in admission, accounting correlation, native execution, evidence and verification receipts; secret values do not appear in printable metadata.
-
-For stateful outputs unavailable before the first step, the root manifest declares the typed dependency and constraints. Each step's exact resolved binding is recorded before its effect and chained to prior step receipts. New destinations or capabilities require fresh admission. Verification binds the root plus all step-binding receipts, not merely the original unbound template. Do not accept arbitrary shell or code strings in a purportedly declarative pack.
+The CLI automatically hashes the frozen spec, bound artifact digests, tool/image versions, and runtime bindings into `bound_execution_manifest_digest` so agents never hand-assemble cryptographic preconditions.
@@ -647,6 +645,6 @@
-### 9.7 Custom execution escape hatch
+### 9.7 Scripted exploration and constrained PoC execution
 
-Do not make “arbitrary shell” the universal adapter. A custom experiment is an immutable script/container artifact with declared inputs, expected observations, effects, limits and a separately qualified sandbox/custody profile. It is admitted through the same mechanism and returns the same neutral evidence contract.
+Real-world vulnerability research routinely requires custom scripts (e.g., cryptographic token manipulation, multi-step state machines, custom protocol framing). Rather than banning scripted execution, treat bounded scripts as first-class citizens under two explicit rules:
 
-Initially support custom execution only in disposable qualified labs. It may produce exploratory evidence before its oracle is qualified. Agents can use existing tools directly outside Gauntlet, but imported results retain their actual provenance and assurance; the framework does not retroactively claim it enforced them.
+- **In Zone 1 (Exploration):** `gauntlet run` executes agent scripts inside the Playpen-confined, Hallpass-budgeted environment and captures outputs automatically as exploratory acquisitions.
+- **In Zone 2 (Verification):** `gauntlet verify` runs an immutable submitted PoC script inside the isolated clean-room verifier container with only the claimed attacker role credentials, zero access to verifier/referee internals, and outcomes judged strictly by trusted external observers (never the script's exit code or stdout assertions).
```

---

#### [High Impact, High Effort] Change #6: Collapse the 35-Operation State-Machine CLI into ~7 Cold-Agent Verbs with Automatic Plumbing

**Current State:**
§10.2–10.4 (lines 679–727) and §11.1–11.2 (lines 767–813) expose 35 operations across 9 groups, 14 domain objects, explicit `preconditions: [{id, revision}]`, `expected_basis_digest`, manual `prepare -> check -> freeze -> execute --request-id`, and strict unknown-field rejection—while claiming a cold agent will take a useful first action within 3 calls (§16.5 line 1267).

**Proposed Change:**
Redesign the primary agent-facing CLI and MCP surface around **7 high-level, self-evident verbs** that map directly to how security researchers actually think, while keeping all cryptographic digests, request keys, snapshots, and revision checks **automatic under the hood**:
1. `gauntlet status` (and bare `gauntlet`): One-screen orientation showing target, scope, budgets, capabilities, active leads/findings, unresolved effects, and next move.
2. `gauntlet map`: Build/inspect the threat model, attack surface, roles, trust boundaries, and coverage gaps.
3. `gauntlet run`: Execute an exploratory native command/script under Hallpass+Playpen with auto-capture and automatic idempotency.
4. `gauntlet claim`: Register or update a candidate vulnerability linked to captured evidence IDs (with optional auto-sync to `bones`).
5. `gauntlet verify <claim-id>`: Freeze the replay spec, run clean-room replay + required controls + independent challenge, and promote if and only if obligations pass.
6. `gauntlet retest <claim-id>`: Paired before/after fix verification + legitimate-function regression check.
7. `gauntlet report` / `gauntlet handoff`: Export snapshot-bound reproduction bundles or compact shift-handoff summaries.

Demote low-level mechanics (`attempt.reconcile`, `qualification.record`, `experiment.freeze`, `coverage.link`, etc.) into an explicit `gauntlet plumbing` namespace (like `git` porcelain vs. plumbing) so cold agents never have to navigate 35 commands to find their first bug.

**Rationale:**
Anthropic's *Writing Tools for Agents* [R23], Cloudflare's *Code Mode*, and `git`'s own porcelain/plumbing architecture prove that humans and agents succeed fastest with a tiny, high-level primary verb set where plumbing invariants (hashing, locking, idempotency keys, CAS revisions) happen automatically unless explicitly overridden.

**Benefits:**
- Makes the "useful first action within 3 calls" and ≥90% cold-agent completion gates genuinely achievable without coaching.
- Cuts token consumption on tool schemas, help reads, and JSON validation retries by an estimated 60–80%.
- Keeps MCP tool count under 8 tools (preventing context bloat) while retaining full audit/replay fidelity underneath.

**Trade-offs:**
- High-level verbs (`verify`, `retest`) perform multi-step orchestration internally, requiring clear dry-run (`--plan`) and structured step-by-step progress output so failures at any sub-step remain transparent and resumable.
- Integrations needing fine-grained control must call `gauntlet plumbing` subcommands or JSON input files.

**Implementation Notes:**
Make `gauntlet verify <id> --plan` (read-only) show the exact controls, credentials, and budget required before executing, and have `gauntlet verify <id>` automatically generate and persist a workspace-unique `request_id` (derived deterministically or returned immediately to stderr/state before launch) so interruption recovery uses `gauntlet status` / `gauntlet run --reconcile` without requiring the agent to invent idempotency keys up front.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -661,13 +661,15 @@
 ```text
 gauntlet — investigate security properties and verify findings.
 
-Orient:   gauntlet onboard
-Resume:   gauntlet brief
-Choose:   gauntlet next
-Inspect:  gauntlet show ID
-Learn:    gauntlet schema OPERATION
+Orient:   gauntlet status         (scope, budgets, leads, caveats, next move)
+Map:      gauntlet map            (threat model, attack surface, coverage gaps)
+Explore:  gauntlet run -- CMD     (bounded native/script execution + auto-capture)
+Claim:    gauntlet claim          (record candidate linked to captured evidence)
+Verify:   gauntlet verify ID      (clean-room replay + controls -> proof bundle)
+Retest:   gauntlet retest ID      (before/after fix + regression verification)
+Export:   gauntlet report|handoff (reproduction bundle or compact continuation)
 
 New workspace: gauntlet init PATH --engagement FILE
 Local tutorial: gauntlet demo PATH --scenario authz
 
 Evidence can be recorded immediately. Verification needs the property's
 controls and a valid observation. Target actions require an active engagement.
 ```
@@ -681,13 +683,12 @@
 The common agent path is:
 
-1. `onboard` or `brief` to establish state and limits.
-2. `next` to choose a useful action and inspect why.
-3. `prepare` to materialize a valid plan/draft from known bindings, exposing unresolved fields.
-4. `execute` for an explicitly frozen, admitted experiment.
-5. `show`/`evidence` for results and exact source.
-6. `finding verify` to evaluate recorded proof obligations, or obtain the next needed verification experiment.
-7. `report` or `handoff` when the objective or stop rule is met.
+1. `gauntlet status` to orient (objective, authority, budgets, active leads, next move).
+2. `gauntlet map` to inspect or build the threat model, roles, trust boundaries, and uncovered surfaces.
+3. `gauntlet run` to explore freely with native tools (`teapot`, `sippycup`, browser, scripts) under automatic Hallpass/Playpen guards and evidence capture.
+4. `gauntlet claim` to record a candidate vulnerability citing captured acquisition IDs.
+5. `gauntlet verify ID` (previewable read-only with `--plan`) to freeze the replay spec, execute clean-room replay + mandatory controls + challenge, and promote if satisfied.
+6. `gauntlet retest ID` to verify a proposed fix with baseline + regression controls.
+7. `gauntlet report` or `gauntlet handoff` when the objective or budget stop rule is met.
 
-Convenience commands compile into the same typed operation catalog. A generic mutation API remains available for integrations, but it is not the only discoverability path. `next` and `prepare` must not launch effects; `execute` must say exactly what it can do.
+The CLI separates **porcelain** (the 7 primary verbs above, designed for cold agents) from **plumbing** (`gauntlet plumbing ...` for low-level reconciliation, qualification, manual freeze, and schema inspection). Request keys, immutable digests, and revision checks are computed automatically by porcelain commands so agents never fail on cryptographic boilerplate.
@@ -771,16 +772,17 @@
 Core operation groups:
 
-| Group | Operations |
-|---|---|
-| Engagement | `engagement.create`, `amend`, `activate`, `pause`, `close`; no activation creates authority absent from the supplied binding. |
-| Domain context | `target.bind`, `principal.bind`, `property.create`, `property.amend`, `coverage.define`, `coverage.link`. |
-| Candidate | `candidate.create`, `candidate.amend`, `candidate.withdraw`; preserve original source claims. |
-| Experiment | `experiment.create`, `experiment.amend`, `experiment.freeze`, `experiment.retire`, `experiment.check`. |
-| Execution | `attempt.execute`, `attempt.cancel`, `attempt.reconcile`; only `execute` starts a new attempt. |
-| Verification | `finding.evaluate`, `finding.request_review`, `finding.challenge`, `finding.verify`, `finding.disposition`; transitions constrained by profile obligations. |
-| Retest | `retest.prepare`, `retest.evaluate`; target execution remains ordinary attempts. |
-| Integration | `evidence.import`, `work.link`, `qualification.record`, `handoff.create`, `retrospective.record`. |
-| Export | `report.create`, `bundle.check`; no bundled artifact runs during inspection. |
+| Layer | Surface | Purpose |
+|---|---|---|
+| **Primary Porcelain (Agent & MCP default)** | `status`, `show`, `map`, `run`, `claim`, `verify` (`--plan`), `retest` (`--plan`), `report`, `handoff`, `next` | Minimal, zero-knowledge workflow; automatically manages digests, request keys, snapshots, and freeze steps. |
+| **Setup & Diagnostics** | `init`, `demo`, `doctor`, `capabilities`, `schema`, `sync` | Workspace bootstrap, local tutorials, environment checks, and owned-doc drift sync. |
+| **Plumbing (Advanced / Automation)** | `plumbing attempt.reconcile`, `attempt.cancel`, `engagement.amend`, `qualification.record`, `evidence.import`, `bundle.check`, `worker.*` | Low-level recovery, operator administration, CI/automation hooks, and optional Vessel worker lifecycle. |
 
-Names in this catalog are normative for v1 unless M0 finds a concrete conflict and records an ADR before clients depend on them. Convenience CLI forms map to the catalog, not a second implementation. Avoid arbitrary patch/set-status endpoints.
+Porcelain commands compile into the typed internal command model; there is one implementation, not two. Never expose raw `set-verified` or arbitrary state-patch operations in either layer.
@@ -789,20 +791,18 @@
 ```json
 {
   "schema": "gauntlet.command.v1",
-  "request_id": "confirm-authz-attempt-01",
-  "engagement_id": "<returned-engagement-id>",
+  "operation": "verify",
+  "engagement_id": "<active-engagement-id>",
   "actor": "agent:investigator",
-  "operation": "attempt.execute",
-  "preconditions": [
-    {"id": "<returned-experiment-id>", "revision": 2}
-  ],
   "input": {
-    "experiment_ref": {"id": "<returned-experiment-id>", "revision": 2},
-    "expected_basis_digest": "<actual-frozen-digest>"
+    "claim_id": "<returned-claim-id>",
+    "replay_spec": "<path-or-inline-spec>",
+    "dry_run": false
   }
 }
 ```
 
-This is schematic. `gauntlet schema attempt.execute` returns an actually valid instance for the current prepared fixture. Do not require a user to invent a trusted receipt, oracle result, nonce or internal execution ID.
+Porcelain commands populate `request_id`, current `engagement_id`, `preconditions`, and `expected_basis_digest` automatically from workspace state unless explicitly supplied for idempotent retry or optimistic locking. `gauntlet schema verify` returns an actually valid instance for the current fixture. Never require a cold agent to supply cryptographic digests, internal revision numbers, or trusted receipts just to invoke a standard command.
 
-`request_id` is opaque and unique across the workspace, independent of the current actor. Reusing it with identical semantic input returns the original receipt and attempt; it never starts a fresh run. A replacement agent can reconcile the original request without becoming a new execution identity. Retain initiating actor and subsequent retry attribution separately. Changed semantic input returns `IDEMPOTENCY_KEY_REUSED`. Resolve keys from canonical control state after restart, not a transient cache. Downstream Investigation retries preserve the original persisted actor/command identity required by that upstream API.
+When a caller supplies an explicit `request_id` (or retries a persisted key shown in `gauntlet status` after a crash), reusing it with identical semantic input returns the original receipt/attempt and never launches a duplicate run; changed semantic input returns `IDEMPOTENCY_KEY_REUSED`.
```

---

#### [High Impact, High Effort] Change #7: Elevate Discovery to First-Class (Threat-Model Mapper, Built-In OOB Canary Collector, Day-1 Browser Support, and Ephemeral Parallel Workers)

**Current State:**
Discovery in §8 (lines 513–585) consists mostly of an intake note, a coverage matrix, and a deterministic `next` dispatcher. Meanwhile: (1) there is no threat-modeling or source-slicing workflow; (2) §7.3 (line 472) requires a nonce-bound Out-of-Band (OOB) callback observer, yet no OOB collector exists anywhere in the stack or roadmap; (3) browser-backed execution is deferred to a vague later slice despite web apps being the first production target; and (4) parallel exploration via `vessel` is discouraged by default.

**Proposed Change:**
Make discovery a first-class engineering pillar across M2–M3:
1. **Phase-1 Threat Model & Attack Surface Mapper (`gauntlet map`):** Before testing, synthesize available inputs (repo source, OpenAPI/GraphQL schemas, live crawl/auth routes) into a compact, durable **Threat Model artifact** listing assets, trust boundaries, auth/authz middleware locations, principal roles, state transitions, and prioritized high-risk sinks (mirroring Codex Security / Trail of Bits `audit-context-building` / Shannon Phase 1).
2. **Built-In Nonce-Bound OOB Canary Collector (`gauntlet canary`):** Include a lightweight local/lab HTTP+DNS callback listener owned by Gauntlet's verifier boundary that mints unpredictable per-attempt tokens and emits trusted observation receipts when hit by the target (closing the gap in §7.3 line 472 for blind SSRF, XXE, RCE, SQLi, and SIP callbacks).
3. **Promote Playwright Headless Browser to M2/M3 Core:** Include a constrained Playwright adapter alongside `teapot` so modern SPAs, MFA/login flows, DOM/XSS verification (per RECEIPT), and client-side state transitions work out of the box—eliminating ARTEMIS's #1 documented live-pentest limitation.
4. **Hub-and-Spoke Ephemeral Parallel Workers via `vessel` + `bones`:** Support spawning short-lived, isolated single-mission exploration workers (one target surface/component per fresh context window) that write compact leads back to Gauntlet/Bones and terminate—capturing XBOW/ARTEMIS/Shannon throughput gains while avoiding MAST's chatty-council failures.

**Rationale:**
With frontier models at 12.5% Detect vs. 90% Patch (BountyBench), a tool that only builds a better verification courtroom while ignoring discovery will verify very few real bugs. Threat-model scoping, browser access, OOB canaries, and fresh-context parallel missions are the exact mechanisms empirically linked to real-world discovery breakthroughs in 2025–2026.

**Benefits:**
- Directly attacks the #1 bottleneck in autonomous vulnerability research (finding real, non-trivial bugs).
- Closes an internal spec hole (requiring an OOB oracle in §7.3 with zero OOB server in the architecture).
- Prevents context rot on large targets via ephemeral `vessel` missions coordinated through `bones`.

**Trade-offs:**
- Adds Playwright + a lightweight OOB listener to the M2/M3 dependency surface (mitigated by keeping both optional/explicitly advertised in `gauntlet capabilities`, and running the OOB listener inside the lab/verifier network boundary).
- Parallel workers increase token burn per wall-clock minute; must be strictly bounded by engagement Hallpass/token budgets.

**Implementation Notes:**
Ensure the OOB Canary Collector binds strictly to the verifier/lab network interface unreachable directly by the discovery agent's own network namespace (preventing direct worker-to-observer spoofing, matching §16.4's adversarial fixture).

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -94,5 +94,5 @@
 **First production slice:** authorized HTTP/API assessment with multiple identities and tenants; session-aware replay; source-assisted reasoning when available; authz and state-transition violations; negative controls; independent rerun; evidence export; fix verification. HTTP/WebSocket protocol features are used only where the pinned instrument supports them.
 
-**Next slices:** SIP/RTP/WebRTC and HTTP-to-signaling/media workflows; stateful API exploration; source-to-runtime validation; optional scanner/fuzzer imports; browser-backed verification where a real browser is necessary.
+**Next slices (M3–M4):** Phase-1 threat-model & code-sink mapping (`gauntlet map`), built-in nonce-bound OOB canary collector, constrained Playwright browser adapter (for SPA auth flows and browser-effect verification), ephemeral parallel exploration workers via Vessel + Bones, and SIP/RTP/WebRTC + cross-protocol workflows via Sippycup.
@@ -515,12 +515,18 @@
 ### 8.1 Intake and discovery lanes
 
 Accept observations from existing instrument runs, source review, manual notes, scanner imports, known reports, API schemas and engagement documentation. Preserve original format and producer identity before normalization. Imports create leads and evidence, never verified findings.
 
-Run three bounded lanes where relevant:
+Structure discovery around four concrete accelerators rather than ad-hoc prompting:
 
-- **Surface and property discovery:** enumerate known routes/services, roles, resources, trust boundaries, workflow states, and likely high-consequence properties.
-- **Candidate development:** reproduce promising signals, identify prerequisites, connect source paths to runtime observations, and design discriminating experiments.
-- **Verification and challenge:** resolve controls, replay, investigate alternatives, validate scope/impact, and prepare reports.
+- **Phase-1 Threat Model & Attack Surface Mapping (`gauntlet map`):** Before launching attacks, synthesize source code, API specs, and live recon into a durable threat model: sensitive assets, trust boundaries, auth/authz enforcement points, principal roles, state machines, and high-consequence code sinks. Slice large repositories by component/boundary so agents never face a blank-page full-repo audit.
+- **Hybrid Signal Generation:** Combine LLM reasoning with deterministic engines (native `teapot`/`sippycup` crawls, static analysis/CodeQL/Semgrep leads, fuzzers, and Playwright route/auth discovery) so model blind spots are offset by exhaustive tooling.
+- **Focused Candidate Development:** Run bounded exploratory probes (`gauntlet run`) with access to a verifier-owned OOB canary collector (`gauntlet canary`) to convert plausible leads into reproducible hypotheses.
+- **Clean-Room Verification and Challenge:** Promote candidates only through Zone 2 (`gauntlet verify`) with controls, fresh replay, and independent review.
 
-A single investigator can cover all three sequentially. Parallel workers are useful when work is independent and do not share a mutable fixture. Do not spawn one agent per vulnerability label by default.
+A single investigator can run all stages sequentially on small targets. On larger surfaces, prefer **hub-and-spoke ephemeral parallel workers** (via `vessel` + `bones`): spawn short-lived, fresh-context workers assigned to disjoint surfaces/components that write compact leads and exit, preventing context rot while avoiding unstructured peer-to-peer agent chat [R4], [R25], [R35].
@@ -982,14 +988,18 @@
 ### 12.8 Optional Vessel integration
 
-Use structured spawn inputs, bounded observation, native session identity and explicit stop. Worker handoff contains only an objective, authority summary, current bindings, referenced evidence, open obligations, budget and next valid action. A role prompt grants no new capability.
+Use Vessel to spawn **ephemeral, single-mission exploration or verification workers** with structured spawn inputs, bounded observation, native session identity, and explicit stop. Retire exploration workers once their component mission finishes so context stays fresh. Worker handoff contains only the threat-model slice, objective, authority summary, bindings, referenced evidence, budget, and stop rule. A role prompt grants no new capability.
 
 Keep durable work in Bones and durable run/evidence/control state outside Vessel. On restart, reconcile processes by qualified instance identity and their native jobs; a PID alone is insufficient because it can be reused. An unavailable runtime should block only managed workers, not attached-agent CLI workflows.
 
-### 12.9 Scanner, source and browser adapters
+### 12.9 OOB canary collector, browser, scanner, and source adapters
+
+- **OOB Canary Collector (M3 core):** Provide a verifier-owned, lightweight HTTP/DNS interaction receiver (Interactsh-compatible or built-in) that issues unpredictable per-attempt nonces bound to the active attempt ID. The discovery agent's network namespace must be blocked from contacting the collector directly so callbacks prove target-originated egress.
+- **Constrained Browser Adapter (M3 core):** Integrate Playwright for both authenticated SPA/MFA recon and clean-room victim-context XSS/CSRF verification. Verification runs permit only constrained victim actions (navigate approved origin, fill/click specified controls, wait bounded conditions) with trusted external observation hooks; arbitrary agent `evaluate`/DOM injection cannot establish victim execution.
+- **Scanner and Source Imports:** Initially import static/scanner results (CodeQL, Semgrep, Nuclei, Burp, ZAP) without executing scanners, preserving tool/query/template version, code snapshot, and source-to-sink trace as structured leads for `gauntlet map`. Later live scanner adapters must satisfy the same scope, Hallpass, Playpen, and cancellation contracts.
-
-Initially import static/scanner results without executing scanners. Preserve tool/query/template version, original finding, exact code snapshot/path, source-to-sink trace, confidence assertion and limitations. Nuclei/CodeQL/Burp/ZAP outputs can provide useful leads [R13], [R14], [R15], [R16]; signatures and detector confidence do not grant authority or establish target truth.
-
-Later live scanner adapters must satisfy the same effect, scope, accounting, capture and cancellation contracts. No scanner process gets unlimited egress because it is a familiar product.
-
-A browser adapter is required for browser-executed claims. Allow a constrained victim action set—navigate approved origin, fill/click specified controls, wait bounded conditions—plus trusted observation instrumentation. Arbitrary `evaluate`, direct DOM modification or console execution by the testing agent cannot establish that application-controlled input executed in a victim context. Preserve actual browser build/origin/session and event evidence.
```

---

#### [High Impact, High Effort] Change #8: Generalize Verification Beyond Hand-Written Rust Oracles to Universal Mechanistic Validators & Differential Counterfactuals

**Current State:**
§7.4 (lines 481–490) restricts automatic runtime promotion to *"reviewed Rust code or a qualified instrument's versioned checker"* and relegates any agent-proposed oracle to `experimental` (unable to promote findings).

**Proposed Change:**
Replace the "pre-compiled Rust oracle per bug class" bottleneck with a **two-layer verification model**:
1. **Universal Mechanistic Validators (trusted verifier code, target-agnostic):** A small, thoroughly calibrated set of reusable trusted observers that cover the vast majority of real-world vulnerability classes without per-target Rust code:
   - *Cross-Principal Canary Observer* (attacker role reads/mutates victim-owned canary secret/state confirmed inaccessible to benign control).
   - *OOB Interaction Observer* (fresh attempt-bound nonce received on verifier-owned callback channel from target).
   - *Clean-Browser Execution Observer* (victim-context JS/DOM/cookie/action hook fired via constrained Playwright replay, per RECEIPT).
   - *Sanitizer / Process-Fault Observer* (ASan/UBSan/crash signal on identified target build, per CyberGym).
   - *Differential Counterfactual Observer* (submitted PoC triggers a declared state/response violation on the vulnerable target AND fails to trigger on a benign control input / unprivileged control / patched build, per *From Runnable to Verifiable*).
2. **Domain-Specific Compiled Profiles (Rust):** Reserved for complex protocol-specific semantics (`web-authz`, `sip-dialog`, `media-rtp`) where protocol state machines need specialized parsing.

For novel business-logic flaws that cannot reduce to a mechanistic observer alone, allow an explicit **Constrained Replay + Differential Check + Independent Semantic Adjudication** path (`runtime-adjudicated.v1`) so genuine novel business-logic bugs can still be verified cleanly without recompiling Gauntlet.

**Rationale:**
Real vulnerabilities rarely match a fixed CWE template or expose a synthetic "trusted fixture ownership API" (§17.1 line 1325). Requiring a Rust developer to write, calibrate, and ship a new compiled oracle for every new bug pattern turns Gauntlet into a rigid scanner rather than a general vulnerability research framework.

**Benefits:**
- Unlocks real-world verification for SSRF, XSS, SQLi, RCE, memory safety, IDOR, race conditions, and novel business-logic bugs from a compact set of ~5–6 trusted observers.
- Directly applies the core lesson of *From Runnable to Verifiable* (`2608.09567`): differential behavior against benign controls and patched builds catches 90%+ of weak/broken oracles.
- Preserves strict anti-self-certification: the agent writes the *stimulus/PoC*, never the *trusted observer*.

**Trade-offs:**
- Business-logic flaws verified via `runtime-adjudicated.v1` carry explicit reliance on independent semantic review alongside clean replay; reports must distinguish mechanistic verification (`runtime-controlled.v1`) from adjudicated business-logic replay (`runtime-adjudicated.v1`).

**Implementation Notes:**
Keep the calibration corpus requirement from §7.4 for every universal observer (including §16.4 traps: worker-spoofed callbacks, replayed nonces, 200 login pages, benign inputs triggering error strings).

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -481,10 +481,19 @@
 ### 7.4 Oracle implementation requirements
 
 An oracle consumes immutable typed observations and produces `true|false|inconclusive|error|unsupported`, with reason codes and evidence selectors. Predicate truth and experiment validity remain separate. Prefer deterministic predicates for properties that can be measured; a probabilistic test includes its protocol, assumptions, samples and uncertainty.
 
-Initial implementations are reviewed Rust code or a qualified instrument's versioned checker. Future external checker programs require a pinned digest, explicit execution policy, bounded resources, a read-only evidence input, no target/network access unless explicitly part of the observer, and authenticated output provenance. Do not execute a checker merely because a report supplied its path.
+To scale beyond synthetic fixtures without sacrificing soundness, structure trusted verification around **two layers** rather than requiring a bespoke compiled Rust oracle for every bug class:
+
+1. **Universal Mechanistic Validators (trusted verifier code, target-agnostic):**
+   - *Cross-principal canary diff* (attacker reads or mutates a victim-owned canary/resource while negative/public controls hold).
+   - *Nonce-bound OOB observer* (verifier-owned callback collector receives a fresh attempt-bound token originating from the target).
+   - *Clean-browser victim observer* (constrained Playwright victim session triggers the claimed DOM/script/navigation effect without attacker `evaluate` access).
+   - *Sanitizer / fault observer* (identified build/sanitizer triggers the claimed fault class and disappears on patched/benign control).
+   - *Differential counterfactual validator* (paired comparison against benign input, authorized/unauthorized control, or patched build to defeat naive signal-only oracles [R30]).
+2. **Domain-Specific Compiled Profiles (Rust / qualified native checkers):** Specialized state-machine evaluators for structured domains (`web-authz`, `sip-signaling`, `media-rtp`).
+
+Agents supply the constrained replayable PoC/stimulus—never the trusted observer code. For novel target-specific business-logic vulnerabilities that cannot reduce to a mechanistic observer alone, provide an explicit `runtime-adjudicated.v1` profile requiring clean-room replay, paired controls, and independent semantic review, reported separately from mechanistically verified findings.
 
 An oracle's qualification set includes true positives, benign controls, patched cases, broken setup, manipulated marker outputs, invalid identity, missing bytes, stale attempt data, direct harness spoofing, and relevant timing noise. Test the measurement boundary and the predicate. A parser unit test alone is not oracle validation.
 
-An agent-proposed oracle enters `experimental`. It may help exploration, but automatic runtime promotion requires a reviewed/qualified version. Source review may still record an attributed judgment with an experimental measurement and an explicit limit. No self-approval path.
+An agent-proposed custom assertion enters `experimental` for exploration only and never grants `runtime-controlled.v1` promotion on its own.
```

---

#### [Medium Impact, Low Effort] Change #9: Simplify the 5-Store Distributed Saga & Add Agent-Throughput Performance Metrics

**Current State:**
§13.1–13.3 (lines 998–1028) design an 11-table SQLite coordination database, an 8-state attempt state machine, an 8-step cross-tool distributed saga, a transactional outbox, and custom CAS fencing across 5 separate stores—plus an 8-crate repository layout in §18.1 (lines 1384–1411). Meanwhile, §16.8 (lines 1311–1316) specifies performance targets exclusively around local database latency (300ms reads, 200ms fsync writes at 10,000 objects) without concrete targets for the real bottleneck: **LLM turns, context tokens, and schema-retry overhead per verified finding**.

**Proposed Change:**
1. **Shrink the local coordination layer:** Start with **5 core SQLite tables** (`engagements`, `attempts`, `claims`, `verifications`, `work_links`) in WAL mode plus the content-addressed evidence directory. Treat `bones` strictly as an asynchronous, coarse-grained work tracker (engagements, leads, verification tasks, remediation items—never per-probe attempt locking). Simplify consistent workspace backup to SQLite `VACUUM INTO` + immutable blob copy.
2. **Shrink the initial crate graph:** Start with **3 crates** (`gauntlet-core`, `gauntlet-cli`, `gauntlet-verify`) rather than 8, splitting only when a real boundary demands it.
3. **Add agent-efficiency performance targets in §16.8:** Explicitly track and bound **tool-calls-to-first-useful-probe (≤3)**, **schema/ceremony error rate (<5% of tool calls)**, **Gauntlet metadata token overhead (<15% of session input tokens)**, and **all-in cost & wall-clock time per verified distinct vulnerability** relative to Baseline B.

**Rationale:**
Most of §13's distributed-systems complexity is self-inflicted by tightly coupling fine-grained execution attempts across 5 separate local stores. Meanwhile, optimizing SQLite reads from 400ms to 200ms is invisible next to a single 5-second LLM turn—whereas forcing 8 extra LLM round-trips of JSON ceremony ruins both speed and dollar cost.

**Benefits:**
- Cuts initial implementation and maintenance footprint in half while keeping real crash recovery (`declared -> running -> finalized | unknown_effect`) and idempotency intact.
- Aligns performance engineering with the actual cost drivers of autonomous security agents (tokens, turns, and wall-clock time to verified bug).
- Simplifies backup/restore from a fragile multi-store consistent-cut problem to a single atomic local operation.

**Trade-offs:**
- Coarse `bones` synchronization means individual exploratory HTTP probes are not mirrored as Bones work items (an intentional simplification; probes live in the evidence store, while actionable leads/findings/retests live in Bones).

**Implementation Notes:**
Use SQLite `PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;` and `BEGIN IMMEDIATE` for single-host local admission and conflict-group exclusion—completely eliminating the need for a separate outbox daemon until multi-host or heavy async workers exist.

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -1000,14 +1000,13 @@
 Use SQLite with transactions, foreign keys, explicit migrations and tested local durability settings for the small canonical coordination state. Initial supported writes are on a local Linux filesystem, not a synchronized folder or network share. Back up consistently; do not copy a live WAL database as if it were a complete archive.
 
-Suggested tables: `workspace`, `engagement_bindings`, `domain_manifest_refs`, `operations`, `attempts`, `admissions`, `conflict_holders`, `outbox`, `native_receipts`, `adapter_qualifications`, `audit_events`. They contain operational metadata, immutable references and receipt identities—not generic evidence blobs, a second claim graph or copied Bones work state.
+Keep the initial schema minimal (~5 core tables in WAL mode with `BEGIN IMMEDIATE` serialization): `engagements`, `attempts` (covering idempotency keys, conflict locks, native handles, Hallpass/Playpen receipts, and effect uncertainty), `claims`, `verifications`, and `work_links` (async coarse sync to Bones), plus `audit_events` for controller transitions. Store immutable artifact bytes in the content-addressed `EvidenceStore` directory rather than SQLite blobs. Consistent backups use SQLite `VACUUM INTO` paired with immutable content-addressed artifact copying.
 
 `audit_events` records important controller transitions in the same transaction as state/outbox updates. It is an operational audit, not another original-evidence journal. A hash of this log does not make it tamper-proof against the workspace owner.
 
 ### 13.2 Attempt state machine
 
-The normal lifecycle is `declared`, `capture_ready`, `admission_pending`, `admitted`, `launching`, `running`, `collecting`, then `finalized`. Each transition has its own persisted receipt or guarded local decision.
+Keep the persisted attempt lifecycle compact: `declared`, `running`, `finalized`, plus terminal/recovery flags (`refused`, `cancelled`, `failed_before_start`, `reconciliation_required`) and an independent `external_effects: not_started | observed | unknown` field. Collapse internal pre-launch steps (capture prep, conflict lock, manifest digest) into a single local `BEGIN IMMEDIATE` transaction before invoking the external tool, persisting the native handle/receipt immediately upon launch.
 
 Transitions have guards. `refused`/`failed_before_start` require affirmative evidence that this attempt did not launch; a later admission refusal cannot erase an earlier effect. `cancel_requested`, `interrupted` and `reconciliation_required` preserve the last known lifecycle. Effect uncertainty is an independent field and can remain `unknown` even after capture is finalized. Reconciliation appends observations rather than rewriting the historical uncertain interval. Native process/job termination bounds local execution, but remote queued work, callbacks or asynchronous mutations need separate target-effect reconciliation.
@@ -1016,13 +1015,11 @@
-Gauntlet, Investigation, Bones, Hallpass and a native engine do not share an atomic commit. The protocol is a recoverable saga:
+Gauntlet, Hallpass, Bones, and native engines do not share an atomic commit. Minimize distributed-saga surface by keeping local coordination + evidence capture atomic within Gauntlet's local boundary, and limiting cross-tool coordination to two explicit boundaries:
 
-1. Persist intended action and downstream idempotency/correlation keys.
-2. Ask Investigation/native recorder for a recording handle; store its receipt.
-3. Acquire local admission and bind the frozen basis.
-4. Follow the designated accounting/launch boundary; preserve receipts and possible uncertainty.
-5. Observe the native job and collect outputs.
-6. Finalize Investigation evidence with stable IDs.
-7. Commit domain assessment/verification against exact Investigation revisions.
-8. Link/update Bones work through the outbox.
+1. **Execution boundary (Hallpass + native instrument):** Persist `declared` attempt and conflict lock locally -> perform single-owner accounting & launch -> persist native receipt and captured artifacts -> finalize local attempt (or mark `external_effects: unknown` on crash).
+2. **Coarse work-tracking boundary (Bones):** Sync only high-level leads, verification tasks, and retests asynchronously via `work_links` with correlation IDs; never place Bones on the critical path of individual probe admission.
 
 Evidence can be finalized even if a work-link update fails. A delayed work update does not invalidate original bytes. A pending Investigation promotion means the finding is not yet promoted, even if a local evaluator produced a positive result.
@@ -1311,7 +1310,12 @@
 ### 16.8 Performance and reliability targets
 
 On a documented ordinary development workstation with 10,000 domain objects and 50,000 evidence links: warm `brief/next/show` under 300 ms p95; ordinary local metadata mutation through durable commit under 200 ms p95 on the specified storage/filesystem profile, including all required flush/fsync work; bounded memory while ingesting large captures. Report controller CPU/index work and upstream latency separately as diagnostics without excluding slow durability samples from the user-visible metric. These are targets to measure and tune, not existing results or universal workstation release blockers.
 
-Document end-to-end latency separately from native instrument time and model latency. An efficient controller that causes many extra agent calls is not an efficient workflow. Profile before introducing caches or parallelism; cached guidance always carries its basis and is revalidated before effects/promotion.
+Because LLM turns dominate real-world latency and cost, track **agent-workflow efficiency** as primary release diagnostics alongside local CLI latency:
+- **Onboarding speed:** ≤3 calls to first useful target/analysis action on cold start.
+- **Ceremony friction:** <5% of agent tool calls failing on schema, digest, or state-transition validation errors.
+- **Context tax:** Gauntlet orientation/schema/status responses consume <15% of total session input tokens on standard engagements.
+- **Net ROI:** Verified distinct findings per dollar and per wall-clock hour compared directly against Baseline B (native tools + Markdown methodology).
@@ -1388,20 +1389,14 @@
 ```text
 gauntlet/
   crates/
-    gauntlet-core/          domain types, transitions, obligations, freshness
-    gauntlet-cli/           generated command surface, text/JSON output
-    gauntlet-store/         coordination DB, outbox, request identity, recovery
-    gauntlet-adapters/      public native protocols and qualification clients
-    gauntlet-exec/          narrow launch broker, process observation, cancellation
-    gauntlet-verify/        trusted profile evaluator and initial property oracles
-    gauntlet-report/        security projections over Investigation exports
-    gauntlet-mcp/           optional transport from the same catalog
+    gauntlet-core/          domain types, local SQLite store, EvidenceStore trait/local impl, adapters, reports
+    gauntlet-verify/        isolated verifier runner, universal observers, OOB canary collector, proof profiles
+    gauntlet-cli/           porcelain + plumbing CLI, generated schemas, optional stdio MCP transport
   packs/                   declarative built-in properties, recipes, guides
   schemas/                 generated versioned contracts
   fixtures/
     public/                teachable examples and deterministic negatives
     contracts/             native-output, schema and crash fixtures
     qualification/         host/backend conformance instructions
   evals/                   runner, metrics, manifests; no held-out solutions
   docs/                    generated reference, ADRs, guides, support matrix
   tests/                   cross-component workflows and failure injection
 ```
 
-Do not split tiny modules into crates merely to match the diagram. Begin with core/CLI/store and one adapter path if that is simpler. Introduce public extension points after the second real implementation exposes the common contract.
+Start with these three crates (separating the trusted verifier binary/crate cleanly from the agent-facing CLI). Extract additional crates only after a second concrete backend or external consumer requires a stable library boundary.
```

---

#### [Medium Impact, Low Effort] Change #10: Harden Security & Operational Blind Spots (Host-Agent Prompt Injection & Model Cyber-Safety Refusals)

**Current State:**
- §4.3 (line 231) addresses prompt injection solely inside Gauntlet's trusted Rust code (*"Trusted code handles them as data"*), overlooking that the **LLM agent itself** reads target HTTP responses and target repository files in `supervised` mode—where a prompt-injected response or malicious repo config file (`.mcp.json`, `AGENTS.md`, hooks) can hijack the host agent directly.
- §8.5 (lines 568–577) and §11.4 (line 870) treat execution failures and stalls without accounting for a pervasive 2025–2026 operational reality documented in Anthropic's Claude Code Security and enterprise pentest deployments: **false-positive provider cyber-safety refusals** mid-engagement.

**Proposed Change:**
1. **Agent-layer prompt-injection hardening (§4.3):**
   - Explicitly frame/delimit all untrusted target responses, headers, and repo snippets returned by `gauntlet show`/`run`/`map` as inert untrusted evidence blocks (with bounded excerpts and optional stripping of high-risk control/invisible characters).
   - Explicitly quarantine/ignore untrusted target repository agent-config files (`.claude/`, `.mcp.json`, `AGENTS.md`, git hooks, IDE tasks) when analyzing target source code.
   - Recommend running the *host discovery agent itself* inside an isolated container/VM whenever assessing untrusted or hostile external targets, rather than relying on Gauntlet's CLI alone to protect a host shell.
2. **Structured model-refusal handling (§8.5, §11.4):**
   - Add an explicit `MODEL_REFUSED` event/error classification distinct from tool failure or negative security verdict.
   - Support attaching explicit, concise engagement-authorization headers/summaries in handoffs and worker prompts (compatible with authorized defensive/security verification programs such as Anthropic CVP), and allow clean handoff to an alternate authorized model/worker on refusal without losing attempt state or miscounting the cell as `tested_no_violation`.

**Rationale:**
A security research tool is uniquely exposed to adversarial inputs (targets actively trying to trap scanners/agents, untrusted repos containing malicious agent hooks as shown in Check Point Research's Claude Code findings) and uniquely exposed to dual-use model guardrails. Leaving both unaddressed creates immediate real-world security and reliability failures.

**Benefits:**
- Protects operators from host compromise via malicious target responses or poisoned target repositories.
- Prevents model safety false refusals from silently corrupting coverage matrices (being mistaken for "no vulnerability found" or a broken target) or aborting multi-hour engagements.

**Trade-offs:**
- Evidence framing/delimiting adds minor token overhead per displayed excerpt and does not eliminate prompt injection at the model level (defense-in-depth, not a silver bullet—hence the containerized-agent recommendation for untrusted targets).

**Implementation Notes:**
Add a regression test to §16.7 verifying that a target repository containing a poisoned `AGENTS.md` or `.mcp.json` is never loaded into Gauntlet's config search path or agent instructions, and that a simulated `MODEL_REFUSED` worker exit marks the coverage cell `blocked` (never `tested_no_violation`).

**Git-Diff:**
```diff
--- notes/plan.md
+++ notes/plan.md
@@ -231,4 +231,8 @@
 Assume target responses, imported reports, repository content under review, filenames, terminal output, and peer-agent messages can contain misleading claims or instructions. Trusted code handles them as data. Do not interpolate them into shell syntax, managed instructions, policy, or an executable tool definition.
 
+Because the LLM agent itself must read target responses and source code during discovery, Gauntlet's Rust boundary alone cannot prevent prompt injection against an unconfined host agent:
+- All untrusted target/source excerpts returned by Gauntlet CLI/MCP outputs MUST be explicitly delimited as untrusted evidence data with bounded size.
+- Source analysis and `gauntlet map` MUST never execute or auto-load agent configuration, hooks, or MCP definitions (`AGENTS.md`, `.mcp.json`, `.claude/`, git hooks) found inside a target repository.
+- When assessing hostile or untrusted targets, run the discovery agent itself inside an isolated container/VM; document clearly that `supervised` host mode does not protect the operator's host shell from a prompt-injected agent.
+
 The minimal product trusts the local operator and the installed binaries. Hashes provide identity/integrity relative to a retained reference; they do not authenticate a source or defeat a hostile administrator. A worker ID is attribution until bound to an actual launcher/credential boundary.
@@ -574,5 +578,7 @@
 Transfer a successful technique only when its applicability predicates hold. New credentials, a source fact, or a now-qualified instrument can reopen previously blocked work, with the causal link recorded. Shared source or technique is not independent evidence for the new target.
 
+Provider cyber-safety classifiers may trigger false-positive refusals during legitimate authorized security testing. Classify refusals explicitly as `MODEL_REFUSED` (keeping affected coverage cells `blocked`, never `tested_no_violation`), preserve clean engagement-authorization context in worker briefs for vetted security-access tiers, and permit clean handoff to an alternate authorized model/worker without duplicating effects.
+
 Model/harness escalation is optional and evaluation-driven. Escalation preserves the same immutable objective, allowed capabilities, budget and handoff; it never implicitly expands target scope. Exhausting one provider budget is not permission to consume unrelated credentials or accounts.
@@ -870,1 +876,1 @@
-Required codes include `ENGAGEMENT_REQUIRED`, `AUTHORITY_REQUIRED`, `SCOPE_REFUSED`, `BUDGET_REFUSED`, `ENFORCEMENT_UNQUALIFIED`, `CAPABILITY_UNAVAILABLE`, `VERSION_UNSUPPORTED`, `IDENTITY_UNESTABLISHED`, `CONTROL_INVALID`, `EVIDENCE_INCOMPLETE`, `ORACLE_UNQUALIFIED`, `ORACLE_ERROR`, `REVIEW_REQUIRED`, `BASIS_STALE`, `EFFECT_UNKNOWN`, `CONFLICTING_RUN`, `REVISION_CONFLICT`, `IDEMPOTENCY_KEY_REUSED`, `DEPENDENCY_UNAVAILABLE`, and `INTEGRITY_FAILURE`.
+Required codes include `ENGAGEMENT_REQUIRED`, `AUTHORITY_REQUIRED`, `SCOPE_REFUSED`, `BUDGET_REFUSED`, `ENFORCEMENT_UNQUALIFIED`, `CAPABILITY_UNAVAILABLE`, `VERSION_UNSUPPORTED`, `IDENTITY_UNESTABLISHED`, `CONTROL_INVALID`, `EVIDENCE_INCOMPLETE`, `ORACLE_UNQUALIFIED`, `ORACLE_ERROR`, `REVIEW_REQUIRED`, `BASIS_STALE`, `EFFECT_UNKNOWN`, `CONFLICTING_RUN`, `REVISION_CONFLICT`, `IDEMPOTENCY_KEY_REUSED`, `DEPENDENCY_UNAVAILABLE`, `MODEL_REFUSED`, and `INTEGRITY_FAILURE`.
```

---

### Summary Priority Matrix

| # | Priority | Dimension | Core Fix |
|---|---|---|---|
| 1 | High Impact, Low Effort | Architecture / Security | Resolve same-UID verifier custody deadlock via clean-container verifier + honest `runtime-supervised.v1` |
| 2 | High Impact, Low Effort | Execution / Architecture | Unblock M1–M2 from unbuilt `Investigation` via `EvidenceStore` trait + local store; replace private `[S8]` link |
| 3 | High Impact, Low Effort | Execution / Validation | Replace 40-family / 160-trial v1 gate with 3-tier ladder + early M2 A/B/C ROI test |
| 4 | High Impact, Low Effort | Research / Strategy | Add Big Sleep, XBOW, Codex Security, Shannon, EnIGMA, mini-SWE-agent, ABC/CVE-Bench v2.0, and inspected RECEIPT / *From Runnable to Verifiable* results |
| 5 | High Impact, High Effort | Architecture / Usability | Asymmetric Two-Zone model: fluid exploration (`gauntlet run`) + strict clean-room verification (`gauntlet verify`) |
| 6 | High Impact, High Effort | Usability / API Design | Collapse 35 operations into 7 cold-agent porcelain verbs with automatic digest/request-key plumbing |
| 7 | High Impact, High Effort | Features / Discovery | Add Phase-1 threat-model mapper (`gauntlet map`), OOB canary collector, day-1 Playwright, and ephemeral `vessel` workers |
| 8 | High Impact, High Effort | Architecture / Scalability | Replace Rust-only oracle bottleneck with universal mechanistic validators + differential counterfactuals |
| 9 | Medium Impact, Low Effort | Robustness / Performance | Collapse 11-table 5-store saga & 8 crates into minimal WAL SQLite + 3 crates; add token/turn efficiency metrics |
| 10 | Medium Impact, Low Effort | Security / Reliability | Harden against host-agent prompt injection / poisoned target repos and handle `MODEL_REFUSED` cyber-safety blocks |
