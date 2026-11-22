# Scourge — implementation plan

**Status:** implementation specification; this document does not describe an already implemented product.  
**Revision:** 1 — 2026-11-21, with fact corrections from review. **Superseded by revision 2 in [`plan.md`](plan.md).** This file is kept because the three reviews cite it by section and line, and because §24 holds the full reasoning behind the redesign. Do not implement from it.  
**Codename:** `scourge`, temporary. Isolate the display name, executable aliases, package names, and schema namespace mapping so a later rename is routine. Do not spend implementation time choosing the permanent brand.  
**Product:** a security methodology and verification layer over the Reliquary tools, usable by an existing agent or a human, with optional managed workers.  
**Primary constraint:** an agent that has never seen the tool can discover and correctly complete its workflow from the executable itself.  
**Input specification:** the attached *Investigation — implementation plan*, revision 3, dated 2026-11-21, is the authoritative design of the domain-neutral evidence substrate. It is a planned interface, not evidence that those APIs already ship.

## Read this first

Build a system that turns plausible security observations into **bounded, independently replayable, causally supported findings**, and makes the missing proof obvious. Optimize the number of distinct, meaningful vulnerabilities correctly verified under a fixed time and resource budget, while making false promotion, evidence loss, and unauthorized effects hard to introduce and easy to detect.

The hard part is deciding what an observation proves. An HTTP success code, scanner alert, crash, callback, passing test, model verdict, or completed work item is insufficient by itself. Scourge must preserve the exact observation and enforce the additional obligations appropriate to the claim.

Use agents for hypothesis generation, source reasoning, test design, interpretation, and challenge. Use ordinary code for durable state, authority checks, execution receipts, evidence binding, oracle evaluation, and promotion gates. The public mutation API must not let a model declare its own oracle authoritative or write a trusted oracle result. Preventing a same-user shell process from tampering outside that API requires the separately qualified custody boundary in §4.3.

The result should feel like an excellent investigative instrument: easy to begin, explicit about its limits, fast to resume, difficult to fool, and able to produce a finding another engineer can actually reproduce.

### Binding decisions

| Area | Decision |
|---|---|
| Product boundary | Security-specific methodology, engagement coordination, typed experiments, proof obligations, verification, coverage, and reporting. |
| Investigation | Owns generic evidence, acquisitions, runs, observations, hypotheses, assessments, conclusions, provenance, and casebook. It never imports Scourge or any named security tool. |
| Bones | Owns work items and dependencies. Scourge translates security work into Bones; it does not build a competing task graph. |
| Native instruments | Teapot/HTTP and Sippycup/protocol tools perform their existing domain operations. Scourge supplies orchestration and evidence interpretation. |
| Authority | Hallpass provides its actual authorization/accounting contract. Playpen provides its actual execution/network restrictions. Neither is assumed to provide guarantees outside that contract. |
| Runtime | Existing agent harness first; optional Vessel for worker lifecycle. No new model SDK, universal agent runtime, terminal emulator, or mandatory agent council. |
| Workflow style | Edict-like local bootstrap, managed instructions, contextual guidance, and explicit machine-readable protocols. Edict need not be a runtime dependency. |
| Verification | Claim-specific, versioned proof contracts with controls, causal evidence, fresh replay, and explicit uncertainty. No universal numeric confidence score. |
| Storage | Investigation is the evidence authority; Bones is the work authority; Scourge has a small durable coordination store for its own domain bindings and execution sagas. |
| Inputs | Strict typed operations and receipts. Never infer mutations from agent chat, terminal prose, or a Markdown report. |
| UX | One command catalog generates help, schemas, examples, MCP surfaces, managed instructions, and repair hints. |
| Autonomy | Continue within a valid engagement's authority and budgets. Ask an operator only for genuinely missing authority or a consequential choice the engagement did not settle. |
| Learning | Evidence-backed technique proposals with applicability and regression tests; deliberate promotion into pinned packs. No silent self-modification. |
| Release order | Prove one complete HTTP authorization workflow, including false-positive rejection, crash recovery, cold-agent use, and fix verification; then extend protocols and discovery. |
| Claims about excellence | Research informs hypotheses. Held-out measurements determine whether the implemented framework improves outcomes. Nothing here establishes universal optimality. |

### Naming clarification

The request names **teacup**. No such repository exists locally or under `bobisme` on GitHub, and the string does not appear in Teapot (checked 2026-11-21, review 1). The HTTP workbench is **Teapot**. This plan uses the logical capability `http-workbench` and a `teapot` adapter.

### Normative language

`MUST` and explicit rejection conditions are implementation requirements. Performance numbers and evaluation thresholds are proposed release targets, not observed results. All `scourge` commands and schemas below are proposed APIs. Upstream contracts are identified separately as inspected, planned, or requiring qualification. Examples with angle-bracket identifiers are schematic; shipped examples must use real IDs returned by their own fixtures.

### Contents

1. [Product scope and success](#1-product-scope-and-success)
2. [Research and design consequences](#2-research-and-design-consequences)
3. [Existing stack and ownership](#3-existing-stack-and-ownership)
4. [Architecture and trust boundaries](#4-architecture-and-trust-boundaries)
5. [Domain model and identity](#5-domain-model-and-identity)
6. [Finding lifecycle and verification contracts](#6-finding-lifecycle-and-verification-contracts)
7. [Experiment design and oracle profiles](#7-experiment-design-and-oracle-profiles)
8. [Discovery, coverage, and next-action selection](#8-discovery-coverage-and-next-action-selection)
9. [Authorized execution and resource control](#9-authorized-execution-and-resource-control)
10. [Agent experience and CLI](#10-agent-experience-and-cli)
11. [Mutation, response, and schema contracts](#11-mutation-response-and-schema-contracts)
12. [Adapter protocol and integration details](#12-adapter-protocol-and-integration-details)
13. [Durability, concurrency, and recovery](#13-durability-concurrency-and-recovery)
14. [Evidence bundles, reports, and fix verification](#14-evidence-bundles-reports-and-fix-verification)
15. [Playbooks and transferable learning](#15-playbooks-and-transferable-learning)
16. [Evaluation and release gates](#16-evaluation-and-release-gates)
17. [Worked end-to-end scenarios](#17-worked-end-to-end-scenarios)
18. [Implementation structure](#18-implementation-structure)
19. [Milestones and work packages](#19-milestones-and-work-packages)
20. [Shipping instructions and operator experience](#20-shipping-instructions-and-operator-experience)
21. [Risks, deferred work, and decisions](#21-risks-deferred-work-and-decisions)
22. [Research references and inspection record](#22-research-references-and-inspection-record)
23. [Final handoff checklist](#23-final-handoff-checklist)
24. [Review disposition](#24-review-disposition)

## 1. Product scope and success

### 1.1 The job

Given an explicitly bounded engagement, its objectives, available identities, a target description, and any existing findings or source code, help an unfamiliar agent:

1. Establish what is authorized, what is reachable, what tools work, and what evidence already exists.
2. Identify important security properties and plausible violations.
3. Choose a discriminating, affordable test with valid preconditions and observable effects.
4. Execute through a qualified instrument while recording the complete attempt.
5. Separate an observed signal from a demonstrated security consequence.
6. Reproduce and challenge promising findings, rejecting confounded or unsupported conclusions.
7. Produce an inspectable report, a portable reproduction specification, and a precise next step.
8. Verify remediation without losing legitimate behavior or hiding incomplete patches.
9. Resume after agent replacement or process failure without guessing which external effects occurred.

Support both starting from a candidate and discovering candidates. Verification excellence must not become a system that reports nothing and celebrates perfect precision. Measure discovery recall and verified yield alongside false promotions.

### 1.2 Initial scope

**First production slice:** authorized HTTP/API assessment with multiple identities and tenants; session-aware replay; source-assisted reasoning when available; authz and state-transition violations; negative controls; independent rerun; evidence export; fix verification. HTTP/WebSocket protocol features are used only where the pinned instrument supports them.

**Next slices:** SIP/RTP/WebRTC and HTTP-to-signaling/media workflows; stateful API exploration; source-to-runtime validation; optional scanner/fuzzer imports; browser-backed verification where a real browser is necessary.

**Broader framework:** modular proof profiles for other security domains. A domain becomes supported when its adapter, oracle, fixtures, authority boundaries, and cold-agent workflow pass qualification. A taxonomy label alone does not constitute support.

**Outside the initial product:** exploit databases, Internet-wide scanning, a new proxy or packet engine, a universal fuzzing engine, automatic patch synthesis, vulnerability disclosure delivery, deployment/merge authority, distributed multi-host scheduling, and an unrestricted autonomous shell exposed as a verified instrument. Evidence imports and reasoned static findings remain useful without live execution.

### 1.3 Success has several independent dimensions

| Dimension | Measure |
|---|---|
| Soundness | False promotions on known-negative and confounded cases; correct claim scope; resistance to weak oracles. |
| Discovery | Distinct true vulnerabilities found and verified; recall where ground truth is knowable; important untested surfaces. |
| Reproducibility | A new worker or reviewer reproduces the stated consequence from the bundle in a compatible fresh environment. |
| Practical value | Meaningful findings per wall-clock hour, per dollar/token budget, and per allowed target operation; time to first verified finding. |
| Agent usability | Cold-start success, valid first action, error repair, handoff accuracy, unnecessary reads and calls. |
| Operational integrity | Recorded effect uncertainty, reliable cancellation, accounting fidelity, no automatic re-execution of an action with unknown effects, honest cleanup. |
| Coverage honesty | Unexamined and blocked areas stay visible; denominator and target revision are explicit. |

Do not collapse these into one opaque score. Compare a Pareto frontier and publish the tradeoff: a slightly slower verifier may be worthwhile if it removes false findings, while excessive ceremony that loses real findings must also be visible.

### 1.4 What “fucking awesome” means here

An agent starts with only a task, the executable, and the engagement fixture. It gets to a valid useful action quickly. It finds a planted vulnerability without being told where it is, rejects a convincing decoy, produces a reproducible finding, survives interruption, and proves a fix while checking legitimate behavior. Another agent can audit the conclusion without the first conversation. Every strong claim resolves to exact evidence and a tested rule. The same experience works outside the tutorial.

## 2. Research and design consequences

### 2.1 How to read the evidence

Research support is classified by what was actually inspected:

- **Organizer or independent observation:** a competition organizer's measured outcome or an evaluator's audit, within that setting.
- **Primary experimental result:** an author's experiment with methods and denominators; useful, but not an independent reproduction.
- **Implementation evidence:** inspected source/test definitions establish implementation presence; official documentation describes supported mechanisms/contracts. Neither establishes successful execution here or comparative effectiveness.
- **Design reference:** a promising architecture or author-reported deployment without a transferable controlled result.

No cross-paper leaderboard is constructed. CTF flag recovery, known-CVE exploitation, source-level PoV generation, live pentesting, finding triage, and patch validation measure different jobs. Model, scaffold, budget, metadata, target set, and evaluator all matter. Public benchmark scores cannot establish expected production recall.

The complete source ledger and inspection limits are in §22. Concrete research rows will be maintained alongside the implementation's benchmark configuration, so changing a paper version does not silently change the engineering requirement.

### 2.2 Synthesis

The most defensible architecture combines five ideas:

1. **Stateful exploration and source-informed hypotheses.** Use dependency-aware instrumented tests and available code context to reach meaningful states; do not ask a model to improvise every low-level action.
2. **Executable, claim-specific verification.** Check the actual protected property and identities, not merely the presence of a string or process exit code.
3. **Control and counterfactual experiments.** Healthy control, minimally changed input/role, fresh replay, and fixed-build comparison expose false signals and incomplete remediations.
4. **Durable, layered knowledge.** Preserve original evidence and failed attempts; expose a small current brief and exact drill-down references.
5. **Evaluation of the complete workflow.** Measure fresh agents, meaningful environment outcomes, false positives, recall, recovery, and cost under matched budgets and hidden cases.

More agents are optional. More reliable evidence is compulsory. Roles are justified by a distinct information need, isolated authority, or a measured benefit; adding a reviewer prompt is not itself verification.

### 2.3 Research table

The final research table appears in §22 with measured results and limitations. The following decisions are binding regardless of whether a particular upstream project remains fashionable:

| Observation from research | Scourge requirement |
|---|---|
| Successful agents still submit false findings [R4]. | Promotion consumes typed run/evidence/oracle receipts, not a natural-language success field. |
| Evaluation graders can accept unintended effects [R18], [R33]. | Bind the consequence to the claimed mechanism; audit alternate causes and grader isolation. |
| State dependencies matter for API testing [R8], [R9]. | Plans describe setup, action, observation, control, and cleanup as a typed dependency sequence. |
| Public task sets can saturate or leak answers [R18], [R19]. | Maintain private held-out families, fresh fixture secrets, isolated referees, and contamination accounting. |
| Source/location hints can materially change performance in studied settings [R5], [R26]. | Preserve black/grey/white-box conditions and provide authorized source context efficiently. |
| Source and runtime tools supply complementary evidence [R2], [R13]. | Use scanner/static output as leads, then connect reachability, prerequisites, and measured effects. |
| Context and interface design affect agent success [R7], [R22], [R23]. | State-aware onboarding, bounded output, useful errors, generated examples, and cold-agent evaluation are release gates. |
| A reached effect or executable reproduction can fail to establish the intended original-target vulnerability [R18], [R28]. | Treat runnable, signal-producing, causally supported, independently reproduced, and fixed as different claims. |

## 3. Existing stack and ownership

### 3.1 One owner for each kind of truth

| Component | Owns | Scourge must not duplicate |
|---|---|---|
| Investigation | Generic cases, source/artifact custody, observations, runs, assessments, conclusions, provenance, generic archive/casebook. | A second generic fact graph, blob store, evidence journal, or Obsidian renderer. |
| Bones | Work identity, work status, dependencies, prioritization inputs, links to assigned work. | Another persistent work DAG or a second authoritative “done” field. |
| Hallpass | Recorded approval policy and its supported budget ledger semantics; a pass does not authenticate the owner's real-world consent. | A fake local permission grant or a competing debit ledger. |
| Playpen | Its supported restricted process/network execution and reports. | A claimed sandbox implemented by prompt instructions. |
| HTTP workbench | HTTP capture, request/session/replay/crawl/authz operations actually present in the qualified version. | A new HTTP proxy, cookie jar, or raw-request editor. |
| Sippycup | Protocol/scenario execution, SIP/media capture and instrument-specific interpretation. | A new SIP/RTP stack or packet-capture implementation. |
| Vessel, optional | Worker/process lifecycle and interaction in its supported host. | A new agent terminal or model loop; no assumption of durable jobs. |
| Scourge | Engagement bindings, security properties, proof profiles, experiment coordination, promotion rules, security coverage, verification receipts, report assembly. | Upstream semantics it can call through a stable contract. |

Scourge's security concepts are an external consumer of Investigation. Store security manifests as inert, versioned artifacts/annotations with generic references. Investigation must still build, test, and run with no Scourge, Bones, Hallpass, Playpen, or protocol instrument installed.

### 3.2 Current capability qualification

M0 must pin actual revisions and verify each advertised operation. The research snapshot is in §22; do not infer functionality from a filename or README milestone alone. Important findings already affect the design:

- Investigation is a **plan with no implementation**: its repository holds `notes/plan.md` (rev. 3) and reviews, and there is no `inv` binary (checked 2026-11-21). Build against a conformance contract; a simulator can unblock tests but never qualify a real release. See §24 for how the dependency is narrowed.
- The current inspected Teapot source contains substantive authz/crawl handlers and corresponding test code. Older observations that these were placeholders are stale. Inspection is not a claim that the suites were run here.
- Hallpass accounting and caller correlation do not establish exactly-once external execution. A committed debit can precede a failed send.
- Playpen's documented IP egress controls are not filesystem confinement or semantic request-count enforcement. Its platform, container, raw-socket, and loopback limitations matter.
- Sippycup's container/capture execution needs a specifically qualified confinement composition. Wrapping its launcher in Playpen and declaring the whole run confined is unacceptable.
- Vessel liveness is not durable scheduling. Scourge and Bones retain the information needed to reconcile a missing worker.

Every adapter advertises `available`, `unsupported`, or `unqualified` per capability, with a reason and a concrete remediation route. Missing features must produce honest blocks, never fabricated evidence or silent fallback to an unrestricted command.

### 3.3 Integrate incrementally

First implement external adapters and public contracts. Changes inside an upstream repository should add a useful general capability, such as stable receipt identity, capture integration, or machine-readable limits. Keep security-specific decisions in Scourge.

If a producer retains its existing native journal, it remains the execution receipt authority for that run; Investigation imports an exact immutable acquisition with lineage. That is an import boundary, not two competing generic histories. When a producer adopts `investigation-recording`, switch one run path at a time to a single evidence authority. Do not partially dual-write or silently reconcile contradictory canonical records.

## 4. Architecture and trust boundaries

### 4.1 Execution topology

```mermaid
flowchart TB
  A["Existing agent or human"] --> G["Scourge CLI and domain engine"]
  G --> B["Bones work graph"]
  G --> I["Investigation evidence and reasoning"]
  G --> X["Qualified execution adapter"]
  X --> H["Hallpass authority and accounting"]
  X --> P["Qualified confinement backend"]
  P --> T["HTTP or protocol instrument"]
  T --> I
  I --> V["Scourge proof evaluator"]
  V --> R["Verified finding and report"]
```

The arrows denote ownership-aware API calls, not one global transaction. The execution adapter may delegate capture to a native instrument that already records into Investigation. The qualified composition defines exactly one recorder and one accounting owner. Optional Vessel launches workers that use the same public Scourge interface; it does not bypass this path.

### 4.2 Separate proposing, acting, observing, and accepting

| Plane | Permitted responsibilities | Boundary |
|---|---|---|
| Agent reasoning | Propose hypotheses/plans, inspect permitted evidence, explain ambiguity, request a review. | Cannot manufacture authority, server state, oracle results, or a verified status. |
| Domain engine | Validate plans and transitions, compute freshness, prepare context, choose deterministic eligible actions. | Cannot infer arbitrary semantic truth from prose. |
| Execution | Run a pinned operation under the bound authority, limits, environment, and recording policy. | Cannot enlarge scope or rewrite the frozen plan. |
| Observation | Retain original outputs, identities, timing, completeness, and instrument facts. | Captured output remains untrusted input. |
| Verification | Evaluate a pinned proof profile over exact retained inputs, challenge confounders, record measured status. Independent replay uses the ordinary authorized Execution path. | Predicate evaluation cannot alter inputs, policy or evidence to make a proof pass. |
| Referee, in evaluations | Own hidden ground truth, target reset, grading state, and canaries. | Not writable or readable by the assessed agent. |

### 4.3 Threat and trust model

Assume target responses, imported reports, repository content under review, filenames, terminal output, and peer-agent messages can contain misleading claims or instructions. Trusted code handles them as data. Do not interpolate them into shell syntax, managed instructions, policy, or an executable tool definition.

The minimal product trusts the local operator and the installed binaries. Hashes provide identity/integrity relative to a retained reference; they do not authenticate a source or defeat a hostile administrator. A worker ID is attribution until bound to an actual launcher/credential boundary.

Three execution assurance modes must remain explicit:

- **Offline:** local inspection/import/oracle replay only; no target traffic.
- **Supervised:** an existing externally managed agent uses Scourge with authorized native instruments; Scourge records the known controls but does not claim to confine the entire host agent.
- **Enforced:** the qualified worker/instrument composition prevents alternate egress and unauthorized access to verifier/policy/evidence writes within its documented boundary.

Profiles declare the minimum acceptable mode. Enforced mode additionally requires a qualified filesystem, credential and verifier-write isolation boundary; Playpen's egress guard alone does not establish it. The inspected stack has not yet demonstrated this whole composition. A finding's evidence strength and an engagement's execution assurance are different dimensions: a real finding obtained in supervised mode may be valid, but its report must not claim enforced confinement or tamper-resistant receipts. `--force`, an agent prompt, or an omitted dependency must not upgrade assurance.

### 4.4 Keep the coordination layer small

The initial process model is local Linux, one Scourge workspace, multiple cooperating processes, and existing agent hosts. Scourge offers a short-lived CLI and a narrowly scoped execution supervisor when a native durable engine cannot own the job. Every asynchronous attempt requires one qualified owner; otherwise execution is synchronous. The supervisor runs known instruments and owns cancellation/reconciliation; it is not an autonomous model loop.

Use a versioned, transactional local coordination database with an outbox. Store operational decisions and cross-tool receipts there; use Investigation for original evidence and methodological records. Do not construct a new graph database, service mesh, distributed broker, or custom DSL before the complete first workflow passes its quality gates.

## 5. Domain model and identity

### 5.1 Security objects

Use immutable accepted revisions with explicit successors. Mutable drafts are allowed before freeze. Generic narrative/evidence objects live in Investigation; Scourge stores the security meaning and links needed to use them.

| Object | Required purpose and fields | Canonical home |
|---|---|---|
| Engagement | Objective, bounded targets, exclusions, authority binding, information regime, limits, effect policy, required assurance, stop conditions, reporting audience. | Scourge coordination state; immutable manifest also retained in Investigation. |
| TargetSnapshot | Deployment/build/config identity, origins/addresses, protocol endpoints, observation time, identity strength, environment class, change detector. | Investigation source/observation + typed Scourge manifest. |
| PrincipalBinding | Role, tenant, authenticated subject, credential reference, who-am-I evidence, permitted capabilities, session epoch, freshness. | Investigation evidence + Scourge binding; secrets held externally. |
| SecurityProperty | Subject/action/resource/boundary, required behavior, policy provenance, applicability, controls, allowed proof profiles. | Versioned Scourge manifest in Investigation. |
| Candidate | Bounded alleged property violation, observed versus proposed impact, source leads, prerequisites, rivals, generic Hypothesis/Conclusion refs. | Investigation claim + Scourge typed view. |
| Experiment | Question, mode, target/principal refs, recipe, controls, oracle, budget, reset/cleanup, expected observations, effect class. | Frozen artifact + generic InquiryPlan in Investigation. |
| Attempt | A single intended external execution, admission state, native job identity, recorder handle, accounting receipts, reconciliation state. | Scourge execution ledger; exact original results recorded in Investigation Run. |
| OracleDefinition | Version/digest, input schema, predicate semantics, scope, trusted implementation, calibration fixtures, accepted channels, limitations. | Installed trusted registry; pinned artifact/reference in Investigation. |
| OracleResult | Evaluated predicate, validity, reason, exact evidence selectors, run/environment/nonce binding, evaluator version and provenance. | Investigation original/derived artifacts and observations. |
| VerificationRecord | Claim basis, profile, discharged/missing obligations, review, fresh acquisitions, dependence, result, limits. | Immutable Investigation artifact + Assessment/Review/Conclusion references. |
| CoverageCell | Property × surface × principal/state class, applicability, planned method, attempts and interpretation, denominator revision. | Investigation generic coverage records; Scourge domain projection. |
| Technique | Versioned experiment pattern, preconditions, controls, counterexamples, evidence of utility, transfer limits. | Pinned Scourge pack; provenance references to Investigation cases. |
| RemediationCheck | Original claim/recipe, before/after target snapshots, paired runs, regression/variant obligations, bounded result. | Investigation comparison/run/assessment plus Scourge manifest. |
| WorkBinding | Bones item ID, Scourge subject ID, work purpose, returned mutation receipts. | Scourge references only; Bones owns work status. |

Security manifest artifacts have one current binding pointer in Scourge's store. They are not a second editable copy of generic Investigation fields. If the pointers are damaged, `doctor` reports repairable linkage loss; it must not guess which historical manifest was current.

### 5.2 Shared identity rules

- Generate stable opaque IDs; readable prefixes help distinguish objects. Do not derive identity from titles, target URLs, a process ID, or wall-clock time alone.
- References carry `{workspace_id, id, revision, basis_digest}` where applicable. External IDs include producer namespace and instance.
- SHA-256 binds immutable bytes; canonical structured manifests use the same documented canonical JSON rules as Investigation where possible. Reject duplicate keys and unsafe numeric ambiguity.
- Distinct executions always have distinct attempt/acquisition IDs even if all bytes match. A retry of a recording operation retains its original operation ID. Reimport is not reproduction.
- A recipe digest binds setup, parameters, role references, observation channels, controls, reset, cleanup, and oracle. Runtime bindings are captured separately and must satisfy its constraints.
- Secret values are never part of printable identifiers or reports. Bind opaque secret version/handle where available; do not publish unsalted hashes of low-entropy secrets as an identity shortcut.
- Tool identity includes executable/package version and executable or image digest when available; an unavailable commit remains unknown, not inferred from a friendly version string.

### 5.3 Target identity and reconstruction

Record `environment_kind: original | reconstructed | instrumented | reduced | simulated`. A manifest describes the relationship to the claimed real target and what differs. A simulation can validate a hypothesis about a mechanism; it cannot establish that the original deployment is vulnerable.

For a service, bind origin, intended logical service name, resolved allowed addresses, TLS/service identifiers where relevant, deployment marker if available, API/config revision, and observation window. For source, bind repository commit, exact blobs, build toolchain/configuration, dependency lock, sanitizer and architecture. A source checkout alone does not identify the remotely running version.

Use explicit identity strengths: `operator_asserted`, `remotely_observed`, `build_bound`, or an authenticated deployment attestation with a named trust policy. If strong identity is unavailable, use a bounded claim about the observed endpoint at the observed time. Do not make verified reporting impossible on normal black-box systems, and do not invent a build identity.

### 5.4 Information regime

Each engagement and evaluated task records what the investigator was given: service-only, authenticated roles, documentation, localized finding/CWE, full source, patch history, known reproducer, privileged fixture access, or other hints. Changes are events. A patch-informed reproduction is not scored as unassisted discovery.

Privileged setup information may be available to a trusted fixture service without becoming an attacker capability. Keep those roles distinct throughout the record and execution environment.

### 5.5 Security policy provenance

A property requires a source: explicit engagement expectation, product authorization model, versioned specification, owner-confirmed rule, or an attributed inference. For example, equal responses to two users do not establish an IDOR if the object is public by design. Where the rule is genuinely ambiguous, record a policy question and a conditional result; do not fabricate intent to make a detector positive.

Severity, business consequence, exploitability, evidence strength, and remediation priority are separate. A severity assessment may use a versioned scoring standard, but it cannot substitute for proof or expand observed impact.

## 6. Finding lifecycle and verification contracts

### 6.1 Lifecycle

```mermaid
stateDiagram-v2
  [*] --> Candidate
  Candidate --> EvidenceReady: evidence and obligations assembled
  EvidenceReady --> Verifying: qualified validation attempt
  Verifying --> Verified: selected profile satisfied
  Verifying --> Candidate: inconclusive or more evidence needed
  Verifying --> Refuted: valid evidence refutes bounded claim
  Verified --> NeedsReview: material basis changes
  NeedsReview --> Verifying: new evidence or review
  Candidate --> Withdrawn: attributed withdrawal
  Verified --> Superseded: narrower or corrected successor
```

The implementation stores lifecycle history and computes effective status. `NeedsReview` is a freshness overlay, not an erasure of historical verification. Findings can also be `disputed` when a material objection is unresolved. Rejected reproduction, refused execution, and withdrawn claim are different events.

### 6.2 Independent result dimensions

| Dimension | Values |
|---|---|
| Execution | `not_started`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, `refused`, `unknown`. |
| Evidence completeness | `complete`, `partial`, `missing`, `corrupt`, `unknown`, per channel. |
| Setup/measurement validity | `valid`, `invalid`, `unknown`, per observation or required condition. |
| Oracle | `true`, `false`, `inconclusive`, `error`, `unsupported`, `not_run`. |
| Claim interpretation | `supports`, `contradicts`, `non_diagnostic`, `inconclusive`, with attributed rationale. |
| Reproduction | `not_attempted`, `reproduced`, `intermittent`, `not_reproduced_under_conditions`, `blocked`, `invalid`. |
| Independence | Declared dimensions and shared dependencies; never a boolean inferred from actor count. |
| Freshness | `current_for_basis`, `needs_review`, `applicability_to_current_target_unknown`. |
| Cleanup | `complete`, `not_required`, `partial`, `failed`, `unknown`. |

A run may fail after producing one valid observation. Preserve that observation with its limits; do not pretend all outputs failed or that the complete intended experiment succeeded. A pass/refusal in an authorization or confinement report is not a security verdict about the target.

### 6.3 Proof profiles, not a universal confidence ladder

Every accepted claim names a versioned profile and the exact obligations it satisfied. Initial profiles:

| Profile | Required evidence | Display |
|---|---|---|
| `runtime-controlled.v1` | Property and role bindings, valid setup, causal observation, class-appropriate controls, fresh acquisition/replay, qualified oracle, challenge review, no unresolved required obligations. | `Verified by controlled execution` with exact scope. |
| `runtime-intermittent.v1` | Same semantic evidence, observed intermittent conditions, predefined repetitions/stop rules, successful and unsuccessful trials, valid noise/sequential controls, observed rate and uncertainty; mechanism may remain a hypothesis. | `Verified intermittent behavior`; never imply reliable exploitation. |
| `source-validated.v1` | Exact source/configuration, independently checked control/reachability/guard reasoning, bounded consequence, counterarguments, explicit deployment applicability. | `Validated from source`; never `reproduced`. |
| `external-evidence-reviewed.v1` | Preserved external originals/receipts, qualified producer and trust policy, independent evidence review, compatible obligations. | `Validated from external evidence`; reproduction status separate. |

These are not interchangeable levels. A missing live observer might allow a source-based conclusion if the source independently establishes it; it does not magically satisfy runtime obligations. A merely plausible path stays a candidate. Source judgment is attributed review, not an automatic theorem proven by filling in fields.

Only the first two profiles count as dynamically verified findings in that benchmark track. Report source-only and externally reviewed results separately so changing the mix cannot inflate the runtime verification metric.

### 6.4 Proof obligations and profile applicability

The list below defines the obligation vocabulary; it is not a requirement to apply runtime experiments to every kind of claim. The profile fixes applicability. An agent cannot turn a missing required obligation into `not_applicable` with free text.

| Obligation | Runtime controlled/intermittent | Source validated | External evidence reviewed |
|---|---|---|---|
| Bounded property, target applicability, initial capabilities | Required | Required from exact source/config and reachable context | Required from retained provenance; unknowns limit the accepted claim |
| Pre-effect plan and actual execution binding | Required for confirmation; new run if discovery was retrospective | Not applicable; immutable analysis/review basis required | Preserve actual chronology strength; cannot assert unobserved prospective binding |
| Runtime observation and qualified oracle | Required | Not applicable; exact source/guard/control reasoning required | Establish what the producer actually measured and the admissible trust basis |
| Causal controls | Class-specific runtime controls required | Counterexamples, guards and alternate reachable paths reviewed | Review available controls; missing runtime obligations forbid a runtime-profile badge |
| Fresh runtime reproduction | Profile-defined protocol required | Not applicable; no reproduction claim | Separately reported; imported reruns must be distinct authenticated acquisitions |
| Independent semantic challenge and current read-set | Required | Required | Required |
| Verification custody | Isolated trusted executor or authenticated qualified external verifier | Attributed reviewer/source integrity; disclose shared custody | Declared producer custody and trust policy; no invented authentication |

Detailed obligation vocabulary:

1. **Claim:** precise protected property, violated boundary, affected subject/action/resource, and bounded observed consequence.
2. **Target:** identified tested instance and configuration, with identity strength and applicability limits.
3. **Capability:** evidence that the attacker had only the claimed initial powers; principal/tenant/session bindings verified where relevant.
4. **Preconditions:** required state exists; authentication, instrument, fixture, and observation channel actually work.
5. **Chronology:** frozen confirmatory plan bound before admission; otherwise mark exploratory/retrospective and perform a fresh confirmatory attempt.
6. **Observation:** original retained evidence with exact selectors and completeness; an explanation alone cannot satisfy this obligation.
7. **Causality:** class-appropriate control or counterfactual that rules out material alternatives; reasons for inapplicable controls are checked by the profile, not a generic escape hatch.
8. **Oracle:** allowed version, correct input provenance, valid execution, calibrated positive/negative fixtures, and the claimed predicate rather than a surrogate signal.
9. **Reproduction:** a distinct acquisition under known state, or a profile-specific intermittent protocol; record all attempts.
10. **Challenge:** reviewer examines the strongest alternative explanation, claim/impact scope, dependencies and original evidence.
11. **Freshness:** full substantive read-set current at promotion, including relevant evidence validity and unresolved objections.
12. **Authority/cleanup disclosure:** execution assurance, accounting and cleanup outcomes recorded; unresolved operational obligations remain prominent and can block engagement closure independently of finding truth.

The policy engine checks structure, bindings, trusted receipts and predicates. Semantic judgment remains necessary for rules and consequences that cannot be mechanically established. Expose which obligations are machine-checked and which are attributed expert judgments.

### 6.5 Constrained verification boundary

Discovery may run with rich source access and a disposable lab. Confirmation must not inherit arbitrary mutations or privileged access from that environment.

The submission boundary is an immutable object containing claim, required roles, recipe, oracle/profile references and evidence pointers. For the controlled runtime profiles, a qualified verifier prepares a clean target instance or confirms the existing instance's state, obtains the intended roles from the fixture/credential service, and executes only the submitted permitted actions. Its custody boundary prevents the discoverer from editing the verifier binary, oracle, target database/build outside claimed attacker actions, hidden fixture state, trusted receipt store, or reference tests during this run.

Track **verification custody** separately from host execution assurance: `isolated_trusted`, `authenticated_external`, or `operator_asserted_shared`. A supervised host agent can submit to an isolated verifier and obtain a strong proof. A shared writable UID/environment cannot claim that isolation; its results may support an explicitly external-evidence-reviewed/source judgment, but do not meet the controlled runtime profile until independently confirmed under qualified custody.

For black-box production assessments, clean reset and server instrumentation may be unavailable. The profile must specify acceptable observational controls, state observations and limitations, or leave the particular verification blocked. Never manufacture a clone and silently substitute it for the target.

The verification receipt binds at least:

```text
verification_id, attempt_id, attempt_nonce,
engagement_id, claim_basis_digest, profile_id/version/digest,
experiment_digest, bound_execution_manifest_digest, step_binding_receipts,
oracle_id/version/digest,
target_snapshot_ref, environment_instance_id, environment_kind,
principal_bindings, setup_receipts, stimulus_refs,
observation_refs/selectors, observation_window, controls,
validity, predicate_result, reason_codes, evaluator_identity,
execution_assurance, verification_custody, evidence_completeness, limitations
```

A local trusted supervisor can authenticate receipt provenance through an isolated process channel and protected storage. An external verifier needs an authenticated channel or signature plus an explicit trust policy. A self-asserted `producer: trusted-verifier` field or hash is not authentication. Untrusted user-supplied result JSON is retained as an assertion, never a trusted oracle receipt.

### 6.6 Independent challenge without a ceremonial council

Default to one investigator and one distinct verification pass for a runtime finding. The pass can be performed by a fresh agent/human with a qualified executor; a permanent multi-agent fleet is unnecessary.

A verifier first receives the bounded proposition, threat model, target/role binding, reproduction specification, and evidence manifest. Delay the discoverer's detailed narrative until after its initial assessment when practical; do not call this blind if the original conclusion or recipe was provided. Then reconcile differences with access to all relevant evidence.

Record new target state/reset, new credential instances, new acquisitions, reused instruments/oracles, separate implementation of the test, model/harness identity, and what evidence was seen. Two model vendors can share an invalid oracle. Two executions can share a dirty fixture. These dependencies remain visible.

If a second agent adds cost without improving the matched-budget evaluation, keep the independent execution and semantic review contract while changing who performs it. The goal is a different opportunity to expose an error, not more conversation.

### 6.7 Promotion and invalidation

`finding.verify` evaluates obligations and records a verification result; it is not a writable `verified: true` field. It cannot silently execute a new target test. If additional execution is required, it returns a prepared verification plan and a specific execution action.

Final promotion must atomically bind the relevant Investigation claim/evidence/review revisions through its public transaction and CAS contract. This atomicity covers Investigation's store only. Bind the immutable Scourge domain manifests and a material Scourge basis generation into that transaction. After its receipt is reconciled, compare that generation and current profile/oracle qualification before publishing a current verified view. A concurrent change preserves an accepted historical record with `needs_review`; it does not create a current verified cache entry.

A generic Investigation `validated` state is never sufficient for Scourge verification. Queries, exports and promotion require a matching qualified VerificationRecord, the profile's required verifier provenance/custody, exact evidence/claim basis, and current applicable qualification. Direct `inv` writes, imported extensions, or self-asserted producer identities cannot bypass this gate; they remain attributed generic conclusions until the Scourge requirements are met.

Substantive changes to claim, property, required policy, oracle validity, target binding, principal binding, or supporting evidence invalidate the affected proof. Cosmetic changes and lifecycle bookkeeping do not invalidate their own verification. Use Investigation's `basis_digest` and dependency semantics; Scourge adds only domain-specific dependencies.

An engagement revocation stops new actions; it does not retroactively make a correctly observed historical vulnerability false. A new deployment likewise leaves the old finding historically valid while its applicability to the new deployment is unestablished. Reports show both distinctions. An oracle bug that undermines the historical evidence does require review of affected findings.

## 7. Experiment design and oracle profiles

### 7.1 Experiment structure

Use a small typed recipe model, not a general programming language. Steps are native adapter operations with data bindings and bounded predicates. Complex tool-specific procedures stay in their instrument; Scourge references their immutable scenario artifacts.

An experiment contains:

- Objective/question, candidate/property refs, exploration versus confirmation, and predicted discriminatory observations.
- Target/principal/session refs and required state; an information-regime declaration.
- Setup and instrument checks; stimulus; observation; controls; reset and cleanup.
- Dependency bindings between steps; typed outputs consumed by later inputs.
- Pinned oracle/profile, observable channels, identity/nonce correlation and maximum observation delay.
- Maximum requests/messages/bytes/duration/concurrency/retries and expected resource charges.
- Effect class, allowed resources, halt conditions, and whether an operation is naturally repeatable, target-idempotent, or potentially irreversible.
- Evidence requirements and completeness policy, result interpretation rules and limitations.

Freeze produces an immutable recipe digest. Editing any substantive field produces a new experiment revision. Runtime parameters may be bound after freeze only through declared typed slots with constraints. Before launch, create an immutable `bound_execution_manifest` containing recipe digest, resolved slots, secret handle/version identities, native input artifacts, target/role/session bindings, tool/image identity, oracle/profile, limits and effects. Its digest appears in admission, accounting correlation, native execution, evidence and verification receipts; secret values do not appear in printable metadata.

For stateful outputs unavailable before the first step, the root manifest declares the typed dependency and constraints. Each step's exact resolved binding is recorded before its effect and chained to prior step receipts. New destinations or capabilities require fresh admission. Verification binds the root plus all step-binding receipts, not merely the original unbound template. Do not accept arbitrary shell or code strings in a purportedly declarative pack.

### 7.2 Controls must have a purpose

Distinguish a healthy/authorized-path control, a negative stimulus, a role/resource counterfactual, a patched counterfactual, an instrument positive control, and a reset check. They address different failure modes. One `control_passed: true` checkbox is inadequate.

Every control declares the alternative explanation it addresses, expected observation, allowable differences, order/reset requirements, and what a failure invalidates. Controls may be paired, interleaved or randomized when order/time matters. Record any state mutation that makes a later comparison non-equivalent.

A negative observation can support a bounded claim only if the signal could have been observed: the credential was valid, the endpoint existed, the observer was functioning, the observation window was sufficient, and the test actually exercised the relevant path. No finding and no valid test are different outcomes.

### 7.3 Initial oracle catalog

| Profile family | Required discriminating observation | Mandatory traps/controls |
|---|---|---|
| Object/tenant authorization | Authenticated B reads protected A-owned canary data or causes a forbidden state change; ownership/privacy policy and identities established. | Same-user sessions, public object, 200 login page, 403 containing protected data, stale cache, expired role, invalid object. |
| Function/role authorization | Low-role action produces the protected effect; authorized high-role control succeeds. | Status-only equality, intentionally public operation, role change not applied, failed legitimate operation. |
| Session/revocation | Old capability works beyond a specified revocation boundary while current controls show intended state and identity. | Propagation grace, wrong token/session, clock uncertainty, already-invalid credential, unrelated cache. |
| Stateful business invariant | A forbidden state transition or duplicate protected effect is observed with causal operation lineage. | Failed setup, eventual consistency, client retry, hidden mutation from another worker, dirty fixture. |
| Input injection | Input-specific bounded semantic effect or trusted instrumented failure tied to the tested boundary. | Echoed marker, generic error page, harness invocation of callback, unsafe condition without attacker reachability. |
| Out-of-band effect | Fresh unpredictable attempt-bound token observed on a controlled channel in the correct window with stimulus attribution. | Old callback, DNS prefetch, unrelated scanner callback, worker directly contacting observer, shared tokens. |
| Concurrency/race | Forbidden durable state under a specified concurrent history; sequential control remains valid. | Client-generated duplicate, timing alone, failed reset, operations outside overlap window, correlated infrastructure outage. |
| Parser/memory safety | Exact input triggers the relevant instrumented failure on identified build/config; cause preserved under reduction. | Wrong sanitizer/architecture, unsupported API contract, harness bug, resource exhaustion unrelated to claimed defect. |
| SIP/signaling authorization | Principal and dialog/transaction bindings show unauthorized transition or use of a protected signaling capability. | Transport success mistaken for protocol success, retransmissions, dialog mismatch, endpoint-role confusion. |
| Media authorization | Controlled protected media canary is accessible/usable through a prohibited principal/path, with channel and key/codec context. | Packets without usable media, unrelated SSRC/stream, authorized relay, missing decode/key support. |
| Browser behavior | Attacker-controlled content causes the claimed effect in a distinct victim context under constrained real-browser actions. | Reflection, agent `evaluate`/DOM insertion, attacker browser only, privileged victim credential leak, forged console output. |

Not all rows ship in M2. The shipped capability registry must state which profiles have a qualified instrument and calibration corpus. Browser-dependent claims require a separate trusted browser adapter; HTTP replay alone cannot satisfy them. A media profile lacking the necessary decoder/observer remains unavailable, even if signaling tests work.

### 7.4 Oracle implementation requirements

An oracle consumes immutable typed observations and produces `true|false|inconclusive|error|unsupported`, with reason codes and evidence selectors. Predicate truth and experiment validity remain separate. Prefer deterministic predicates for properties that can be measured; a probabilistic test includes its protocol, assumptions, samples and uncertainty.

Initial implementations are reviewed Rust code or a qualified instrument's versioned checker. Future external checker programs require a pinned digest, explicit execution policy, bounded resources, a read-only evidence input, no target/network access unless explicitly part of the observer, and authenticated output provenance. Do not execute a checker merely because a report supplied its path.

An oracle's qualification set includes true positives, benign controls, patched cases, broken setup, manipulated marker outputs, invalid identity, missing bytes, stale attempt data, direct harness spoofing, and relevant timing noise. Test the measurement boundary and the predicate. A parser unit test alone is not oracle validation.

An agent-proposed oracle enters `experimental`. It may help exploration, but automatic runtime promotion requires a reviewed/qualified version. Source review may still record an attributed judgment with an experimental measurement and an explicit limit. No self-approval path.

### 7.5 Stateful, differential and metamorphic tests

Reuse schema- and instrument-supported operations. Bind IDs, tokens and resources generated by earlier steps; preserve the complete causal chain for replay. At minimum support create/use/delete and authenticate/act/revoke/retry patterns with owned fixtures. RESTler and Schemathesis are relevant design references [R8], [R9], [R10], not dependencies Scourge must reimplement.

Represent useful relations explicitly: changing principal while holding a private resource constant should change authorization; changing irrelevant encoding should preserve semantics; revoking a capability should remove the specified access; a fixed build should remove the forbidden effect while preserving a legitimate path.

Normalization is an identified transform with version and original-byte lineage. It may remove a timestamp from a response comparison, but must not erase identity, authorization headers, secret exposure or other fields relevant to the property. Different responses are evidence to interpret, not automatically different security outcomes.

### 7.6 Attack chains

Every chain edge declares consumed and produced capabilities, principal, tenant, resource, target instance, state epoch, validity interval and necessary effects. Candidate chains may be proposed from compatible facts; verified chains require a connected end-to-end run with actual bindings across every edge.

Individually verified steps do not prove a chain when they use incompatible accounts, builds, resources, clocks or sessions. If a final step is unavailable or outside the engagement, report the verified prefix and a conditional consequence. Do not inflate impact from an unexecuted hypothetical continuation.

### 7.7 Minimization, flaky behavior, and bounded work

Minimization is a new bounded experiment that preserves the original evidence. Each reduction must retain the same relevant property violation/failure identity. A smaller script that causes an unrelated error is not an equivalent reproducer. Keep original and reduced cases with lineage [R11], [R12].

For intermittent behavior, specify trials, interleaving, reset conditions and a stopping rule before confirmation. Preserve all trials, including timeouts and invalid setup. Report observed recurrence and uncertainty; do not keep rerunning until one pass appears and discard the denominator. Do not reject a real intermittent flaw solely because every replay is not positive [R15].

For timing-based observations, collect a healthy null distribution, pair/interleave treatment and control, record timing source, and distinguish target latency from runner scheduling or network outage. The plan may conclude the available environment is too noisy for that proof profile.

## 8. Discovery, coverage, and next-action selection

### 8.1 Intake and discovery lanes

Accept observations from existing instrument runs, source review, manual notes, scanner imports, known reports, API schemas and engagement documentation. Preserve original format and producer identity before normalization. Imports create leads and evidence, never verified findings.

Run three bounded lanes where relevant:

- **Surface and property discovery:** enumerate known routes/services, roles, resources, trust boundaries, workflow states, and likely high-consequence properties.
- **Candidate development:** reproduce promising signals, identify prerequisites, connect source paths to runtime observations, and design discriminating experiments.
- **Verification and challenge:** resolve controls, replay, investigate alternatives, validate scope/impact, and prepare reports.

A single investigator can cover all three sequentially. Parallel workers are useful when work is independent and do not share a mutable fixture. Do not spawn one agent per vulnerability label by default.

### 8.2 Coverage model

Use an explicit bounded matrix, not an enormous Cartesian product. Cells describe a meaningful combination of surface/resource, property, principal class, lifecycle state and deployed configuration. Discovery may add cells, with a denominator revision and reason.

Cell states are `unexamined`, `not_applicable_with_reason`, `planned`, `blocked`, `attempted_invalid`, `tested_no_violation_under_conditions`, `candidate`, `verified_violation`, or `deferred`. Each tested cell references actual attempts and their validity. A URL visited, payload sent, scanner completed, or work item closed cannot alone mark a property tested.

Show:

- Known applicable cells and how they were selected.
- Validly tested, invalid, blocked, deferred and still unexamined cells.
- Role/state/deployment coverage and observation-channel gaps.
- Surfaces not inventoried and any unknown denominator.
- Time and target snapshot to which the matrix applies.

Versioned OWASP ASVS/WSTG identifiers can label properties and guide coverage [R17]. They do not certify the target or prove that the surface inventory is complete. Code/route coverage and security-property coverage stay separate.

### 8.3 `next` is useful, transparent, and read-only

`scourge next` joins current Scourge obligations, Investigation's epistemic frontier and Bones' available work. It returns at most three suggested actions plus blocked counts and a complete `frontier` route. It does not claim work, call a model, spend a budget, send a packet, or launch a worker.

Eligibility comes first and is action-specific. Effectful actions require an active authorized engagement, qualified capability, valid target/identity binding, prerequisites, no conflicting in-flight action and required resources. Offline import, local analysis, evidence review, reporting and repair remain eligible when live authority is absent or expired, subject to their own local access requirements. Availability checks must distinguish cached observations from actual admission; recommendations do not reserve permission.

Rank eligible actions lexicographically by explainable factors:

1. Resolve uncertain external effects, broken capture, or operational cleanup before starting conflicting new actions.
2. Preserve explicitly identified volatile evidence.
3. Repair invalid controls or material contradictions affecting a consequential claim.
4. Complete a short, high-value verification discriminator for a credible candidate.
5. Address a high-consequence uncovered property/boundary.
6. Try a genuinely different method when repeated attempts have not changed knowledge.
7. Prefer lower bounded cost/effects where expected decision value is comparable.
8. Stable ID tie-break for reproducibility.

Inputs such as consequence, plausible diagnostic value and cost carry provenance and may be unknown. No invented probability of compromise or information-gain decimal. Optional learned scheduling is deferred until a measured baseline exists.

### 8.4 Reserve effort for both discovery and proof

Engagement configuration allocates resources to discovery, confirmation/review and cleanup. The first default is a **starting policy**, not a universal optimum: reserve roughly one-third of the available action/time budget for verification and cleanup; tune from pilot data. A run may spend less than the reserve. If important verification cannot fit, stop opening new candidate work and return the exact tradeoff.

Do not let repeated easy findings exhaust the budget while major boundaries remain untouched. Conversely, do not spend the whole engagement on a heroic low-yield lead. Expose consumed budget, queued proof obligations, coverage gaps and deferral rationale.

### 8.5 Stalls, transfer and escalation

Progress is a new valid observation, resolved prerequisite, eliminated material alternative, improved reproducibility, or qualified finding—not a new message or larger transcript.

After the configured number of non-informative attempts, show the repeated blocker and suggest a different observation channel, source inspection, narrower claim, new control, different method, or explicit stop. Do not require an arbitrary fifteen-minute timer across all domains.

Transfer a successful technique only when its applicability predicates hold. New credentials, a source fact, or a now-qualified instrument can reopen previously blocked work, with the causal link recorded. Shared source or technique is not independent evidence for the new target.

Model/harness escalation is optional and evaluation-driven. Escalation preserves the same immutable objective, allowed capabilities, budget and handoff; it never implicitly expands target scope. Exhausting one provider budget is not permission to consume unrelated credentials or accounts.

### 8.6 Work and worker coordination

Scourge creates or links Bones work for investigation, verification, cleanup and follow-up. Inspect each result in batch mutations. A work item may close as inconclusive or blocked with a useful handoff; a closed item does not promote its finding.

Use a narrow local execution-admission transaction for attempt uniqueness and conflict groups. This is necessary because the inspected Bones work transition is not a demonstrated exclusive lease/fence. Do not reimplement general scheduling. If Bones gains a qualified claim/CAS primitive, adapt it without changing security semantics.

Conflict groups include target instance, fixture reset domain, principal/session, mutable resource and observation channel. Independent reads may run in parallel; reset, session rotation or shared resource mutation excludes incompatible work. Tests deliberately exercising a race declare their internal concurrency as one controlled experiment.

## 9. Authorized execution and resource control

### 9.1 Engagement manifest

An engagement binds objective, target/service names and endpoints, excluded assets, authorized roles, permitted effect classes, approved time window, Hallpass identity/digest, limits, data policy, required confinement, cleanup budget, emergency stop, and reporting audience. The operator supplies real authority; Scourge validates its recorded representation and supported enforcement.

Effect classes are descriptive and policy-bound: passive local analysis; target observation; fixture mutation; stateful test; bounded load/concurrency; callback observation; custom executable. Method names do not determine risk. A GET can mutate state, and a browser navigation can execute code; adapters must declare actual possible effects.

Newly discovered destinations, role credentials, callback services, redirect origins, resolved IPs, media endpoints and proxy-mediated paths are evaluated against the bound policy before use. A successful discovery does not authorize following it. Authorized next steps continue without redundant human confirmation.

### 9.2 Admission sequence

Before every new effectful unit or bounded native batch:

1. Resolve exact engagement, experiment revision, target/principal bindings and attempt identity.
2. Check current material revisions, policy, deadlines, revocation and adapter qualification.
3. Prepare durable Investigation capture or a native qualified recording handle and retain its receipt. An optional early conflict reservation grants no execution authority. If required recording cannot begin, do not start the unit.
4. Resolve the single budget owner and its exact charge protocol. Check limits without treating preview as a committed debit.
5. Bind confinement plan, tool/image identity, allowed addresses/names, credential handles/versions, observer endpoints and immutable input artifacts into the final bound execution manifest. Record its digest before admission; any material change requires a new binding.
6. Obtain execution admission and conflicting-resource exclusion in a short transaction, rechecking material state; record the admission generation and that exact bound manifest digest. Revalidate it at launch rather than filling in material fields after admission.
7. Commit accounting at the instrument's defined boundary, retain its receipt, and launch with a durable attempt/plan reference.
8. Observe execution, capture, cancellation and cleanup; finalize or reconcile honestly.

No cross-tool atomicity is claimed. §13 defines the uncertain windows and recovery obligations. The sole qualified launcher verifies and consumes the current admission generation at the actual launch boundary under exclusive launch ownership. A database counter alone cannot prevent a paused stale process from later spawning. Native tools do not understand this generation: it is local broker fencing, not remote effect fencing. Unresolved launch acknowledgment blocks conflicting takeover.

### 9.3 Exactly one accounting owner

Teapot has inspected native Hallpass integration. A native Sippycup-to-Hallpass debit path was not established; its existing profile/campaign limits are a separate mechanism. Adapter metadata declares `accounting_owner: native|scourge` only when qualified, otherwise `unavailable|unqualified`, and describes the charged units. Never pre-debit in Scourge and debit the same units again inside a native tool. A Scourge-owned conservative Sippycup batch debit is new integration work, not an existing guarantee.

Hallpass `caller_ref` is correlation, not idempotency. Preserve pass identity, exact digest, ledger sequence, caller reference, named charges and outcome. A successful preview is not an authorization receipt. A debit can commit before a crash or before any send; no automatic refund or blind repeat is allowed.

Requested maxima, admitted units, actual observed sends/effects, and charged units are different counters. Expose discrepancies and unknowns. An adapter with hidden retries or unknown maximum fanout cannot claim exact request budgeting. Either qualify a bounded native batch with a declared conservative ceiling or refuse it under an exact-count policy.

Use a monotonic clock for local elapsed budgets and record its relation to wall-clock authorization checks. One initial authorization check does not authorize a background process indefinitely. Multi-host copied-pass accounting is not supported initially.

### 9.4 Confinement composition

For the initial HTTP path, qualify a concrete Linux topology: test target and any fixture administration live outside the worker; the client instrument has only its permitted egress and session capabilities; the worker cannot reach container/admin sockets, oracle control, hidden data, or the trusted recorder's mutation surface. A private local lab can use dedicated non-loopback endpoints when the actual Playpen/backend contract requires them.

Require explicit fail-closed enforcement flags when the engagement requires enforcement. Teapot's automatic fallback behavior must not silently choose an unenforced run. A suggested `--no-enforce` repair is a policy change, not an automatic recovery action.

For Sippycup, qualify the **whole** native container/capture boundary. Its raw-packet capture and container setup requirements cannot be assumed compatible with a Playpen-wrapped launcher. Choose and test one supported topology: a trusted pre-created protocol lab with brokered execution and explicit egress rules, or a qualified native runner whose boundary covers the child containers and media traffic. Do not route around restrictions with a broader host socket or privileged daemon exposed to the agent.

Filesystem/credential isolation is an additional requirement for untrusted executable submissions and trusted verification custody. Reuse a qualified container/VM/OS mechanism; do not expand Playpen's advertised guarantees by prose. Until the topology passes its qualification suite, report `enforcement_unqualified` and allow only modes/policies that explicitly permit the observed guarantees.

### 9.5 Sessions and secrets

Use instrument-native session/credential handling. Scourge resolves opaque references at execution time; it does not keep another cookie database. Confirm subject/tenant/role with a trusted fixture or appropriate live identity observation, and record session epoch/rotation. A label such as `bob` is not identity evidence.

Credentials for attacker, victim, privileged setup and verifier are separate capabilities. Only the appropriate process receives each. No secrets in command-line arguments, default summaries, task titles, error messages or telemetry. Preserve raw credential-bearing evidence only under the declared retention/access policy; reports use derived redacted artifacts with lineage.

Do not silently refresh sessions during a paired experiment if that changes the tested condition. Record the refresh and either satisfy the declared binding or invalidate/restart the comparison with a new attempt.

### 9.6 Cancellation and cleanup

Cancel means request cancellation, observe acknowledgment and termination, then reconcile residual effects. Killing a CLI or losing a Vessel session does not establish that its engine/background job stopped. Track native job/engine identity and the qualified process group/cgroup or equivalent boundary.

Support engagement stop that blocks new admissions immediately in the local controller, requests existing cancellations, and reports the observed stop/remaining uncertainty. Respect the actual backend's revocation polling and grace periods; do not promise instantaneous traffic cessation.

Cleanup is an explicit recipe over known owned resources, with time headroom, resource counters and idempotency semantics reserved before starting. Local cancellation/containment continues after expiration or revocation; target-restoring traffic requires still-valid cleanup authority or a new operator authorization. A reserve does not override revocation. An engagement can close only when residual effects/cleanup are resolved or explicitly accepted by the operator. A verified finding can coexist with failed cleanup; the operational problem remains visible.

### 9.7 Custom execution escape hatch

Do not make “arbitrary shell” the universal adapter. A custom experiment is an immutable script/container artifact with declared inputs, expected observations, effects, limits and a separately qualified sandbox/custody profile. It is admitted through the same mechanism and returns the same neutral evidence contract.

Initially support custom execution only in disposable qualified labs. It may produce exploratory evidence before its oracle is qualified. Agents can use existing tools directly outside Scourge, but imported results retain their actual provenance and assurance; the framework does not retroactively claim it enforced them.

## 10. Agent experience and CLI

### 10.1 First thirty seconds

Bare `scourge`, `scourge --help`, and `scourge onboard --format json` are read-only and useful both inside and outside a workspace. They explain the job, the current state, and the next valid action. No automatic installation, target probing, model call, browser launch, or mutation.

The entry screen should fit roughly one terminal screen:

```text
scourge — investigate security properties and verify findings.

Orient:   scourge onboard
Resume:   scourge brief
Choose:   scourge next
Inspect:  scourge show ID
Learn:    scourge schema OPERATION

New workspace: scourge init PATH --engagement FILE
Local tutorial: scourge demo PATH --scenario authz

Evidence can be recorded immediately. Verification needs the property's
controls and a valid observation. Target actions require an active engagement.
```

Outside a workspace, return the exact minimal engagement schema and a local demo route. Inside an empty workspace, offer the actual missing prerequisite. Inside an active one, show current targets, assurance, unresolved effects, candidate/verified counts, caveats and one next action. Never send a novice to a payload that requires unknown IDs without providing the creation route.

### 10.2 Core user loop

The common agent path is:

1. `onboard` or `brief` to establish state and limits.
2. `next` to choose a useful action and inspect why.
3. `prepare` to materialize a valid plan/draft from known bindings, exposing unresolved fields.
4. `execute` for an explicitly frozen, admitted experiment.
5. `show`/`evidence` for results and exact source.
6. `finding verify` to evaluate recorded proof obligations, or obtain the next needed verification experiment.
7. `report` or `handoff` when the objective or stop rule is met.

Convenience commands compile into the same typed operation catalog. A generic mutation API remains available for integrations, but it is not the only discoverability path. `next` and `prepare` must not launch effects; `execute` must say exactly what it can do.

### 10.3 Command surface

| Command | Contract |
|---|---|
| `init PATH --engagement FILE` | Validate and create local configuration, explicit component bindings and owned instructions. No target effects. |
| `demo PATH --scenario NAME` | Create a known local tutorial fixture and executable walkthrough; fixture launch is a separate explicit step unless the command documents and receives that action. |
| `onboard`, `brief`, `next`, `frontier` | State-aware, bounded, read-only orientation and recommendations. |
| `show ID --depth title|summary|full`, `explain ID` | Current effective state, evidence basis, blockers, rationale and drill-down. |
| `search QUERY` | Selected engagement by default; source pointers, freshness and acquisition identity. |
| `schema OPERATION`, `guide TOPIC` | Purpose, when to use, effects, input/output schemas, valid example, errors and repair. |
| `capabilities`, `doctor` | Installed/qualified/unsupported surfaces, versions and local diagnostics; live checks require an explicit prepared experiment. |
| `prepare --action ID` | Create a draft/frozen local plan only when inputs are sufficient; returns a receipt and the next command. No effectful execution. |
| `experiment check ID`, `experiment freeze ID` | Validate obligations and bindings; freeze an immutable recipe. |
| `execute EXPERIMENT_ID --request-id KEY` | Admit one bounded attempt. Asynchronous mode returns its ID only with a qualified native job owner/supervisor; otherwise run synchronously. |
| `run show|events|cancel|reconcile ID` | Inspect lifecycle; request/observe cancel; reconcile without automatic rerun. |
| `finding verify ID`, `finding challenge ID` | Evaluate the current proof or record a challenge; no hidden target execution. |
| `coverage`, `gaps` | Bounded denominator, tested validity and unmet obligations. |
| `retest prepare FINDING_ID --target ID` | Prepare paired fix verification with required controls; execution remains explicit. |
| `import --input FILE`, `record --input FILE` | Preserve external evidence or commit typed security metadata through public contracts. |
| `report --kind review|reproduction|summary`, `bundle check PATH` | Snapshot-bound export and offline verification. Executing a reproducer requires new authority. |
| `handoff`, `retrospective` | Produce bounded continuation context and record process lessons. |
| `integration show|apply`, `sync --check|--apply` | Inspect or apply owned bootstrap/method changes with drift protection. |
| `worker prepare|start|status|stop` | Optional qualified Vessel integration; unavailable unless implemented. |
| `mcp` | Optional stdio transport generated from the same catalog. |

These are the intended released surface, not a requirement to ship placeholder commands in M1. Help advertises only implemented capability. Disabled features return a useful missing-capability explanation through discovery rather than a fake success stub.

### 10.4 State-aware action responses

Every recommendation returns `action_id`, `subject_refs`, `basis_digest`, purpose, rank reasons, prerequisites, effects, capability, budget estimate with provenance, and a concrete next `argv` array. It includes `valid_until_conditions`, not just a time-to-live. Admission always rechecks current state.

If known inputs permit execution, `prepare` writes the actual schema-valid plan and a durable request key to an owned workspace path and returns them for inspection, including `execute ... --request-id <returned-key>`. A lost response can be recovered with `run show --request-id KEY` before any attempt ID is known. A deliberate fresh reproduction obtains a new key. If inputs are missing, return a clearly marked incomplete form and explicit lookup/creation commands. Never mix fabricated IDs or `verified: true` placeholders into an allegedly runnable example.

`next --explain ACTION_ID` shows the deterministic rule and selected inputs. Recommendations derived from untrusted source text may quote that text only as evidence; the trusted operation and its arguments come from the command registry and validated bindings.

### 10.5 Bounded context that does not hide caveats

Use Investigation's title → synopsis → full record → exact evidence layers. Scourge's `brief` adds only engagement limits, domain obligations, native execution state and security coverage.

Default standard brief budget: 16 KiB serialized UTF-8, configurable. Include objective/snapshot; effective findings; strongest contradiction; unknown effects/cleanup; active authority/assurance; remaining budgets; three next actions; explicit omissions and deeper routes. If mandatory caveats do not fit, shorten claims or return the minimum required budget. Never remove the caveat while retaining a confident conclusion.

`brief --since RECEIPT` returns meaningful changes and newly stale results. Lists use snapshot-bound pagination. JSON output is valid even when truncated by a deliberate item budget; raw byte truncation is not allowed. Binary captures remain files. Raw source is opt-in, bounded, inert and marked untrusted.

### 10.6 Managed bootstrap

Borrow Edict's embedded docs and owned-block style. `init` and explicit integration apply may create a compact managed block and a local guide directory. Preserve unrelated `AGENTS.md`, skills, harness settings and user edits. Track generated-file digests; `sync --check` reports drift, and apply updates only owned unchanged regions or presents an exact conflict.

Never auto-accept a host's trust/permission dialog, silently disable harness restrictions, or install global hooks. Existing engagement authority permits normal work; it is not authorization to change the user's harness security configuration.

The binary works without any installed skill or harness integration. The managed block is an accelerator, not a hidden prerequisite for cold-start success. Tutorials, CLI schemas and errors must teach the same loop.

### 10.7 Repairable failures

A failure answers: what failed, whether any metadata committed, whether any external effect may have occurred, what evidence remains, and the next valid repair.

Examples:

- Unknown session: list case-local available bindings and the identity-check recipe; do not guess another identity.
- Expired pass: preserve the prepared plan and give the exact missing authority; no policy-bypass suggestion.
- Stale review: show the changed basis and required recheck, not “try force.”
- Lost execution response: return the attempt ID and reconciliation command; do not suggest `execute` again.
- Missing observer: preserve a signal as a candidate, explain why it is insufficient, and identify the missing capability.
- Evidence committed but report render failed: return the durable receipt and a local rerender action.

Error repair suggestions are structured and effect-labeled. They never convert a refused scope or confinement requirement into a weaker automatic retry.

### 10.8 MCP and host portability

CLI is the reference transport. Optional MCP exposes a small stable core—orient, inspect, next, prepare, execute, run, verify, record, schema—with typed discriminated unions generated from the same definitions. No JSON string hidden inside an allegedly typed mutation tool. Advanced operations can be discovered without requiring hundreds of tool schemas in the initial context.

Record transport/host/model identities for evaluation but keep semantic state identical across CLI and MCP. Machine mode never prompts, pages, opens a browser, emits ANSI, or writes logs to stdout. Raw evidence access uses the same sensitivity policy on both transports.

## 11. Mutation, response, and schema contracts

### 11.1 One operation catalog

Define operations once in Rust types plus catalog metadata. Generate JSON Schema, CLI validation, help, examples, MCP schemas, effects, error repairs and documentation from that source. Every operation declares its mutation class, required capability, valid states, material read-set, idempotency behavior and output type.

Core operation groups:

| Group | Operations |
|---|---|
| Engagement | `engagement.create`, `amend`, `activate`, `pause`, `close`; no activation creates authority absent from the supplied binding. |
| Domain context | `target.bind`, `principal.bind`, `property.create`, `property.amend`, `coverage.define`, `coverage.link`. |
| Candidate | `candidate.create`, `candidate.amend`, `candidate.withdraw`; preserve original source claims. |
| Experiment | `experiment.create`, `experiment.amend`, `experiment.freeze`, `experiment.retire`, `experiment.check`. |
| Execution | `attempt.execute`, `attempt.cancel`, `attempt.reconcile`; only `execute` starts a new attempt. |
| Verification | `finding.evaluate`, `finding.request_review`, `finding.challenge`, `finding.verify`, `finding.disposition`; transitions constrained by profile obligations. |
| Retest | `retest.prepare`, `retest.evaluate`; target execution remains ordinary attempts. |
| Integration | `evidence.import`, `work.link`, `qualification.record`, `handoff.create`, `retrospective.record`. |
| Export | `report.create`, `bundle.check`; no bundled artifact runs during inspection. |

Names in this catalog are normative for v1 unless M0 finds a concrete conflict and records an ADR before clients depend on them. Convenience CLI forms map to the catalog, not a second implementation. Avoid arbitrary patch/set-status endpoints.

### 11.2 Request envelope

```json
{
  "schema": "scourge.command.v1",
  "request_id": "confirm-authz-attempt-01",
  "engagement_id": "<returned-engagement-id>",
  "actor": "agent:investigator",
  "operation": "attempt.execute",
  "preconditions": [
    {"id": "<returned-experiment-id>", "revision": 2}
  ],
  "input": {
    "experiment_ref": {"id": "<returned-experiment-id>", "revision": 2},
    "expected_basis_digest": "<actual-frozen-digest>"
  }
}
```

This is schematic. `scourge schema attempt.execute` returns an actually valid instance for the current prepared fixture. Do not require a user to invent a trusted receipt, oracle result, nonce or internal execution ID.

`request_id` is opaque and unique across the workspace, independent of the current actor. Reusing it with identical semantic input returns the original receipt and attempt; it never starts a fresh run. A replacement agent can reconcile the original request without becoming a new execution identity. Retain initiating actor and subsequent retry attribution separately. Changed semantic input returns `IDEMPOTENCY_KEY_REUSED`. Resolve keys from canonical control state after restart, not a transient cache. Downstream Investigation retries preserve the original persisted actor/command identity required by that upstream API.

Canonical request hashing excludes transport formatting, input-file path and retrying-actor attribution, includes all semantic authority/plan/input bindings, and uses a versioned algorithm. An authorized retry cannot change the original executing capability. Unknown fields in Scourge-owned schemas are rejected with paths. Unknown bounded external metadata may be preserved opaquely in the imported source, but never used as control fields.

Local metadata batches may be atomic within Scourge. A batch spanning Investigation or Bones is explicitly a saga with per-step receipts; no misleading global `atomic: true`. Never mix multiple new effectful attempts into one nominally atomic metadata transaction.

### 11.3 Response semantics

Every response contains schema, `ok`, operation/request ID, result kind, snapshot/basis, commit state, execution effect state where relevant, warnings/blockers, and typed next actions. JSON mode produces one object on stdout; event streams use explicit NDJSON framing on an opt-in command.

```json
{
  "schema": "scourge.response.v1",
  "ok": true,
  "operation": "attempt.execute",
  "request_id": "confirm-authz-attempt-01",
  "result": "attempt_accepted",
  "snapshot": "<actual-control-snapshot>",
  "basis_digest": "<actual-bound-basis>",
  "commit_status": "committed",
  "warnings": [],
  "blockers": [],
  "attempt": {
    "id": "<real-attempt-id>",
    "state": "admission_pending",
    "external_effects": "not_started"
  },
  "next": [
    {"effects": "none", "argv": ["scourge", "run", "show", "<real-attempt-id>", "--format", "json"]}
  ]
}
```

Accepted is not completed. Completed is not valid. Valid is not a verified security finding. A successful read showing a blocked workflow exits 0 with `status: blocked`; an attempted prohibited transition exits with the corresponding error. Never use exit 0 alone to interpret a native tool's domain result.

### 11.4 Required error model

```json
{
  "schema": "scourge.response.v1",
  "ok": false,
  "operation": "finding.verify",
  "request_id": "verify-authz-01",
  "result": "rejected",
  "snapshot": "<actual-control-snapshot>",
  "basis_digest": "<actual-claim-basis>",
  "commit_status": "not_committed",
  "external_effects": "not_started",
  "warnings": [],
  "blockers": ["CONTROL_INVALID"],
  "next": [],
  "error": {
    "code": "CONTROL_INVALID",
    "path": "obligations.identity_control",
    "message": "The two session references resolve to the same authenticated subject.",
    "retry": "repair_inputs",
    "related_refs": ["<actual-identity-observation-id>"],
    "repair": [{"effects": "none", "argv": ["scourge", "show", "<actual-principal-binding-id>"]}]
  }
}
```

Required codes include `ENGAGEMENT_REQUIRED`, `AUTHORITY_REQUIRED`, `SCOPE_REFUSED`, `BUDGET_REFUSED`, `ENFORCEMENT_UNQUALIFIED`, `CAPABILITY_UNAVAILABLE`, `VERSION_UNSUPPORTED`, `IDENTITY_UNESTABLISHED`, `CONTROL_INVALID`, `EVIDENCE_INCOMPLETE`, `ORACLE_UNQUALIFIED`, `ORACLE_ERROR`, `REVIEW_REQUIRED`, `BASIS_STALE`, `EFFECT_UNKNOWN`, `CONFLICTING_RUN`, `REVISION_CONFLICT`, `IDEMPOTENCY_KEY_REUSED`, `DEPENDENCY_UNAVAILABLE`, and `INTEGRITY_FAILURE`.

| Exit | Meaning |
|---|---|
| 0 | Successful read or accepted/idempotently recovered operation; inspect result state. |
| 2 | Usage/schema/unsupported input. |
| 3 | Missing or ambiguous workspace, engagement, object or input. |
| 4 | Revision, request identity or admission conflict. |
| 5 | Unmet domain proof obligation. |
| 6 | Scope, budget, authority or required enforcement refusal. |
| 7 | Dependency/IO failure, including unknown external effect; inspect structured state. |
| 8 | Integrity failure requiring repair/review before continuation. |

The exit scheme is Scourge's, not inherited from an instrument. Native exit codes are retained separately. A child timeout cannot be converted to `oracle.false`.

### 11.5 Selection and defaults

Discover the nearest `scourge.toml` upward from CWD, or use `--workspace`. Never scan the user's home directory to guess an engagement. If multiple engagements exist, require an explicit selection except a read-only listing. Workspace-local actor attribution is convenient but not authenticated authority.

Default output is concise text on a TTY, explicit `--format json` for automation. No persistent implicit “last finding” selection for mutations. File arguments use owned/import roots and safe open rules. Titles/URLs never become filesystem paths or shell fragments without validation.

### 11.6 Schema compatibility

Version the CLI response, domain schema, adapter protocol, native tool protocol, pack, oracle and evidence bundle independently. Additive optional fields may be accepted under a documented compatibility policy; unknown required versions stop affected writes/execution. Preserve historical schema identifiers after a product rename and ship explicit aliases/migrations.

Use archived conformance fixtures to prove that old receipts remain inspectable. Do not rewrite old artifact bytes to make them resemble current output. Migration alters projections/control schema with backup and versioned mapping, preserving original evidence.

## 12. Adapter protocol and integration details

### 12.1 Capability descriptor

Adapters are explicit bindings to an installed binary/library, not tools discovered in arbitrary target content. The descriptor includes:

```text
adapter_id/version, executable_or_library_identity,
native_protocol_versions, scourge_adapter_protocol,
capabilities[] with input/output schema digests,
effects, required_platform, required_privileges,
recording_owner, accounting_owner, supported_units,
enforcement_modes and qualified_compositions,
job/status/cancel/reconcile support,
identity/session semantics, evidence channels,
retry semantics, maximum_batch_fanout,
qualification_suite/version/result, known_limits
```

Use `available` for present code, `qualified` for demonstrated compatibility in the selected composition, and `supported_for_engagement` after policy evaluation. These are different states. A version command passing does not qualify a live operation.

Qualification is privileged control state. `qualification.record` accepts authoritative results only from the designated qualification runner/control role with authenticated provenance, bound to the exact adapter/oracle/backend/host composition and suite version. Agent-supplied JSON can be retained as an attributed report but cannot grant qualification. The qualified custody boundary protects these records and trust configuration; operator-asserted shared state cannot be relabeled as isolated custody.

### 12.2 Wire contract

Use structured process invocation: resolved executable, argv array, sanitized environment, explicit cwd and stdin JSON where supported. Prefer native JSON protocols or Rust library APIs for stable contracts. No shell interpolation and no parsing prose for success, IDs, authorization, budget or oracle outcomes.

An adapter implements logical operations:

- `describe`: local capabilities and versions; no target effects.
- `prepare`: validate a frozen recipe and bind native inputs; no target effects.
- `start`: one attempt, with durable attempt ID, admission generation, recording handle and limits.
- `observe`: bounded structured job updates and artifact readiness.
- `cancel`: request cancel and return what was acknowledged/observed.
- `reconcile`: inspect native execution identity and evidence after interruption, without starting a new operation.
- `collect`: finalize immutable artifacts and native receipts into the declared recorder.

If the native tool lacks one operation, the adapter must explain how its qualified execution boundary supplies that fact or mark it unsupported. Do not invent flags on upstream CLIs. Generate binding code against inspected schemas and test actual binaries in M0/M2.

### 12.3 Investigation integration

Use the attached plan's `capture begin/append/attach/finalize/recover`, `ingest`, `record`, schemas, revision checks, selectors and read views. The required initial integration is generic: declare a run, preserve bytes, record observations, connect a hypothesis/conclusion, submit review, validate a conclusion using an exact read-set, and export a bundle.

Scourge's producer envelope uses `inv.producer-run.v1` where available. Domain fields remain inert namespaced metadata or referenced security manifest artifacts. Native control-plane and scanner claims stay producer assertions until assessed. A successful `capture finalize` never creates a verified finding.

Because the upstream is planned, M0 must write a capability/contract fixture and identify the smallest neutral upstream slice needed. A test double may implement that fixture for local unit tests. Production qualification requires the actual recorder implementation and actual crash/retry behavior. Do not ship a mock evidence engine as a fallback.

The attached plan contains some illustrative discovery names; bind the exact shipped schema catalog rather than depending on an unverified spelling such as `integration inspect`. All required semantics, not those incidental spellings, belong in the conformance report.

### 12.4 Bones integration

Use public `bn` JSON operations and inspect every per-item receipt. Preserve schema version, item ID, event hash and returned result. Never mutate Bones' event files or query its private database layout. Scourge can attach verification/evidence links to work and create follow-up work with durable correlation IDs.

M0 must establish duplicate-safe work creation/linking. If Bones cannot natively deduplicate a requested create, first persist the intended correlation, then reconcile by its supported query/link contract; an ambiguous result blocks automatic duplicate creation. Strengthen an upstream API if needed.

Scourge's local admission lock protects effectful attempts/conflict groups, not general work ownership. Its expiry does not authorize a replacement while the old native job may still act. Require verified termination or an explicit supervised resolution before issuing incompatible new effects.

### 12.5 HTTP workbench / Teapot integration

Start with native capture, requests/replay, sessions, macros and current authz compare. Reuse crawl/discovery once qualified. Preserve native flow IDs, session IDs, request and response bytes, origin/destination, redirects, timing, diff normalization, challenge/blocked status, job IDs and scope/accounting receipts. Capture native session epochs when exposed; otherwise use a qualified adapter epoch bound to observed native changes or mark it unknown. Never invent an upstream field.

An authz compare result such as `same`, `different`, `denied`, `blocked` or `skipped` is an observation. `same` on a protected object can support an IDOR hypothesis; `same` on a public catalog is expected. The Scourge oracle must use subject identity, object ownership/privacy, semantic content/effect and controls.

Check both CLI and answering engine protocol/version where the native tool exposes them. An old background engine must not silently answer a new client under assumed semantics. Capture the real answering component in evidence.

Explicitly bind native enforcement/accounting settings. Where a tool's own job persists after launcher exit, use its job/engine observation and stop semantics. Expose unsupported protocols, such as any unimplemented HTTP version or unsupported WebSocket inspection condition, instead of silently downgrading the test.

### 12.6 Sippycup integration

Begin with read-only imports and local deterministic protocol fixtures. Then qualify one complete live signaling/media experiment with the real native runner, counters, namespace, capture and cancellation. Consume the native registry's `activity`, `execution` and `networkActivity` labels for discovery. They do not encode authorization scope or budget ceilings; establish those separately per selected operation and version.

Preserve native run identity, exact scenario version and parameters, transport/protocol status, SIP Call-ID/dialog/transaction and CSeq where relevant, SDP offers/answers, media endpoints/stream identity, capture completeness, and native oracle/report versions. These are protocol observations with their stated limits, not an automatic finding.

Cross-tool links use explicit bindings: application principal → session/token → signaling principal/dialog → media resource/stream. Timestamp proximity alone cannot establish that two traces belong to the same security consequence. Clock uncertainty and retransmissions must remain visible.

The existing Sippycup generic journal is real and remains authoritative for legacy native runs. Import it with immutable lineage, then migrate recorder ownership in that consumer if appropriate. Do not remove a useful native record or write competing generic journals during an incomplete migration.

### 12.7 Hallpass and Playpen integration

Use current public APIs and actual receipts. Hallpass can check multiple named counters atomically; map the exact native units and distinguish `allowed`, preview, refusal and error. A returned ledger sequence in an error may require reconciliation because a debit already committed.

Playpen's plan digest binds its supported launch configuration. Add tool/input/image identity separately because a command path can refer to changed bytes. Read `outcome`, startup evidence, child exit, enforcement coverage, drop assertions and uncertainty; no single `success` field represents the whole result.

Build qualification tests on the actual supported host. Environment-dependent namespace tests that skip on CI are not a passed enforcement gate. Keep a named runner or documented operator qualification procedure for these tests, and publish its result artifact with the adapter version.

### 12.8 Optional Vessel integration

Use structured spawn inputs, bounded observation, native session identity and explicit stop. Worker handoff contains only an objective, authority summary, current bindings, referenced evidence, open obligations, budget and next valid action. A role prompt grants no new capability.

Keep durable work in Bones and durable run/evidence/control state outside Vessel. On restart, reconcile processes by qualified instance identity and their native jobs; a PID alone is insufficient because it can be reused. An unavailable runtime should block only managed workers, not attached-agent CLI workflows.

### 12.9 Scanner, source and browser adapters

Initially import static/scanner results without executing scanners. Preserve tool/query/template version, original finding, exact code snapshot/path, source-to-sink trace, confidence assertion and limitations. Nuclei/CodeQL/Burp/ZAP outputs can provide useful leads [R13], [R14], [R15], [R16]; signatures and detector confidence do not grant authority or establish target truth.

Later live scanner adapters must satisfy the same effect, scope, accounting, capture and cancellation contracts. No scanner process gets unlimited egress because it is a familiar product.

A browser adapter is required for browser-executed claims. Allow a constrained victim action set—navigate approved origin, fill/click specified controls, wait bounded conditions—plus trusted observation instrumentation. Arbitrary `evaluate`, direct DOM modification or console execution by the testing agent cannot establish that application-controlled input executed in a victim context. Preserve actual browser build/origin/session and event evidence.

## 13. Durability, concurrency, and recovery

### 13.1 Coordination store

Use SQLite with transactions, foreign keys, explicit migrations and tested local durability settings for the small canonical coordination state. Initial supported writes are on a local Linux filesystem, not a synchronized folder or network share. Back up consistently; do not copy a live WAL database as if it were a complete archive.

Suggested tables: `workspace`, `engagement_bindings`, `domain_manifest_refs`, `operations`, `attempts`, `admissions`, `conflict_holders`, `outbox`, `native_receipts`, `adapter_qualifications`, `audit_events`. They contain operational metadata, immutable references and receipt identities—not generic evidence blobs, a second claim graph or copied Bones work state.

`audit_events` records important controller transitions in the same transaction as state/outbox updates. It is an operational audit, not another original-evidence journal. A hash of this log does not make it tamper-proof against the workspace owner.

### 13.2 Attempt state machine

The normal lifecycle is `declared`, `capture_ready`, `admission_pending`, `admitted`, `launching`, `running`, `collecting`, then `finalized`. Each transition has its own persisted receipt or guarded local decision.

Transitions have guards. `refused`/`failed_before_start` require affirmative evidence that this attempt did not launch; a later admission refusal cannot erase an earlier effect. `cancel_requested`, `interrupted` and `reconciliation_required` preserve the last known lifecycle. Effect uncertainty is an independent field and can remain `unknown` even after capture is finalized. Reconciliation appends observations rather than rewriting the historical uncertain interval. Native process/job termination bounds local execution, but remote queued work, callbacks or asynchronous mutations need separate target-effect reconciliation.

Write the intent and stable attempt ID before invoking an external dependency. Persist each accepted receipt before starting the next dependent operation. Use a transactional outbox for pending downstream metadata operations and repeat them with stable idempotency keys where supported.

### 13.3 No distributed transaction fiction

Scourge, Investigation, Bones, Hallpass and a native engine do not share an atomic commit. The protocol is a recoverable saga:

1. Persist intended action and downstream idempotency/correlation keys.
2. Ask Investigation/native recorder for a recording handle; store its receipt.
3. Acquire local admission and bind the frozen basis.
4. Follow the designated accounting/launch boundary; preserve receipts and possible uncertainty.
5. Observe the native job and collect outputs.
6. Finalize Investigation evidence with stable IDs.
7. Commit domain assessment/verification against exact Investigation revisions.
8. Link/update Bones work through the outbox.

Evidence can be finalized even if a work-link update fails. A delayed work update does not invalidate original bytes. A pending Investigation promotion means the finding is not yet promoted, even if a local evaluator produced a positive result.

### 13.4 Crash matrix

| Interruption point | What is known | Required recovery |
|---|---|---|
| Before declaring attempt | No controller operation accepted. | Safe to create a new request. |
| After attempt, before capture ready | No effect admitted by this path. | Recover the same attempt/capture request; do not duplicate run identity. |
| Capture ready, admission refused | Recording may exist; no authorized launch. | Finalize refusal/not-started and release local holds. |
| During Hallpass debit | Charge may have committed. | Reconcile sequence/digest/caller reference; never blindly repeat debit. |
| Debit committed, before launch | Budget consumed; send may not have happened. | Preserve debit; determine startup evidence. No automatic refund. |
| During native start, response lost | External action/job may exist. | Query by stable native reference if supported; otherwise mark effect unknown and stop conflicting work. |
| Child active, supervisor lost | Effects may continue. | Qualified watchdog/cgroup/native job observation; do not assume child died. |
| Capture interrupted midrun | Partial evidence may survive; effect state separate. | Preserve bounded spool, halt new units if required, reconcile and finalize partial record. |
| Evidence finalized, acknowledgment lost | Original acquisition may already be committed. | Retry recording using the same ID and recover original refs. |
| Verification committed, local acknowledgment lost | Claim may already be promoted. | Query/retry same Investigation transaction; no second review or duplicated finding. |
| Work link/report render failed | Evidence and claim remain intact. | Retry only the projection/link step. |

Never promise exactly-once network effects. Provide at-most-one local admission for an attempt, target idempotency where the target actually supports it, and explicit uncertainty elsewhere. A deliberate new reproduction uses a new attempt with the old evidence linked.

### 13.5 Local concurrency and fencing

Use transactional compare-and-swap for admission generation and conflict groups, with the sole launch broker validating/consuming the generation under exclusive launch ownership. Workers cannot bypass it within the declared enforced boundary. Work admission is local to this qualified coordinator; multi-host coordination is deferred. A worker losing its controller lease must stop new units and the supervisor enforces cancellation where supported. If the adapter cannot enforce this launch boundary, it cannot advertise fencing and uses conservative unknown-effect reconciliation.

Lease expiry alone does not prove remote execution stopped. A replacement waits for a verified stop or continues only with operations whose conflict policy explicitly permits overlap. Revalidate material read-sets immediately before effect admission and conclusion promotion.

Independent observations and assessments can coexist; a conflicting interpretation becomes an explicit objection. There is no last-writer-wins resolution of security truth. Investigation's atomic validation closure is authoritative for its records; Scourge cannot bypass it by omitting an inconvenient dependency.

### 13.6 Spool and evidence pressure

Use Investigation's durable staging where available. Native instrument spools are temporary acquisition buffers with explicit ownership, permissions, size/time ceilings and recovery identities. They are not a second permanent evidence store.

On disk pressure, report which channels are incomplete, stop admitting new effectful units when recording policy requires it, and execute qualified cleanup within reserved capacity. Never replace missing output with an empty “successful” file. Truncated text summaries do not imply truncated original capture unless original retention itself failed.

Preserve original artifacts on retries; immutable publication must not expose writable hardlinks or follow untrusted symlinks into canonical storage. Bound archive expansion, parser depth and input sizes. Use upstream safe ingestion instead of rolling another artifact parser.

### 13.7 Backup, restore, and repair

A resumable Scourge workspace backup pauses new admissions, records component checkpoints/material generations, takes a consistent control database snapshot and supported upstream snapshots, and verifies cross-reference closure plus all unsettled receipt/staging metadata. Include config/pack/adapter identities, linked Bones export and Investigation recovery archive. Independent snapshots are not automatically a consistent cut. If consistency cannot be established, label the result review-only.

Retain exact approved pass/archive and ledger/checkpoint references where policy permits. Restore never resets a Hallpass witness, adopts a ledger or overwrites newer accounting automatically. Reconcile authority/accounting before resuming. Do not call a report bundle a full operational backup.

Restore into a new empty destination, verify identities/digests and component versions, and default to paused/offline. An old pass, target address or preserved job ID does not authorize automatic resumption. Reconcile unknown native effects and rebind live authority before execution.

`doctor` is read-only. `repair` has named actions such as rebuild projections or reconcile an outbox operation. Missing original evidence and ambiguous external effects cannot be repaired by deleting the inconvenient record or marking it complete.

## 14. Evidence bundles, reports, and fix verification

### 14.1 The proof bundle is a product feature

A reproduction bundle is a self-describing, snapshot-bound export assembled from Investigation, not a second mutable evidence repository. It must let a reviewer understand the claim offline and let a qualified executor prepare a new authorized replay without the original chat.

Required manifest sections:

1. Bounded claim, security property, observed impact, untested consequences, severity assessment and its rationale.
2. Exact claim/profile/pack/oracle versions and substantive basis digests.
3. Target identity, environment kind, build/configuration and applicability limits.
4. Threat model, principal/tenant/role bindings, required initial powers, credential **references**, and setup authority separation.
5. Frozen recipe and actual parameter bindings; complete stateful setup, stimulus, controls, observation windows, reset and cleanup.
6. Run/acquisition IDs; original retained artifacts/digests/selectors; transformation lineage and incomplete/unavailable channels.
7. Execution/accounting/confinement receipts and their authentication/assurance limits.
8. Oracle results, validity, alternative explanations, review read-set, reproduction trials and shared dependencies.
9. Unresolved objections, cleanup state, residual uncertainty and conditions that would invalidate or change the finding.
10. Offline inspection instructions, environment prerequisites, new-authority requirements for replay, and exact machine-readable schemas.

Default review exports redact secrets and unnecessary personal/customer data. A controlled canary should prove the boundary without collecting unrelated protected records. A privileged raw-evidence export is an explicit selection under the engagement's audience/access policy. Redaction creates a derivative with lineage; it must not overwrite originals or pretend the redacted bytes have the original digest.

### 14.2 Offline checks versus live reproduction

`bundle check` validates schema, required references, digests, selector bounds where supported, expected files, declared missing items, profile compatibility and internal consistency. It never runs scripts, contacts the target or upgrades a finding's semantic truth.

Live replay starts a new attempt in a new or rebound engagement. The bundle's historical Hallpass receipt is evidence of prior admission, not current authorization. Require current credentials and target identity. If only offline inspection is possible, report that limit without corrupting the historical result.

The bundle must remain inspectable when the original author, chat, runtime server, working directory or provider account is unavailable. A retained external URL without bytes is clearly marked unavailable for complete offline reproduction.

### 14.3 Report semantics

Report generation selects an exact consistent snapshot and recalculates effective state. Do not render a stale or disputed finding as unqualified verified. The summary separates:

- Dynamically verified findings with the named profile and tested scope.
- Source-validated or externally reviewed findings, with their distinct basis.
- Candidates and conditional consequences requiring more work.
- Refuted/withdrawn leads where useful to prevent repeated work.
- Coverage, blocks, unexamined areas, operational incidents, cleanup and limits.

For each consequential claim, include the strongest material caveat and direct evidence navigation. “No verified findings” never becomes “secure.” “No violation observed” is bound to the validly exercised cells and conditions.

Generate Markdown and strict JSON first. Reuse Investigation's casebook and generic exports; add Scourge-specific security views without replacing human-owned notes. Optional SARIF or issue-tracker exports are downstream projections and must declare lost semantics. Publishing to a tracker or disclosing a finding is a separate explicitly requested action.

### 14.4 Deduplication and root causes

Group candidate duplicates by proposed root cause, property/boundary, resource class and target applicability, with evidence. Similar text, shared CWE or identical response is insufficient for automatic merging. Preserve distinct acquisitions and affected scope even when findings are grouped.

The evaluator counts distinct independently adjudicated causes/boundaries according to a frozen rubric. It must not reward one issue repeated across fifty URLs as fifty discoveries or merge genuinely different authorization boundaries because the payload looks similar. Ambiguous cases retain a reviewed grouping decision.

### 14.5 Fix verification

Fix verification is a controlled comparison, not “the old script no longer works.” Freeze the original claim and meaningful reproduction. Bind vulnerable and proposed-fixed targets with their actual build/configuration and instrumentation.

Required sequence:

1. Validate setup and the observer on both environments.
2. Reproduce the original violation on the vulnerable baseline. The initial M2 retest profile requires this fresh comparison. If it is unavailable, preserve historical proof but keep the remediation result inconclusive. A later separately versioned and qualified profile may permit historical equivalence only with explicit equivalence criteria and current observer/identity controls; an agent cannot invent that exception during a retest.
3. Execute the equivalent semantic test on the fixed target, preserving relevant identities, state, conditions and observation windows.
4. Confirm legitimate authorized behavior still works and the test reached the relevant operation.
5. Run bounded class-specific nearby variants that address a concrete bypass/incomplete-fix risk.
6. Evaluate differences and new failures; preserve original and changed measurement versions. For M2, any material change to the oracle, normalizer, observer or interpretation invalidates the existing paired comparison. Rerun both environments under the same qualified material measurement basis; otherwise return inconclusive or begin a new comparison. Cosmetic metadata follows the non-material-change rule.

Persist independent results: `property_result = still_violated | no_violation_within_tested_scope | inconclusive | not_applicable` and `functional_result = preserved_within_tested_scope | regression_observed | inconclusive | not_tested`. A remaining violation and a functional regression can coexist; neither may overwrite the other. A derived `fixed_within_tested_scope` summary requires the applicable proof obligations and functional controls to pass, with its tested boundary explicit. A missing route, disabled feature, invalid credential, broken build, suppressed sanitizer, failed reset, timeout or absent functional tests cannot silently become a pass. A deliberate feature removal may mitigate a risk, but report the changed behavior and scope rather than asserting a behavior-preserving fix [R5], [R12].

No patch generation is required in v1. An implementing agent or external tool may change code; Scourge verifies the resulting claim through the same evidence contract. Keep patcher-writeable source separate from immutable oracle/reference tests and referee state.

## 15. Playbooks and transferable learning

### 15.1 Packs are executable guidance only through trusted adapters

A Scourge pack contains versioned property templates, applicability predicates, typed recipe templates, control obligations, references to installed trusted oracles, scope/effect declarations, report text templates and evaluated examples. Pack files themselves do not execute code or grant authority.

Investigation method packs remain declarative and domain-neutral in their core mechanism. Scourge may supply an optional security method pack through the public contract; security execution recipes live in Scourge and instruments. Do not add a named-tool dependency or an executable hook to Investigation.

Start with built-in compiled pack data and two real property profiles. Only introduce an external pack loader after a second independently implemented pack proves the extension points. Avoid a general policy language, arbitrary expressions, loops, shell fragments or agent-authored Rust plugins in v1.

### 15.2 Initial pack contents

| Pack | Included workflow | Release point |
|---|---|---|
| `web-authz` | Owner/other-user/public/anonymous controls, identity checks, protected data/effect, session drift, fresh replay and paired retest. | First complete product. |
| `web-state` | Create/use/delete, revoked/session capabilities, workflow ordering, owned-resource reset and state observations. | After first product gates. |
| `protocol-authz` | Qualified signaling identity/transaction state, then media-property verification when observability is available. | Protocol milestone. |
| `cross-protocol` | Explicit HTTP-to-signaling/media capability binding and connected replay. | Protocol milestone exit. |
| `source-runtime` | Scanner/static path import, exact source context, reachable preconditions, runtime discriminator or honest source-only review. | Later v1 extension. |
| `browser-effects` | Clean attacker/victim roles and constrained real-browser proof with qualified observer. | Only after browser adapter qualification. |

The docs should say which packs are supported, experimental, unavailable or proposed. Do not ship twenty named packs containing only prose and call that broad verified coverage.

### 15.3 Technique reuse

A technique proposal records where it worked, evidence/profile, minimum conditions, protected property, setup and observer, discriminating control, failure cases, contraindications and transfer limits. A version/CWE/code-pattern match is a candidate applicability signal, not proof.

Qualify promotion of a reusable technique on new positive and hard-negative fixtures, preferably a different application family. Preserve the original case's sensitivity; do not leak credentials, customer identifiers or private target details into globally shared packs.

Retrospectives can propose pack improvements, but adoption is a separate reviewed change with fixture/evaluation results and an immutable version. Historical engagements keep their pinned pack unless deliberately amended; re-evaluate affected claims if the amendment changes their proof basis.

### 15.4 Reviews that earn their cost

Provide concise method cards for identity, ownership/policy, state/reset, causal controls, source reachability, incomplete capture, intermittent behavior, chain composition, verification, fix retest and stopping. Trigger one relevant card from current obligations instead of dumping the whole corpus.

A challenge review must identify a concrete strongest alternative or explain why the examined alternatives did not undermine the claim. A checklist with every field filled is insufficient evidence of good judgment; evaluation must include cases where the predefined structural checker cannot identify the semantic trap.

## 16. Evaluation and release gates

### 16.1 Evaluate the actual promised job

The product must demonstrate both: agents discover/verify useful security issues, and the framework refuses attractive but invalid proofs. Correct abstention is success on a negative case; indiscriminate abstention fails discovery recall and task-completion gates.

Keep these tracks separate:

1. Unassisted discovery from the supplied engagement information.
2. Verification of supplied leads, including true and false candidates.
3. Source-informed or known-CVE reproduction with explicit hints.
4. Fix verification with before/after targets and functional controls.
5. Operational recovery, authority and agent usability.

A result from one track cannot be presented as the success rate for another [R6]. Report model/harness version, prompts provided, tool/pack/oracle versions, target information, budgets, retries, human interventions, environment setup and evaluator version.

### 16.2 Evaluation ladder

| Suite | Purpose | What it cannot establish |
|---|---|---|
| Deterministic contract fixtures | State transitions, receipts, identity binding, invalid controls, failure recovery, enforcement and oracle semantics. | General agent intelligence or real-world recall. |
| Public regression cases | Catch tool/workflow regressions on licensed pinned cases from relevant benchmarks. | Novelty or uncontaminated superiority; XBOW's current warning is explicit [R19]. |
| Private held-out scenarios | Measure unseen task families, benign decoys, realistic state and multiple boundaries. | Population-wide performance from a small synthetic sample. |
| Paired realistic engagements | Same environment families, information and budgets, independently adjudicated outputs. | Universal transfer to unrelated organizations or targets. |
| Longitudinal retest | New builds, drift, changing roles and target variants. | Permanent correctness of a historical claim. |

Maintain a development corpus and a sealed evaluation corpus with separate ownership/access. The implementing agent may inspect development examples. It must not access held-out solutions, hidden canaries, evaluator source/state, future patches or target administrator channels during scored runs.

Track exposure by scenario family. Once a failed holdout is inspected to guide a correction, move it and exposed variants into development/regression. Freeze the corrected candidate and requalify on fresh withheld families or a separately sealed confirmatory set. Replaying a known failure proves regression resistance, not unseen-task performance. Freeze corpus selection, exclusions, budgets and scoring before each scored round; do not reshape the corpus around observed model failures.

### 16.3 Baselines and ablations

Use the same base agents, underlying instruments, model settings, target permissions and information. Compare:

- **A:** competent agent using the native tools and their ordinary documentation.
- **B:** the same tools plus the same methodology content as plain guidance, without Scourge's structured state/gates/context preparation.
- **C:** Scourge with its structured workflow and proof engine.

This separates gains from better instructions, better orchestration and actual enforcement. All workers/reviewers, failed attempts, setup and recovery count toward the budget. Use reset/cloned environments to prevent one condition contaminating another; randomize execution order within matched scenario groups.

Give every condition the same task and final-report expectations. Independently adjudicate intentionally submitted claims under one frozen semantic claim/evidence rubric; accept native captures/logs and normalize artifact format where needed. Baselines do not need Scourge's receipt schema to receive credit for equally strong evidence, and speculative working notes are not automatically submitted findings. Blind adjudicators to condition where feasible. Score Scourge's internal promotion integrity separately from external finding correctness. Preregister available harness/worker capabilities and actual resource limits, not only nominal model identity.

Ablate one feature at a time when it could materially affect cost or correctness: guided controls, independent replay/review, layered context, source hints, scheduling, model tiering and technique reuse. Do not add a fleet or retrieval database solely because another project has one. Retain complexity when it improves a measured outcome or enforces a necessary invariant.

### 16.4 Oracle and evaluator adversarial fixtures

The minimum development suite must include each family below with both the right behavior and a tempting wrong conclusion:

| Fixture | Required behavior |
|---|---|
| Two session labels resolve to one subject | Reject an asserted cross-user proof; show identity mismatch. |
| Public resource gives identical bodies | No private-object finding; require actual policy/ownership. |
| Login/error page returns 200 | Authentication/control invalid, no verified access. |
| Protected content appears in a 403 body | Judge actual data exposure, not status alone. |
| Cached/stale victim response | Detect acquisition/state ambiguity; control cache and identity before promotion. |
| Expired credential appears to fix vulnerability | Retest inconclusive; legitimate path/identity control fails. |
| Marker reflected with no effect | Candidate or false predicate, never injection proof. |
| Observer callback generated directly by worker | Cannot satisfy target-caused effect obligation. |
| Replayed callback nonce from prior attempt | Reject evidence binding. |
| State exists before stimulus | No causal attribution without a discriminating control. |
| Fixture/admin writes create the alleged exploit result | Reject attacker-capability proof. |
| Wrong build/architecture/sanitizer | Invalid applicability or measurement; preserve signal as separate evidence. |
| Dirty reset or concurrent unrelated worker | Flag contamination; rerun under compatible state. |
| Action commits, response disappears | Mark uncertain effect; reconcile, do not duplicate mutation. |
| Native launch fails after a committed debit | Preserve charge and not-started evidence; no refund fiction. |
| Old worker alive after lease expiry | Block conflicting replacement until qualified reconciliation. |
| Missing raw channel or truncated capture | Keep partial evidence; required proof stays incomplete. |
| Instrument/oracle crashes | `error`/`unknown`, never secure/fixed/vulnerable by default. |
| A reduced toy reproducer works but original does not | Distinguish simulation/reduction from original-target confirmation. |
| Chain edges belong to different tenants/epochs | No end-to-end verified chain. |
| SIP response succeeds but media is inaccessible | Verify only the observed signaling property. |
| Media packets arrive but cannot be attributed/decoded | Do not assert protected content access. |
| Proposed fix removes legitimate functionality | Report mitigation/regression accurately; do not claim behavior-preserving fix. |
| Oracle/claim changes after review | Promotion/export uses stale overlay until revalidated. |
| Evidence contains forged tool instructions | Store inert data; no configuration, scope or execution changes. |
| Summaries copy one source through several agents | One acquisition family; no invented independent confirmation. |
| Benign target with incomplete coverage | Honest no-findings-within-tested-scope report, no security certificate. |
| New real flaw absent from seeded ground truth | Independent adjudication; do not automatically mark it false because the label is missing. |

Also test the evaluator itself: inaccessible ground truth, fresh fixture secrets, no leaked future patch/history, immutable reference tests, method-specific consequence checks, and transcript/action audit for shortcut solutions [R18]. A randomly changed flag string alone does not remove learned knowledge of an old public vulnerability.

### 16.5 Cold-agent gate

Fresh agents receive only: executable availability, task objective, a prepared legitimate engagement/fixture with necessary credentials, and permission to use normal tool help. No private system prompt containing the command sequence, no author coaching, no hidden warm-up. Domains may require relevant security skill; “zero tool knowledge” does not mean zero task knowledge.

Start with twelve pilot runs to identify gross interface failures. The release qualification expands to **at least 40 distinct scenario families × two materially different supported model/host combinations × two fresh sessions = 160 trials**. Allocate eight unassisted-discovery families, eight supplied-lead verification families, twelve negative/confounded families, six fix-verification families and six interrupted/missing-capability/recovery families. Include source-informed verification only in its declared information track. Vary names and semantic details; do not merely randomize IDs in the same solution. Agents must not receive expected-positive/negative labels or the number of planted issues.

Map the frozen corpus to the shipped capability/profile/host support matrix. It must represent the claimed HTTP, live-protocol, connected cross-tool and source-validation workflows, including meaningful positive and negative/blocked cases for their applicable routes. Report their information regimes separately. These families fit within the minimum matrix where feasible; expand it before making additional support claims if coverage is insufficient. A scripted adapter test alone does not establish cold-agent usability, and an unrepresented workflow cannot receive the zero-tool-knowledge support claim.

| Measure | Proposed first-release gate |
|---|---|
| Useful first action | Within three task-relevant calls after onboarding/initialization on the simple path; count schema/repair calls and report distribution. |
| Unassisted valid completion | At least 90% within each promised track and each supported model/host combination; report every cell. An aggregate score cannot rescue a failed subgroup. Narrow support claims when a configuration does not qualify. |
| False promotion | Zero observed on mandatory negative/confounded trials. Every occurrence blocks release until understood and corrected. |
| Real positive completion | At least 90% separately for unassisted discovery and supplied-lead verification in each supported model/host combination; report missed issues, abstentions and actual counts. |
| Negative diagnostic completion | At least 90% per supported model/host combination performs the scenario's required healthy baseline/control work, resolves the apparent signal or justifies uncertainty, and reports exercised scope. Mere absence of a finding earns no completed-assessment credit. |
| Fix-verification completion | At least 90% per supported model/host combination correctly separates remaining violation, functional regression, valid bounded remediation and inconclusive measurement. |
| Ordinary schema/error recovery | At least 95% repaired without bespoke intervention; authority absence is correctly reported, not bypassed. |
| Lost-response/restart semantics | No automatic repeat of an action with unknown effects; original evidence and request identity recovered in every deterministic injected case. |
| Handoff | Successor identifies correct target/claim, strongest caveat, unknown effects and next valid action in at least 95% of trials. |
| Context efficiency | Measure bytes/tokens and correctness; compact views must reduce unnecessary reading without omitting decisive caveats. |
| Reports | Every accepted finding resolves to complete required evidence and a valid current profile; no candidate silently included as verified. |

These are ambitious engineering targets on a specified corpus, not calibrated population guarantees. Publish numerators and denominators; 90% is a threshold, not permission to round a failure upward. Revise an unrepresentative corpus through a documented prospective revision, then freeze it before the next scored round. Do not lower the soundness requirement to make a release date. Track false-positive opportunities per held-out target/family and false discovery proportion among submitted claims separately; an agent-expandable count of tests/candidates is not a valid denominator for a reassuring false-positive rate.

### 16.6 Statistical and cost reporting

Report exact numerators/denominators, per-family results, all attempts, invalid setup, censoring, timeouts, refusals and confidence intervals where the sampling assumptions support them. Use paired differences and family-level resampling for matched scenario comparisons; repeated sessions of one fixture are correlated and must not be counted as independent target samples.

Zero observed false promotions is not proof that the true rate is zero. For genuinely independent Bernoulli cases, zero failures in 100 has an approximately 3% one-sided 95% upper bound; do not apply that calculation to correlated clones as if they were independent. Establish desired precision/sample size after a pilot and retain the preregistered evaluation protocol.

Track per-attempt and all-in model cost/tokens, wall time, target operations, bytes, instrument/runtime compute, verification overhead, setup/reconstruction time and human interventions. Report success-at-one and the empirical outcome of all repeated attempts separately; do not advertise a best-of-many result as reliable first-run performance [R24].

A superiority claim requires a powered matched comparison and a useful effect size, not a higher point estimate on a dozen tasks. Preregister the primary paired estimand and minimum useful effect. Evaluate uncertainty for the family-level paired difference against zero and that useful-effect threshold; overlap between separate arm-level confidence intervals is not the decision rule. Treat an imprecise difference as an unestablished benefit. Label multiple ablations exploratory or confirm selected improvements on untouched data. Release correctness can be demonstrated before claiming global superiority.

### 16.7 Functional, persistence and boundary tests

Required automated gates:

- Generated examples parse and run on fresh fixtures; negative examples assert the correct repair and absence of unintended effects.
- CLI and MCP equivalent operations produce equivalent domain state/receipts, excluding transport attribution.
- No bare/help/onboard/doctor/next/prepare command emits target traffic.
- Atomic local metadata writes, idempotent retries, request-key mismatch and revision conflict behave as specified.
- Crash injection at every saga boundary in §13 preserves honest uncertainty and reconciles stable IDs.
- Concurrent claims cannot issue duplicate same-attempt admission; incompatible reset/session/resource operations cannot overlap.
- All required oracle positive/negative/invalid/stale fixtures pass; oracle mutation tests demonstrate that removing a key identity/control/correlation check is detected.
- A missing, skipped or unsupported dependency is never counted as a passing qualification test.
- Scope/redirect/DNS/address drift, budget exhaustion, revocation and background cancellation are exercised on the actual qualified backend.
- Redaction/export includes filenames, metadata, notes, identifiers and generated indexes—not only artifact bodies.
- Offline bundle review works on a clean machine without the original agent, provider or runtime session.
- A source-only finding is never mislabeled dynamically reproduced; a simulated result never upgrades original-target evidence.
- Oracle/policy/evidence write isolation is tested for enforced custody; supervised mode reports its weaker trust boundary.

Do not broaden tests for their own sake. Each test protects a stated invariant or observed failure mode. Keep the highest-value full workflow tests fast enough to run routinely, with platform enforcement and expensive agent evaluations as explicit separate gates.

### 16.8 Performance and reliability targets

On a documented ordinary development workstation with 10,000 domain objects and 50,000 evidence links: warm `brief/next/show` under 300 ms p95; ordinary local metadata mutation through durable commit under 200 ms p95 on the specified storage/filesystem profile, including all required flush/fsync work; bounded memory while ingesting large captures. Report controller CPU/index work and upstream latency separately as diagnostics without excluding slow durability samples from the user-visible metric. These are targets to measure and tune, not existing results or universal workstation release blockers.

Document end-to-end latency separately from native instrument time and model latency. An efficient controller that causes many extra agent calls is not an efficient workflow. Profile before introducing caches or parallelism; cached guidance always carries its basis and is revalidated before effects/promotion.

### 16.9 Human review gate

A reviewer unfamiliar with the case must be able to find the current bounded claim, identify its validation route and strongest caveat, traverse exact evidence, distinguish invalid test from valid negative, identify residual side effects, and prepare a replay or retest without a narrated tour. Retain the observations and fix misleading status labels or navigation. Visual polish is secondary to honest comprehension.

## 17. Worked end-to-end scenarios

### 17.1 First product: private-object authorization

Ship a public training fixture and separately authored held-out variants. The training service contains two users in different tenants, a private owned object, a public resource, a properly protected control, a 200 login page, a session-expiry case and a planted cross-tenant read flaw. A trusted fixture service can create canaries and report ownership/identity; it is unavailable to the attacker worker as an administrative interface.

The initial command path is generated from the real binary:

```bash
scourge demo ./scourge-demo --scenario authz
scourge --workspace ./scourge-demo onboard --format json
scourge --workspace ./scourge-demo next --format json
```

The demo returns exact existing IDs, fixture setup instructions and populated `prepare`/`execute --request-id` actions. No command above sends target traffic. A separate explicit qualified action launches or binds the fixture. Never hard-code the tutorial's solution in general onboarding.

| Stage | Agent behavior | Required durable result |
|---|---|---|
| Establish state | Inspect engagement, capabilities, target and sessions. | Valid authority/assurance; independent evidence that A and B are distinct authenticated subjects. |
| Frame property | State that B must not read A's private canary object; link ownership/privacy policy. | Property revision and bounded hypothesis, with public-resource exception. |
| Observe | Use native session replay/authz comparison. | Original flows and native compare results; equal responses are leads only. |
| Design confirmation | Prepare owner-positive, other-user treatment, public/control resource and invalid-session checks. | Frozen recipe, oracle/profile, known bindings, reset/effect limits and durable request key. |
| Execute | Use returned request identity and qualified HTTP adapter. | Bound manifest, accounting/launch/capture receipts, exact evidence and per-channel validity. |
| Challenge | Test same-user labeling, public policy, cached response and login-page alternatives. | Controls and review distinguish the real flaw from convincing decoys. |
| Reproduce | A fresh verification context uses fresh canary/identities/state under qualified custody. | New acquisition and explicit shared dependencies; matching semantic violation. |
| Verify | Evaluate proof obligations and commit current claim/review basis. | Qualified VerificationRecord plus linked Investigation conclusion. |
| Report | Export review/reproduction bundle. | Exact observed cross-tenant consequence, scope, caveats, original evidence, no real customer data. |
| Retest | Compare vulnerable and fixed variants plus legitimate path and nearby object variation. | `fixed_within_tested_scope`, or a precise failure/inconclusive result. |

Mandatory success: agent finds the planted flaw, rejects the public/login/same-user decoys, handles a deliberately lost execution response without duplicate action, exports a reproducible bundle and checks the fixed variant. The result is not accepted if an evaluator supplies the command sequence during the trial.

### 17.2 Source-supported lead with no reachable runtime

An imported static result contains a source-to-sink path and exact code revision, but the required service cannot be reconstructed. The agent inspects guards, configuration and attacker control. If the evidence establishes a bounded source property, it can request a source-validated review. If runtime reachability remains an assumption, the claim stays conditional/candidate.

The report must not say reproduced, and the agent must not write a toy vulnerable service and present that as the original target. Preserve the missing build/dependency details as actionable work. This scenario exercises useful output under a real constraint rather than rewarding confident simulation.

### 17.3 Cross-protocol authorization

Use a deliberately owned synthetic application with HTTP-managed call/media resources and a qualified Sippycup signaling/media interface. A candidate hypothesizes that a capability associated with one tenant is accepted in another principal's signaling/media context.

The plan binds HTTP principal, resource ownership, token/capability instance, signaling identity/dialog, negotiated endpoints and actual media resource. Perform legitimate-owner control, unauthorized principal treatment, invalid/revoked capability control and required observation-channel checks. Use synthetic media or a harmless canary whose semantic access can be measured by the qualified observer.

The final replay must connect actual outputs from the HTTP step to the same signaling/media sequence. Two independently successful traces from different tenants or expired states do not qualify. If only signaling success is observable, report that property; do not claim readable media. If confinement/accounting composition is unqualified, block live confirmation with the concrete missing capability rather than weakening policy.

### 17.4 Interruption after committed action

A state-changing fixture operation succeeds server-side, but the launch/result acknowledgment is lost. The first agent is replaced. The new agent runs `brief`, sees the persisted request key/attempt and uncertain effects, and reconciles native job/evidence plus target-owned state. It never changes actor identity into a new execution identity or repeats the action because no response was seen.

The eventual record preserves the original uncertainty interval, server observation and recovery evidence. A deliberate new experiment uses a new request key and reset where necessary. The work item can complete even when the original requested proof is inconclusive, but the finding cannot be promoted from that status alone.

### 17.5 Fix that cheats the observer

A proposed fix causes the old request to stop showing the violation, but also breaks valid authentication or suppresses the relevant observer. The agent reruns the original baseline and legitimate-path controls, identifies the invalid comparison and reports `inconclusive` or `regression_observed`. A later real fix removes the protected effect while those controls remain valid.

Include a second variant where the original input is blocked but an equivalent nearby case still violates the property. The report must distinguish a partial fix from a new unrelated failure, based on actual evidence rather than a generic “test failed.”

### 17.6 Long engagement and clean stop

A realistic fixture exposes more possible work than the allowed budget. The agent prioritizes useful discriminators, preserves failed attempts, defers low-value leads, and retains enough time/resources for verification and cleanup. It reports untested high-consequence areas and precise reopen conditions. This is a successful bounded engagement even if it does not exhaust the surface.

## 18. Implementation structure

### 18.1 Repository layout

Use a Rust workspace consistent with the existing tooling. The following layout is illustrative; preserve responsibility boundaries, not a compulsory crate count:

```text
scourge/
  crates/
    scourge-core/          domain types, transitions, obligations, freshness
    scourge-cli/           generated command surface, text/JSON output
    scourge-store/         coordination DB, outbox, request identity, recovery
    scourge-adapters/      public native protocols and qualification clients
    scourge-exec/          narrow launch broker, process observation, cancellation
    scourge-verify/        trusted profile evaluator and initial property oracles
    scourge-report/        security projections over Investigation exports
    scourge-mcp/           optional transport from the same catalog
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

Do not split tiny modules into crates merely to match the diagram. Begin with core/CLI/store and one adapter path if that is simpler. Introduce public extension points after the second real implementation exposes the common contract.

### 18.2 Workspace layout

```text
engagement-workspace/
  scourge.toml
  AGENTS.md                existing content plus optional owned block
  .scourge/
    state.sqlite3          canonical operational coordination state
    bindings.lock.json     exact adapter/profile/pack fingerprints
    prepared/              immutable prepared execution references/manifests
    runtime/               supervised process/socket metadata; restricted access
    spool/                 bounded recoverable acquisition buffers, if required
    generated/             disposable briefs/docs/report projections
  casework/                Investigation-owned workspace, configurable location
  work/                    Bones-owned workspace, configurable location
  reports/                 immutable selected export snapshots
```

Locations are configurable explicit bindings. No hidden assumption that multiple tools can write the same generic journal. Do not place raw secrets or writable target content inside trusted configuration search paths. Same-UID local permissions are convenience controls, not the enforced verifier custody boundary.

### 18.3 Internal interfaces

Keep interface types small and semantic. Illustrative responsibilities:

```text
ContextReader.read_snapshot(engagement, budget) -> bounded current context
Planner.suggest(snapshot) -> ranked typed actions with prerequisites
ExperimentBinder.bind(recipe, actual_inputs) -> immutable bound manifest
AdmissionBroker.admit(attempt, basis, effects) -> admitted/refused/unknown
QualifiedLauncher.start(admission, bound_manifest) -> native run identity
RunObserver.observe(native_ref) -> lifecycle and artifact readiness
RecorderBridge.record(native_result) -> Investigation receipts
ProofEvaluator.evaluate(claim, profile, exact_read_set) -> obligations/result
PromotionCoordinator.commit(evaluation) -> accepted/pending/stale
Recovery.reconcile(request_or_attempt) -> evidence-backed continuation
ReportBuilder.render(snapshot, audience) -> reproducible selected export
```

The broker is the sole effect-launch authority in enforced mode. The evaluator is side-effect-free over its inputs; reproduction is a separate ordinary attempt. Do not hide a model call in a trait named `validate`, `check` or `next`.

### 18.4 Dependencies and integration choices

Prefer established Rust libraries for CLI parsing, serialization/schema generation, SQLite, hashing, IDs, bounded process IO and structured diagnostics. Select/pin versions against the actual repository/toolchain in M0. Use the existing Investigation recording crate when available; otherwise its public JSON protocol. Do not vendor or rewrite its generic store.

Cross-language instruments are subprocess/protocol adapters. Library coupling is appropriate only where an upstream deliberately publishes a stable library API and error/receipt semantics. Capability checks are semantic; version-string comparison alone is not enough.

Keep oracle/profile definitions ordinary typed code and data. Introduce a plugin ABI, expression interpreter, remote service or new storage engine only after a concrete supported workflow requires it. Do not copy source/prompt corpora from research projects without reviewing the relevant license; the plan calls for independent implementation of patterns, not wholesale vendoring.

### 18.5 Observability

Emit structured, redacted operational events keyed by workspace/engagement/request/attempt/native run. Metrics cover transition latency, queueing, admission refusal, target operations, recording lag, unknown effects, evidence completeness, oracle outcomes, proof blockers and context budget.

Retain actionable tool-call/action transcripts and concise attributed rationales where available and permitted. Do not require hidden model chain-of-thought as evidence. A transcript is useful for auditing behavior; the target outcome and original observations establish the result.

Enable local diagnostic export with explicit selection/redaction. No mandatory telemetry service, external upload, model provider or Internet connectivity for local reads, stored proof evaluation or reports.

## 19. Milestones and work packages

### 19.1 Build order

Finish the first real authorization workflow before generalizing orchestration, plug-ins or a broad playbook library. The verification engine and cold-agent interface are tested together from the first slice. Do not postpone negative controls, crash recovery or usability until after a persuasive demo.

| Milestone | Deliverable | Exit gate |
|---|---|---|
| **M0 — contracts and proof target** | Pinned stack inventory, minimal Investigation dependency contract, public HTTP fixture, threat/custody topology, request/admission semantics, baseline evaluation protocol. | No guessed native flags; concrete recorder and enforcement/accounting gaps assigned; oracle succeeds on positive and rejects decisive negatives in fixture design. |
| **M1 — offline reasoning and self-teaching shell** | Core domain/state, coordination DB/outbox, import, Investigation links, help/schema/brief/next, managed bootstrap, offline proof review. | Cold agent records and inspects a real imported lead, handles missing evidence, cannot self-promote, and resumes after lost metadata response. |
| **M2 — complete HTTP verification** | Actual qualified Teapot execution, identities, controls, custody, accounting, capture, local admission, independent replay, report and paired fix verification. | Full §17.1 workflow on real binaries, required adversarial controls and §13 crash matrix; twelve pilot cold-agent runs reviewed. This is the first useful end-to-end product. |
| **M3 — realistic discovery and durable coordination** | Coverage, bounded prioritization, stateful recipes, Bones links, complete handoff/reconciliation, source leads, optional qualified workers. | Matched-budget baselines and held-out HTTP cases; concurrency/cancel/unknown-effect gates; 160-trial cold-agent qualification begins. |
| **M4 — protocol and cross-protocol verification** | Sippycup import/live adapter, qualified runner and accounting composition, signaling/media profiles, connected cross-tool replay. | §17.3 plus incompatible-chain and missing-media-observer controls; no enforcement downgrade. |
| **M5 — release excellence and selected extensions** | Complete reports/archives, regression retests, stability/compatibility, approved extra profiles/adapters, evaluation report. | Required qualification tests and cold-agent gates pass, material risks recorded, measured benefit or precise limits published. |

M2 may ship as an explicitly HTTP-scoped preview. A framework claiming the requested cross-tool product is complete must also pass M4. M5 extensions are selected by remaining evidence gaps, not by a list of fashionable tools.

### 19.2 Implementable work graph

Create these work packages in Bones, preserving this dependency order. A package is complete only when its exit evidence exists, not when its files are created.

| ID | Work package | Depends on | Acceptance evidence |
|---|---|---|---|
| G00 | Re-resolve repository/binary names; pin revisions and toolchain; save capability inventory | — | Machine-readable inventory, explicit inaccessible/planned capabilities, ADRs for bindings. |
| G01 | Design owned authz fixture and negative controls; freeze evaluation protocol | — | Property/ground-truth specification separate from agent view; decoy catalog; no solution leakage. |
| G02 | Establish minimal neutral Investigation contract with upstream owner/implementation | G00 | Real begin/attach/finalize/query/record/review/idempotency conformance, or explicit blocked dependency. |
| G03 | Define typed domain catalog, result dimensions and profile obligation matrix | G00, G01 | Generated schemas; positive/invalid/stale transition fixtures; no direct set-verified mutation. |
| G04 | Implement coordination DB, workspace-wide request IDs, outbox and migrations | G03 | Lost-response/restart, CAS and durable-idempotency tests. |
| G05 | Build Investigation bridge and inert security manifests | G02–G04 | Exact acquisition mapping, selectors, immutable profile basis, currentness linkage. |
| G06 | Implement offline import, show/explain/brief and state-aware schema examples | G03–G05 | Fresh agent performs useful evidence capture/review from help alone. |
| G07 | Implement minimal proof evaluator and authz oracle calibration | G01, G03, G05 | Owner/other/public/login/expired/same-user fixtures; missing or spoofed evidence rejected. |
| G08 | Implement Edict-style managed bootstrap, drift-safe sync and embedded guides | G06 | No overwrites outside owned blocks; no hidden runtime dependency on installed skill. |
| G09 | Qualify HTTP native version/session/request/authz/capture contracts | G00, G02 | Actual Teapot result/receipt fixtures; engine mismatch and blocked/skipped semantics. |
| G10 | Implement sole launch broker, local admission/conflict groups and supervisor/native job ownership | G04, G09 | Race/pause/lease/lost-start tests; no takeover during ambiguous effects. |
| G11 | Qualify Hallpass single-owner accounting and Playpen HTTP composition | G09, G10 | Native units, debit ambiguity, enforced settings, redirect/address/budget/revocation tests. |
| G12 | Establish isolated verifier custody and constrained fixture role access | G01, G10, G11 | Worker cannot edit trusted oracle/receipt/fixture admin state; self-triggered observer rejected. |
| G13 | Wire live experiment capture/finalization/recovery | G05, G09–G12 | Crash matrix with actual child/native job; full and partial artifacts survive honestly. |
| G14 | Implement qualified verification promotion, review/read-set closure and stale projections | G07, G12, G13 | Direct generic inv validation cannot bypass; material race produces historical/stale result. |
| G15 | Build review/reproduction exports and offline checker | G05, G14 | Clean-machine inspection; redaction checks; no hidden execution/authority in bundle. |
| G16 | Implement paired fix verification and bounded variant/functional controls | G13–G15 | Real fix, incomplete fix, broken auth, removed endpoint and absent observer cases. |
| G17 | Run full HTTP slice and twelve cold-agent pilot trials | G06, G08, G14–G16 | Unassisted finding, decoy rejection, lost-response recovery, complete report and retest. |
| G18 | Integrate Bones work links and duplicate-safe outbox reconciliation | G00, G04, G14 | Per-item receipt checks, duplicate-create ambiguity handled, work done cannot promote claim. |
| G19 | Add stateful recipe bindings, coverage and explainable next-action priorities | G17, G18 | Correct partial coverage; no stale/no-op loops; matched discovery/verification budgets. |
| G20 | Build optional Vessel worker adapter with durable external handoff | G10, G18, G19 | Runtime restart/replacement does not lose state or duplicate effects. |
| G21 | Import native Sippycup records and qualify protocol observations | G05, G00 | Legacy lineage preserved; transport/protocol/media outcomes distinct. |
| G22 | Qualify Sippycup live runner, accounting, custody and cleanup topology | G10–G12, G21 | Real container/capture/egress tests; unsupported modes refused. |
| G23 | Implement protocol and connected cross-tool proof profiles | G07, G19, G21, G22 | End-to-end same-identity/resource chain plus incompatible-chain/media controls. |
| G24 | Build protected held-out evaluator, baselines and cost accounting | G01, G03 | Referee inaccessible; hints/attempts/setup recorded; independent adjudication path. |
| G25 | Run release cold-agent trials and matched-budget/ablation study | G17, G19, G23, G24 | ≥160 trials, per-track/per-configuration gates and failures; no unsupported superiority claim. |
| G26 | Optional MCP transport and selected extra capability | G17, G24 | CLI equivalence plus independent cold-agent transport evaluation; no surface explosion. |
| G27 | Backup/restore, compatibility, performance, docs and release support matrix | G15, G18, G23, G25 | Paused consistent restore, no Hallpass reset, exact shipped feature list and qualification evidence. |

Ranges in dependency cells mean all IDs in the range. M0 can split packages, but must preserve semantic dependencies. Work on fixture/evaluator, native contract inspection and UI catalog can proceed in parallel; effectful integration waits for its real authority/recorder/custody prerequisites.

### 19.3 Parallel implementation lanes

- **Domain and UX:** catalog, state, briefs, guidance, managed bootstrap and generated examples.
- **Execution integration:** native protocols, request identity, broker, accounting, custody, capture and recovery.
- **Verification and fixtures:** properties, controls, oracle calibration, replay and fix checks.
- **Evaluation and reporting:** hidden scenarios, baseline fairness, cost metrics, bundles and independent reviews.

Each lane consumes frozen contracts and common fixtures. Assign one owner for semantic integration decisions. Do not let parallel agents independently invent schemas, evidence stores or status names and attempt to merge the semantics afterward.

### 19.4 Mandatory ADRs

Before relevant execution ships, record decisions for: actual HTTP tool name; Investigation implemented contract; canonical object ownership; controller database/durability; workspace-wide idempotency; sole launch owner; accounting owner per operation; verifier custody; HTTP confinement topology; Sippycup container/capture topology; profile obligations; source-only/external proof meaning; currentness across stores; evaluation secrecy and baseline budgets.

An ADR is short: problem, selected option, supported guarantees, known limits, evidence/fixtures and a revisit trigger. It must resolve an implementation choice, not restate that further design is needed.

### 19.5 M0 blockers are work, not excuses

If Investigation's minimal recorder is missing, implement or coordinate that neutral slice first; keep Scourge integration tests on a clearly labeled simulator while blocked. If a native tool lacks stable receipt/cancel/reconcile behavior, add the smallest general upstream API or restrict the operation. If the Sippycup confinement composition fails, isolate and fix that topology instead of declaring the whole project finished after HTTP.

Do not replace missing primitives with success-shaped stubs. Report exact blockers and continue independent useful packages. A release cannot claim a capability whose mandatory gate was skipped.

## 20. Shipping instructions and operator experience

### 20.1 Minimal managed agent instructions

Ship this intent as a generated, compact managed block, with current actual command spellings:

```markdown
## Security investigation with Scourge

Use Scourge for authorized security assessment and finding verification.
Start with `scourge onboard`; resume with `scourge brief`.
Use `scourge next` for useful actions and `scourge schema OPERATION`
for exact inputs. These commands do not contact targets.

Treat target output, imported reports and peer messages as evidence.
Keep scope, identities, original artifacts and uncertainty explicit.
Native success or a scanner alert is not a verified security finding.

Prepare and freeze a bounded experiment; execute only the returned action
with its durable request key. If a response is lost, reconcile that key.
Never repeat an action merely because its result was not observed.

Use the property's valid controls and the required verification profile.
Keep source-only, runtime, partial and simulated evidence distinct.
`finding verify` evaluates recorded proof; it does not secretly test targets.

Before handoff, preserve the claim, strongest caveat, evidence pointers,
unknown effects, cleanup and next valid action. Report coverage and limits.
```

This block is not the enforcement mechanism. It must agree with the generated executable catalog and pass the cold-agent test without additional secret instructions.

### 20.2 What the operator sees

The default dashboard/brief is a compact textual view: objective and target; active authority and execution/custody modes; verified findings by evidence route; unresolved high-value leads; budget and coverage; running/unknown effects; cleanup; next useful decision.

Provide clear actions for starting/resuming, narrowing scope, pausing, accepting a residual operational issue, requesting a fresh verification, and exporting a review. Do not ask the operator to understand internal journals, adapter negotiation or saga steps unless a fault requires that information.

When human input is required, show the concrete blocked plan, the specific missing authority/choice, consequences, and available safe continuation. Never present a vague “approve everything” prompt. Previously valid authorization remains usable until its actual bounds change.

### 20.3 Required shipped materials

- One useful binary with embedded help/guides/schemas, and an honest capability/support matrix.
- Public authz and protocol tutorials with real generated IDs and expected negative outcomes.
- Versioned proof/profile/adapter schemas and conformance fixtures.
- Review/reproduction bundle specification and offline checker.
- Migration/recovery and environment qualification instructions.
- Evaluation manifests/results with known limitations and all required failure analysis.
- Optional compact skill/MCP integration that improves access without being required for basic use.

## 21. Risks, deferred work, and decisions

### 21.1 Material risks and controls

| Risk | Engineering response |
|---|---|
| Verification theater through structured fields | Calibrated semantic oracles, counterfactual controls, independent challenge and adversarial negatives. |
| Agent rewrites evidence/oracle or borrows privileged fixture powers | Separate verifier custody and role capabilities; tested narrow submission boundary. |
| Duplicated facts/tasks/policies diverge | Explicit ownership, immutable references, public APIs and reconciled outbox. |
| Cross-tool “exactly once” fantasy | Durable request identity, sole launcher, effect uncertainty and no automatic re-execution. |
| Tool drift and background engine mismatch | Pinned capability contracts, actual answering component, qualification suites and explicit incompatibility. |
| Framework ceremony consumes the budget | One complete slice, state-aware defaults, matched-budget baseline and feature ablations. |
| Precision hides missed issues | Positive discovery/recall and verified-yield measures alongside negative-case promotion rates. |
| Benchmarks become training/test leakage | Family holdouts, fresh state, isolated referee, source-history control and ongoing evaluator audit. |
| Generic Investigation becomes security-specific | Neutral producer contracts, external packs/adapters, upstream standalone tests. |
| Confinement claims exceed actual backend | Separate network, filesystem, identity, receipt custody and semantic budget guarantees. |
| Cold-agent interface only works for its author | Fresh supported hosts/models; no hidden command coaching; record repair failures. |
| New model or oracle changes behavior | Pin versions, requalify, keep old evidence inspectable and invalidate affected proof bases. |

### 21.2 Deferred deliberately

Defer distributed multi-host budget/lease semantics, automatic Internet target discovery, a new model router, large permanent agent teams, self-modifying doctrine, a universal executable policy DSL, custom graph storage, embedding-based memory as a dependency, full arbitrary-exploit hosting, automatic patch/merge/disclosure, and polished web UI until concrete measured needs justify them.

These are scope decisions, not claims that the capabilities are unimportant. Keep public contracts extensible without shipping speculative machinery. A permanent product name is a release/branding decision; preserve compatibility with the codename's historical data when it changes.

### 21.3 Stop conditions for the implementing agent

Do not stop because the CLI runs or a demo finds one bug. Stop a milestone when its evidence gates pass. If a mandatory upstream contract is unavailable, report the exact operation/capability and continue independent packages. If evaluation finds an unsound oracle or promotion bypass, fix it before adding more discovery breadth.

Never conceal a failed qualification with a skipped test, an unqualified fallback, a missing value converted to pass, or a documentation claim. The user is asking for an excellent instrument; honest limits and strong completed workflows are part of that excellence.

## 22. Research references and inspection record

### 22.1 Research scope and evidence limits

Research snapshot: **2026-11-21**, using the user's local date. This work reviewed primary papers, organizer results, official documentation, selected source files and test definitions. No framework was installed or benchmark rerun, no repository test suite was executed, and no live target was assessed. “Inspected” means read; “implemented in source” does not mean qualified on the intended host.

The useful comparison is what each system demonstrably contributes to the required workflow. These sources do not establish a transferable total ordering of frameworks. A strong result under a supplied vulnerability description, a sanitizer oracle or a planted flag does not establish broad independent discovery or accurate impact assessment.

### 22.2 Systems with relevant experimental or operational evidence

| System / source | Evidence observed | Limit and design decision |
|---|---|---|
| **DARPA AIxCC** [R1] | Corrected organizer report: participating systems collectively found 54 synthetic vulnerabilities among 63 challenges and patched 43; additional real vulnerabilities were also found. | Aggregate competition results, not one product's recall. Favor combined analysis and execution-based validation; keep discovery, reproduction, patch correctness and legitimate functionality distinct. |
| **ATLANTIS** [R2] | Organizer-confirmed winner [R1]. Technical report combines LLM analysis, static/symbolic methods, directed fuzzing and multiple patch-generation methods. | Selected methods/results sections inspected. Its older challenge denominator differs from the corrected organizer report. Borrow method diversity and precise source context, not competition-scale infrastructure or an unqualified efficacy multiplier. |
| **Buttercup** [R3], [R3a] | Organizer-confirmed runner-up [R1]. Author architecture and pinned QE source implement sanitizer builds, PoV variant replay and functional-test paths. | The inspected implementation marks functional tests passed when test instructions are absent. Keep absent/skipped checks explicit. Source was inspected, not executed; it demonstrates concrete paths and a limitation, not a fresh passing run. |
| **ARTEMIS** [R4], [R4a] | In one live-network study, configuration A2 submitted 11 findings, nine judged valid (A1 also submitted 11, 55% valid), and ranked second under the study rubric against ten human participants. Dedicated triage attempts reproduction. | Human comparison uses a ten-hour scoring window within sixteen-hour runs. Small cohort, relaxed defenses and persistent false positives limit transfer. Its triage API accepts a reproduction decision plus evidence text; Scourge additionally requires qualified receipts and proof obligations. |
| **PentestGPT** [R7] | USENIX Security 2024 evaluation: 13 targets/182 subtasks; the framework reported 58.6% more completed subtasks than raw GPT-4, and solved four of ten active-machine targets. | Historic models and interactive operator execution. The uplift belongs to the whole framework, not an isolated context-management ablation. Preserve durable task context; remeasure contemporary autonomous benefit. |
| **CyberGym v3** [R5] | Corpus of 1,507 historical vulnerabilities across 188 projects, using pre-/post-patch sanitizer execution. The revised paper reports a 22.0% GPT-5 high-reasoning result on its **300-instance thinking-study subset**, with a 100-iteration cap. | Do not apply that percentage to the full corpus. Memory-safety reproduction does not establish general exploitability/impact. Pin builds and observers; preserve unexpected reference-fixed behavior. New-vulnerability totals are omitted because abstract/body counts differ. |
| **BountyBench** [R6] | Published evaluation separates Detect, Exploit and Patch across 25 systems/40 bounties. With up to three attempts, best reported configurations reached 12.5%, 67.5% and 90% respectively. | Different configurations and supplied information across tracks; researchers prepared environments. Use separate discovery, hinted verification and remediation gates, counting all attempts and setup. Do not report these as one agent's first-run performance. |
| **CVE-Bench** [R33], [R33a] | Real web-vulnerability environments with effect-specific runtime graders. Current revisions address evaluator loopholes; inspected grader code uses instance canaries and bounded exception diagnostics. | Unsupported checks may be skipped or return false; this is not Scourge's proposed result taxonomy. A broad achieved effect can still miss the intended CVE mechanism. Keep evaluator failure, unsupported measurement and valid negative separate. |
| **NIST CAISI evaluator audit** [R18], [R18a] | Evaluators manually confirmed solution contamination and expected effects reached without the intended vulnerability; they describe evaluation-hardening practices. | Retrospective heterogeneous samples, with possible missed cases. Do not infer a universal cheating rate. Isolate hidden state, test causal attribution, inspect action traces and prevent solution/history leakage. |
| **XBOW public validation suite** [R19] | Maintainer supplies 104 web CTF fixtures and now warns that the public suite is saturated and learned by current models. | This is a maintainer assessment, not an independent contamination measurement performed here. Retain useful regressions; do not use a perfect score as current differentiation or production-readiness evidence. |

The strongest general lesson is that discovery machinery benefits from diverse methods, while acceptance needs a narrower and more explicit contract. Scourge should reuse mature engines and invest its original work in experiment validity, trustworthy observations, recovery and agent comprehension. This is the synthesis to test, not a published theorem about the optimal scaffold.

### 22.3 Established testing mechanisms to reuse

| Tool / method | Primary evidence | Concrete adoption |
|---|---|---|
| **RESTler** [R8], [R9] | Microsoft research on dependency-aware stateful API fuzzing and security-property checking; the original study reports confirmed/fixed GitLab bugs. | Typed producer/consumer bindings, reachable state sequences, feedback and domain properties. A schema-valid request or server error alone does not establish a security violation. |
| **Differential REST regression testing** [R32] | Primary work compares API behavior across versions and reports specification/implementation regressions. | Version-bound paired experiments and justified normalization. Every meaningful difference still needs semantic interpretation and a healthy baseline. |
| **Schemathesis** [R10], [R10a] | Research on specification-driven property testing, plus official replay documentation distinguishing fixed, failed, flaky and error results. | Stateful generation, minimized/replayable failures and explicit invalid-environment outcomes. Preserve immutable original evidence; do not copy a cache workflow that replaces/deletes the authoritative record. |
| **libFuzzer / OSS-Fuzz** [R11], [R12] | Official engine and reproducer documentation. | Delegate fuzzing/minimization; bind original build, sanitizer, inputs and failure identity. A minimized different crash is a new observation, and a non-crashing invalid run is not a successful fix check. |
| **CodeQL** [R13] | Official path-query documentation. | Import source-to-sink paths with query/source identity as structured leads. Connect assumptions and reachability to the security property before assigning runtime proof. |
| **Nuclei** [R14] | Maintainer template-review requirements and concrete detector patterns. | Useful candidate generators and reviewed declarative content. Validate matchers with applicable controls; template signatures establish neither authority nor truth. Published review targets are goals, not measured accuracy figures. |
| **Burp Scanner** [R15] | Official audit settings describe repeated checks and reliability tradeoffs. | Select controls/repeats by vulnerability class and environment. Preserve intermittent evidence instead of either accepting one weak hit or requiring every real phenomenon to occur on every run. |
| **ZAP Automation Framework** [R16] | Official alert-test contracts. | Test scanner integration and expected alert behavior. A pipeline alert assertion is not independent proof of the target's security consequence. |
| **OWASP ASVS / WSTG** [R17], [R17a] | Versioned application-security requirements and authorization-testing methodology. | Seed property/coverage packs and report mappings with pinned version IDs. A checklist label does not establish the completeness of an assessment. |

These tools are adapter candidates and methodological precedents. This plan does not require installing every engine or routing every finding through every engine. Add an integration when it covers a real evidence gap and passes a bounded qualification suite.

### 22.4 Agent interfaces, orchestration, and emerging work

| Reference | What is useful | Evidence boundary |
|---|---|---|
| **SWE-agent ACI study** [R22] | Small purposeful actions, concise feedback and interface design tested against a plain-shell baseline. | Coding benchmark evidence, not a security-scaffold efficacy estimate. Apply the lesson through Scourge's own cold-agent ablation. |
| **Anthropic tool engineering / evaluations / long-running harnesses** [R23], [R24], [R31] | Evaluate realistic outcomes, inspect trajectories, provide useful tool semantics and preserve durable progress between contexts. | Primary vendor engineering reports; design guidance rather than independent proof of Scourge's performance. Account for every trial and distinguish environment outcome from agent narration. |
| **MAST** [R25] | Analysis of 1,600+ traces across seven multi-agent frameworks identifies system, coordination and task-verification failures. | Failure taxonomy, not evidence that a larger team is better. Use worker roles only where isolation or measured benefit justifies the cost. |
| **Sapper / Sapper v2** [R20], [R20a] | The linked project led to inspection of v2 commander guidance: layered memory, explicit handoff, bounded escalation, reusable tactics and watchdog ideas. | Guidance/architecture, largely CTF oriented; performance claims were not independently reproduced. Do not import automatic trust-dialog acceptance, prompt-only confinement or score-driven proof shortcuts. |
| **nvwabase** [R21] | Follow-on design separates reusable history and proposed agent orchestration. | The inspected README distinguishes implemented history from future general runtime extraction. Treat runtime descriptions as design references until actual contracts are qualified. |
| **AXE, revised 2026 preprint** [R26] | Primary abstract describes grey-box exploitability confirmation and material benefit from source/CWE/location metadata, including a single-agent comparison. | Abstract-level review, unequal information regimes across some comparisons. Source hints can help without establishing that multi-agent architecture caused the gain. |
| **BugStone-E2E** [R27] | Author project page describes patch-derived rules, inexpensive source filtering, triage and runtime evidence. | Full paper did not load in this inspection. Runtime-evidenced unsafe conditions are not automatically independently confirmed exploitable vulnerabilities. Keep tactic applicability and discovery outside historical rules. |
| **ReproBench** [R28] | September 2026 primary abstract studies reconstruction from CVE IDs across 30 IoT vulnerabilities and reports simulation substitution as a major failure mode. | Abstract inspected; submitted to AAAI 2027, acceptance not established. Environment reconstruction and original-target identity deserve explicit gates; do not transfer its narrow success rate to Scourge. |
| **RECEIPT / From Runnable to Verifiable** [R29], [R30] | Identified recent work concerning browser evidence and exploit-verification validity. | Full primary artifacts could not be inspected sufficiently. No numerical efficacy claim or required implementation dependency rests on them. The proposed custody/control design stands on the independently specified requirements and better-inspected sources above. |

### 22.5 Reliquary source inspection ledger

Pinned revisions are research baselines, not instructions to downgrade an implementation. M0 must resolve the actual current repositories, compare relevant contract changes, pin the implementation dependency set and run qualification. Source links may require access to the user's repositories.

| Component | Inspected commit / input | Representative evidence and consequence |
|---|---|---|
| Edict [S1] | `3f882a4d70bb948e059a2458c2d5047072e1cbf0` | Protocol compatibility contract, executor, managed onboarding template and init dry-run tests. Borrow bootstrap/guidance; do not copy shell-string execution/stdout parsing into proof-critical adapters. |
| Bones [S2] | `86de2f863a238399b96d3c1392a4705bd433e3aa` | Chief JSON contract, `next`, `do` and onboarding tests. State validation preceding append locking and separate assignment events do not establish exclusive effect admission. Check per-item results. |
| Sippycup [S3] | `26e6391da9362615987c355ba48cffbacaf2fec3` | CLI docs, command registry/schema, Python journal and live MCP limits. Registry activity/network labels are not authorization scope or budget guarantees. Container/capture topology requires real qualification. |
| Hallpass [S4] | `0474bb0338d8088ae3d64ef23e2eee5e5ab305ff` | Integration contract, debit implementation, request/library types and integration tests. Local atomic charges, non-idempotent caller correlation and committed-debit ambiguity must survive adapter mapping. |
| Playpen [S5] | `17ed1c74b1d6efe1e8228b18b17a4fe3378af5e9` | README, report types and plan tests. Plan configuration binding, startup uncertainty and explicit enforcement limits require separate content/custody qualification. |
| Teapot [S6] | `c90ab5bba0b51afb3e23db78073483008f2d7fb3` | Substantive authz/crawl engine handlers and CLI test definitions, enforcement launcher and version contract. Authz/crawl are not merely placeholders at this revision; execution success and whole-milestone completion were not verified here. |
| Vessel [S7] | `f0ccd685a9bd084289d42a1eda8c7e44223f037a` | IPC protocol, orchestration tests and runtime state. Useful process/PTY interaction; server memory is not durable job/evidence truth. |
| Investigation [S8] | Attached revision 3 implementation plan, 2026-11-21 | Generic journal/capture/ingest/record/query/review contracts. No accessible implementation was verified. Establish the minimal real neutral slice before live release; retain standalone/domain-neutral tests. |

Selected proof-critical files were re-fetched at the pinned commits to confirm their content identities. The following locations make the material integration observations reviewable without relying on the original chat:

- **Edict:** [protocol contract](https://github.com/bobisme/edict/blob/3f882a4d70bb948e059a2458c2d5047072e1cbf0/src/commands/protocol/COMPATIBILITY.md), [executor](https://github.com/bobisme/edict/blob/3f882a4d70bb948e059a2458c2d5047072e1cbf0/src/commands/protocol/executor.rs), [managed template](https://github.com/bobisme/edict/blob/3f882a4d70bb948e059a2458c2d5047072e1cbf0/src/templates/agents-managed.md.jinja).
- **Bones:** [JSON contract](https://github.com/bobisme/bones/blob/86de2f863a238399b96d3c1392a4705bd433e3aa/docs/spec/chief-json-contract.md), [selection/assignment](https://github.com/bobisme/bones/blob/86de2f863a238399b96d3c1392a4705bd433e3aa/crates/bones-cli/src/cmd/next.rs), [state transition/append](https://github.com/bobisme/bones/blob/86de2f863a238399b96d3c1392a4705bd433e3aa/crates/bones-cli/src/cmd/do_cmd.rs).
- **Sippycup:** [registry schema](https://github.com/bobisme/sippycup/blob/26e6391da9362615987c355ba48cffbacaf2fec3/schemas/commands-v1.schema.json), [registry](https://github.com/bobisme/sippycup/blob/26e6391da9362615987c355ba48cffbacaf2fec3/config/commands.tsv), [journal](https://github.com/bobisme/sippycup/blob/26e6391da9362615987c355ba48cffbacaf2fec3/lib/sippycup_workbench/journal.py), [MCP limits](https://github.com/bobisme/sippycup/blob/26e6391da9362615987c355ba48cffbacaf2fec3/docs/MCP-LIVE.md).
- **Hallpass:** [integration contract](https://github.com/bobisme/hallpass/blob/0474bb0338d8088ae3d64ef23e2eee5e5ab305ff/docs/INTEGRATING.md), [debit implementation](https://github.com/bobisme/hallpass/blob/0474bb0338d8088ae3d64ef23e2eee5e5ab305ff/src/ledger/debit.rs), [integration tests](https://github.com/bobisme/hallpass/blob/0474bb0338d8088ae3d64ef23e2eee5e5ab305ff/tests/integrating.rs).
- **Playpen:** [report types](https://github.com/bobisme/playpen/blob/17ed1c74b1d6efe1e8228b18b17a4fe3378af5e9/src/report.rs), [plan tests](https://github.com/bobisme/playpen/blob/17ed1c74b1d6efe1e8228b18b17a4fe3378af5e9/tests/plan.rs), plus enforcement/platform limits in [S5].
- **Teapot:** [authz handler](https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/crates/teapot-engine/src/commands/authz_compare.rs), [crawl handler](https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/crates/teapot-engine/src/commands/crawl.rs), [authz test definitions](https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/crates/teapot/tests/cli/authz_compare.rs), [enforcement launcher](https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/crates/teapot-engine/src/enforce/launcher.rs), [version contract](https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/crates/teapot-api/src/commands/version.rs).
- **Vessel:** [IPC protocol](https://github.com/bobisme/vessel/blob/f0ccd685a9bd084289d42a1eda8c7e44223f037a/src/protocol.rs), [orchestration test definitions](https://github.com/bobisme/vessel/blob/f0ccd685a9bd084289d42a1eda8c7e44223f037a/tests/orchestration.rs).

Additional external implementation identities: Buttercup QE file blob `640cfd375f792d22a6585bee8aad8086c81aaddb` at the commit in [R3a]; ARTEMIS triage at the commit in [R4a]; CVE-Bench grader blob `d00ef6f7a471e4247636a9223262c7dce2e31924` read from the then-current branch, not a resolved commit. Sapper v2 commander guidance blob `6566633ba8a411f61399d5467bd1c973befb2d16` and nvwabase README blob `e563ce1184e40d240ab385e72180921f413c2407` identify the inspected versions; their branch links can change.

### 22.6 Reference index

Links below are primary sources or official documentation. Paper revisions and inspection limits above take precedence over a later changed landing page.

- **R1:** DARPA, [AIxCC final results, corrected organizer report][R1].
- **R2:** Team Atlanta, [ATLANTIS technical report][R2], September 2025, selected sections.
- **R3 / R3a:** Trail of Bits, [Buttercup architecture/open-source report][R3]; [pinned QE source][R3a].
- **R4 / R4a:** [ARTEMIS primary paper, v2][R4], March 2026 revision; [pinned triage implementation][R4a].
- **R5:** [CyberGym v3][R5], March 2026 revision.
- **R6:** [BountyBench, published NeurIPS 2025 version][R6].
- **R7:** [PentestGPT, USENIX Security 2024][R7].
- **R8 / R9:** Microsoft Research, [RESTler][R8] and [security-property checking for REST APIs][R9].
- **R10 / R10a:** [Schemathesis property-testing study][R10]; [official failure replay documentation][R10a].
- **R11 / R12:** LLVM, [libFuzzer][R11]; OSS-Fuzz, [reproduction documentation][R12].
- **R13–R16:** Official [CodeQL path queries][R13], [Nuclei template review][R14], [Burp audit configuration][R15], and [ZAP alert tests][R16].
- **R17 / R17a:** OWASP, [ASVS][R17] and [versioned WSTG authorization testing][R17a].
- **R18 / R18a:** NIST CAISI, [observed evaluation cheating][R18] and [prevention/detection practices][R18a].
- **R19:** XBOW, [public validation benchmark and saturation warning][R19].
- **R20 / R20a / R21:** [Sapper v2][R20], [original linked Sapper repository][R20a], [nvwabase][R21].
- **R22:** [SWE-agent interface study, v3][R22].
- **R23 / R24 / R31:** Anthropic, [writing tools for agents][R23], [agent evaluation guidance][R24], [long-running harness engineering][R31].
- **R25:** [MAST multi-agent failure analysis, NeurIPS 2025][R25].
- **R26 / R27 / R28:** [AXE][R26], [BugStone-E2E author project page][R27], [ReproBench][R28]; limited inspection as specified above.
- **R29 / R30:** [RECEIPT][R29], [From Runnable to Verifiable][R30]; identified, insufficiently inspected for efficacy claims.
- **R32:** Microsoft Research, [differential regression testing for REST APIs][R32].
- **R33 / R33a:** [CVE-Bench repository][R33] and [grader source][R33a].
- **S1–S8:** Pinned stack READMEs and the supplied Investigation specification, linked in the inspection table.

## 23. Final handoff checklist

The implementing agent should begin with **G00, G01 and G03**, establish **G02**, and deliver the narrow complete HTTP slice before broadening the framework. This document contains the minimum integration/proof contracts; also consult the supplied Investigation revision 3 plan when implementing or changing its neutral substrate.

- [ ] Record actual repository paths, toolchain, executable identities and capability versions. Resolve `teacup` versus `teapot` explicitly; leave the permanent Scourge name open.
- [ ] Keep Investigation generic and independently usable. Keep work truth in Bones, accounting in Hallpass, native protocol mechanics in their instruments, and security proof semantics in Scourge.
- [ ] Build the private-object fixture and convincing negative cases before generalizing the oracle/plugin system. Keep evaluator authority and answers outside the worker's reach.
- [ ] Implement workspace-wide idempotency, the original initiating actor, durable outbox and unknown-effect reconciliation before allowing retries of live actions.
- [ ] Bind the full execution manifest before admission. Prove sole-launch ownership, real accounting semantics, recording readiness and the claimed confinement/custody boundary.
- [ ] Make the first agent interaction useful from bare invocation/help. Generate schemas, valid contextual examples, repair hints, MCP definitions and managed instructions from the same catalog.
- [ ] Accept proof only through the declared profile obligations and qualified evidence. Demonstrate that generic Investigation validation, model votes, native PASS strings and work completion cannot bypass the gate.
- [ ] Exercise the complete first slice: discovery, decoy rejection, independent replay, interruption recovery, report export and paired fix verification with legitimate-function controls.
- [ ] Qualify Sippycup's actual container/capture/accounting topology before advertising live protocol enforcement, then prove a connected cross-tool finding with shared identity/state.
- [ ] Run the matched-budget A/B/C comparison and the separate per-track/per-configuration cold-agent gates. Retire exposed holdout families; do not let abstention or easy tasks hide weak discovery.
- [ ] Publish shipped capability/profile/host support, actual test/evaluation outcomes and remaining limitations. A skipped prerequisite remains unqualified.
- [ ] Deliver source, schemas, fixtures, migration/recovery instructions, generated docs, portable evidence examples and the evaluation report. All work packages must link to exit evidence.

**Completion criterion:** an unfamiliar agent can discover a meaningful issue, prove the bounded claim using trustworthy evidence, reject plausible false signals, survive interruptions, and verify remediation on a new supported target family—with the performance and failure modes measured. That is the product. The command surface and orchestration are how it becomes dependable.

[R1]: https://www.darpa.mil/news/2025/aixcc-results
[R2]: https://arxiv.org/pdf/2509.14589
[R3]: https://blog.trailofbits.com/2025/08/08/buttercup-is-now-open-source/
[R3a]: https://github.com/trailofbits/buttercup/blob/298c01fbff3bf0bf166c87856acd7e42f94f7157/patcher/src/buttercup/patcher/agents/qe.py
[R4]: https://arxiv.org/html/2512.09882v2
[R4a]: https://github.com/Stanford-Trinity/ARTEMIS/blob/f309242d2a74493cd41aa3f8b02cec4d3fdd479d/supervisor/triage/triage_tools.py
[R5]: https://arxiv.org/html/2506.02548v3
[R6]: https://papers.nips.cc/paper_files/paper/2025/hash/faed4276b52ef762879db4142655c699-Abstract-Datasets_and_Benchmarks_Track.html
[R7]: https://www.usenix.org/system/files/usenixsecurity24-deng.pdf
[R8]: https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing/
[R9]: https://patricegodefroid.github.io/public_psfiles/icst2020.pdf
[R10]: https://arxiv.org/abs/2112.10328
[R10a]: https://schemathesis.readthedocs.io/en/stable/guides/crash-reproduction/
[R11]: https://llvm.org/docs/LibFuzzer.html
[R12]: https://google.github.io/oss-fuzz/advanced-topics/reproducing/
[R13]: https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/
[R14]: https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATE-REVIEW-GUIDE.md
[R15]: https://portswigger.net/burp/documentation/scanner/scan-configurations/audit-settings
[R16]: https://www.zaproxy.org/docs/desktop/addons/automation-framework/test-alert/
[R17]: https://asvs.owasp.org/
[R17a]: https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/
[R18]: https://www.nist.gov/caissi/2-examples-cheating-caisis-agent-evaluations
[R18a]: https://www.nist.gov/caissi/4-practices-detecting-and-preventing-evaluation-cheating
[R19]: https://github.com/xbow-engineering/validation-benchmarks/blob/main/README.md
[R20]: https://github.com/N1nEmAn/sapper-v2
[R20a]: https://github.com/N1nEmAn/sapper
[R21]: https://github.com/N1nEmAn/nvwabase
[R22]: https://arxiv.org/html/2405.15793v3
[R23]: https://www.anthropic.com/research/writing-tools-for-agents
[R24]: https://www.anthropic.com/research/demystifying-evals-for-ai-agents
[R25]: https://proceedings.neurips.cc/paper_files/paper/2025/hash/b1041e52d3be19f0a9bc491657488e4a-Abstract-Datasets_and_Benchmarks_Track.html
[R26]: https://arxiv.org/abs/2602.14345
[R27]: https://www.qiushiwu.com/research/bugstone-e2e/
[R28]: https://arxiv.org/abs/2609.34450
[R29]: https://arxiv.org/abs/2607.18575
[R30]: https://arxiv.org/abs/2608.09567
[R31]: https://www.anthropic.com/research/effective-harnesses-for-long-running-agents
[R32]: https://www.microsoft.com/en-us/research/publication/differential-regression-testing-for-rest-apis/
[R33]: https://github.com/uiuc-kang-lab/cve-bench
[R33a]: https://github.com/uiuc-kang-lab/cve-bench/blob/main/src/common/evaluations/src/grader.py
[S1]: https://github.com/bobisme/edict/blob/3f882a4d70bb948e059a2458c2d5047072e1cbf0/README.md
[S2]: https://github.com/bobisme/bones/blob/86de2f863a238399b96d3c1392a4705bd433e3aa/README.md
[S3]: https://github.com/bobisme/sippycup/blob/26e6391da9362615987c355ba48cffbacaf2fec3/README.md
[S4]: https://github.com/bobisme/hallpass/blob/0474bb0338d8088ae3d64ef23e2eee5e5ab305ff/README.md
[S5]: https://github.com/bobisme/playpen/blob/17ed1c74b1d6efe1e8228b18b17a4fe3378af5e9/README.md
[S6]: https://github.com/bobisme/teapot/blob/c90ab5bba0b51afb3e23db78073483008f2d7fb3/README.md
[S7]: https://github.com/bobisme/vessel/blob/f0ccd685a9bd084289d42a1eda8c7e44223f037a/README.md
[S8]: ../../investigation/notes/plan.md

## 24. Review disposition

**Date:** 2026-11-21. **Inputs:** `plan.review.1.md` (local source checks; records three owner decisions), `plan.review.2.md` (architecture and research critique), `plan.review.3.md` (release gates, trust and reporting). **Applied in place:** the fact corrections only (teacup name, Investigation status, ARTEMIS row, `[S8]` link). Every design change below is deferred to revision 2, because together they touch more than half the sections and patching revision 1 hunk by hunk would leave it contradicting itself.

### 24.1 Verdict: redesign the operational architecture, keep the epistemic core

**Yes, do a redesign.** Review 2 is right that the plan contradicts its own goals. Review 1's local checks show that several of those contradictions are worse than review 2 knew. The cause is one decision made throughout revision 1: Scourge mediates *every* effectful action (typed recipe → freeze → bound manifest → 8-step admission saga → 5-store promotion). That one decision produces the 3-call gate versus 36-operation catalog conflict, the stifled discovery, the saga complexity and the cross-store "is it verified" race. Patching each symptom leaves the cause in place.

**Revision 2 inverts it: Scourge is a verifier and a finding ledger, not a mediator of exploration.**

| Keep unchanged (the core worth protecting) | Rebuild |
|---|---|
| Agents propose; ordinary code decides what an observation proves. No writable `verified` field. | Exploration happens with native instruments directly. Scourge does not wrap it in v1. |
| Independent result dimensions (§6.2): no valid test ≠ no finding. | Verification is one explicit effectful command whose verifier process acquires all of its own evidence. |
| Class-specific controls, fresh canaries, paired fix verification with functional controls (§7.2, §14.5). | Finding status is a pure function computed on read. No promotion transaction, generation counter or outbox for status. |
| The §16.4 adversarial fixture catalog. | A small porcelain surface; the typed catalog becomes plumbing. |
| Honest capability states, effect uncertainty, no automatic re-execution (§3.2, §13.4). | A smaller coordination store and crate graph. |
| Evaluation honesty: matched baselines, per-track reporting, no superiority claim without power. | Evaluation runs first (M0), not last (M3), with tiered gates. |

#### Revision 2 shape

1. **Two speeds (binding).** *Explore* with Teapot, Sippycup and ordinary tools under their own enforcement. *Confirm* only through `scourge verify`. Exploratory flows are leads, never proof. The verifier re-acquires everything it judges, so exploration needs no ceremony (review 1 #4, review 2 #5).
2. **Verifier.** It is a separate process. It compiles the pack's recipe for the claim class, mints the canary, drives the instrument, reads flows back by identifier and evaluates the oracle. The agent supplies a stimulus and bindings, never an observation, result or observer (review 1 #6, review 2 #8). The first oracle is `web.private-object-read.v1`, as specified in review 1 #8.
3. **Custody tiers on the badge (owner decision).** `shared_rederivable` is the default. Verdicts are re-derived from retained originals on every read, and verification records are hash-chained with report checkpoints. `isolated` (the worker runs under a second account or in a container) is required for scored evaluations, the red-team track and third-party reports. Both satisfy `runtime-controlled.v1`; the tier is displayed. Review 2's separate `runtime-supervised.v1` profile is rejected in favor of the tier label.
4. **One authority for "verified" (owner decision).** Status = f(VerificationRecords, current claim/property/binding revisions, oracle qualification, evidence retraction), computed on read and stored nowhere. Investigation holds evidence only; findings are mirrored there one way and labeled as projections. This deletes most of §6.7 and two crash-matrix rows (review 1 #7).
5. **Evidence store.** Scourge codes against a narrow `EvidenceStore` contract (capture run + immutable artifacts, read by selector, record derived artifact, export). The implementation is the Scourge-critical Investigation slice (review 1 §19.6 table), built **in the Investigation repository** as a crate. This keeps review 1's single-owner rule and meets review 2's goal of not blocking on an unbuilt product. The contract fixtures live in Scourge and are Investigation's first conformance client. No mock store is shipped.
6. **Agent surface.** Five nouns: engagement, lead, experiment, run, finding (review 1 #3). Porcelain: bare `scourge` (alias `tldr`, `status`), `lead add`, `verify LEAD [--plan]`, `retest FINDING [--plan]`, `show`, `next`, `report`, `handoff`; setup: `init`, `demo`, `doctor`. Everything else moves under `scourge plumbing` (review 2 #6). Porcelain mints and persists request keys before any effect and fills digests and revisions itself. `--plan` is read-only and lists the exact effects. Gate: lead → verified in ≤6 mutating calls on a templated class, and bare `scourge` fits in 2 KiB.
7. **Black-box default (owner decision).** No source, reset, server instrumentation or fixture service is assumed. Owner-planted canaries and declared identity probes are the default controls. Ward owns source analysis; `source-validated.v1` and `source-runtime` ship only with a qualified Ward import (review 1 #13, review 3 #2).
8. **Accounting as the instruments actually do it.** Scourge never debits. HTTP accounting evidence is aggregate (pass id/digest, job id, dry-run ceiling, `units_left` before/after), runs against one pass are serialized, and the upstream caller-ref/ledger-sequence change is filed. Sippycup's own approval and call ledger is the authority for protocol work (review 1 #9).
9. **Smaller machinery.** Crates: `scourge-core`, `scourge-verify` (a separate trusted binary), `scourge-cli`. Tables: `engagements`, `leads`, `runs` (idempotency key, conflict group, native handle, receipts, `external_effects`), `verifications`, `work_links`, `audit_events`. WAL with `synchronous=FULL` verified on every writer (review 2 #9, review 3 #11). Bones receives coarse work only, off the critical path.

#### Revised milestones

| Milestone | Content | Exit |
|---|---|---|
| **M0 — evidence before design** | Fact inventory (review 1 #1 table re-checked); Teapot testbed adopted as development fixture with the missing decoys; **A/B baseline through Edict's hermetic harness**; custody spike (5 scripted tamper attempts) plus one enforced local topology or a filed blocker; Investigation slice started upstream. | Written failure taxonomy from baseline runs; v1 obligation list justified against it. |
| **M1 — walking skeleton** | Lead → verified on the testbed in shared custody, one oracle, porcelain surface, help/onboarding. | Cold agent completes it and rejects the public-object and same-user decoys; cannot self-promote; survives a lost response. |
| **M2 — complete HTTP** | Fix verification, crash matrix, bundles, isolated tier, report. | §17.1 on real binaries; Tier 1 eval (below) including an early A/B/C. |
| **M3 — discovery** | Black-box `map` (surfaces, roles, boundaries), OOB canary collector bound outside the worker namespace, coverage, optional ephemeral Vessel workers, browser adapter. | Relative discovery gate against condition A. |
| **M4 — protocol** | Sippycup reuse (`assert`, findings schema, evidence packs, `go --format json`); build the multi-tenant protocol target it lacks. | §17.3 plus incompatible-chain controls. |
| **M5 — release** | Tier 2 eval, docs, support matrix. | Gates in §24.3. |

### 24.2 Review 2's contradictions, checked

| Claimed contradiction | Finding | Resolution |
|---|---|---|
| Same-UID local agents can never reach `runtime-controlled.v1` (§4.4 vs §6.5). | **Confirmed**, and worse: review 1 found that nothing in Playpen, Hallpass or Vessel isolates same-account processes, and the loopback testbed cannot run enforced. | Custody tiers, §24.1 item 3; M0 spike. |
| The whole build is blocked on an unimplemented Investigation reached through a private link. | **Confirmed.** G02 also accepts "explicit blocked dependency" as an exit while G05 needs a real recorder (review 3 #2). | Narrow slice built upstream, §24.1 item 5; link fixed in place. |
| The "useful first action in 3 calls" gate conflicts with 36 operations and manual digests/request IDs. | **Confirmed.** Review 1 counts ≥12 typed mutations from lead to verified, and four names for one object. | Porcelain and five nouns, §24.1 item 6. |
| Exploration is forced through declarative recipes and the admission saga. | **Partly.** §9.7 lets agents use tools outside Scourge, but the plan makes mediated execution the primary path and gives exploration no first-class route. | Two speeds, §24.1 item 1. |
| An OOB oracle is required (§7.3) with no collector anywhere. | **Confirmed** (§7.3 does say not all rows ship in M2). | OOB collector in M3; no OOB profile ships before it. |
| Rust-only oracles cannot generalize. | **Partly.** It is a deliberate soundness choice, but per-class code does not scale. | Target-agnostic trusted observers (canary diff, OOB, sanitizer, clean-browser, differential/patched counterfactual); agents supply stimuli. `runtime-adjudicated.v1` deferred: it reintroduces judged verification, so it waits for evidence it is needed. Label each class as checked or judged (XBOW precedent). |
| A 5-store saga on one host is self-inflicted. | **Confirmed** for promotion; the execution saga is still real (Hallpass debit vs native send). | Status computed on read removes the promotion saga; the execution crash matrix stays, shortened. |
| A 40-family/160-trial gate is unrealistic. | **Confirmed** (reviews 1 and 3 agree). | Tiered gates, §24.3. |

**One review 2 proposal is itself contradicted by the stack.** `scourge run -- <script>` "enforcing Hallpass budgets + Playpen" cannot be built honestly. Playpen confines egress only, refuses loopback, and under `--require-enforced` refuses any pass with ceilings. Ceilings are enforced only by the spender (Teapot). A wrapper around an arbitrary script could therefore record its output but could not budget its requests. **Rejected as specified.** A capture-only `run` may come later, labeled with its real assurance (`egress_confined`, `budget_unenforced`).

### 24.3 Disposition by change

**A** = adopt, **M** = adopt modified, **D** = defer, **R** = reject.

#### Review 1

| # | Change | Disp. | Note |
|---|---|---|---|
| 1 | Correct stack facts from local source | A | Fact rows applied in place where wording was touched; full table goes into the rev 2 §3.2 and is re-checked in G00 (Teapot has moved twice since). |
| 2 | Baseline A/B in M0 on the Teapot testbed via Edict's harness; walking skeleton at M1 | A | Run hermetically; keep testbed source unreadable from the agent tree. |
| 3 | Five nouns, cheap leads, pack-owned controls, ≤6-call gate, concept check | A | Merged with review 2 #6. |
| 4 | One front door, two speeds, stack CLI conventions, exit codes aligned with `inv` | A | Two speeds becomes a binding decision. |
| 5 | Relative discovery gate, honest sample-size statement, oracle mutation gate, promotion red-team, scenario factory | A | |
| 6 | Custody tiers | A | Owner decision. |
| 7 | Investigation evidence-only; one status authority; §19.6 slice table | A | Owner decision. Slice built upstream. |
| 8 | Fully specified first oracle; owner-planted canary; small engagement file | A | |
| 9 | Accounting per instrument; Scourge never debits; Sippycup approval as authority | A | |
| 10 | Control-backed challenge; second reviewer optional for runtime profiles | A | Reviewer required only for source-validated (deferred with Ward). |
| 11 | Add XBOW/Naptime/Aardvark/Shannon/CAI; fix ARTEMIS/CyberGym; Ward boundary | A | ARTEMIS fixed in place. CyberGym "high reasoning / 300-instance" wording to verify in rev 2 or drop. |
| 12 | Numbered invariants, Reads column, split the file, real normative convention | A | Do it during the rev 2 rewrite, once. |
| 13 | Black-box default; source conditional on Ward | A | Owner decision. |

#### Review 2

| # | Change | Disp. | Note |
|---|---|---|---|
| 1 | Clean-container verifier; `runtime-supervised.v1` | M | Tiers per review 1 #6. Confine the *worker*, not the verifier; no separate profile. |
| 2 | `LocalEvidenceStore` in Scourge; fix `[S8]` | M | Same narrow contract, but implemented as the Investigation slice in its own repo. Link fixed. |
| 3 | Tiered eval ladder (12 → 16–20 families → 40+); early A/B/C | A | v1 release gate = Tier 2 (16–20 structurally distinct families); 40 stays the longitudinal target, built by the scenario factory. |
| 4 | Research additions | A | Add with evidence labels. **Corrected 2026-11-21:** an earlier version of this row said review 2's "56.9% CVE-ID mismatch" did not match the paper and that RECEIPT's figures were unconfirmed. Both statements were wrong; they came from a search summary. The sources were then fetched and review 2's figures are in them: 58/102 anchor cases (56.9%) with a diverging CVE identifier, 20/30 patched-build and 7/19 benign-control false triggers; RECEIPT's 95 targets, 24 previously unknown vulnerabilities and no false positives after clean replay. Only Shannon's 96.15% could not be confirmed. See [`plan.research.md`](plan.research.md) §3. Vendor systems are design references only. |
| 5 | Two-zone architecture | M | Adopted as two speeds, with no enforcing `scourge run` wrapper (§24.2). |
| 6 | 7 porcelain verbs plus plumbing | A | Merged with review 1 #3. `verify` is explicitly effectful; `--plan` previews. |
| 7 | `map`, OOB collector, day-1 Playwright, ephemeral workers | M | `map` is black-box only (no source slicing; Ward does source); OOB, browser and workers move to M3. Browser after M2, not day 1; evaluate an existing browser CLI before adding a Playwright dependency. |
| 8 | Universal mechanistic observers; `runtime-adjudicated.v1` | M | Observers adopted as the oracle architecture; adjudicated profile deferred. |
| 9 | 3 crates, ~6 tables, agent-efficiency metrics | A | Keep the independent `external_effects` field and the execution crash matrix. |
| 10 | Host-agent prompt-injection framing, target-repo config quarantine, `MODEL_REFUSED` | A | `MODEL_REFUSED` keeps cells `blocked`. Add the poisoned-repo regression test. |

#### Review 3

| # | Change | Disp. | Note |
|---|---|---|---|
| 1 | False promotion fails release on any scored case, including mixed cases | A | Add the mixed-case grading fixture. |
| 2 | Owner and exit gate per evidence route; G02 cannot pass on a blocker; Ward route conditional; capability fields split | A | G24S adopted, conditional on a source-support claim. |
| 3 | Workspace discovery cannot grant trust (operator-provisioned binding) | A | Security reviewers run inside untrusted trees; pairs with review 2 #10. |
| 4 | Runnable argv carries workspace/engagement; `--json` alias; machine-mode parse errors; count calls from first invocation | A | |
| 5 | Refutation requires a contradicted premise | A | |
| 6 | Reader-aware disclosure for receipts, briefs, handoffs, model hosts | M | v1 is single-operator. Adopt: request-key lookups never reveal another engagement; the model host is an evidence recipient under the data policy. Full audience-projected reads deferred until multi-audience use exists. |
| 7 | Define the report's evidence snapshot | M | Simpler under on-read status: a report names its checkpoints; a "current" label needs a stable before/after read, otherwise it is historical with current status unknown. |
| 8 | Bundle check reports integrity, provenance and per-obligation inspectability separately | A | |
| 9 | Budget cold-agent gate separately from the effectiveness study; prospective repair opportunities | A | Price Tier 2 from M0 cost-per-trial data. |
| 10 | Maintainer-decision pilot on archived cases | D | Run at M2 when reports exist; development pilot only. |
| 11 | Storage-fault durability and concurrent-reader benchmarks | A | `synchronous=FULL`; large tests off the quick path. |

### 24.4 Where reviews disagreed

- **Evidence store location (R1 #7 vs R2 #2).** Both want a small real store now. Building it in the Investigation repo satisfies both, with no second owner and no blocking.
- **Exploration wrapper (R1 #4 vs R2 #5).** R1's version (use the instrument directly) wins, because the stack cannot enforce budgets for arbitrary scripts.
- **Corpus size (R1 #5: keep 40 with a factory; R2 #3: 16–20; R3 #9: budget it).** 16–20 for the v1 gate, with R1's statistical honesty statement next to the numbers; 40 is the longitudinal target; R3's budget ledger is required.
- **Custody (R1 #6 vs R2 #1).** Owner decision already taken; R2's container is one way to implement the `isolated` tier.

### 24.5 Next steps

1. Owner confirms the redesign direction in §24.1.
2. Write `plan.md` revision 2 from §24.1–24.3: numbered invariants, Reads column, research ledger and evaluation protocol split into sibling files (review 1 #12).
3. Run M0's baseline and custody spike before freezing the domain catalog.
4. Then `/plan-to-bones`.
