# Gauntlet — research ledger and stack inspection record

**Companion to** [`plan.md`](plan.md), revision 5 — 2026-11-22.

Research informs the design. It does not show that Gauntlet works. That is decided by the evaluation in [`plan.evaluation.md`](plan.evaluation.md).

## 1. How to read this

Every row carries how deeply the source was inspected and by whom.

| Label | Meaning |
|---|---|
| **rev 1** | Inspected by the author of revision 1, as recorded in [`plan.rev1.md`](plan.rev1.md) §22. Not re-checked for revision 2. |
| **fetched** | The abstract or page was fetched and read for this plan: on 2026-11-21 for revision 2, or on 2026-11-22 where the row says so. Numbers quoted are in the source. |
| **cited** | Named by a review. Not fetched. Carries no design weight. |

Kinds of evidence, strongest first:

- **Organizer or independent observation:** a competition organizer's measured result or an evaluator's audit, within that setting.
- **Author experiment:** methods and denominators given by the authors. Not an independent reproduction.
- **Implementation or documentation:** shows a mechanism exists. Does not show it works here.
- **Vendor report:** operational claims without a transferable controlled result.

No cross-paper ranking is built. Flag recovery, known-vulnerability exploitation, source-level proof generation, live testing, triage and patch validation are different jobs, and model, scaffold, budget, hints, targets and grader all matter. Nothing was installed or rerun. "Inspected" means read.

## 2. What the research supports

| Observation | Sources | Decision in the plan |
|---|---|---|
| Capable agents still submit false findings. A naive automatic check accepts most false claims. | [R4], [R29] | The verifier acquires its own observations with a fresh canary and controls (D3). |
| Reports of IDOR that coding agents make from source are mostly false, and one named cause is data that is public by design. | [R51] | Policy comes from the operator, never from the agent (D15). Leads derived from source need runtime verification (the Ward route). The agents read source, so this says less about a black-box agent with Teapot, and the M0 baseline measures that (plan §12.1). |
| Published exploit artifacts often fail their own controls: the claimed signal survives a patch or appears on benign input. | [R30] | Fix verification needs a working observer and a legitimate path, and reports two results (plan §6.8). Counterfactuals are an observer in their own right. |
| Free exploration with strict, separate verification has produced real findings without false positives in one studied setting. | [R29] | Two speeds (D2). The exploration there had source access, so only the verification design transfers. |
| A production system labels each class as checked by a deterministic validator or judged by an agent. It labels IDOR as agent-judged. | [R35] | `validation: deterministic` on every v1 finding; `judged` reserved and counted apart (plan §5.4). Testing with an object the tester created has precedents ([R9], [R52]). The content canary, the controls and the separate policy are this plan's additions (plan §6.4). |
| Graders accept unintended effects, and benchmark scores are inflated when they do. | [R18], [R33], [R38] | Every oracle publishes its known misses. Mutation gate. Referee isolation. |
| Public task sets saturate and leak. | [R18], [R19] | Held-out scenario families with exposure accounting. |
| Detection is much harder than exploitation or patching once the issue is known. | [R6] | Discovery is its own milestone and has a relative gate against the instruments alone. |
| Interface design changes agent success. | [R22], [R23], [R36] | Five nouns, about ten commands, measured cold-agent gates. |
| Peer-agent discussion adds coordination and verification failures. | [R25] | Workers are optional, short-lived and hub-and-spoke. No second agent is required for challenge. |
| Across 13 penetration-testing frameworks, single-agent designs were not inferior to multi-agent ones on most easy and medium tasks, and invented success was widespread. | [R48] | The verifier takes no observation from an agent (D3). Workers stay optional. |
| Repository context files raise inference cost and do not reliably raise task success. | [R50] | A short managed block, and every cold start measured with and without it (plan §8.9, E§3). |
| Source and location hints change performance. | [R5], [R26] | The information regime is labeled. Black-box is the default; source-fed work is reported apart. |
| A runnable reproduction can fail to establish the original vulnerability. | [R28], [R30] | Target identity strength and environment kind are recorded; a simulation never establishes the original. |

## 3. Verification precedents

These bear most directly on the verifier design.

| Source | What was observed | Depth | Limit |
|---|---|---|---|
| **RECEIPT** [R29] (UC Berkeley) | 95 open-source web application targets. 30 confirmed cross-site scripting vulnerabilities on latest releases from a 50-application subset at a stated budget of $20 per application; 24 previously unknown, 12 acknowledged by maintainers. The authors report admitting no false positives. A naive check ("did script execute in a browser") accepted 111 claims, of which 10 were real. Design: fresh environment per submission; the attacker's script runs as a remote client with attacker-only credentials; the victim is a real browser with victim-only credentials; a sentinel with a single-use token is installed through the browser's debugging protocol; victim actions come from a fixed vocabulary. | fetched | One class. Exploration is white-box. "No false positives" is the authors' claim on their corpus. The 10-of-111 figure is against a browser-execution check, not against agent self-report. |
| **From Runnable to Verifiable** [R30] | Pre-registered, exploratory audit of exploit artifacts from a 104-paper corpus. 59 (56.7%) had reachable artifacts. Of 18 examined in depth, 10 completed their workflow at first run and 11 after environment-only repair. In 58 of 102 anchor cases (56.9%) the script's own CVE identifier differed from the declared one. 20 of 30 patched-build checks still fired. 7 of 19 benign controls still triggered. Reported sensitivity 60%, specificity 45%. | fetched | Single author. Exploratory. A study of research artifacts, not of agents. |
| **XBOW documentation** [R35] | Each vulnerability class is labeled "Deterministic" (a non-AI exploit validator; documented as reporting no false positives), "AI agent" (some false positives possible) or "Not applicable". IDOR (CWE-639) and Incorrect Authorization (CWE-863) are labeled "AI agent". Missing Authorization (CWE-862), path traversal, injection, XSS and SSRF are labeled "Deterministic". | fetched; class labels read again 2026-11-22 | Vendor documentation. The plan's deterministic IDOR check goes past this precedent (plan §6.4). The conference talk review 1 cites [R35a] was not fetched. |
| **XBOW, validate with canaries** [R35c] | The customer plants a secret GUID where the test account should not reach: a file, a SQL row, an internal web server, or a custom location such as an administrator's email. "The only information passed to the test coordinator is the location of the canary token and the SHA256 of the GUID", and results from attack agents are compared with that value. Classes named: business logic, SQL injection, local file read, remote code execution, SSRF. | fetched 2026-11-22 | Vendor documentation. IDOR and access control are not named. Precedent for canaries the operator plants and discloses only as a hash ([`plan.later.md`](plan.later.md) §5). |
| **RESTler security checkers** [R9] | Four rules. The user-namespace rule: "A resource created in a user namespace must not be accessible from another user namespace." Its checker sends the last request of a test case again with another user's token, after the fuzzer has created the resource. Also use-after-free, resource-leak and resource-hierarchy rules. "Our fuzzer only observes the HTTP status codes." It found new bugs in production Azure and Office 365 services. | fetched 2026-11-22 (full text) | Decides by status code. The direct precedent for creating the object in the test (plan §6.4). |
| **BOLABuster** [R52] (Unit 42, "Harnessing LLMs for Automating BOLA Detection") | Scripted sequences with at least two users, where one creates the objects and the other acts on them. The last call's outcome is analyzed by a model, and "humans verify the results". Found Grafana CVE-2024-1313 (a user outside an organization deletes its dashboard snapshot), Harbor CVE-2024-22278 (a Maintainer changes project metadata) and 15 endpoints in Easy!Appointments (CVE-2023-3285 to 3290, CVE-2023-38047 to 38055). | fetched 2026-11-22 | Vendor research. Judged verdicts. A source of historical fixtures (E§5), each to be checked against a shipped oracle: the Grafana flaw is a delete. |
| **AuthProbe** [R53] | Black-box testing with several identities, driven by an API specification. It confirms a leak by "comparing the response against a ground-truth fetch by the true owner", and reports no false positives on a hardened copy of its target. | fetched 2026-11-22 (abstract) | One author. One synthetic API. Comparing with the owner's response can match stale, cached or echoed content, which a canary minted in the run does not. |
| **Project Naptime** [R34] | Five design principles for agent vulnerability research, including "perfect verification" (the result must be checkable automatically with certainty) and a sampling strategy over hypotheses. | fetched | Vendor engineering post. The Big Sleep follow-up [R34a] was not fetched. |
| **Aardvark, now Codex Security** [R41] | Builds a threat model first. Attempts to trigger each candidate in a sandbox before reporting. Reports 92% detection on "golden" repositories. | fetched | Vendor figure on the vendor's own set. Source-based. |
| **Shannon** [R37a] | Open-source web testing agent with the rule "No exploit, no report." Uses browser automation. The open edition is white-box. | fetched | The 96.15% benchmark figure quoted by review 2 is not in the README and is unverified. |

## 4. Benchmarks and measured systems

| Source | What was observed | Depth | Limit and use |
|---|---|---|---|
| **DARPA AIxCC** [R1] | Corrected organizer report: finalists' systems together found 54 synthetic vulnerabilities across 63 challenges and patched 43. | rev 1; spot-checked by review 3 | Aggregate competition result. Keep discovery, reproduction, patch correctness and functionality separate. |
| **ATLANTIS** [R2] | Winner per the organizer. Combines model analysis, static and symbolic methods, directed fuzzing and several patch methods. | rev 1, selected sections | Borrow method diversity, not competition-scale infrastructure. |
| **Buttercup** [R3], [R3a] | Runner-up. The inspected source marks functional tests passed when test instructions are absent. | rev 1, source read | A concrete example of a skipped check counted as a pass. Gauntlet keeps absent and skipped checks explicit. |
| **ARTEMIS** [R4], [R4a] | One live-network study. Configuration A2 submitted 11 findings, 9 judged valid; A1 also submitted 11, 55% valid. Ranked second against ten human participants under the study rubric. | rev 1; figures corrected in review | Small cohort, relaxed defenses. Its triage accepts a reproduction decision with evidence text. |
| **PentestGPT** [R7] | 13 targets, 182 subtasks. 58.6% more completed subtasks than the raw model of the time. | rev 1 | Old models, interactive operator. Remeasure any benefit. |
| **CyberGym v3** [R5] | 1,507 instances across 188 projects, graded by sanitizer on pre- and post-patch builds. 22.0% for the best reasoning configuration on a 300-instance random subset with a 100-iteration cap. Best non-reasoning configuration 17.9%. The abstract reports 34 previously unknown vulnerabilities and 18 incomplete patches. | fetched | The percentage is for the subset. The introduction's breakdown sums to 35, not 34. Memory-safety reproduction is not general exploitability. |
| **CyberGym-E2E** [R40] | 920 vulnerabilities across 139 projects. Adds discovery, proof and patch as one task. | fetched (abstract) | A reference for end-to-end versus hinted tracks. |
| **BountyBench** [R6] | 25 systems, 40 bounties. With up to three attempts, best configurations reached 12.5% (detect), 67.5% (exploit) and 90% (patch). | rev 1; spot-checked by review 3 | Different configurations per track. Not one agent's first-run performance. |
| **CVE-Bench** [R33], [R33a] | Real web vulnerabilities with effect-specific graders. The grader uses instance canaries. Unsupported checks may be skipped or return false. | rev 1, source read | Not Gauntlet's result taxonomy. Keep evaluator failure, unsupported measurement and valid negative apart. |
| **Agentic Benchmark Checklist** [R38] | Applied to CVE-Bench, the checklist "reduces the performance overestimation by 33%". | fetched (abstract) | Supports auditing graders and outcome validity. |
| **NIST CAISI evaluator audit** [R18], [R18a] | Evaluators confirmed solution contamination and expected effects reached without the intended vulnerability. | rev 1; spot-checked by review 3 | Retrospective. No universal cheating rate. Isolate hidden state and inspect traces. |
| **XBOW public validation suite** [R19] | 104 web challenges. The maintainers warn that the suite is saturated and learned by current models. | rev 1 | Regression use only. |
| **MAPTA** [R37] | 76.9% on the 104-challenge XBOW suite at a reported total cost of $21.38. | fetched (abstract) | On a suite its maintainers call saturated. |
| **Hackers or Hallucinators?** [R48] | A study of 13 open-source automated penetration-testing frameworks and 2 baselines: over 10 billion tokens, and more than 1,500 execution logs reviewed by hand. Flag hallucination is widespread. Single-agent designs are not inferior to multi-agent ones on most easy and medium tasks. A larger tool pool "does not equate to an improvement", and external knowledge bases "often yield negative returns". | fetched 2026-11-22 (abstract and the first part of the text) | Capture-the-flag style tasks. Review 4 said tool pools degrade performance; the paper says only that they do not improve it. |
| **From Controlled to the Wild** (code name EthiBench) [R49] | A methodology, not a fixed benchmark, for scoring pentesting agents on realistic applications. Three open-source targets (vuln-bank, paygoat, xben-090) and three systems (Strix, PentAGI, and Claude Code with Sonnet). The general coding agent had the highest F-scores and the lowest cost and time. | fetched 2026-11-22 (abstract and the first part of the text; the appendix figures through a summary) | Three targets. The late build-up of false positives that review 4 cites is described for one run, and the paper calls the pattern erratic and target-dependent. |
| **Can LLMs Detect IDORs?** [R51] (Semgrep, 2025-11-03) | Coding agents were asked to find IDORs in open-source applications from their source. Claude Code: 13 true and 46 false, "22% (13/59)". Codex with GPT-5-Codex: 2 true and 42 false, "4.5% (2/44)". Causes of false reports include authorization done in middleware or in another file, and data that "was intentionally public". | fetched 2026-11-22 | Vendor blog. Source-based, so a different information regime from v1. The number of applications is not stated. |

The general lesson stands from revision 1: discovery benefits from diverse methods, and acceptance needs a narrow, explicit contract. Gauntlet reuses mature engines and spends its own effort on experiment validity, trustworthy observations, recovery and agent comprehension.

## 5. Established testing mechanisms

All inspected by the revision 1 author from primary papers or official documentation.

| Tool or method | Use in Gauntlet |
|---|---|
| **RESTler** [R8], [R9] | Producer and consumer bindings and reachable state sequences for stateful recipes (M3). Its user-namespace rule is the precedent for the first oracle, and its resource-hierarchy rule for a later nested-resource template (§3). A schema-valid request or a server error is not a security violation. |
| **Differential regression testing for REST** [R32] | Version-bound paired comparison with justified normalization. Precedent for the differential observer. |
| **Schemathesis** [R10], [R10a] | Replayable minimized failures and explicit invalid-environment outcomes. Do not copy a cache that replaces the original record. |
| **libFuzzer and OSS-Fuzz** [R11], [R12] | Delegate fuzzing. Bind build, sanitizer, input and failure identity. A minimized different crash is a new observation. |
| **CodeQL** [R13] | Source-to-sink paths as structured leads. In this stack that route goes through Ward. |
| **Nuclei** [R14] | Candidate generators. A template signature establishes neither authority nor truth. |
| **Burp Scanner** [R15] | Repeats chosen by class and environment. Precedent for keeping intermittent evidence. |
| **ZAP Automation Framework** [R16] | An alert assertion in a pipeline is not proof of a consequence. |
| **OWASP ASVS and WSTG** [R17], [R17a] | Versioned identifiers to label properties and coverage cells. A label certifies nothing. |

These are adapter candidates and precedents. None is a required dependency.

## 6. Agent interfaces and orchestration

| Source | What is useful | Depth | Limit |
|---|---|---|---|
| **SWE-agent interface study** [R22] | Small purposeful actions and concise feedback, tested against a plain shell. | rev 1; cited by review 3 | Coding tasks. Apply through Gauntlet's own cold-agent trials. |
| **Evaluating AGENTS.md** [R50] | Repository context files raised inference cost by more than 20% on average. Generated files lowered the resolution rate by 0.5% and 2% on the two benchmarks. Developer-written files raised it by 2.4%, which the authors report as not statistically significant. Agents: Claude Code, Codex and Qwen Code. | fetched 2026-11-22 (abstract and the first part of the text; the 2.4% figure through a summary of the later sections) | Coding tasks. Review 4 quoted −3% and +4%, which are not in the paper. Supports a short managed block and measuring cold starts with and without it. |
| **EnIGMA** [R36] | Interactive tools for agents in security tasks; state of the art at publication on three capture-the-flag benchmarks. Names "soliloquizing": a model inventing tool output. | fetched (abstract) | Capture-the-flag evidence. Supports treating agent-supplied observations as untrusted. |
| **Anthropic engineering reports** [R23], [R24], [R31] | Evaluate realistic outcomes, inspect trajectories, give tools useful semantics, keep progress durable. | rev 1 | Vendor guidance. |
| **MAST** [R25] | Failure taxonomy from more than 1,600 traces across seven multi-agent frameworks. | rev 1 | Not evidence that a larger team is better. |
| **Sapper v2, nvwabase** [R20], [R20a], [R21] | Layered memory, explicit handoff, bounded escalation. | rev 1 | Guidance, mostly capture-the-flag. Do not import automatic trust-dialog acceptance or prompt-only confinement. |
| **AXE** [R26] | Material benefit from source and location metadata. | rev 1, abstract | Unequal information across comparisons. |
| **BugStone-E2E** [R27] | Patch-derived rules, cheap source filtering, runtime evidence. | rev 1, project page | Full paper not read. |
| **ReproBench** [R28] | Reconstruction from identifiers on 30 device vulnerabilities; substituting a simulation is a major failure mode. | rev 1, abstract | Narrow corpus. Supports recording environment kind. |

## 7. Stack inspection record

Local checkouts under the owner's source directory, read on 2026-11-21. Source was read. No tool was run except to list what is installed. "rev 1 pin" is the commit the revision 1 author inspected. M0.1 produces the authoritative inventory.

| Tool | rev 1 pin | HEAD read for revision 2 | On PATH | Notes |
|---|---|---|---|---|
| Teapot | `c90ab5bb` | `38d88c50a2` | no | Moved three times during the day (`3eec1146`, `8d6dab9a`, `d89827cd` seen earlier). Vendors its own copy of Hallpass. |
| Hallpass | `0474bb03` | `261e74d57d` (0.2.0) | no | Three copies in use: this HEAD, Playpen's pinned revision `05d657aa`, and Teapot's vendored snapshot. |
| Playpen | `17ed1c74` | `206190c78d` | no | |
| Sippycup | `26e6391d` | `26e6391da9` | no | Unchanged. |
| Edict | `3f882a4d` | `3f882a4d70` | yes | Unchanged. |
| Bones | `86de2f86` | `86de2f863a` | yes (`bn`) | Unchanged. |
| Vessel | `f0ccd685` | `f0ccd685a9` | yes | Unchanged. |
| Ward | not inspected | `9c6bd71c33` | yes | Pre-release. README read only. |
| `rite` | not inspected | not recorded | yes | Advisory claims only. |
| Investigation | plan revision 3 | `12c90ab` | no binary | Notes only. Plan is now revision 4. |

**Files read for the facts in plan §2.2:**

- Teapot: `crates/teapot-engine/src/allocator/mod.rs`, `crates/teapot/src/globals.rs`, `crates/teapot-api/src/commands/{authz_compare,flows_replay,macros_run,sessions,sessions_check}.rs`, `crates/teapot-testbed/src/{routes.rs,main.rs,endpoints/app/planted.rs,endpoints/app/auth.rs}`.
- Playpen: `docs/spec.md`, `README.md`.
- Hallpass: `docs/EVIDENCE.md`.
- Sippycup: `config/commands.tsv`, `lib/sippycup/`.
- Edict: `evals/README.md`, `evals/results/`.
- Bones: `.agents/edict/design/cli-conventions.md`.
- Investigation: `notes/plan.md` (exit codes; work packages W00–W16; milestones A–D).
- Ward: `README.md`.

**Local facts stated by a review and not confirmed here:**

- Review 1's figures for Edict's last A/B evaluation (cost, duration, run count and the larger variant's word count). The 658-word `current` variant is confirmed in `evals/results/`. The plan uses the run only as an order-of-magnitude anchor to be replaced by M0.4.
- The exact marker format of Edict's managed block. M1.8 reads it from Edict's template.

The revision 1 file links to proof-critical source files at its pins (its §22.5). Those links remain valid for the pinned commits.

**Read on 2026-11-22 to check review 5** (revision 3). Teapot at `2f63fad7`, a newer HEAD than the table above: `crates/teapot-engine/src/replay/outcome.rs` (a replay hop's flow ID is optional, and absent while capture is off although the request was sent), `crates/teapot-engine/src/pipeline/capture.rs` (a flow is relayed uncaptured when capture is unavailable or is lost mid-flow), and `crates/teapot-engine/src/allocator/mod.rs` (the request counter includes spending on the ledger from outside Teapot, and is absent until the ledger can be read). Hallpass: `docs/EVIDENCE.md` (a receipt shows a debit; "Hallpass cannot determine whether the action ran"). Bones: `.agents/edict/design/cli-conventions.md` (output to a pipe defaults to text). Review 5 read Teapot at `a4ee405`; the statements it cites hold at the newer HEAD. Its reference to Investigation's export design was not read again.

**Read on 2026-11-22 to check review 6** (revision 4). Teapot at `876b2165`, 22 commits past `2f63fad7` and five past the review's own read: `crates/teapot-core/src/findings.rs` (confidence `certain` is "a reproduction confirmed it"; state `fixed` is "a `--verify` that no longer reproduces"), `crates/teapot-api/src/commands/findings_repro.rs` at `da01de3c` (the re-check answers `reproduces`, `fixed`, `changed` or `blocked`, and a logged-out answer is `blocked`, so review 6's statement that a broken login gives `fixed` does not hold), `crates/teapot-api/src/commands/guide.rs` (the findings guide and `leads promote`), `crates/teapot-testbed/src/endpoints/app/planted.rs` and `router.rs` (orders have a read route only; the basket accepts only catalog items; the planted catalog is a contract for Teapot's own exit tests), `crates/teapot-engine/src/pipeline/installed.rs` (rules, intercept and Lua hooks are stages of the proxy listener), `crates/teapot-engine/src/replay/mod.rs` (the replay client behind `requests send` is a separate path that applies only a session), `crates/teapot-engine/src/sessions/mod.rs` (one login and one retry of a GET or HEAD on a logged-out answer) and `crates/teapot-store/src/sessions.rs` (session secrets stored whole in `project.db`). Investigation near `0de9a1c`, while it was being committed to: `bn list` showed 308 items, 29 done, all in milestone A, and W07, W10 and W11 each sized extra large. The review's count of 305 open items was already out of date. Whether a rule or hook can reach a verifier send was judged from module structure and not traced through every caller, so M0.1 tests it.

## 8. Cited by a review and not verified

These were named in reviews 1 to 4. None was fetched for this plan, so nothing in it depends on them. Verify before citing any as evidence. Review 4 reports that it consulted [R35a], [R34a], [R42], [R45] and [R46a]; that is the reviewer's check and not this ledger's. Review 6 lists three sources it searched and did not use (a 2022 paper on IDOR attack groups derived from specifications, a vendor article on BOLA detection and a vendor benchmark of pentesting agents); none was fetched.

| Source | Cited for |
|---|---|
| XBOW conference talk [R35a] | Canary-based validation with zero false positives. |
| Big Sleep [R34a] | Real vulnerabilities found by a grounded agent. |
| mini-SWE-agent [R39] | A minimal shell-only agent performing well on a coding benchmark. The specific figure in review 2 is unverified. |
| Code Mode, code execution with tool protocols | Programmatic tool use reducing token cost. No link given. |
| Claude Code Security, Trail of Bits AI auditing | Threat-model-first pipelines and model refusals during authorized testing. No link given. |
| Check Point research on agent configuration in repositories | Malicious agent hooks in untrusted repositories. No link given. |
| Strix [R42] | An open-source agent that reports only findings with a working exploit. |
| CAI and CAIBench [R43], [R43a] | An open security agent framework and its benchmark. |
| Tricorder [R44] | Program analysis evaluated inside an engineering workflow. |
| Lin et al., USENIX Security 2025 [R45] | Practitioners reporting that tool output lacks deployment context. |
| SQLite documentation [R46], [R46a], [R46b] | Durability under `synchronous` settings, WAL growth under long readers, isolation. Official documentation, not re-fetched; the durability claim is the basis for INV-26 and is tested directly in M2.9. |
| Git protected configuration [R47] | Precedent for not trusting configuration inside an inspected tree. |

The design points these were cited for (hostile repository configuration, model refusals, hub-and-spoke workers) are adopted on their merits and tested by fixtures F-28 to F-31. They do not rest on these sources.

## 9. Reference index

Paper revisions and the inspection limits above take precedence over a later changed landing page.

- **R1:** DARPA, [AIxCC final results][R1].
- **R2:** Team Atlanta, [ATLANTIS technical report][R2].
- **R3 / R3a:** Trail of Bits, [Buttercup][R3]; [pinned source][R3a].
- **R4 / R4a:** [ARTEMIS, v2][R4]; [pinned triage implementation][R4a].
- **R5:** [CyberGym v3][R5].
- **R6:** [BountyBench][R6].
- **R7:** [PentestGPT][R7].
- **R8 / R9:** Microsoft Research, [RESTler][R8]; [security-property checking for REST APIs][R9].
- **R10 / R10a:** [Schemathesis study][R10]; [failure replay documentation][R10a].
- **R11 / R12:** [libFuzzer][R11]; [OSS-Fuzz reproduction][R12].
- **R13–R16:** [CodeQL path queries][R13]; [Nuclei template review][R14]; [Burp audit settings][R15]; [ZAP alert tests][R16].
- **R17 / R17a:** OWASP [ASVS][R17]; [WSTG authorization testing][R17a].
- **R18 / R18a:** NIST CAISI, [observed evaluation cheating][R18]; [prevention practices][R18a].
- **R19:** XBOW, [public validation benchmarks][R19].
- **R20 / R20a / R21:** [Sapper v2][R20]; [Sapper][R20a]; [nvwabase][R21].
- **R22:** [SWE-agent interface study][R22].
- **R23 / R24 / R31:** Anthropic, [writing tools for agents][R23]; [agent evaluation guidance][R24]; [long-running harnesses][R31].
- **R25:** [MAST][R25].
- **R26 / R27 / R28:** [AXE][R26]; [BugStone-E2E][R27]; [ReproBench][R28].
- **R29:** [RECEIPT][R29].
- **R30:** [From Runnable to Verifiable][R30].
- **R32:** Microsoft Research, [differential regression testing for REST APIs][R32].
- **R33 / R33a:** [CVE-Bench][R33]; [grader source][R33a].
- **R34 / R34a:** Google Project Zero, [Project Naptime][R34]; [From Naptime to Big Sleep][R34a].
- **R35 / R35a / R35b:** XBOW, [vulnerability classification][R35]; [conference talk][R35a]; [interpreting results][R35b]; [validate with canaries][R35c].
- **R36:** [EnIGMA][R36].
- **R37 / R37a:** [MAPTA][R37]; Keygraph, [Shannon][R37a].
- **R38:** [Agentic Benchmark Checklist][R38].
- **R39:** [mini-SWE-agent][R39].
- **R40:** [CyberGym-E2E][R40].
- **R41:** OpenAI, [Introducing Aardvark][R41].
- **R42:** [Strix][R42].
- **R43 / R43a:** Alias Robotics, [CAI][R43]; [CAIBench][R43a].
- **R44:** Google, [Tricorder][R44].
- **R45:** [Lin et al., USENIX Security 2025][R45].
- **R46 / R46a / R46b:** SQLite, [synchronous settings][R46]; [WAL checkpoint behavior][R46a]; [isolation][R46b].
- **R47:** [Git configuration scopes][R47].
- **R48:** Peng et al., [Hackers or Hallucinators? A Comprehensive Analysis of LLM-Based Automated Penetration Testing][R48].
- **R49:** Conde et al., [From Controlled to the Wild: Evaluation of Pentesting Agents for the Real-World][R49].
- **R50:** Gloaguen et al., [Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents?][R50].
- **R51:** Semgrep, [Can LLMs Detect IDORs? Understanding the Boundaries of AI Reasoning][R51].
- **R52:** Palo Alto Networks Unit 42, [Harnessing LLMs for Automating BOLA Detection][R52].
- **R53:** Barach, [AuthProbe: Specification-Driven, Multi-Identity Detection of Broken Object-Level Authorization in Recruitment API][R53].

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
[R34]: https://projectzero.google/2024/06/project-naptime.html
[R34a]: https://projectzero.google/2024/10/from-naptime-to-big-sleep.html
[R35]: https://docs.xbow.com/console/reference/vulnerability-classification
[R35a]: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Dolan-Gavitt-AI-Agents-for-Offsec-with-Zero-False-Positives-Thursday.pdf
[R35b]: https://docs.xbow.com/console/guidance/interpreting-results/
[R35c]: https://docs.xbow.com/console/how-to/validate-with-canaries
[R36]: https://arxiv.org/abs/2409.16165
[R37]: https://arxiv.org/abs/2508.20816
[R37a]: https://github.com/KeygraphHQ/shannon
[R38]: https://arxiv.org/abs/2507.02825
[R39]: https://github.com/SWE-agent/mini-swe-agent
[R40]: https://arxiv.org/abs/2606.04460
[R41]: https://openai.com/index/introducing-aardvark
[R42]: https://github.com/UseStrix/strix
[R43]: https://arxiv.org/html/2504.06017v2
[R43a]: https://arxiv.org/html/2510.24317v1
[R44]: https://research.google/pubs/tricorder-building-a-program-analysis-ecosystem/
[R45]: https://www.usenix.org/conference/usenixsecurity25/presentation/lin-elizabeth
[R46]: https://www.sqlite.org/pragma.html#pragma_synchronous
[R46a]: https://www.sqlite.org/wal.html#avoiding_excessively_large_wal_files
[R46b]: https://www.sqlite.org/isolation.html
[R47]: https://git-scm.com/docs/git-config#SCOPES
[R48]: https://arxiv.org/abs/2604.05719
[R49]: https://arxiv.org/abs/2605.10834
[R50]: https://arxiv.org/abs/2602.11988
[R51]: https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning
[R52]: https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
[R53]: https://arxiv.org/abs/2607.20574
