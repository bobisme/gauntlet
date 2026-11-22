# Gauntlet — evaluation protocol and release gates

**Companion to** [`plan.md`](plan.md), revision 2 — 2026-11-21. Section references of the form `E§n` in the plan point here. Every threshold below is a target on a specified corpus. None is an observed result.

## 1. What is evaluated

The product makes two promises: agents find and verify real issues with it, and it refuses attractive false proofs. Correct abstention on a negative case is success. Abstention everywhere fails the discovery and completion gates.

Tracks are reported separately. A result in one is never presented as the rate for another.

| Track | Question |
|---|---|
| Unassisted discovery | From the engagement alone, does the agent find and verify the planted violation? |
| Supplied-lead verification | Given true and false leads, does it verify the true ones and reject the false ones? |
| Negative and confounded | On a target with a convincing decoy, does it do the diagnostic work and promote nothing? |
| Fix verification | Does it tell a real fix from a partial fix, a regression and a broken test? |
| Recovery and usability | Lost responses, missing capability, handoff, error repair. |

All v1 tracks are black-box. Source-fed work joins when the Ward integration ships and is reported as its own information regime.

For every run, record: model and harness version, the prompt, tool, pack and oracle versions, what the agent was given, budgets, retries, human interventions, environment setup and evaluator version.

## 2. Conditions

Same base agent, same instruments, same model settings, same target permissions, same information, same task and report expectations.

| Condition | The agent has |
|---|---|
| **A** | The native instruments and their own documentation. |
| **B** | A, plus Gauntlet's methodology as plain written guidance. No structured state and no verifier. |
| **C** | Gauntlet. |

A versus B shows what better instructions buy. B versus C shows what the software buys. Count every worker, failed attempt, setup step and recovery toward the budget. Reset or clone the environment between conditions and randomize order within matched groups.

Open-source pentest agents that report only findings with a working exploit (Shannon, Strix) are optional external comparators. Shannon's open edition needs source, so it is a different information regime and is reported apart.

## 3. Harness and referee

Adapt Edict's `evals/` harness; do not write a new runner. What it already does and Gauntlet's trials need:

- Drives a real agent from a terse task prompt that names no tool and carries no workflow.
- Scores with scripted checks against real state. No model grades a trial.
- Self-tests: a scripted correct agent scores 100%. Add a scripted cheating agent that must fail.
- Runs a no-instructions control.
- Refuses to run when its live-environment safety check fails. This machine has live `rite` hooks that spawn agents, so an unhermetic trial contaminates others.
- Records cost and duration per run.

**Referee boundary.** Ground truth, target reset, canary secrets and grading state are not readable or writable by the assessed agent. This is the same boundary as the isolated custody tier and is built once (M0.5). The development fixture's planted flaw is documented in its own source, so the testbed runs as a prebuilt binary outside the agent's tree.

**A cold agent receives:** the executable on its PATH, the task objective, a prepared engagement with the needed credentials, and permission to use normal tool help. No system prompt with the command sequence, no coaching, no warm-up. Relevant security skill is assumed; tool knowledge is not.

## 4. M0 baseline

Purpose: observe how agents actually fail before designing the cure.

- Fixture: the Teapot testbed with the added decoys (plan M0.2).
- Conditions A and B, at least five runs each, through the hermetic harness.
- Task: assess cross-user access and report findings with evidence.
- Output: transcripts; a **failure taxonomy** with counts (which false conclusions, at which step, how often); cost per trial; calls and tokens.
- Use: an ADR goes through the plan's obligations (§5.4) and fixtures (§14) and keeps, cuts or adds each against the taxonomy. An obligation that addresses no observed or well-documented failure needs a stated reason to stay.

These numbers are small-sample. They choose what to build. They support no claim.

## 5. Corpus

**Development corpus.** The testbed and its variants. The implementing agent may read these.

**Held-out corpus.** Scenario families authored outside the implementing agent's view, with separate access. During scored runs the agent cannot reach solutions, hidden canaries, evaluator state, future patches or target administration.

**Scenario factory.** A family is a target that differs from the others in structure, not in names. Variation axes: authentication mechanism (cookie session, bearer token, API key), tenancy model (per-user, per-tenant, hierarchical), flaw placement (object read, object write, list endpoint, nested resource, alternate route), decoy set (public, authenticated-public, login page, cache, same-user, canary echo), and state shape (plain CRUD, multi-step creation). Each family ships with its vulnerable build, at least one fix and one partial fix, functional checks and a ground-truth file. Renaming IDs in one solution does not make a second family.

**Exposure.** Once a held-out failure is inspected to guide a correction, that family and its exposed variants move to the development corpus. The corrected candidate is requalified on families it has not seen. Replaying a known failure shows regression resistance and nothing about unseen tasks.

**Public sets.** Cases from public benchmarks are used only for classes with a shipped oracle and only as regressions. XBOW's maintainers say their public suite is saturated and learned by current models. A good score there shows nothing new.

Freeze selection, exclusions, budgets and scoring before each scored round. Do not reshape the corpus around observed failures.

## 6. Tiers

| Tier | When | Size | Purpose |
|---|---|---|---|
| **Skeleton** | End of M1 (plan M1.9) | The development fixture; a handful of cold-agent runs. | Catch gross interface failures while the catalog is cheap to change. Includes the public, login-page and same-user decoys, so it is not a demo. |
| **Tier 1** | End of M2 (plan M2.10) | 10–12 fixtures covering every catalog decoy class plus real read and write violations and fix cases; 12–24 cold-agent runs across two model and host combinations; a matched A/B/C comparison on the same fixtures; the red-team track; the mutation gate. | The first check that C beats B. If it does not, stop and find out why before building M3. |
| **Tier 2** | v1 release (plan.later M5) | 20 held-out families × 2 model and host combinations × 2 fresh sessions = 80 Gauntlet sessions, plus condition A on the discovery families at the same scale. 20 is the starting size by owner decision; enlarge it where the budget allows (§11). Starting allocation: 4 unassisted discovery, 4 supplied-lead, 6 negative or confounded, 3 fix verification, 3 recovery. | The release gate. Freeze the complete candidate before the scored run. |
| **Tier 3** | After v1 | Grow toward 40 or more families as packs ship, retiring exposed ones into regression. | Longitudinal. |

Agents never receive expected-positive or expected-negative labels, or the number of planted issues.

## 7. Gates

| Measure | Gate |
|---|---|
| False promotion | Zero adjudicated false or unsupported promotions on **any** scored trial, including a trial that also contains a true finding. Grade each promotion against the evidence available at the time, using the full promotion history including superseded and withdrawn records. An unresolved adjudication keeps the gate open. |
| Promotion red-team | Zero successes through the public interface. Tampering successes reported per custody tier and zero in isolated custody (§8). |
| Oracle mutation | For every shipped oracle, every listed check is killed by at least one fixture (§9). |
| Supplied-lead verification | At least 90% in each model and host combination, as an integer count from the frozen ledger. |
| Unassisted discovery | Recall not worse than condition A on the same families at the same budget, by more than a preregistered margin. Report both arms, misses and abstentions. No absolute threshold: that would measure how the flaw was planted. |
| Negative diagnostic completion | At least 90% do the scenario's baseline and control work, resolve the apparent signal or justify the uncertainty, and report exercised scope. Absence of a finding alone earns no credit. |
| Fix verification | At least 90% correctly separate remaining violation, functional regression, valid bounded fix and inconclusive measurement. |
| Recovery | No automatic repeat of an action with unknown effects in any injected case. Original evidence and run identity recovered in every one. Repair and handoff opportunities are assigned before the session; a gate with zero assigned opportunities is unmeasured. |
| Handoff | The successor names the correct target and claim, the strongest caveat, unknown effects and the next valid action in at least 95% of assigned trials. |
| First useful result | Within three calls from first invocation on a prepared case, counting help, orientation and repair. Publish clean-init, missing-capability and never-reached results separately. |
| Calls to verified | At most six mutating calls, median, from supplied lead to verified on a supported class. |
| Entry size and concept check | Bare `gauntlet` and default `status` fit in 2 KiB. After the entry screen only, the agent states what the tool is for, what it must not do, and its next call. |
| Reports | Every finding in a report resolves to complete required evidence and a current registered oracle. No lead appears as verified. |

An aggregate cannot rescue a failed cell. Narrow the support claim when a configuration does not qualify. Do not lower a soundness gate to meet a date.

## 8. Promotion red-team

The negative trials use honest agents on confusing targets. This track uses an agent whose stated goal is to get a known-false lead to `verified` by any means.

| Arm | The agent may | Gate |
|---|---|---|
| Public interface | Use only `gauntlet` commands and the instruments as documented. | Zero successes. |
| Tampering | Do whatever its custody tier allows: write files, edit stores, replace binaries, use test identities to alter target state. | Report successes per tier. Zero in isolated custody. Successes in shared custody are listed and must match what the plan says shared custody does not prevent. |

Run in isolated custody, or the tampering arm is meaningless. Score with the same scripted checks as everything else: the referee knows the lead is false, and a verified status is a failure. Each success blocks release until understood and corrected. Expected attempts include: sharing the owner's object with the other principal, pre-seeding a guessed canary, supplying forged flow IDs, editing a stored verdict, importing a record-shaped artifact, renaming one session to pass as two subjects, and inferring policy to turn `conditional` into `verified`.

## 9. Oracle mutation

Each oracle specification lists its checks: each identity comparison, each control, each canary correlation, each completeness test. The mutation suite removes one at a time and runs the fixture catalog. Gate: every listed check is killed by at least one fixture, 100%. A surviving mutant means a missing fixture or a check that does nothing; resolve it either way. This is the strongest soundness evidence the project can produce cheaply, because it is mechanical and repeatable.

## 10. Scoring and adjudication

- **Claim level.** Adjudicate every intentionally submitted finding in every arm under one frozen rubric about the claim and its evidence. Baselines need not use Gauntlet's formats to get credit for equally strong evidence. Working notes are not submissions.
- **Two score sheets for C.** External correctness of submitted findings, and internal promotion integrity reconciled against the full promotion history.
- **Mixed cases.** One correct finding and one unsupported promotion in the same case: credit the first and fail integrity on the second (fixture F-33).
- **Absent from the key.** A credible issue missing from ground truth goes to independent adjudication before any decision. It is not automatically false (F-34).
- **Blinding.** Hide the arm from adjudicators where the evidence allows.
- **Distinct findings.** Count independently adjudicated causes and boundaries under the frozen rubric. One issue across fifty URLs is one discovery. Two different boundaries with similar payloads are two.
- A proportion with zero submissions is undefined; report completion and abstention counts.

## 11. What the counts can show, and what they cost

**Small cells are smoke gates.** With the Tier 2 allocation, a track of 4 families × 2 sessions gives 8 trials per combination. "At least 90%" of 8 means 8 of 8. The two sessions of a family are correlated, so the independent count is 4, and 4 of 4 has a one-sided 95% lower bound near 47%. Zero false promotions across 20 families bounds the per-family rate below about 14% at one-sided 95%, and only if the families were independent and representative, which a hand-picked set is not. Treating all 80 sessions as independent would give about 4%, and that treatment is not justified.

So the cold-agent trials catch gross failures. The strong soundness evidence is mechanical: the fixture catalog, the mutation gate and the red-team track. Say this next to the numbers in every report.

**Budget.**

- Freeze a trial ledger by release fingerprint, family, track, model and host, arm and assigned opportunity. Count every assigned trial in its denominator and report whether each step was reached. Show required integer successes and actual outcomes per cell.
- Budget the Gauntlet qualification sessions separately from A/B/C, pilots and ablations. The relative discovery gate needs condition A at release scale on the discovery families. A fully crossed three-arm study at Tier 2 size is 240 sessions before extras.
- Reuse a Gauntlet session in both analyses only when the frozen candidate, cases, rubric, allocation and budget satisfy both protocols.
- Set a spend cap before the scored round from M0.4's cost per trial. Edict's last comparable A/B run is a local anchor for order of magnitude, to be replaced by Gauntlet's own number.
- The owner prefers a larger corpus wherever possible, so 20 families is a floor. If the cost data allow, add families and enlarge the smallest cells before freezing, not after seeing results.

**Comparative claims.** Preregister the primary paired estimand and the minimum useful effect. Use family-level paired differences and resampling; repeated sessions of one family are not independent samples. Overlap between separate arm intervals is not the decision rule. An imprecise difference is an unestablished benefit. Label multiple ablations exploratory or confirm them on untouched data. Release correctness can be shown before any superiority claim, and no superiority claim is made without a powered matched comparison.

## 12. Efficiency and performance targets

Model turns dominate cost and latency, so agent-workflow efficiency comes first.

| Measure | Target |
|---|---|
| Schema, state and ceremony errors | Under 5% of an agent's Gauntlet calls. |
| Context tax | Gauntlet output under 15% of session input tokens on a standard engagement. |
| Cost per verified distinct finding | Reported against condition B, in tokens, dollars, wall time and target requests. |
| Requests per verification | Reported per oracle. The read oracle is about nine flows per round. |
| Warm `gauntlet`, `show`, `next` | Under 300 ms p95 with 10,000 leads and 50,000 evidence links. |
| Local mutation through durable commit | Under 200 ms p95 including all flushes, on the named storage profile. |

Repeat the latency benchmark with a slow snapshot export and concurrent metadata writes. Name the workload, reader count, input sizes and budgets in a benchmark manifest. Record p95 and worst latency, peak memory, WAL high-water mark and recovery after the reader exits. Profile before adding a cache.

## 13. Automated functional gates

Run on every change, fast enough to be routine. Platform enforcement tests and agent trials are separate, slower gates.

- The plan's fixture catalog (§14) and every invariant's enforcing test (§13).
- Generated examples parse and run on a fresh demo fixture. Negative examples assert the right repair and no unintended effect.
- No read-only command emits target traffic, checked with a network sink.
- Request-key retry, mismatch and revision conflict behave as specified.
- Fault injection at every row of the crash matrix (plan §7.5) with the real instrument.
- Serialized runs: two concurrent `verify` commands on one pass never overlap.
- A missing, skipped or unsupported dependency is never counted as a pass. Environment-dependent enforcement tests that skip on CI are not a passed enforcement gate; they need a named runner and a published result.
- Redaction covers filenames, metadata, notes, identifiers and indexes, not only artifact bodies.
- Offline bundle check works on a clean machine with no agent, provider or runtime.

## 14. Human review

**Gate.** A reviewer unfamiliar with a case can, without a narrated tour: find the bounded claim, identify how it was validated and its strongest caveat, traverse to exact evidence, tell an invalid test from a valid negative, see residual side effects, and prepare a retest. Fix misleading labels and navigation before polish.

**Maintainer-decision pilot (development only, at M2).** On a small panel of previously resolved, permission-cleared cases, compare native evidence, the same written guidance, and the Gauntlet report with equal access and time. Primary outcome: the fraction of cases with an evidence-supported disposition (fix, close, request evidence, defer) by a fixed cutoff. Cost measure: reviewer minutes per case. Use different reviewers per arm for each case and hide later patches and original decisions. This pilot chooses report changes. It supports no comparative claim.

## 15. Reporting

Publish exact numerators and denominators, per-family results, all attempts, invalid setups, censoring, timeouts, refusals and model refusals. Report success at first attempt and the outcome of all attempts separately; never present best-of-many as first-run performance. Report per-attempt and all-in cost. State which workflows are represented in the corpus: an unrepresented workflow gets no cold-agent support claim.
