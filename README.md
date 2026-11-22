# Gauntlet

Gauntlet is a planned security verification tool for AI agents and human testers. An agent explores a target with ordinary tools and records what it sees as **leads**. Gauntlet then decides, with ordinary code, which leads are **verified findings**. The verifier re-runs the test itself, with fresh canaries and controls.

> **Status: design only.** This repository holds an implementation plan (revision 2), the superseded revision 1, and three reviews. There is no code yet. All commands below are proposed and none of them exist.

## The problem

Agents that look for vulnerabilities often report false findings. A `200 OK`, a scanner alert, a crash or a reflected marker can look like proof and not be proof. Common causes:

- two session labels resolve to the same user;
- the object is public by design;
- a login page returns 200;
- a cached response is replayed;
- a fix "works" only because it broke authentication.

Gauntlet's job is to make that kind of false promotion hard to produce and easy to detect, without making the search for bugs slower.

## Design in brief

- **Explore freely, verify strictly.** Exploration uses the native instruments directly, under their own scope and budget enforcement. Confirmation goes through `gauntlet verify` only, which acquires every observation it judges.
- **Agents propose; code decides.** An agent supplies a claim and its bindings. It never supplies an observation, an oracle result or a `verified` flag. A finding's status is computed from immutable verification records every time it is read.
- **Controls are part of the claim.** The first oracle (`web.private-object-read.v1`) creates a new object with a fresh canary, then needs an owner read, an other-user read, an anonymous read, a different-object read, and identity probes before and after. HTTP status codes play no part.
- **Policy is recorded, not guessed.** A test can show that one user read another's object. Only policy says they should not have. A finding whose policy basis is the agent's own inference is `conditional`, not `verified`.
- **Honest labels.** Separate fields record execution, evidence completeness, the oracle result, reproduction and cleanup. An invalid test is never reported as a negative, and a negative is never reported as "secure". Each badge shows its custody tier (shared or isolated).
- **Fix verification is a comparison.** A retest checks that the observer still works and that legitimate behavior is intact, then tries the original test and nearby variants. A fix that breaks login is `inconclusive`, not fixed.
- **Black-box by default.** When source code is available, a separate tool, Ward, does the static analysis.

A minimal session, as designed:

```text
gauntlet                                  # state and the next step
gauntlet lead add "bob reads alice's order" --flow 41 \
    --class web-authz/private-object-read --property private-orders
gauntlet verify L-1 --plan                # what it would send; sends nothing
gauntlet verify L-1                       # re-runs the test with its own controls
gauntlet report
```

## Planned stack

Gauntlet coordinates existing tools rather than replacing them:

| Tool | Role |
|---|---|
| [Teapot](https://github.com/bobisme/teapot) | HTTP workbench: capture, sessions, replay, authz compare |
| [Sippycup](https://github.com/bobisme/sippycup) | SIP/RTP protocol testing (later milestone) |
| [Hallpass](https://github.com/bobisme/hallpass) | Approval passes and budget accounting |
| [Playpen](https://github.com/bobisme/playpen) | Network egress confinement |
| [Bones](https://github.com/bobisme/bones) | Work tracking |
| Investigation | Evidence custody (planned; not yet implemented) |
| Ward | Static analysis of source, when source is available |
| [Edict](https://github.com/bobisme/edict) | Model for bootstrap, managed instructions and the evaluation harness |
| [Vessel](https://github.com/bobisme/vessel) | Optional worker lifecycle |

## Documents

- [`notes/plan.md`](notes/plan.md): the implementation plan, revision 2. Binding decisions, architecture, domain model, the verifier and its two oracle specifications, milestones M0–M2, numbered invariants and the fixture catalog.
- [`notes/plan.evaluation.md`](notes/plan.evaluation.md): evaluation protocol and release gates.
- [`notes/plan.later.md`](notes/plan.later.md): milestones M3–M5 and deferred work.
- [`notes/plan.research.md`](notes/plan.research.md): research ledger with inspection depth, and the record of what was read in the stack.
- [`notes/plan.rev1.md`](notes/plan.rev1.md): revision 1, superseded. Its §24 holds the review disposition that led to revision 2.
- [`notes/plan.review.1.md`](notes/plan.review.1.md), [`2`](notes/plan.review.2.md), [`3`](notes/plan.review.3.md): reviews of revision 1. Their section and line references point into `plan.rev1.md`.

## Roadmap

Investigation, the evidence store, is built first. Then:

1. **M0 — evidence before design:** check facts about the stack, run baseline trials with plain tools on the Teapot testbed, prove the custody boundary, check conformance against Investigation.
2. **M1 — walking skeleton:** lead to verified finding with one oracle, used by a cold agent.
3. **M2 — complete HTTP:** second oracle, fix verification, crash recovery, isolated custody, reports and offline-checkable bundles.
4. **M3 — discovery:** surface map, coverage, out-of-band canaries, browser adapter, parallel workers.
5. **M4 — protocol:** SIP and media verification with Sippycup.
6. **M5 — release:** held-out evaluation, support matrix, documentation.

## Name

`gauntlet` is a working codename.
