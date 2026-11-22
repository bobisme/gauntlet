# Gauntlet

Gauntlet is a planned security verification tool for AI agents and human testers. An agent explores a target with ordinary tools and records what it sees as **leads**. Gauntlet then decides, with ordinary code, which leads are **verified findings**. The verifier re-runs the test itself, with fresh canaries and controls.

> **Status: design only.** This repository holds an implementation plan and three reviews of it. There is no code yet. All commands below are proposed and none of them exist.

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
- **Agents propose; code decides.** An agent supplies a stimulus and bindings. It never supplies an observation, an oracle result or a `verified` flag. A finding's status is computed from immutable verification records every time it is read.
- **Controls are part of the claim.** For example, the first oracle (`web.private-object-read.v1`) needs a fresh canary, an owner read, an other-user read, an anonymous read, a different-object read, and identity probes before and after. HTTP status codes play no part.
- **Honest labels.** Separate fields record execution, evidence completeness, validity, the oracle result, reproduction and cleanup. "No valid test" is never reported as "no finding". Each verified badge shows its custody tier (shared or isolated).
- **Fix verification is a paired comparison.** It reproduces the issue on the vulnerable build, checks that legitimate behavior still works on the fixed build, and tries nearby variants.
- **Black-box by default.** When source code is available, a separate tool, Ward, does the static analysis.

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
| [Edict](https://github.com/bobisme/edict) | Model for bootstrap, managed instructions and the evaluation harness |
| [Vessel](https://github.com/bobisme/vessel) | Optional worker lifecycle |

## Documents

- [`notes/plan.md`](notes/plan.md): implementation plan, revision 1. **Start with §24, the review disposition.** It recommends a revision 2 redesign of the operational architecture and keeps the verification model.
- [`notes/plan.review.1.md`](notes/plan.review.1.md): review against local source of the stack; records three owner decisions.
- [`notes/plan.review.2.md`](notes/plan.review.2.md): architecture and research critique.
- [`notes/plan.review.3.md`](notes/plan.review.3.md): release gates, trust boundaries and reporting.

## Roadmap (from the disposition)

1. **M0:** check facts about the stack; baseline runs with plain tools on the Teapot testbed; custody spike.
2. **M1:** walking skeleton from lead to verified finding, used by a cold agent.
3. **M2:** complete HTTP authorization workflow with fix verification and crash recovery.
4. **M3:** discovery aids (surface mapping, out-of-band canaries, browser adapter, parallel workers).
5. **M4:** protocol and cross-protocol verification with Sippycup.
6. **M5:** release evaluation.

## Name

`gauntlet` is a working codename.
