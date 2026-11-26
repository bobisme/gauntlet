# Scourge

![Scourge. Verify security findings. A three-lashed leather whip rests on a scratched wooden table in raking window light.](assets/scourge-cover.webp)

Scourge is a security verification tool for AI agents and human testers. An agent explores a target with ordinary tools and records what it sees as **leads**. Scourge then decides, with ordinary code, which leads are **verified findings**. The verifier re-runs the test itself, with fresh canaries and controls.

> **Status: M1 walking skeleton, not a release.** The CLI can create and inspect workspaces, record leads, preview verification without target traffic, and run the M1 `web-authz/private-object-read` verifier through qualified Teapot and Investigation executables. `scourge demo PATH` supplies a disposable local workspace for the tutorial. Retest, report, and release qualification remain future work in M2 and later milestones. Run repository tests with `just test`, or all pre-commit checks with `just check`.

## The problem

Agents that look for vulnerabilities often report false findings. A `200 OK`, a scanner alert, a crash or a reflected marker can look like proof and not be proof. Common causes:

- two session labels resolve to the same user;
- the object is public by design;
- a login page returns 200;
- a cached response is replayed;
- a fix "works" only because it broke authentication.

Scourge's job is to make that kind of false promotion hard to produce and easy to detect, without making the search for bugs slower.

## Design in brief

- **Explore freely, verify strictly.** Exploration uses the native instruments directly, under their own scope and budget enforcement. Confirmation goes through `scourge verify` only, which acquires every observation it judges.
- **Agents propose; code decides.** An agent supplies a claim and its bindings. It never supplies an observation, an oracle result or a `verified` flag. A finding's status is computed from immutable verification records every time it is read.
- **Controls are part of the claim.** The first oracle (`web.private-object-read.v1`) creates its own objects with fresh canaries, then needs an owner read, an other-user read, anonymous reads, a different-object read, and identity probes before and after. HTTP status codes play no part.
- **Measurement and policy are separate.** A test can show who received the canary. Only policy says whether they should have. The operator puts a rule on record for each resource (owner only, group, any logged-in user, or public). With no admitted rule a finding is `conditional`, not `verified`, and an agent cannot admit one.
- **The agent does not act as the victim.** Requests the verifier sends as an object's owner come from the engagement file, never from a lead.
- **What an instrument concludes is a lead.** Teapot has findings, a `certain` confidence and a `fixed` state of its own. In a Scourge workspace those are leads until `scourge verify` has run.
- **Honest labels.** Separate fields record execution, evidence completeness, the oracle result, reproduction and cleanup. An invalid test is never reported as a negative, and a negative is never reported as "secure". Each badge shows its custody tier (shared or isolated).
- **Fix verification is a comparison.** A retest checks that the observer still works and that legitimate behavior is intact, then tries the original test and nearby variants. A fix that breaks login is `inconclusive`, not fixed.
- **Black-box by default.** When source code is available, a separate tool, Ward, does the static analysis.

The tutorial needs the exact Teapot and Investigation executables listed in the
[Teapot qualification manifest](fixtures/contracts/manifest.json) and
[Investigation conformance record](fixtures/contracts/evidence/investigation-conformance.json).
Put those executables on the absolute entries of `PATH` or pass their paths
using `--teapot PATH` and `--investigation PATH`. The shell walkthrough also uses
`jq`.

```sh
workspace=./scourge-demo
scourge demo "$workspace"
scourge --workspace "$workspace" status
lead_id="$(
    scourge --format json --workspace "$workspace" lead add "bob reads alice's order" \
        --class web-authz/private-object-read --property orders \
        --slot other=bob |
        jq -er '.lead.id'
)"
scourge --workspace "$workspace" verify "$lead_id" --plan
scourge --workspace "$workspace" verify "$lead_id"
scourge demo --stop "$workspace"
```

The demo starts a loopback development fixture and its dedicated Teapot
engine, installs the managed guide, and returns the lead command in `next`.
The demo binds Alice as the owner through the workspace's runtime authority.
`verify --plan` is read-only. The explicit live `verify` call runs the verifier
against the local fixture. The fixture and engine stop after eight hours or
when you run the stop command. The workspace and evidence remain available
after stopping.

`scourge report` and `scourge retest FINDING` are planned for M2.

## Planned stack

Scourge coordinates existing tools rather than replacing them:

| Tool | Role |
|---|---|
| [Teapot](https://github.com/bobisme/teapot) | HTTP workbench: capture, sessions, replay, authz compare, scanner, and its own leads and findings |
| [Sippycup](https://github.com/bobisme/sippycup) | SIP/RTP protocol testing (later milestone) |
| [Hallpass](https://github.com/bobisme/hallpass) | Approval passes and budget accounting |
| [Playpen](https://github.com/bobisme/playpen) | Network egress confinement |
| [Bones](https://github.com/bobisme/bones) | Work tracking |
| Investigation | Evidence custody (in development) |
| Ward | Static analysis of source, when source is available |
| [Edict](https://github.com/bobisme/edict) | Model for bootstrap, managed instructions and the evaluation harness |
| [Vessel](https://github.com/bobisme/vessel) | Optional worker lifecycle |

## Documents

- [`notes/plan.md`](notes/plan.md): the implementation plan, revision 5. Binding decisions, architecture, domain model, the verifier and its two oracle specifications, milestones M0–M2, numbered invariants and the fixture catalog.
- [`notes/plan.evaluation.md`](notes/plan.evaluation.md): evaluation protocol and release gates.
- [`notes/plan.later.md`](notes/plan.later.md): milestones M3–M5 and deferred work.
- [`notes/plan.research.md`](notes/plan.research.md): research ledger with inspection depth, and the record of what was read in the stack.
- [`notes/plan.disposition.md`](notes/plan.disposition.md): what was done with every change the six reviews proposed, and the calls that still await the owner. It is §16 of the plan.
- [`notes/plan.rev1.md`](notes/plan.rev1.md): revision 1, superseded. Its §24 holds the review disposition that led to revision 2.
- [`notes/plan.review.1.md`](notes/plan.review.1.md), [`2`](notes/plan.review.2.md), [`3`](notes/plan.review.3.md): reviews of revision 1. Their section and line references point into `plan.rev1.md`.
- [`notes/plan.review.4.md`](notes/plan.review.4.md), [`5`](notes/plan.review.5.md): reviews of revision 2. Their line references point into `notes/plan.md` at commit `9d7ef0b`.
- [`notes/plan.review.6.md`](notes/plan.review.6.md): review of revision 3. Its line references point into `notes/plan.md` at commit `9115059`.

## Roadmap

M0 retained the verifier-led scope and froze the engagement, claim-template,
cross-lane and oracle contracts. The M1 implementation now has the thin local
path from lead through deterministic private-object-read verification, plus
recovery and the optional managed guide. Cold-agent qualification and the
remaining milestone gates are still required before an M1 completion or
release claim.

Investigation, the evidence store, is built first. Then:

1. **M0 — evidence before design:** check facts about the stack, build a development fixture that can run both oracles, run baseline trials on it with plain tools, prove the custody boundary, check conformance against Investigation.
2. **M1 — walking skeleton:** lead to verified finding with one oracle, used by a cold agent.
3. **M2 — complete HTTP:** second oracle, fix verification, crash recovery, isolated custody, reports and offline-checkable bundles.
4. **M3 — discovery:** surface map, coverage, out-of-band canaries, browser adapter, parallel workers.
5. **M4 — protocol:** SIP and media verification with Sippycup.
6. **M5 — release:** held-out evaluation, support matrix, documentation.

## Name

`scourge` is a working codename.
