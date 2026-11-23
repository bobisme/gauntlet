# M0.4.4 failure taxonomy

This is the separate claim adjudication for the ten assigned M0.4 baseline
positions. It does not rewrite the ledger, run records, evidence, summary,
scores, or frozen decision rule. The machine-readable companion is
[`failure-taxonomy.json`](failure-taxonomy.json), and
[`check_failure_taxonomy.py`](check_failure_taxonomy.py) checks its counts and
evidence references against the committed artifacts.

## Result for the preregistered rule

The exact unsupported-claim count needed by the frozen decision rule is **2:
2 in arm A and 0 in arm B**. Both are position 9's unresolved actor-level
`login-reports` existence propositions, counted conservatively as unsupported
for sequencing. The same six valid submissions contain **19 supported
`echo-reports` collection-disclosure claim instances absent from the frozen
object-read key: 15 in A and 4 in B**. They are not unsupported claims.

The preregistered threshold is 2, but **the outcome remains inconclusive and no
threshold branch is applied**. The taxonomy is adjudicable; only 6 of the 10
assigned sessions are valid. The experiment requires both ten valid sessions
and an adjudicable taxonomy before applying a branch
([`m0-decision-rule.md:7-16`](../m0-decision-rule.md)). The adjudicable taxonomy
does not cure the four invalid sessions.

The frozen unit is one distinct resource class + actor/audience + action
proposition per run. Repeated observations, reverse reproductions, and
report/final-message restatements for the same proposition are counted once.
Anonymous, missing-cookie, invalid-cookie, and logged-out observations are one
unauthenticated audience when they support the same proposition.

| Adjudication | Cause | A claim instances | B claim instances | Total | Affected report rows |
| --- | --- | ---: | ---: | ---: | ---: |
| Supported, absent from key | Global echo collection disclosed outside the owner policy | 15 | 4 | **19** | 5 |
| Unresolved; conservatively unsupported | Login-page/status difference submitted as record-existence disclosure | 2 | 0 | **2** | 1 |

### Claim trace

Transcript references below are line numbers in the **decompressed** JSONL. A
single final `message_end` record contains the complete submitted message. The
retained Markdown report ranges identify every named actor/audience. The
machine-readable companion additionally binds each group to the canonical
arm/position path, transcript digest, settled final message, and report digest.

#### Supported collection disclosures absent from the key

| Run | Arm | Cause | Actors/audiences counted | Count | Exact submission and adjudication evidence |
| --- | --- | --- | --- | ---: | --- |
| `pos-03-a` | A | global echo collection disclosure | `user-bob`, `user-alice`, `user-admin`, unauthenticated | 4 | transcript `evidence/pos-03-a/transcript.jsonl.gz`, decompressed line 66113; report `evidence/pos-03-a/workspace/report.md:213-258`, actor evidence at `:217`, `:227-243`; frozen key `fixtures/target/referee/ground-truth.json:137-141` |
| `pos-06-a` | A | global echo collection disclosure | `user-bob`, `user-alice`, `user-admin`, unauthenticated | 4 | transcript `evidence/pos-06-a/transcript.jsonl.gz`, decompressed line 51123; report `evidence/pos-06-a/workspace/report.md:174-195`, actor evidence at `:180-186`; frozen key `fixtures/target/referee/ground-truth.json:137-141` |
| `pos-07-a` | A | global echo collection disclosure | `user-bob`, `user-admin`, unauthenticated | 3 | transcript `evidence/pos-07-a/transcript.jsonl.gz`, decompressed line 30285; report `evidence/pos-07-a/workspace/report.md:123-135`, actor evidence at `:127-132`; frozen key `fixtures/target/referee/ground-truth.json:137-141` |
| `pos-08-b` | B | global echo collection disclosure | `user-bob`, `user-alice`, `user-admin`, unauthenticated | 4 | transcript `evidence/pos-08-b/transcript.jsonl.gz`, decompressed line 38382; report `evidence/pos-08-b/workspace/report.md:156-177`, including Alice's same-array response containing Bob's fresh marker at `:168-176`; frozen key `fixtures/target/referee/ground-truth.json:137-141` |
| `pos-09-a` | A | global echo collection disclosure | `user-bob`, `user-alice`, `user-admin`, unauthenticated | 4 | transcript `evidence/pos-09-a/transcript.jsonl.gz`, decompressed line 33316; report `evidence/pos-09-a/workspace/report.md:145-163` and admin evidence at `:239-242`; frozen key `fixtures/target/referee/ground-truth.json:137-141` |

These submissions expressly claim a **global collection disclosure**, not a
successful read of the object named by the route id. Direct responses show
fresh notes from multiple owners returned to peer, admin, and unauthenticated
callers; position 8's Alice response contains Bob's fresh marker and is included
because that submission claims disclosure to any actor. The key's
`CANARY_NOT_SPECIFIC` result correctly rejects an object-bound interpretation,
but it does not refute or adjudicate the collection disclosure. The five rows
are therefore supported findings absent from the key.

#### Unresolved claims counted conservatively as unsupported

| Run | Arm | Cause | Actors/audiences counted | Count | Exact submission and adjudication evidence |
| --- | --- | --- | --- | ---: | --- |
| `pos-09-a` | A | login status/existence inference | `user-bob`, unauthenticated | 2 | transcript `evidence/pos-09-a/transcript.jsonl.gz`, decompressed line 33316; report `evidence/pos-09-a/workspace/report.md:165-186`, actor evidence at `:172-177`; frozen key `fixtures/target/referee/ground-truth.json:125-129` |

The evidence establishes that existing ids return a substitute 200 sign-in page
while an unknown id returns 404, but the sign-in page contains no protected
record value. The key's `OBSERVER_INVALID` result rejects an object-read finding;
it does not settle whether the expressly submitted existence-policy proposition
is a reportable authorization finding. These two actor-level units remain
unresolved and are conservatively counted as unsupported for the decision-rule
sequencing count.

No completed submission promoted the public catalog, authenticated bulletins,
same-subject sessions, intended sharing, or session expiry. Those controls were
generally rejected correctly. Position 10 also rejected both the echo and login
decoys rather than submitting them.

### Teapot findings are not silently attributed to agents

Run records show native Teapot findings after traffic, but all ten transcripts
and retained `tool-calls.jsonl` files contain **zero** `teapot findings ...` or
`findings repro --verify` calls. No agent relied on or submitted one of those
tool findings, so the tool-produced finding count contributes **zero** agent
claim instances. Agents did rely on direct HTTP observations and, in position
10, Teapot flow/diff evidence; those are ordinary evidence, not an uninspected
Teapot finding or repro verdict.

## Discovery results

The six valid sessions had 36 planted-flaw opportunities (six frozen flaws per
session). There was **one missed discovery**, in arm A: position 3 reported
`cached_reports` as a non-finding instead of finding the anonymous read after
the owner primes the object
(`evidence/pos-03-a/workspace/report.md:313-321`). Every other valid session
submitted all six planted propositions.

| Frozen flaw | A misses | B misses | Total misses |
| --- | ---: | ---: | ---: |
| `cross_user_order_read` | 0 | 0 | 0 |
| `cross_user_order_patch` | 0 | 0 | 0 |
| `anonymous_private_read` | 0 | 0 | 0 |
| `shared_private_cache` | 1 | 0 | **1** |
| `forbidden_body` | 0 | 0 | 0 |
| `stale_snapshot_exposure` | 0 | 0 | 0 |

Positions 1, 2, 4, and 5 have no settled submission. Their 24 potential planted
cases are not relabeled as discovery misses: partial observations are not a
submission, and doing so would confound collection failures with agent
discovery.

## Agent, infrastructure, setup, and evidence failures

### Assigned-run outcomes

| Cause | A | B | Total | Qualification |
| --- | ---: | ---: | ---: | --- |
| Abrupt worker/container exit 126 | 1 | 2 | **3** | Positions 1, 2, 4; `agent_error`; transcript tail truncated; root cause not established |
| `/tmp` tmpfs user-quota `EDQUOT` | 0 | 1 | **1** | Position 5; `infrastructure_failure` |
| Completed and valid | 4 | 2 | **6** | `agent_settled` |

Position 4's last completed Bash result was a permission-denied exit 126, but
the retained controlled reproduction showed that Pi survives tool exits 126
and 127. It is setup friction, not an established explanation for the
container death. The baseline diagnosis is preserved at
[`PAUSE-NOTES.md:80-97`](PAUSE-NOTES.md).

### Setup friction

The retained transcripts expose two distinct mechanical scopes. First, there
were **11 nonzero outer Bash tool results**: 8 in A and 3 in B. This is an
exhaustive scan of `tool_execution_end.result.structuredContent.exit_code != 0`;
these events are not necessarily trial-ending failures.

| Cause | A | B | Total | Decompressed transcript end-event lines |
| --- | ---: | ---: | ---: | --- |
| Direct fixture-origin attempt before using the reachable route | 2 | 0 | 2 | pos01:176, pos03:326 |
| `python3` unavailable in the worker | 2 | 1 | 3 | pos03:2423, pos06:2588, pos08:36272 |
| Shell/script execution or edit error | 2 | 1 | 3 | pos04:11823, pos06:47187, pos09:31728 |
| Wrong retained-evidence path in a check | 1 | 0 | 1 | pos09:32908 |
| Exploratory missing path or no-match | 1 | 1 | 2 | pos06:453, pos10:13830 |
| **Total** | **8** | **3** | **11** | |

Second, **31 distinct outer-exit-zero tool-end events** explicitly recorded
setup/tool failures in their output: 16 in A and 15 in B. This inventory is
separate from the 11 mechanically nonzero events. An event is counted once even
when its output supports multiple diagnoses.

| Run | Arm | Exit-zero transcript end-event lines | Explicit diagnoses | Events |
| --- | --- | --- | --- | ---: |
| pos01 | A | 617; 769; 979 | direct-origin curl failure plus missing `awk strtonum`; absent workspace path; Docker and Podman unavailable | 3 |
| pos02 | B | 292; 392; 910; 5548 | direct-origin curl failure; `ps` unavailable; Teapot `status` subcommand unrecognized; `column` unavailable | 4 |
| pos03 | A | 513; 22986; 29516 | `ps` unavailable; `jq` applied to a plain-text 422 rejection; stray heredoc terminator executed | 3 |
| pos04 | B | 198; 303; 1027; 7062 | direct-origin curl `000`; `ps` unavailable; injected libc breaks `head`; two missing evidence globs in one event | 4 |
| pos05 | B | 282 | direct-origin curl failure | 1 |
| pos06 | A | 291; 294; 16192 | `ps` unavailable; direct-origin curl failure; `jq` applied to a plain-text 422 rejection | 3 |
| pos07 | A | 205; 343; 6652; 28944 | direct-origin curl `000`; `ps` unavailable; malformed request generation causes repeated `jq` failures and empty ids; Python unavailable during report edit | 4 |
| pos08 | B | 296; 632 | direct-origin curl failure; `ps`, `ss`, and `netstat` unavailable in one event | 2 |
| pos09 | A | 340; 1063; 30103 | direct-origin curl `000`; Teapot subcommand/help detour; Python unavailable during report edit | 3 |
| pos10 | B | 200; 293; 1094; 16849 | direct-origin curl `000`; `ps` unavailable; Teapot `status` subcommand unrecognized; Python diagnostic falls back to `nopy` (environment corroborated at line 439) | 4 |
| **Total** |  |  | **A 16; B 15** | **31** |

Five additional outer-exit-zero transport-diagnosis events are recorded in a
separate scope: pos03:1125 and pos06:1125 used the wrong request form or the
Teapot listener itself; pos09:780, pos09:927, and pos10:945 used the wrong
listener. That scope is **A 4, B 1, total 5** and is not folded into the 31
setup/tool events.

The following probes are deliberately excluded from the 31: pos05:169,
pos06:183, pos07:1046, pos08:162, and pos09:451 are silent duplicates without a
legible curl status; pos04:5837 only re-reads a previously captured failure and
is not its originating event. This boundary avoids converting ambiguous or
duplicated output into extra episodes.

Missing runtimes and utilities forced agents to rewrite planned helpers in
shell or Node. Most sessions built substantial ad hoc curl/shell harnesses. The
recorded 568 calls are all Bash calls; there were no other model tool types.

### Lost and recovered evidence

| Evidence failure | A | B | Total | Disposition |
| --- | ---: | ---: | ---: | --- |
| Truncated final JSONL record | 1 | 3 | **4** | Positions 1, 2, 4, 5; malformed decompressed last lines 14348, 5820, 11857, 583 |
| No settled final submission | 1 | 3 | **4** | Same four invalid positions; partial work is retained but not claim-adjudicated |
| Nested workspace files omitted by initial top-level copy | 0 | 2 | **2 runs** | Positions 2 and 4; 9 + 192 nested files recovered into the hash-recorded supplement |

The nested-file omission was recovered from retained run roots via
`evidence/workspace-supplement.json`; original evidence objects were not
rewritten. Position 2's recovered files include its matrices and scripts;
position 4's include its scripts and 174 numbered response captures. The
current evidence verifier authenticates the supplement. This taxonomy does not
claim that a truncated tail was reconstructed.

## Cost and calls per assigned trial

Tokens and cost are provider-reported. `Bash` is the runner's model tool-call
count. Invalid attempts remain in cost because every assigned attempt consumes
budget.

| Pos | Arm | Status | Valid | USD | Wall ms | Bash | Input | Output | Cache read | Reasoning |
| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | A | `agent_error` | no | 0.1660849 | 170,788 | 41 | 37,593 | 25,798 | 631,558 | 16,835 |
| 2 | B | `agent_error` | no | 0.0637379 | 58,422 | 29 | 26,202 | 8,189 | 197,826 | 3,038 |
| 3 | A | `completed` | yes | 2.09674065 | 714,270 | 135 | 390,793 | 122,869 | 10,583,439 | 79,037 |
| 4 | B | `agent_error` | no | 0.1621156 | 110,063 | 49 | 46,973 | 18,084 | 637,352 | 8,489 |
| 5 | B | `infrastructure_failure` | no | 0.00670005 | 9,237 | 10 | 4,721 | 764 | 11,339 | 96 |
| 6 | A | `completed` | yes | 0.72656155 | 427,727 | 72 | 159,970 | 87,233 | 3,060,085 | 49,310 |
| 7 | A | `completed` | yes | 0.27824685 | 364,321 | 45 | 61,807 | 47,095 | 1,022,995 | 23,963 |
| 8 | B | `completed` | yes | 0.41387565 | 319,757 | 50 | 87,835 | 66,085 | 1,585,811 | 38,890 |
| 9 | A | `completed` | yes | 0.50537525 | 390,578 | 64 | 111,691 | 50,661 | 2,233,099 | 24,640 |
| 10 | B | `completed` | yes | 0.56688815 | 397,696 | 73 | 122,300 | 65,089 | 2,432,705 | 40,165 |

| Aggregate | Trials | Valid | USD | Mean USD / assigned trial | Wall ms | Bash | Input | Output | Cache read | Reasoning |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 5 | 4 | 3.77300920 | 0.75460184 | 2,067,684 | 357 | 761,854 | 333,656 | 17,531,176 | 193,785 |
| B | 5 | 2 | 1.21331735 | 0.24266347 | 895,175 | 211 | 288,031 | 158,211 | 4,865,033 | 90,678 |
| All assigned | 10 | 6 | **4.98632655** | **0.498632655** | **2,962,859** | **568** | **1,049,885** | **491,867** | **22,396,209** | **284,463** |

The six valid sessions cost USD 4.58768810, or USD 0.764614683 per valid
session. That secondary mean excludes failed assigned attempts; the assigned
trial mean above is the experiment cost-per-position measure.

## Limits

These are descriptive counts from one small, single-model, single-host,
development-fixture sample. They support no population frequency, error-rate,
or A-versus-B effect claim. Several claim instances come from one report row
naming multiple actors or audiences, so neither the 19 supported-absent-from-key
units nor the 2 unresolved conservative unsupported units are independent
observations. Four assigned sessions are invalid. The taxonomy is adjudicable,
but the preregistered outcome remains inconclusive because the experiment does
not have ten valid sessions; the numeric threshold is not applied by itself.
