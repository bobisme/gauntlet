# `web.private-object-read.v1`

**Shipped class:** `web-authz/private-object-read`  
**Oracle:** `web.private-object-read`, version `1`  
**Observer:** cross-principal canary

This oracle measures whether a value placed in a declared field of one fresh,
run-owned object can be read by another principal or without authentication.
It evaluates object content. HTTP status, response shape, and an instrument's
own confidence do not establish exposure. The exact reason codes and checks
below are checked against the compiled oracle registration and the frozen
`scourge.oracle-specifications.v1` contract.

## Flows

Flows are acquired by the verifier in this exact order. The action, control,
and failure-code cells below are an exact projection of the frozen contract.

| Flow | Principal | Action | Control / what it rules out | Invalid reason, if any |
| --- | --- | --- | --- | --- |
| `I1` | `owner` | `identity_probe` | initial owner subject | `SAME_SUBJECT` |
| `I2` | `other` | `identity_probe` | initial other subject | `SAME_SUBJECT` |
| `P` | `owner` | plant primary object with fresh per-field canaries | fresh run-owned primary object | — |
| `P2` | `owner` | plant distinct control object with fresh per-field canaries | object-specific correlation | — |
| `F0` | `anonymous` | read primary object before owner read | separate cold exposure from owner-primed exposure | — |
| `F1` | `owner` | read primary object | owner observer, credential, and object are usable | `OBSERVER_INVALID` |
| `F2` | `other` | read primary object | cross-principal treatment | — |
| `F3` | `anonymous` | read primary object after owner read | unauthenticated treatment after priming | — |
| `F4` | `other` | read control object | primary canary is specific to the named object | `CANARY_NOT_SPECIFIC` |
| `I3` | `owner` | `identity_probe` | owner subject stayed stable | `SESSION_DRIFT` |
| `I4` | `other` | `identity_probe` | other subject stayed stable | `SESSION_DRIFT` |
| `C` | `owner` | remove both run-owned objects | record cleanup separately | — |

## Result predicate

The primary canary is the current canary planted in P, matched in the decoded
response body. These are the exact frozen predicates:

| Result | Predicate |
| --- | --- |
| `true` | setup is valid; the primary canary is present in F1 and absent from F4; and that same canary is present in at least one of F0, F2, or F3 |
| `false` | setup is valid and the primary canary is absent from F0, F2, and F3 |
| `invalid` | the first applicable reason in the precedence table below; invalid is never converted to false |
| `error` | an instrument or oracle crash |

Exposure is **`unauthenticated`** if F0 or F3 contains the canary. Otherwise,
if F2 contains it, exposure is **`cross_principal`**. The detail
**`after_owner_read`** is recorded when F0 lacks the canary and F3 contains it.
The oracle records exposure independently of whether policy allows it.

## Invalid reason codes

Codes are listed in precedence order. Missing, incomplete, truncated,
over-limit, undecodable-within-limits, or unavailable retained evidence yields
`EVIDENCE_INCOMPLETE` when no higher-precedence invalid reason decides the
result.

| Code | Meaning |
| --- | --- |
| `SAME_SUBJECT` | I1 and I2 resolve to the same stable subject |
| `OBSERVER_INVALID` | F1 does not contain the primary object canary |
| `CANARY_NOT_SPECIFIC` | F4 contains the primary object canary |
| `SESSION_DRIFT` | I3 or I4 differs from its initial subject |
| `EVIDENCE_INCOMPLETE` | a required flow is missing, truncated, undecodable within limits, or lacks retained original bytes |

An instrument or oracle crash is `error`, not an invalid reason code.

## Numbered checks

Each check is one obligation in the mutation gate. Removing it must make its
listed witness fail to kill the corresponding mutant.

| Check | Required check | Killing evidence |
| --- | --- | --- |
| POR-01 | I1 and I2 resolve to distinct stable subjects | F-01, development:decoys.same_subject |
| POR-02 | I3 equals I1 and I4 equals I2 | F-07, development:decoys.session_expiry |
| POR-03 | P and P2 create distinct run-owned objects with fresh, distinct per-field canaries | F-09, F-27 |
| POR-04 | F1 contains the primary canary before any treatment can support a result | F-03, development:decoys.login_page |
| POR-05 | F4 does not contain the primary canary | F-08, development:decoys.canary_echo |
| POR-06 | only the exact current primary canary, not status or stale content, counts in F0, F2, and F3 | F-05, F-06, development:flaws.forbidden_body, development:decoys.stale_snapshot |
| POR-07 | F0 precedes F1 and F3 follows it so after_owner_read is derived from the ordered pair | F-37, development:flaws.shared_private_cache |
| POR-08 | every required flow is present, complete, and bound to this run | F-09, F-11 |
| POR-09 | matching uses the named bounded decoder while original response bytes remain retained | F-42 |
| POR-10 | each declared field has its own canary and every crossed field is reported independently | F-42, F-47 |
| POR-11 | cleanup is attempted only for objects whose plant response established run ownership | F-27, F-40 |
| POR-12 | collection-disclosure and object-existence leads cannot be evaluated or promoted by this object-content oracle | F-03, F-08, M0-ADD-03 |

## Policy and exposure

The oracle answers who could read the canary. An admitted property rule decides
whether that observed exposure is allowed. A `true` oracle result alone does
not make a finding verified.

| Admitted `readers` audience | `cross_principal` | `unauthenticated` |
| --- | --- | --- |
| `owner` | Not allowed | Not allowed |
| `group` | Allowed only when the principals share a declared group | Not allowed |
| `authenticated` | Allowed | Not allowed |
| `public` | Allowed | Allowed |

A rule is admitted when its source is `engagement`, an operator-admitted
`document` scoped to the named resource and version, or an `operator`
statement. An `inferred` rule, including an artifact the operator has not
admitted, is not policy authority. With no admitted rule, a true result remains
`conditional`; the oracle does not guess a default. Policy admission and its
provenance are recorded separately from the measured exposure.

## Scope boundary: separate claim classes

`collection_disclosure` and `object_existence_or_status` are distinct claim
classes. They are **not** negative object-read results and are not adjudicated
by this oracle.

| Unsupported claim class | Dispatch result | Timing |
| --- | --- | --- |
| `collection_disclosure` | `ORACLE_UNAVAILABLE` | before target traffic |
| `object_existence_or_status` | `ORACLE_UNAVAILABLE` | before target traffic |

- A non-specific echo can support a collection-disclosure lead, even when F4
  makes the object-read result `invalid` with `CANARY_NOT_SPECIFIC`. That
  invalid result rejects only the object-specific interpretation; it does not
  refute collection disclosure.
- A login page, status difference, or other existence signal without P's
  protected content can support a separate existence/status lead. If F1 lacks
  P's canary, `OBSERVER_INVALID` rejects the object-content interpretation; it
  does not decide whether the object exists.
- An explicitly scoped lead in either class yields `ORACLE_UNAVAILABLE` in
  `verify --plan`. The normal `verify` path refuses it before target traffic,
  reports supported classes, and leaves it a lead without promotion.

## Known misses

These are the exact registered limitations of the test. A verification record
publishes its applicable subset in `limitations`; full-depth `show` exposes
that subset with a link to this guide.

| Known miss |
| --- |
| fields that carry no canary, including fields the owner cannot write |
| exposure delayed past the observation window |
| the mechanism behind a cross-principal cache exposure |
| cross-account or tenant-wide state that reaches across accounts; separate verifier principals close the account-level route |
| objects the verifier cannot create |
| collection disclosures not specific to the requested object |
| object existence or status disclosures without protected field content |

## Development-fixture example

The development fixture includes the owner-private `orders` property
(INV-34). The demo binds the declaration and its owner policy through the
workspace runtime. The fixture's orders API is described in the
[`fixtures/target/README.md`](../../fixtures/target/README.md#owner-private-orders).
The [tutorial prerequisites](../../README.md) also apply to the runnable
[`private-object-read-workflow.sh`](../../fixtures/target/example/private-object-read-workflow.sh)
witness.

```sh
scourge demo ./scourge-demo
fixtures/target/example/private-object-read-workflow.sh ./scourge-demo demo
scourge demo --stop ./scourge-demo
```

`verify --plan` is read-only: it prints the matched template, slot resolution,
flows, effects, request ceiling, custody, policy outcome, guide link, applicable
known misses, and `next` command. The witness then runs trusted verification
and passes the resulting record ID to `show --depth full`. Summary and title
depths intentionally omit the guide and limitation expansion. The actual
finding depends on fixture state and the admitted rule; the owner-private
example policy is a test setup, not a claim about a real service.

The runnable fixture qualification is `just fixture-check`. It exercises the
development fixture and its public engagement on loopback; the first-oracle
live qualification is `just oracle-fixture-check TEAPOT INVESTIGATION` with
the pinned Teapot and Investigation executables from the project tool setup.
