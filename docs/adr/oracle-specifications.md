# Frozen v1 web oracle specifications

**Status** · Frozen for M0.7.3. The normative machine contract is
[`scourge.oracle-specifications.v1`](../contracts/oracle-specifications.v1.json).
This ADR fixes the inputs, predicates, invalid results, scope and mutation
checks; it does not claim that the M1/M2 implementations or mutation fixtures
already exist. The registry therefore declares `implementation_status` as
`contract_only`.

## Decision basis

The starting definitions are plan §§6.5–6.7 and the 100% mutation gate in the
evaluation plan §9. The development referee catalog confirms the intended
content-read and field-write cases. The M0 baseline adds one necessary boundary:
the echo observations support a collection-disclosure proposition even though
they fail object specificity, while the login-page difference raises a separate
existence/status proposition without exposing protected content. Neither claim
class is adjudicated by `web.private-object-read.v1`.

The cache miss in baseline position 3 also makes the F0/F1/F3 ordering a frozen
control rather than explanatory metadata. The state-change fixture and VAmPI
smoke confirm that a success status does not establish the named state change;
the oracle uses an owner readback of the fresh treatment value.

## `web.private-object-read.v1`

This oracle measures one proposition: whether a value planted in a declared
field of one fresh, run-owned object becomes readable by a forbidden principal
or without authentication. It does not infer from status codes.

| Flow | Principal | Action | Alternative ruled out | Invalid result |
| --- | --- | --- | --- | --- |
| I1, I2 | owner, other | identity probes | two labels for one subject | `SAME_SUBJECT` |
| P, P2 | owner | create two distinct objects with distinct fresh per-field canaries | stale content, prior sharing, response unrelated to the named object | — |
| F0 | anonymous | read P before the owner read | exposure independent of owner cache priming | — |
| F1 | owner | read P | unusable owner credential, object or observer | `OBSERVER_INVALID` |
| F2 | other | read P | cross-principal treatment | — |
| F3 | anonymous | read P after F1 | unauthenticated treatment after priming | — |
| F4 | other | read P2 | a global echo mistaken for an object read | `CANARY_NOT_SPECIFIC` |
| I3, I4 | owner, other | repeat identity probes | session switch or expiry | `SESSION_DRIFT` |
| C | owner | remove only objects whose plant response established run ownership | cleanup without authority | recorded separately |

The result is `true` only when setup is valid, F1 contains P's canary, F4 does
not, and that same canary occurs in F0, F2 or F3. It is `false` only when setup
is valid and the canary occurs in none of F0, F2 and F3. F0 or F3 yields
`unauthenticated`; otherwise F2 yields `cross_principal`. F0 absent plus F3
present records `after_owner_read`.

`SAME_SUBJECT`, `OBSERVER_INVALID`, `CANARY_NOT_SPECIFIC`, `SESSION_DRIFT` and
`EVIDENCE_INCOMPLETE` are `invalid`, never `false`. Missing, truncated,
over-limit or unavailable original bytes are `EVIDENCE_INCOMPLETE`. An
instrument or oracle crash is `error`. Transfer and content decoding is bounded
and named in the record; matching uses decoded bodies while retained originals
stay byte-exact.

Policy remains separate. A `true` observation can be allowed, forbidden or
unresolved according to the admitted property rule. No admitted rule produces
`conditional`, not a guessed default.

### Numbered mutation checks

| Check | Check removed by the mutant | Killing fixture evidence |
| --- | --- | --- |
| POR-01 | initial subjects must differ | F-01; `decoys.same_subject` |
| POR-02 | final subjects must equal their initial subjects | F-07; `decoys.session_expiry` |
| POR-03 | P and P2 are distinct run-owned objects with fresh distinct per-field canaries | F-09, F-27 |
| POR-04 | F1 contains P's canary before treatment can support a result | F-03; `decoys.login_page` |
| POR-05 | F4 excludes P's canary | F-08; `decoys.canary_echo` |
| POR-06 | treatment matching uses the exact current P canary, not status or stale content | F-05, F-06; `flaws.forbidden_body`, `decoys.stale_snapshot` |
| POR-07 | F0 precedes F1 and F3 follows it | F-37; `flaws.shared_private_cache` |
| POR-08 | all required flows are complete and bound to this run | F-09, F-11 |
| POR-09 | decoding is named and bounded and original bytes remain retained | F-42 |
| POR-10 | every declared field has its own canary and crossed fields are reported separately | F-42, F-47 |
| POR-11 | cleanup authority comes from the successful plant response | F-27, F-40 |
| POR-12 | collection and existence/status claims cannot pass this object-content oracle | F-03, F-08; M0-ADD-03 |

Known misses are exposure in uncanaried or owner-unwritable fields, delayed
exposure, the mechanism behind a login-state cache flaw, cross-account or
tenant-wide state that reaches across accounts, and objects the verifier cannot
create. Separate verifier principals close the account-level route. Collection disclosure and object existence/status are
also outside this class. A lead for either class must get `ORACLE_UNAVAILABLE`
before target traffic, list the shipped classes, stay a lead and never promote.
`CANARY_NOT_SPECIFIC` and `OBSERVER_INVALID` reject only the object-content
interpretation; they do not refute those different propositions.

## `web.forbidden-state-change.v1`

This oracle measures whether a forbidden principal changes one declared,
canary-capable field on a fresh run-owned object. It uses the same concrete
canary observer but freezes a different flow and predicate.

| Flow | Principal | Action | Alternative ruled out | Invalid result |
| --- | --- | --- | --- | --- |
| I1, I2 | owner, other | identity probes | two labels for one subject | `SAME_SUBJECT` |
| P | owner | create a fresh object with V0 | stale state and prior sharing | — |
| W2, R2 | owner | write fresh V2, then read it | broken legitimate write/read path or cached read | `OBSERVER_INVALID` |
| W1 | other | write fresh V1 | cross-principal treatment | — |
| R1 | owner | read after W1 | treatment that made the owner's view unusable | `OWNER_VIEW_LOST` |
| W3, R3 | anonymous, owner | write fresh V3, then owner reads | unauthenticated treatment | — |
| I3, I4 | owner, other | repeat identity probes | session switch or expiry | `SESSION_DRIFT` |
| C | owner | remove the run-owned object | cleanup without authority | recorded separately |

The result is `true` only when R2 contains V2 and R1 contains V1 or R3 contains
V3. It is `false` only when R2 contains V2, R1 still contains V2, and R3 does
not contain V3. An R1 owner view containing neither V1 nor V2 is `OWNER_VIEW_LOST`,
not `false`: a lock, transfer or deletion is not evidence that the write was
blocked. `SAME_SUBJECT`, `OBSERVER_INVALID`, `OWNER_VIEW_LOST`,
`SESSION_DRIFT` and `EVIDENCE_INCOMPLETE` are invalid; crashes are `error`.
The owner's W2/R2 control happens before either treatment.

### Numbered mutation checks

| Check | Check removed by the mutant | Killing fixture evidence |
| --- | --- | --- |
| FSC-01 | initial subjects must differ | F-01; `decoys.same_subject` |
| FSC-02 | final subjects must equal their initial subjects | F-07; `decoys.session_expiry` |
| FSC-03 | P establishes a fresh run-owned object and V0 | F-09, F-27 |
| FSC-04 | W2/R2 precede treatments and R2 contains exact V2 | F-03, F-41 |
| FSC-05 | R1 distinguishes exact V1, retained V2 and a lost owner view | F-41; `flaws.cross_user_order_patch` |
| FSC-06 | R3 requires exact V3, and its absence supports false only when R1 retained V2 | F-41 |
| FSC-07 | V0, V1, V2 and V3 are fresh, distinct and field-specific | F-06, F-09, F-47 |
| FSC-08 | all required flows are complete and bound to this run | F-09, F-11 |
| FSC-09 | decoding is named and bounded and original bytes remain retained | F-42 |
| FSC-10 | cleanup authority comes from P's successful response | F-27 |
| FSC-11 | only canary-capable field writes are in class | F-41, F-51 |

Known misses are effects invisible in the owner's read of the declared field,
asynchronous changes after the observation window, fields that cannot hold a
canary string, and destructive or fixed-value transitions such as delete,
cancel and approve. Those actions need the later three-object template; this
oracle must not stretch its predicate to cover them.

## Qualification and revisit triggers

Each released version is compiled into the verifier and is qualified only when
removing every numbered check independently makes at least one named fixture
fail: 100% of listed checks. This ADR records the list; M1/M2 implement the
fixtures and mutation runner. Old versions remain evaluable and a revoked
version makes dependent findings `needs_review`.

Reopen this decision if a numbered check has no killing fixture, an
implementation can produce a result without the frozen predicate, either v1
template accepts a claim class named as a known miss, or target evidence shows
that the next non-string or non-object effect class must be scheduled earlier.

## Evidence

- [`notes/plan.md` §§6.5–6.7](../../notes/plan.md#65-the-first-oracle-webprivate-object-readv1)
- [`notes/plan.evaluation.md` §9](../../notes/plan.evaluation.md#9-oracle-mutation)
- [development referee catalog](../../fixtures/target/referee/ground-truth.json)
- [M0 failure taxonomy](../../evals/baseline/FAILURE-TAXONOMY.md)
- [M0.4.5 scope decision](baseline-taxonomy-decision.md)
