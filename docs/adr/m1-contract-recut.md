# M1 re-cut against the M0 evidence and frozen contracts

**Status** · Adopted for plan revision 6. The machine-readable disposition is
[`scourge.m1-recut.v1`](../contracts/m1-recut.v1.json), checked by
`just m1-recut-check`.

## Decision

The preregistered M0 result was inconclusive: six of ten assigned sessions were
valid, the other four invalid sessions were still categorized, and the taxonomy
was adjudicable for the six valid submissions. The conservative adjudication
found two unsupported claims at the threshold of two. No branch applied solely
because the preregistered ten-valid-session prerequisite failed. Keep the
verifier-led, shared-custody M1 skeleton. No M1 bone is cut or split. Keep all
11 obligations, 51 invariants and 53 fixtures, and add the four measured
acceptance requirements in their existing lanes.

Plan revision 6 replaces proposal-shaped details with the M0.7 contracts:

- engagement, policy and template use `scourge.engagement.v1`,
  `scourge.policy-rule.v1` and `scourge.claim-template.v1`;
- machine responses, request equality, verification/publication and accounting
  use the shapes in `scourge.contract-registry.v1`;
- the adapter uses `scourge.teapot-argv.v1`, preserving the distinction between
  captured and schema-only variants;
- the verifier implements `scourge.oracle-specifications.v1`, including its
  numbered mutation checks and out-of-class boundary.

The important semantic correction is that an engagement contains inert
registered references, never request grammar. The first template's property
slots are operator-only. A lead may select a declared property and supply the
principal pair; it cannot write the owner-side operations.

## Acceptance routes changed

| Requirement | M1 routes |
| --- | --- |
| M0-ADD-01 reachable transport and typed masked failure | `bn-1aw`, `bn-24v`, `bn-360`; adapter diagnostics in `bn-20h` |
| M0-ADD-02 interrupted nested capture qualification | `bn-360`; reuse in M2.10 `bn-wog` |
| M0-ADD-03 collection/existence claim scope | `bn-36n`, `bn-20l`, `bn-23g`; referee reuse in `bn-wog` |
| M0-ADD-04 supplied-lead cache coverage | `bn-360` |

`bn-23g` is the promotion boundary. For an explicitly scoped collection or
existence lead with no shipped template, `verify --plan` is read-only and
returns `ORACLE_UNAVAILABLE` with the supported classes. `verify` refuses before
target traffic. Both objects remain leads; neither becomes a negative finding
for the wider class. The F-08 collection proposition and F-03 existence
proposition are adjudicated independently of the object-read key.

The complete 55-bone keep set and every material contract route are in the JSON
disposition. M1.10 and M1.11 remain in the independent Tier 1/operator lane and
do not enter the M1 exit gate. The existing package order and dependencies are
unchanged.

## Evidence and limits

The sources are the baseline taxonomy decision, M0.1 inventory and native
contracts, and the three M0.7 freeze ADRs. This re-cut changes acceptance and
terminology; it implements no M1 feature and makes no release-readiness claim.
The final M0.6 public-interface run still has to name a passing Investigation
build before M1.4 starts.

Reopen the sequence only at the triggers in the baseline decision: a cold-start
cell cannot complete because of setup, capture or evidence scope, a valid run
promotes outside the first oracle's class, or a separately authorized frozen
replication selects a different preregistered branch.
