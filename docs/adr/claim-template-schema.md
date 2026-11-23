# Claim template schema

**Status** · M0.7.1 freeze for the versioned template contract. Oracle
availability and control sufficiency are not established by it.

## Problem

A template fixes what a lead's claim means: the slots it needs, the ordered
flows, the controls, the oracle, the cleanup and the retest variants. A single
"controls passed" flag is not enough, because a negative result supports a
bounded claim only when the signal could have been seen.
[Plan §6.2](../../notes/plan.md#62-templates-and-slots)
[Plan §6.3](../../notes/plan.md#63-controls-have-a-purpose)

M0.4.5 found the failure this contract must prevent in shape: agents took an
echo that supported a collection disclosure and restated it under an
object-read claim. The same evidence cannot be judged by another class's
oracle. [M0.4.5 decision](baseline-taxonomy-decision.md)

## Decision

[`schemas/claim-template.v1.schema.json`](../../schemas/claim-template.v1.schema.json)
(`scourge.claim-template.v1`) describes one class. The recipe is an ordered list
of steps. Each step names a registered operation, the slots it binds, its effect
class from §7.8 and the controls it carries. Every control names a step, the
alternative explanation it rules out and the reason code a failure produces.

Slots declare a kind and who may supply them:

| Slot kind | May be supplied by | Meaning |
| --- | --- | --- |
| `principal` | operator or lead | The principal pair a lead proposes |
| `property` | operator only | A `read`, `plant`, `remove` or `write` reference the declared property fixes |
| `policy`, `observation`, `artifact`, `selector` | operator or lead, per slot | Other bindings |

The rule that a `property` slot is operator-only is the schema expression of
INV-36: a lead that supplies owner-side requests is asking the verifier to act
as the victim on the agent's instructions, and such a record reaches
`conditional` at best.

The class and the oracle scope must agree. `web-authz/private-object-read`
binds `object_read`; a collection, existence or state-change proposition binds
its own scope. `oracle.web.private-object-read.v1` is pinned to the object-read
class and scope. Cleanup names a step with the `plant` effect, because a run
removes only objects it created (INV-40). Retest variants carry both the
security-property and the legitimate-path dimension.

## Guarantees and limits

Slot bindings cover exactly the declared slots, and property slots are
operator-only. Step IDs are unique. Control references are bidirectional: every
control names a step that lists it, and every listed control exists and names
that step. Cleanup and retest steps resolve. Both retest dimensions are present.
Every non-`none` effect is in the engagement's `allow_effects`.

The template confers no runtime authority. Registered operation and oracle IDs
are inert references resolved by trusted pack code, and no step carries a
request, method, route, payload, credential or command. A shape-valid template
is not evidence that a class is available, that its controls are sufficient or
that cleanup succeeds. `web.private-object-read.v1` names the object-read scope
only, so the F-08 collection disclosure and the F-03 existence proposition need
distinct classes and remain leads until one ships; the verifier must surface
`ORACLE_UNAVAILABLE` and refuse dispatch for them.

## Evidence and revisit trigger

`just schema-check` validates
[`fixtures/target/schema-examples/claim-template-private-object-read.json`](../../fixtures/target/schema-examples/claim-template-private-object-read.json)
and exercises duplicate steps, invalid operation IDs, an unlisted effect,
unknown and mismatched control references, a cleanup step without the plant
effect, a lead-supplied property slot, missing retest dimensions and every
class/scope mismatch above.

Reopen this contract at M1.5, when the mutation suite shows which checks a
template's controls must name, or when a second oracle is specified.
