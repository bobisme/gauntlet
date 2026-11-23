# Policy rule schema

**Status** · M0.7.1 freeze for the versioned rule contract. Admission remains an
operator action outside this file.

## Problem

An oracle can show that bob read alice's object. It cannot show that he was not
supposed to. Measurement and policy are kept apart (D15), and a rule counts only
when the operator has admitted it. The record must name the rule's source, the
property it applies to and the version it was admitted for, or a true
observation can be read as a violation it does not support.
[Plan §4.5](../../notes/plan.md#45-policy) [Plan §5.1](../../notes/plan.md#51-status-is-computed)

## Decision

[`schemas/policy-rule.v1.schema.json`](../../schemas/policy-rule.v1.schema.json)
(`scourge.policy-rule.v1`) describes one rule for one property of one engagement
revision. A rule states the expected audience for reads, for writes, or both,
plus optional operator prose.

The source is typed and each admitted form records an operator admission:

| `source.kind` | Recorded | Effect |
| --- | --- | --- |
| `engagement` | `revision` artifact ID and SHA-256, with admission | Admitted |
| `document` | citation artifact ID and SHA-256, a nonempty forward byte range, with admission | Admitted within the cited scope |
| `operator` | statement artifact ID and SHA-256, with admission | Admitted, attributed in shared custody |
| `inferred` | optional citation, never an admission | Not admitted |

Admission metadata is an `operator.*` actor, a UTC timestamp and an identity of
`attributed` or `authenticated`. Every admitted source requires
`target_version`.

## Guarantees and limits

A shape-valid rule conveys no authority. Only the operator admits a rule against
the bound engagement, and the isolated worker's broker refuses amendments
(INV-39). At least one audience is required. A citation's range must be
nonempty and forward whenever a citation is present, for `document` and
`inferred` sources alike; JSON Schema cannot compare `end` with `start`, so the
local check applies that range rule before it returns for an unadmitted inferred
source. An `inferred` rule with admission fields is invalid, and an admitted
source without a target version is invalid. The local check also compares the
rule with the engagement revision: the property must be declared, a stated
audience must equal the revision's audience, the target version must match, and
shared custody admits only an attributed statement.

Retrieving the cited bytes, checking that a selector covers the asserted text,
and judging whether the document really says it are Investigation's obligations
and the operator's, not this schema's. Severity, exploitability and business
impact are separate assessments and are not fields here.

## Evidence and revisit trigger

`just schema-check` validates
[`fixtures/target/schema-examples/policy-rule-orders.json`](../../fixtures/target/schema-examples/policy-rule-orders.json),
which cites the engagement example's revision by recomputed digest, and
exercises all four source forms plus invalid provenance, scope, audience and
admission. M0.4.5 kept the policy obligation because the baseline's collection
disclosure needed the owner policy to establish its significance.
[M0.4.5 decision](baseline-taxonomy-decision.md)

Reopen this contract when admission is written through the M2.4 broker, when
Investigation's citation interface changes, or if a rule needs a scope the
`property` plus `target_version` pair cannot express.
