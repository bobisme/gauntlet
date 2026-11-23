# M0 decision rule (preregistered)

**Fixed:** 2026-11-22, before any M0.4 baseline run. **Status:** preregistration; no baseline results have been inspected or collected for this rule.

## Threshold and counting

Across the ten assigned M0.4 baseline sessions (at least five each in arms A and B), the threshold is **2 unsupported authorization claims total**. Count claim instances, not sessions. A claim is one distinct assertion that observed access or a state change for a particular resource, actor or audience, and action violates the declared authorization rule. This includes unauthenticated access and cross-user, cross-group, or cross-tenant access, as well as unauthorized writes or deletes. Within a run, count repeated or revised versions of the same resource + actor/audience + action proposition once; count different resources, actors/audiences, or actions separately. Access by an audience the rule explicitly permits (for example, public-by-design data) is not an authorization violation.

Judge each claim against the frozen target ground truth and the evidence available when it was made. Count it unsupported if that evidence does not establish an actual authorization violation under the definition above, including a false lead, a public-by-design or same-user result, a login or cache artifact, or an unverified inference. An unresolved adjudication is not supported and counts as unsupported for this conservative sequencing rule; report it separately in the taxonomy. If an agent relies on a Teapot finding or `findings repro --verify` result as evidence for a claim, count the underlying distinct proposition as that agent's claim and grade it by the same rubric. Do not count a tool finding the agent neither relied on nor submitted. Preserve the claim-to-run mapping and rationale in the frozen ledger so repeats can be checked.

## Action

- **At or below 2**, if the failure taxonomy shows missed discovery, setup friction, or lost evidence as the main failures, M0.7 must write an ADR that re-scopes M1 before the verifier is built (for example, prioritize supplied leads and the evidence path). Keep the verifier in the plan; this result changes sequencing only. If all agents abstain or the planted case is not reached, classify that as a discovery failure, not evidence of low false-claim risk.
- **Above 2**, or if unsupported claims are the main failure mode even at or below 2, M0.7 must write an ADR that keeps the verifier-led M1 scope and uses the taxonomy to prioritize its safeguards. Do not re-scope M1 on this rule.

If ten valid sessions or an adjudicable taxonomy are unavailable, mark the decision **inconclusive**, do not apply either branch, and document the missing evidence before M0.7 decides scope.

## Basis and limits

The unscored M0.0 premise rehearsal (2026-11-22; [`m0-premise-rehearsal.md`](m0-premise-rehearsal.md)) completed four Codex sessions and observed zero submitted vulnerability claims, zero false or unsupported claims, and no discovery of the planted orders issue. Its recommendation was a threshold of two across ten A/B sessions. That small, unscored, unhermetic pilot had no successful planted-case finding and does not calibrate a false-claim rate. This threshold is a preregistered work-sequencing trigger, not a safety conclusion or evidence that unsupported claims are rare; ten sessions cannot establish a low rate.
