# Baseline taxonomy and M1 scope

**Status** · M0.4.5 decision for the M0.7 contract freeze. Evidence cut at
`e4f03fab28d39f8e0d7b9704480a673c2c110e74`.

## Problem

M0 measured how agents handled an HTTP authorization task before Scourge had a
verifier. The result must guide the M1 walking skeleton and justify each proof
requirement. The threshold can select a sequence only when the validity and
adjudication prerequisites both hold. [Evaluation §4][eval-baseline]
[Preregistered rule][rule]

## Choice

**The preregistered result is INCONCLUSIVE. Neither threshold branch applies.**
Ten positions were attempted, five per arm. Six produced valid settled
submissions, four in A and two in B. Three workers exited abruptly with code 126
and one run hit `EDQUOT`. The root cause of the three worker exits remains
unestablished. The taxonomy is adjudicable for the six valid submissions.
[Baseline result][result] [Taxonomy and claim trace][tax-claims]

| Claim adjudication | A | B | Total |
| --- | ---: | ---: | ---: |
| Supported `echo-reports` collection disclosure instances absent from the frozen object-read key | 15 | 4 | 19 |
| Unresolved `login-reports` existence propositions, counted conservatively as unsupported | 2 | 0 | 2 |

The threshold is **2 unsupported authorization claims total**, and the observed
conservative count is **2**. The ten-valid-session prerequisite fails. The frozen
unit is a distinct resource class, actor or audience, and action proposition per
run, with repeated observations and restatements deduplicated. Teapot findings
contributed zero claim instances because agents neither used nor submitted them.
[Preregistered rule][rule] [Taxonomy JSON][tax-json]

**M1 decision under inconclusive evidence.** Keep the verifier-led, shared-custody
walking skeleton and its planned dependency order, with the first object-read
oracle taking a lead through to a finding. Preserve the cold-agent exit gate and
the parallel fixture and operator lanes. The collection and login propositions
show how easily the claim's scope can diverge from the oracle's measurement.
That distinction is a direct reason to ship scoped verification alongside the
setup and evidence improvements below. Resolve the contract details in M0.7,
exercise setup and capture at their existing entry points, and give the missed
cache case a reproducible acceptance test. Keep collection and existence
verification outside the first oracle's scope. [Taxonomy and claim trace][tax-claims]
[Discovery results][tax-discovery] [Milestone order and packages][packages]

## Proof obligations

The source key is the exact obligation label from [plan §5.4][plan-obligations].

| Obligation | Disposition | Reason |
| --- | --- | --- |
| Claim | KEEP | The collection and existence propositions occupied different scopes from the object-read key. A shipped class with explicit slots bounds the claim the verifier evaluates. [Claim trace][tax-claims] |
| Target | KEEP | Workers tried the direct origin and wrong instrument listeners. Recording the observed origin and identity strength ties results to the service actually reached. [Setup friction][tax-setup] [Target identity][target-identity] |
| Capability | KEEP | A real-app write returned a success status while changing only the acting account. Distinct, stable subject probes preserve the actor binding on which the claim depends. [Real-app submissions][smoke-claims] [Identity rules][identity] |
| Policy | KEEP | The collection disclosure required the owner policy to establish its significance. The login response difference alone left the existence-policy proposition unresolved. [Claim trace][tax-claims] |
| Setup | KEEP | The custody spike showed that a worker sharing the owner account could alter its sharing state before an object was created. Restricting owner requests to the engagement keeps the lead from controlling that setup directly. [Custody attempt 06][tamper-hold] [Templates and slots][slots] |
| Observation | KEEP | Four captures ended with truncated transcript tails, and two initially omitted nested files. Require the verifier's own complete originals for the run so loss and provenance are visible. [Evidence loss][tax-loss] [Investigation conformance][evidence] |
| Causality | KEEP | An owner-primed cache disclosure was missed, and a global echo interfered with object attribution. Each class control must establish the particular condition it tests. [Discovery results][tax-discovery] [Claim trace][tax-claims] |
| Oracle | KEEP | The same echo evidence supports a collection claim and fails the object-specific predicate. A registered, unrevoked version fixes which predicate and controls evaluated a run. [Claim trace][tax-claims] [Oracle qualification and revocation][oracles] |
| Reproduction | KEEP | The cache result depends on initial state and the order of reads. Retain the profile's round rule so one positive round cannot establish a repeatability claim. [Discovery results][tax-discovery] [Profiles][profiles] |
| Freshness | KEEP | An initially valid observation can become unusable when its originals disappear or a named oracle version is revoked. Compute status at read time against the recorded basis. [Evidence loss][tax-loss] [Computed status][status] |
| Disclosure | KEEP | Arm A's real-app report said changes were reverted while three created books persisted until teardown. Require the run to disclose custody, enforcement, accounting and cleanup, and block closure on unresolved effects or cleanup under INV-19. [Real-app correction][smoke-correction] [Custody decision][custody] |

## Invariants

The source key is the invariant ID from [plan §13][plan-invariants].

| Invariant | Disposition | Reason |
| --- | --- | --- |
| INV-01 | KEEP | A caller-controlled record would bypass verification. The custody spike showed a same-user worker could write the coordination database stand-in, so only the verifier's publication path may accept a record. [Custody attempts 01 and 04][tamper] |
| INV-02 | KEEP | A cached status can hide a new objection, policy change, revocation, loss of evidence or retest. Name one snapshot for the computation and display. [Computed status][status] [Coherent coordination reads][store] |
| INV-03 | KEEP | Earlier exploration flows can carry valid observations for a different class, object or state. Require the verifier's own run-bound originals. [Claim trace][tax-claims] [Custody attempt 04][tamper] |
| INV-04 | KEEP | Missing originals and omitted evidence arose during collection. Local re-evaluation and bundle completeness checks distinguish lost or changed promised evidence from a declared limitation. [Evidence loss][tax-loss] [Bundle verification][bundle] |
| INV-05 | KEEP | The three custody setups gave materially different access. A badge and its record must disclose which context, oracle and method support its claim. [Custody configurations][tamper-config] [Result dimensions][result-dimensions] |
| INV-06 | KEEP | Public and intended sharing controls were generally rejected correctly. A true observation needs an admitted, applicable rule before it becomes verified. [Claim trace][tax-claims] [Policy rules][policy] |
| INV-07 | KEEP | Invalid observations occurred in the login case, and loss and transport problems occurred in collection. Give invalid setup or measurement its own reason so defective inputs cannot look conclusive. [Claim trace][tax-claims] [Setup friction][tax-setup] [Evidence loss][tax-loss] |
| INV-08 | KEEP | A substitute login page returned 200, protected content was found in a 403 response, and the real-app own-account update returned success. Status alone failed to establish the protected effect in all three cases. [Claim trace][tax-claims] [Discovery results][tax-discovery] [Real-app submissions][smoke-claims] |
| INV-09 | KEEP | A passing example can leave a check unexercised. Each listed check needs a fixture that fails when the check is removed, particularly the object-specificity check implicated by the echo claims. [Claim trace][tax-claims] [Mutation gate][mutation] |
| INV-10 | KEEP | The substitute login page established no protected-value observation and left the existence proposition unresolved. Refutation requires evidence of a contradiction for the specific claim and basis. [Claim trace][tax-claims] [Refutation rules][refutation] |
| INV-11 | KEEP | A successful HTTP response in the real-app smoke did not establish the named state change. The planned fix comparison separately tests the security property and the continuing legitimate path. [Real-app submissions][smoke-claims] [Fix verification][retest] |
| INV-12 | KEEP | Four interrupted runs left partial work. A run and key persisted before an effect give recovery a durable identity even when completion evidence is lost. [Evidence loss][tax-loss] [Run lifecycle][lifecycle] |
| INV-13 | KEEP | A lost reply makes an ordinary caller retry likely. One stable run for the same key, and rejection on conflicting input, prevent a second execution. [Request keys][keys] [Evidence retry conformance][evidence] |
| INV-14 | KEEP | Truncated capture is compatible with a dispatched effect. Treat uncertain effects as unknown and block conflicting execution until reconciliation. [Evidence loss][tax-loss] [Run lifecycle][lifecycle] |
| INV-15 | KEEP | Agents used exploratory commands to diagnose reachability. A known traffic-free inspection surface lets them orient and recover without testing the target or spending an instrument budget. [Setup friction][tax-setup] [Read-only entry screen][entry] |
| INV-16 | KEEP | The shared pass experiment observed exploration traffic with zero project requests handed or drawn. Preserve counter provenance and allow unknown attribution. [Custody decision][custody] [Accounting evidence][accounting] |
| INV-17 | KEEP | Two local enforcement topologies failed to establish approved delivery under enforcement. Refuse required guarantees the environment cannot provide. [Enforcement spike][enforcement] |
| INV-18 | KEEP | Custody attempt 06 changed sharing state during an active run, and the same pass can be shared across projects. Serialize shared state, sessions and pass use within Scourge so one run cannot silently perturb another. [Custody attempt 06][tamper-hold] [Shared-pass experiment][shared-pass] |
| INV-19 | KEEP | Arm A's created books outlived its asserted cleanup. Require an explicit recorded cleanup result and operator disposition for unresolved effects. [Real-app correction][smoke-correction] |
| INV-20 | KEEP | Fresh markers distinguished stale content and different owners' notes. Per-round, per-object, per-field verifier canaries preserve that provenance. [Discovery results][tax-discovery] [Claim trace][tax-claims] [First oracle][first-oracle] |
| INV-21 | KEEP | A workspace inside the target tree could otherwise select executable code, credential sources or a foreign evidence root when the reviewer opens it. Require the operator binding outside that tree. [Workspace trust][threat] |
| INV-22 | KEEP | Target content crosses the UI and evidence boundary. Treat it as bounded, delimited data so it cannot become tool instructions, configuration or executable syntax. [Untrusted data and agent boundary][threat] |
| INV-23 | KEEP | The custody spike reached the verifier sessions in shared custody, and captured authenticated flows can contain credentials. Keep secrets out of the specified outward surfaces and test for seeded leakage. [Custody attempt 07][tamper] [Sessions and secrets][secrets] |
| INV-24 | KEEP | A refusal provides no observation. Counting one as tested misstates coverage in the same way as assigning discovery misses to the four unsettled runs. [Discovery results][tax-discovery] [Blocked work and refusals][refusal] |
| INV-25 | KEEP | An ID or request-key lookup can leak another engagement through the existence of a row even when its payload is hidden. Include engagement authorization in lookup. [Scoped identity][identity] [Selection][selection] |
| INV-26 | KEEP | Interrupted records and the quota failure demonstrate the need to distinguish durable accepted state from partial collection. The storage profile and fault test specify the stronger local commit guarantee. [Evidence loss][tax-loss] [EDQUOT diagnosis][pause] [Storage profile][store] |
| INV-27 | KEEP | The two recovered directories were added as a hash-recorded supplement, preserving original evidence. Redaction likewise keeps its own digest and explicit lineage. [Evidence loss][tax-loss] [Investigation conformance][evidence] |
| INV-28 | KEEP | An import or racing reconciliation could otherwise attach an extra record or advance the chain incorrectly. Bind publication to one verifier intent and advance its head with the record. [Custody attempt 01][tamper] [Chain and checkpoints][chain] |
| INV-29 | KEEP | D8 assigns evidence and its lifecycle to Investigation, and the plan assigns work state to Bones. Copying either into coordination state creates a second source of truth. [Stack ownership][ownership] [Storage schema][store] |
| INV-30 | KEEP | The baseline shows tool-discovery detours. A bounded entry screen with drill-down routes gives a cold agent actionable state and a way to reach omitted details. [Setup friction][tax-setup] [Read-only entry screen][entry] |
| INV-31 | KEEP | Wrong listeners, direct-origin requests and guessed subcommands were all observed. Launchable argv with explicit machine format prevents environment and syntax guessing for suggested commands. [Setup friction][tax-setup] [Response contract][responses] |
| INV-32 | KEEP | Agents applied `jq` to plain-text failures, and 31 exit-zero setup/tool events concealed a failure in output. A uniform machine envelope keeps usage and execution errors parseable. [Setup friction][tax-setup] |
| INV-33 | KEEP | The entry-screen concept check asks a cold agent to explain what Scourge does and choose its next call. Keep the fixed synonym lint on agent-facing catalog strings so one object keeps the same name across help, status, and suggested commands. For example, calling a lead a candidate or hypothesis can imply a second object or send the agent looking for an Investigation command. Qualify Teapot findings so the agent can also identify which tool owns the finding. [Cold-agent concept check][concept-check] [Domain vocabulary][nouns] [Stack ownership][ownership] |
| INV-34 | KEEP | Workers used unrecognized instrument commands and reached for missing helpers. Executed examples and capability-accurate help prevent Scourge from creating those detours. [Setup friction][tax-setup] |
| INV-35 | KEEP | Omitting custody, target isolation, scope or evidence limits can change how a report is interpreted. The real-app correction illustrates the cost of an unqualified statement. [Real-app correction][smoke-correction] [Report semantics][report] |
| INV-36 | KEEP | A worker with shared owner authority changed the account's sharing state. An operator-defined owner request and fixed property slot are separate safeguards against the lead itself introducing a permissive setup. [Custody attempt 06][tamper-hold] [Templates and slots][slots] |
| INV-37 | KEEP | A write in a lead's read slot changes target state under the advertised read operation and can invalidate subsequent controls. Reject it before dispatch. [Templates and slots][slots] [Effect classes][effects] |
| INV-38 | KEEP | All eight tested tamper attempts succeeded in shared custody, and shared principals still allowed the sharing-state change under confinement. Scoring requires the stronger documented boundary. [Custody matrix][tamper] [Custody decision][custody] |
| INV-39 | KEEP | A claim can turn from permitted to forbidden solely by changing the admitted policy. Keep that authority with the operator and out of the isolated worker's broker surface. [Policy rules][policy] [Claim trace][tax-claims] |
| INV-40 | KEEP | Run-owned objects bind test data and cleanup authority to a recorded creation. The surviving real-app books demonstrate why exit and cleanup need independent evidence. [Real-app correction][smoke-correction] [First oracle][first-oracle] |
| INV-41 | KEEP | Truncated capture cannot establish whether a particular request left the instrument. A run- and step-bound receipt is needed to resolve the dispatch question. [Evidence loss][tax-loss] [Run lifecycle][lifecycle] |
| INV-42 | KEEP | A target-derived objection can otherwise suppress a true historical record. Preserve that record and display objections or an admitted-policy refutation beside it. [Threat model][threat] [Refutation rules][refutation] |
| INV-43 | KEEP | The local enforced-topology failures required operator-level diagnosis. Keeping host setup out of Scourge preserves the documented trust boundary. [Enforcement spike][enforcement] [Managed setup][managed] |
| INV-44 | KEEP | A duplicate JSON key can give different readers different policy, experiment or record data. Strict parsing at the contract boundary keeps them on one interpretation. [Verification record][record] [Bundle format][bundle-format] |
| INV-45 | KEEP | The pass is the operator's explicit grant. Expiry, revocation or a changed grant invalidates it for new effects. [Pass authority][authority] |
| INV-46 | KEEP | The workspace may contain several engagements. Explicit mutation selection prevents a retry or copied command from changing an unintended engagement. [Selection rules][selection] |
| INV-47 | KEEP | Same-user access made every tested tamper attempt possible in shared custody. Require isolated custody before using a record to make a third-party verified or fixed claim. [Custody matrix][tamper] [Report semantics][report] |
| INV-48 | KEEP | Native Teapot findings existed in the baseline without any agent use of their verdicts. Keep an instrument conclusion as a lead and preserve the source of a Scourge status decision. [Teapot claim treatment][tax-tool] [Instrument authority][instrument] |
| INV-49 | KEEP | Attempts 07 and 08 reached sessions and edit surfaces in shared custody. The tested edits left pinned direct sends intact, which establishes a specific channel observation and still leaves the run-time guard necessary. [Custody matrix][tamper] [Teapot send channel][channel] |
| INV-50 | KEEP | Later shared records could otherwise replace or qualify stronger evidence in a third-party report. Select the latest true record eligible for the audience and show the others with their tier. [Custody decision][custody] [Computed status][status] |
| INV-51 | KEEP | Changed experiment inputs or an overtaken baseline weaken a sequential comparison. A named current true baseline keeps the fix claim bound to the violation it tested. [Fix verification][retest] |

## Fixtures

The source key is the fixture ID from [plan §14][plan-fixtures].

| Fixture | Disposition | Reason |
| --- | --- | --- |
| F-01 | KEEP | A same-subject result cannot support a cross-subject claim. The baseline generally rejected the control, so retain it as a regression. [Claim trace][tax-claims] |
| F-02 | KEEP | Public-by-design and unset policy can yield the same observation with different findings. Hold the observation fixed while exercising both policy decisions. [Claim trace][tax-claims] [Policy rules][policy] |
| F-03 | KEEP | The login decoy returned a 200 substitute page without the protected value. Keep `OBSERVER_INVALID` or a failed identity probe on the object-read path. [Login adjudication][tax-login] |
| F-04 | KEEP | The same cross-principal observation can have four outcomes depending on admitted rules and version. This fixture isolates the operator-admission decision from the observed exposure. [Policy rules][policy] [Computed status][status] |
| F-05 | KEEP | The baseline found the planted protected-body exposure despite the refusal status. This fixture catches a false negative in a status-based oracle. [Discovery results][tax-discovery] |
| F-06 | KEEP | A cache can return a prior value. Requiring a fresh marker preserves the distinction between that decoy and a newly observed value. [Discovery results][tax-discovery] [First oracle][first-oracle] |
| F-07 | KEEP | The baseline generally rejected expiry. The channel test also showed relogin and retry can occur under one ordinary session send. Test stable identity through the round. [Claim trace][tax-claims] [Teapot send channel][channel] |
| F-08 | KEEP | All five echo report rows concerned a real global collection disclosure. The echo fixture still needs to reject object specificity for that same evidence. [Collection adjudication][tax-echo] |
| F-09 | KEEP | An earlier canary or flow can contaminate a new round. This checks run ownership and fresh observation at ingestion. [First oracle][first-oracle] [Custody attempt 04][tamper] |
| F-10 | KEEP | Agent-supplied exploration evidence can describe a different proposition. This fixture ensures it never supplies inputs to verifier evaluation. [Claim trace][tax-claims] [Verifier inputs][verify-run] |
| F-11 | KEEP | Four transcripts truncated during collection. Test the analogous verifier-flow failure and retention of partial originals explicitly. [Evidence loss][tax-loss] |
| F-12 | KEEP | Lost capture cannot establish dispatch. The three histories exercise missing, ambiguous and affirmatively refused sends without replaying any. [Evidence loss][tax-loss] [Run lifecycle][lifecycle] |
| F-13 | KEEP | A local experiment verified a pass reservation without approved request delivery. Preserve observed debits and require distinct evidence for whether the send started. [Enforcement spike][enforcement] [Accounting evidence][accounting] |
| F-14 | KEEP | Three abrupt worker exits and one quota failure kept four sessions from settling. A crashed verifier dependency likewise needs a distinct error outcome. [Assigned-run outcomes][tax-runs] [Oracle errors][oracles] |
| F-15 | KEEP | The positive fix case requires both the changed security property and a working legitimate path. It establishes the passing counterpart to the partial and broken cases. [Fix verification][retest] |
| F-16 | KEEP | The login decoy illustrates how a failed observer can appear to eliminate exposure. A broken login on retest needs its own inconclusive outcome. [Login adjudication][tax-login] [Fix verification][retest] |
| F-17 | KEEP | Removing an endpoint can hide the violation by removing legitimate functionality as well. Record mitigation and the functional regression separately. [Fix verification][retest] |
| F-18 | KEEP | Blocking one input leaves the property unestablished across the template's nearby declared variants. Keep a fixture where the variant still violates it. [Fix verification][retest] |
| F-19 | KEEP | Reusing a baseline across different predicates can suggest a fix that the pair never tested. Exercise both oracle and experiment drift. [Fix verification][retest] |
| F-20 | KEEP | The custody spike reached a record-store stand-in. Test direct insertion, a lookalike without publication intent, and a racing genuine reconciliation at the chain boundary. [Custody attempt 01][tamper] [Chain and checkpoints][chain] |
| F-21 | KEEP | Revocation must affect old findings even when the original bytes still exist. Exercise status recomputation on a revoked version. [Oracle revocation][oracles] |
| F-22 | KEEP | Status depends on the experiment and admitted rule. The three edits distinguish changed measurement, editorial change and new policy on a standing observation. [Computed status][status] [Policy rules][policy] |
| F-23 | KEEP | Shared custody permitted a direct coordination-store write in the spike. This fixture binds a local result to re-evaluated originals when a stored verdict or memo is edited. [Custody attempt 01][tamper] [Computed status][status] |
| F-24 | KEEP | Retained evidence omitted nested files in two runs. Preserve a direct missing-original integrity regression for product records. [Evidence loss][tax-loss] |
| F-25 | KEEP | A missing premise and a later change are distinct from a same-revision contradiction. Require the actual matching refutation basis. [Login adjudication][tax-login] [Refutation rules][refutation] |
| F-26 | KEEP | The enforced local topology could not deliver the approved request. The fixture requires an explicit refusal when enforcement is required. [Enforcement spike][enforcement] |
| F-27 | KEEP | Arm A's cleanup prose exceeded the observed teardown state. Test failed cleanup, uncertain creation and preservation of a pre-existing object. [Real-app correction][smoke-correction] [Cleanup rules][cleanup] |
| F-28 | KEEP | The inspected tree is untrusted, and a retained-evidence path error occurred in the baseline. Verify that nested config cannot invoke code or follow an evidence root outside the trusted binding. [Workspace trust][threat] [Setup friction][tax-setup] |
| F-29 | KEEP | A target response can contain instructions, including directions to suppress a finding. Exercise inert rendering and retention of the challenged record. [Threat model][threat] [Refutation rules][refutation] |
| F-30 | KEEP | Repository-supplied agent configuration and hooks can change the review environment. Exercise the trusted binding independently of that content. [Threat model][threat] |
| F-31 | KEEP | A refusal must be visible as a block to keep an unrun test out of a coverage count. [Blocked work and refusals][refusal] [Scoring][scoring] |
| F-32 | KEEP | The custody spike distinguished eight refusals, seven refusals and zero refusals across configurations. Keep all eight attempts and label both the topology and stand-in limitations. [Custody matrix][tamper] |
| F-33 | KEEP | One report can contain both supported collection units and unresolved propositions, as position 9 did. Recognition of one supported finding cannot offset an unsupported promotion in scoring. [Claim trace][tax-claims] [Promotion red-team][promotion] |
| F-34 | KEEP | The 19 supported echo units were absent from the object-read key. Independent adjudication is required for a sufficiently evidenced proposition the key did not cover. [Collection adjudication][tax-echo] |
| F-35 | KEEP | The baseline missed one planted flaw during a valid run. A benign trial with incomplete coverage must report its tested scope without claiming security. [Discovery results][tax-discovery] [Report semantics][report] |
| F-36 | KEEP | A private property with missing authentication and a public-by-design property can both return data to an anonymous actor. This fixture preserves the rule distinction against F-02. [Discovery results][tax-discovery] [Policy rules][policy] |
| F-37 | KEEP | Position 3 missed the owner-primed anonymous disclosure. This fixture requires the after-owner-read result and its ordering caveat. [Discovery results][tax-discovery] |
| F-38 | KEEP | Custody attempt 06 demonstrated a sharing-state change that affects fresh objects. Exercise the analogous lead-supplied setup and the rejection of a fixed-slot override. [Custody attempt 06][tamper-hold] [Templates and slots][slots] |
| F-39 | KEEP | A lead-supplied write would alter state in the read slot. Test refusal before any traffic. [Templates and slots][slots] [Effect classes][effects] |
| F-40 | KEEP | The matrix observed an owner sharing-state change with shared principals despite file confinement. Preserve the different result and label when principals are separate. [Custody attempt 06][tamper-hold] |
| F-41 | KEEP | A treatment may change the owner's access or the object's existence. Keeping the genuine owner control before treatment separates an owner view lost by the effect from a broken observer. [Second oracle][second-oracle] |
| F-42 | KEEP | Response encoding changes whether the marker can be found. The within-limit and over-limit cases prevent a false negative or a conclusion from incomplete bytes. [First oracle][first-oracle] [Evidence loss][tax-loss] |
| F-43 | KEEP | A fix can alter applicability while a historical record remains relevant. Exercise the new result and an objection arriving during report generation against the snapshot contract. [Computed status][status] [Coherent coordination reads][store] |
| F-44 | KEEP | A single pass was shared and attributed project counters were incomplete. The fixture keeps outside spenders, counter absence and multi-job blocks out of per-run attribution. [Shared-pass experiment][shared-pass] [Accounting evidence][accounting] |
| F-45 | KEEP | A declared evidence omission, an unavailable oracle and mixed custody limit independent checking in different ways. This fixture tests those distinctions in one recipient workflow. [Bundle verification][bundle] [Custody decision][custody] |
| F-46 | KEEP | An intermittent baseline needs enough rounds to bound a miss. Exercise the specified lower-bound example at an underpowered count and the planned count so a short clean run cannot become fixed. [Fix verification, round rule][retest] |
| F-47 | KEEP | The real-app evidence concerns a particular protected field, while the fixture tests a multi-field property. A fix that hides only one field must leave the remaining exposure visible. [Real-app submissions][smoke-claims] [Fix verification][retest] |
| F-48 | KEEP | The agent baseline never used Teapot's native findings. A replayable integration fixture is needed to exercise confidence, repro and export as inert with respect to Scourge status. [Teapot claim treatment][tax-tool] [Instrument authority][instrument] |
| F-49 | KEEP | Attempts 07 and 08 established session reach and edit access under shared custody. Exercise the badge, the broker refusal and the run guard together. [Custody matrix][tamper] [Teapot send channel][channel] |
| F-50 | KEEP | A later shared record or retest may be adequate for the workspace and inadequate for a third-party report. Verify both audience projections and the retained record history. [Custody decision][custody] [Computed status][status] |
| F-51 | KEEP | Workers spent time on setup and tool failures. Catch unusable property stanzas before an agent starts and require admitted rules before a true result can verify. [Setup friction][tax-setup] [Engagement schema][engagement] |
| F-52 | KEEP | Loss of original evidence can erase the basis for a claimed fix. Exercise read-time integrity handling on a passing retest. [Evidence loss][tax-loss] [Fix verification][retest] |
| F-53 | KEEP | A new true run overtakes the old baseline and can make a past retest misleading. Check that applicability changes while the retest stays in history. [Fix verification][retest] [Computed status][status] |

## Added acceptance

| Addition | Disposition | Requirement and evidence |
| --- | --- | --- |
| M0-ADD-01 | ADD | **Reachable route and failure reporting.** In the existing M1.2 entry path, make the operator-bound transport and supported command discoverable in human and machine output. In M1.9 run the generated argv from a cold worker and exercise a wrong-listener or unavailable-tool case. The check must surface a typed failure even if an outer wrapper exits zero, and read-only orientation must satisfy INV-15. The taxonomy distinguishes 11 nonzero Bash results, 31 masked setup/tool failures, and 5 additional transport diagnoses. [Setup friction][tax-setup] |
| M0-ADD-02 | ADD | **Interrupted evaluation capture.** In the M1.9 harness qualification, preflight the run-root path and writable capacity, then exercise a truncated final event with nested artifacts. Keep the available evidence and verify the recursive digest inventory. The trial must remain unsettled and invalid with no inferred claim score. Reuse this acceptance in M2.10. Four baseline captures truncated and lacked a settled submission. Two omitted nested directories at first capture, later recovering 9 and 192 files in the verified supplement. The prospective baseline copier already has a nested-retention test that the trial can reuse. [Evidence loss][tax-loss] [Collection repair and quota diagnosis][pause] |
| M0-ADD-03 | ADD | **Claim-scope regression.** Pair the F-08 and F-03 object-read invalid results with their distinctly scoped propositions in verifier documentation and referee tests. Adjudicate the supported collection proposition independently of the object-read key, and leave the existence proposition unresolved until an applicable rule and adequate evidence establish it. For explicitly scoped collection and existence leads, `verify --plan` returns `ORACLE_UNAVAILABLE` and lists supported classes. The normal `verify` path refuses the unsupported class before target traffic. Both propositions remain leads without promotion or a negative finding for the wider class. [Agent path][agent-path] Include the supported collection case and contrasting unresolved existence case when auditing the future referee rubric. [Claim trace][tax-claims] [Real-app out-of-class disclosure][smoke-claims] |
| M0-ADD-04 | ADD | **Cache coverage with a supplied lead.** Exercise F-37 through the M1.9 lead-to-verified entry point in a scripted case, with the after-owner-read condition visible in the evidence and finding. Record discovery separately in the existing cold-agent trials. Position 3 missed this planted flaw despite submitting the other five, so the supplied-lead test distinguishes downstream failure from discovery. [Discovery results][tax-discovery] |

## Guarantees

Keep all 11 obligations, 51 invariants and 53 fixtures from the plan. No
package, task or bone closes as a cut. The additions refine acceptance in
existing lanes. They preserve the M1 shared-custody scope and the separate
qualification gates for M2 and third-party reporting. The coverage check in
`just check` requires a unique disposition for each source table row.

The verifier's class, controls, evidence and admitted policy bound its finding.
Code checks every proof obligation and free text cannot waive one. All v1
findings carry `validation: deterministic`. The `judged` kind stays
reserved for a future profile.
Insufficient observation remains visible as invalid, error, inconclusive or
uncheckable as the relevant contract specifies. The evidence path retains
available originals and identifies losses. [Plan obligations][plan-obligations]
[Oracle contract][oracles] [Bundle verification][bundle]

### Proposed tracker actions after review

After review, the lead should record the oracle scope in M0.7.3 and use
`bn-73w` (M0.7.5) for the named M1 acceptance edits. Apply the Tier 1
evaluation edit directly to `bn-wog` (M2.10). Preserve the existing work-package
order and dependencies.

| Bone | Proposed acceptance edit |
| --- | --- |
| `bn-24v` (M1.2.3 entry screen and status) | Add M0-ADD-01's operator-bound transport and supported action to entry-screen acceptance within the existing size and no-traffic requirements. |
| `bn-1aw` (M1.2.2 response envelope) | Add M0-ADD-01's typed diagnostic for the exercised transport or tool failure. |
| `bn-360` (M1.9 cold-agent skeleton trial) | Verify generated transport argv and typed failure (M0-ADD-01), interrupted capture qualification (M0-ADD-02), and scripted F-37 through the normal lead entry point with discovery counted separately (M0-ADD-04). |
| `bn-ggt` (M0.7.3 oracle specifications) | Record the M0-ADD-03 class boundary and known misses in the first oracle specification. |
| `bn-36n` (M1.5.4 first-oracle fixtures) and `bn-20l` (M1.5.8 oracle guide) | Preserve the F-08 and F-03 object-read invalid outcomes in the fixtures and document the separate collection and existence propositions in the guide (M0-ADD-03). |
| `bn-23g` (M1.6.4 `verify` and `verify --plan`) | Exercise collection and existence leads without a shipped class template. Require `verify --plan` to return `ORACLE_UNAVAILABLE` with supported classes and require `verify` to refuse before sending. Verify that both retain lead status and never promote (M0-ADD-03). |
| `bn-wog` (M2.10 Tier 1 evaluation) | Reuse the interrupted-capture qualification (M0-ADD-02) and independently adjudicate the M0-ADD-03 class-scope cases during the referee audit. |

## Limits

The baseline covers one model, one host and one development fixture. Its claim
counts are clustered by report and trial. Four of ten sessions lacked a settled
submission and were excluded from claim adjudication. The 24 planted
opportunities in those sessions remain unscored. The one miss among 36 planted opportunities in valid sessions and the mechanical tool event counts describe what
happened in this sample. They establish neither population rates nor comparative
arm effects. [Taxonomy limits][tax-limits]

The VAmPI smoke was unscored, training-contaminated, and used no instrument in
either arm. It informs the scope and cleanup safeguards but contributes no
sessions or claims to the preregistered count. The custody spike used a single
host, pinned tools and eight fixed attempts, three with stand-ins. Its
enforcement result remained `unenforced`. [Real-app smoke][smoke]
[Custody limits][tamper-limits] [Enforcement spike][enforcement]

## Evidence

- M0.4.2 ledger summary and M0.4.4 Markdown and JSON taxonomy, including the
  counts, decompressed transcript locators, report citations and validity.
  [Baseline result][result] [Failure taxonomy][taxonomy] [Taxonomy JSON][tax-json]
- The decision rule fixed before collection and the evaluation protocol that
  assigns this ADR. [Preregistered rule][rule] [Evaluation §4][eval-baseline]
- The smoke submissions, referee correction and teardown record expose scope
  and cleanup limits on a real upstream application. [Real-app smoke][smoke]
- The custody matrix, instrument pin and evidence API conformance document
  boundaries and specific failures outside the A/B sample. [Custody decision][custody]
  [Custody matrix][tamper] [Teapot send channel][channel] [Investigation conformance][evidence]

## Revisit trigger

Reopen M1 sequencing at the M1.9 review if either cold-start cell cannot
complete lead to verified because of setup, capture or evidence scope, or if a
valid scripted run exposes a promotion outside the first oracle's class.
Record the failing step, retained evidence and disposition before the lead
reviews the sequence. Revisit the scope decision again if a separately
authorized, prospectively frozen replication yields at least ten valid sessions
and an adjudicable taxonomy. Use that study's preregistered rule and keep the
original ten assignments, including the four invalid runs, intact. [Milestone
exits][packages] [Preregistered rule][rule]

[taxonomy]: ../../evals/baseline/FAILURE-TAXONOMY.md
[tax-json]: ../../evals/baseline/failure-taxonomy.json
[tax-claims]: ../../evals/baseline/FAILURE-TAXONOMY.md#claim-trace
[tax-echo]: ../../evals/baseline/FAILURE-TAXONOMY.md#supported-collection-disclosures-absent-from-the-key
[tax-login]: ../../evals/baseline/FAILURE-TAXONOMY.md#unresolved-claims-counted-conservatively-as-unsupported
[tax-tool]: ../../evals/baseline/FAILURE-TAXONOMY.md#teapot-findings-are-not-silently-attributed-to-agents
[tax-discovery]: ../../evals/baseline/FAILURE-TAXONOMY.md#discovery-results
[tax-runs]: ../../evals/baseline/FAILURE-TAXONOMY.md#assigned-run-outcomes
[tax-setup]: ../../evals/baseline/FAILURE-TAXONOMY.md#setup-friction
[tax-loss]: ../../evals/baseline/FAILURE-TAXONOMY.md#lost-and-recovered-evidence
[tax-limits]: ../../evals/baseline/FAILURE-TAXONOMY.md#limits
[result]: ../../evals/baseline/RESULT.md
[pause]: ../../evals/baseline/PAUSE-NOTES.md
[rule]: ../../evals/m0-decision-rule.md
[eval-baseline]: ../../notes/plan.evaluation.md#4-m0-baseline
[concept-check]: ../../notes/plan.evaluation.md#7-gates
[mutation]: ../../notes/plan.evaluation.md#9-oracle-mutation
[promotion]: ../../notes/plan.evaluation.md#8-promotion-red-team
[scoring]: ../../notes/plan.evaluation.md#10-scoring-and-adjudication
[smoke]: ../../evals/realapp/smoke/m0.4.3-20261123T164242Z/README.md
[smoke-claims]: ../../evals/realapp/smoke/m0.4.3-20261123T164242Z/README.md#what-each-arm-submitted-and-what-supported-it
[smoke-correction]: ../../evals/realapp/smoke/m0.4.3-20261123T164242Z/README.md#referee-correction-to-retained-arm-a-prose
[custody]: custody-topology.md
[tamper]: ../tamper-matrix.md#attempt-by-configuration
[tamper-config]: ../tamper-matrix.md#configurations
[tamper-hold]: ../tamper-matrix.md#attempt-06-the-hold-experiment
[tamper-limits]: ../tamper-matrix.md#limits-and-no-claim
[channel]: ../teapot-channel-contracts.md
[enforcement]: ../enforced-local-topology.md
[evidence]: evidence-contract.md#conformance-record
[shared-pass]: ../two-projects-pass.md
[ownership]: ../../notes/plan.md#21-one-owner-for-each-kind-of-truth
[instrument]: ../../notes/plan.md#23-what-an-instrument-concludes-is-a-lead
[threat]: ../../notes/plan.md#33-threat-model
[nouns]: ../../notes/plan.md#41-five-nouns
[identity]: ../../notes/plan.md#43-identity-rules
[target-identity]: ../../notes/plan.md#44-target-identity
[policy]: ../../notes/plan.md#45-policy
[engagement]: ../../notes/plan.md#46-the-engagement-file
[status]: ../../notes/plan.md#51-status-is-computed
[result-dimensions]: ../../notes/plan.md#52-result-dimensions
[profiles]: ../../notes/plan.md#53-profiles
[plan-obligations]: ../../notes/plan.md#54-obligations
[refutation]: ../../notes/plan.md#56-refutation-and-other-endings
[verify-run]: ../../notes/plan.md#61-a-verify-run
[slots]: ../../notes/plan.md#62-templates-and-slots
[first-oracle]: ../../notes/plan.md#65-the-first-oracle-webprivate-object-readv1
[second-oracle]: ../../notes/plan.md#66-the-second-oracle-webforbidden-state-changev1
[oracles]: ../../notes/plan.md#67-oracle-requirements
[retest]: ../../notes/plan.md#68-fix-verification
[record]: ../../notes/plan.md#69-the-verification-record
[authority]: ../../notes/plan.md#71-authority
[accounting]: ../../notes/plan.md#74-accounting-evidence
[lifecycle]: ../../notes/plan.md#75-run-lifecycle-and-recovery
[secrets]: ../../notes/plan.md#76-sessions-identity-and-secrets
[cleanup]: ../../notes/plan.md#77-cancellation-and-cleanup
[effects]: ../../notes/plan.md#78-effect-classes
[entry]: ../../notes/plan.md#81-entry-screen
[agent-path]: ../../notes/plan.md#82-the-path
[responses]: ../../notes/plan.md#84-responses
[keys]: ../../notes/plan.md#86-request-keys
[selection]: ../../notes/plan.md#87-selection
[managed]: ../../notes/plan.md#89-managed-block
[refusal]: ../../notes/plan.md#810-blocked-work-and-model-refusals
[store]: ../../notes/plan.md#91-coordination-store
[chain]: ../../notes/plan.md#93-chain-and-checkpoints
[bundle-format]: ../../notes/plan.md#101-the-bundle
[bundle]: ../../notes/plan.md#102-bundle-check
[report]: ../../notes/plan.md#103-report-semantics
[packages]: ../../notes/plan.md#121-order
[plan-invariants]: ../../notes/plan.md#13-invariants
[plan-fixtures]: ../../notes/plan.md#14-fixture-catalog
