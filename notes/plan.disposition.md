# Scourge — disposition of reviews

**Companion to** [`plan.md`](plan.md), revision 5 — 2026-11-22. This is §16 of the plan. Revision 5 moved it here so that the plan holds only what an implementer needs. The text is unchanged apart from one note in §16.10 and the new §16.13. It keeps the plan's section numbers, so §16.n means here what it meant in every earlier reference. A section reference with no file name points into `plan.md`, and `E§n` points into [`plan.evaluation.md`](plan.evaluation.md).

The full reasoning for reviews 1 to 3 is in [`plan.rev1.md`](plan.rev1.md) §24, and §16.1 to §16.5 record where each of their changes landed in revision 2. §16.6 to §16.9 cover reviews 4 and 5, which were written against revision 2 and applied in revision 3. §16.10 to §16.12 cover review 6, which was written against revision 3 and applied in revision 4. **A** adopted, **M** adopted modified, **D** deferred, **R** rejected.

## 16.1 Review 1

| # | Change | Disp. | Where |
|---|---|---|---|
| 1 | Stack facts from local source | A | §2.2; re-read at current HEADs; M0.1 re-checks. |
| 2 | Baseline in M0; walking skeleton at M1 | A | §12, M0.2–M0.4, M1.9; E§4. |
| 3 | Five nouns, cheap leads, pack-owned controls, call budget, concept check | A | §1.4, §4.1, §6.2, §8.2. |
| 4 | One front door, two speeds, stack conventions, exit codes | A | D2, D12, §8.4, §8.5, §8.9. |
| 5 | Relative discovery gate, sample-size honesty, mutation gate, red-team, scenario factory | A | E§5–E§11. |
| 6 | Custody tiers | A | §3.4, M0.5, M2.4. |
| 7 | Investigation for evidence only; one status authority | A | D4, D8, §5.1, §9.2. |
| 8 | First oracle in full; owner-planted canary; small engagement file | A | §4.6, §6.5. |
| 9 | Accounting as the instruments do it | A | D9, §7.3, §7.4; Sippycup in [`plan.later.md`](plan.later.md) §2. |
| 10 | Control-backed challenge | A | §5.5. |
| 11 | Research additions, citation fixes, Ward boundary | A | [`plan.research.md`](plan.research.md); §2.1. |
| 12 | Numbered invariants, Reads column, split files | A | §13, §12.2, the companion files. |
| 13 | Black-box default | A | D6, D7, §4.4, §6.5, §6.8. |

## 16.2 Review 2

| # | Change | Disp. | Where |
|---|---|---|---|
| 1 | Resolve the custody deadlock | M | §3.4. Tiers, not a separate profile. The worker is confined, not the verifier. |
| 2 | Unblock from Investigation | M | §9.2. Same narrow contract, built in the Investigation repository. |
| 3 | Tiered evaluation with an early A/B/C | A | E§6. |
| 4 | Research additions | A | [`plan.research.md`](plan.research.md). Numbers verified; see §16.4. |
| 5 | Explore freely, verify strictly | M | D2, §3.1. No enforcing `run` wrapper (§3.5). |
| 6 | Small porcelain, plumbing underneath | A | §8. |
| 7 | Discovery as a first-class pillar | M | [`plan.later.md`](plan.later.md) §1. Black-box map; collector, browser and workers in M3. |
| 8 | Observers in place of per-class oracles | M | §6.4. The judged profile is deferred. |
| 9 | Smaller store and crate graph; efficiency metrics | A | §9.1, §11.1; E§12. |
| 10 | Host-agent injection and model refusals | A | §3.3, §8.10, M2.8. |

## 16.3 Review 3

| # | Change | Disp. | Where |
|---|---|---|---|
| 1 | False promotion fails release on any scored case | A | E§7, E§10, F-33. |
| 2 | An owner and exit gate per evidence route | A | M0.6 cannot pass on a blocker; Ward route conditional in [`plan.later.md`](plan.later.md) §3. |
| 3 | Workspace discovery grants no trust | A | §3.3, INV-21, F-28. |
| 4 | Runnable argv, `--json`, calls counted from first invocation | A | §1.4, §8.4. |
| 5 | Evidence for refutation | A | §5.6, INV-10, F-25. |
| 6 | Reader-aware disclosure | M | §8.6, §8.8. Full projection deferred. |
| 7 | Define the report snapshot | M | §10.3. Simpler under computed status. |
| 8 | What a redacted bundle lets a recipient verify | A | §10.2. |
| 9 | Budget the cold-agent gate apart from the effectiveness study | A | E§11. |
| 10 | Maintainer-decision pilot | D | E§14, as a development pilot at M2. |
| 11 | Storage faults and concurrent readers | A | §9.1, M2.9, E§12. |

## 16.4 Corrections to the revision 1 disposition

§24.3 of revision 1 said review 2 had misquoted "From Runnable to Verifiable" and that RECEIPT's numbers were unconfirmed. Both statements were wrong, and came from checking only a search summary. The sources were then fetched. Review 2's figures are in the papers: 58 of 102 anchor cases (56.9%) carry a script-internal CVE identifier that differs from the declared one; 20 of 30 patched builds still showed the claimed signal; 7 of 19 benign controls still triggered. RECEIPT reports 95 targets, 24 previously unknown vulnerabilities and no false positives after clean replay, against 10 true out of 111 claimed under a naive browser-execution check. The one figure that did not check out is Shannon's 96.15%, which is not in its README. Details and depth of each check are in [`plan.research.md`](plan.research.md).

## 16.5 New in revision 2

These are not from a review. They follow from applying the reviews together, and the owner should look at them. Revision 3 changed three of them: the policy gate (§16.7 #3), the plant modes (§16.7 #2) and the order of the second oracle's flows (§16.6 #7a).

| Addition | Why |
|---|---|
| Policy basis gates `verified`; an inferred basis gives `conditional` (§4.5). | The anonymous control cannot rule out an object that every logged-in user may read by design. Only policy can. |
| Plant mode `create` is the default and is required for scored runs (§6.5). | An existing object can be shared with the other principal before the run, which would make a false claim verify. |
| Reason code `CANARY_NOT_SPECIFIC` (§6.5). | Review 1's specification had the different-object control and no outcome for the case where it fails. |
| The second oracle is specified in full (§6.6). | Revision 1 scoped state-change violations into the first product and called for two real profiles before generalizing. |
| Retest has a `sequential` mode with a historical baseline (§6.8). | Under the black-box default the fix is usually deployed in place and no vulnerable build remains to compare against. |
| Two rounds by default (§5.3). | A cheap reproduction that needs no second agent. |
| A broker process in the isolated tier (§3.2). | A confined worker needs some route to the stores that is not the stores. |
| The oracle registry is compiled into the verifier (§6.7). | There is then no qualification record for an agent to write. |

## 16.6 Review 4

Review 4 found real holes in mechanisms that revision 2 had added. Three of them would have let a false lead reach `verified` through the public interface: a plant request written by the agent, a policy citation attached by the agent, and target state changed through a shared test account. Its design fixes are mostly adopted. Several of its research figures did not check out (§16.8).

| # | Change | Disp. | Where |
|---|---|---|---|
| 1 | Anonymous access to a declared-private object is a violation, not a public object | M | §4.5, §6.5, §6.6, F-02, F-36, F-37. The oracle reports the exposure and never reads the policy; the rule decides on read. `PUBLIC_OBJECT` and `PUBLIC_WRITABLE` are gone. The early anonymous read is F0. |
| 2a | A lead cannot override a declared property's slots | A | §6.2, `SLOT_CONFLICT`, INV-36, F-38. |
| 2b | Owner-side requests written by the agent cannot verify | A | §5.1, §6.2, INV-36, F-38. The operator declares the property and the run is repeated. |
| 2c | Safe methods for a lead's read request | M | §6.2, INV-37, F-39. No opt-in flag: a read that needs another method is declared in the engagement. |
| 2d | F4 had no slot and blocked vertical cases | M | §6.5. F4 reads a second object the owner planted, so `other` needs to own nothing. |
| 3 | Separate policy from the endpoint binding; no answer key in discovery trials | M | §4.5, §4.6, E§2. One table, not three: a property is a resource with its rule, declared for every resource class, and names no principal pair. |
| 4a | Shorter managed block | A | §8.9. |
| 4b | Cold start measured with and without the block | A | E§3, M1.9. |
| 4c | Principals, properties and classes on the entry screen | A | §8.1. |
| 4d | `lead add --flow` suggests bindings | A | §8.3. Session name and route only; nothing from the response body. |
| 5a | Delimiters are hygiene, not a boundary | A | §3.3, §8.4. |
| 5b | A verified finding cannot be suppressed by refutation or objection | M | §5.5, §5.6, §10.3, INV-42, F-29. Stricter than proposed: a true record is refuted only by an admitted policy rule, in every tier. |
| 5c | Broker limits on a worker | M | §3.2, §4.6. One optional cap on verification runs; the pass's ceilings already bound spending. |
| 6a | Verifier-only principals or a clean instance; `target_isolation` on the record | A | §3.4, §4.6, INV-38, F-40, E§8. |
| 6b | Hold the worker's traffic during a run | M | §3.4, M0.5. Tested in the spike and kept only if the race succeeds without it. |
| 7a | Owner's control write before the treatment | A | §6.6, F-41, with a new reason code `OWNER_VIEW_LOST`. |
| 7b | A delete and state-transition template in M2 | D | [`plan.later.md`](plan.later.md) §6, as the first template after M2. The design is recorded there. M2 keeps two oracles (D13). |
| 7c | Match over decoded bodies | M | §6.5, F-42. Canaries are hexadecimal, so only transfer and content codings need undoing. |
| 7d | XBOW labels IDOR as agent-validated | A | §6.4; [`plan.research.md`](plan.research.md) §3. Confirmed, with one nuance (§16.8). |
| 8a | One chain per engagement, head advanced atomically | A | §9.3, INV-28. Combined with review 5 #5. |
| 8b | Short read transactions | A | §9.1, §10.3. |
| 8c | Remove `.scourge/experiments/` | A | §11.2. |
| 8d | Atomic writes for durable files outside SQLite | A | §9.1, INV-26, M2.9. |
| 9a | Three more studies in the research ledger | M | [`plan.research.md`](plan.research.md) §4, §6, with the figures corrected (§16.8). The five references review 4 says it verified stay in the unverified list, because nobody fetched them again for this revision. |
| 9b | More discovery families and a named margin | M | E§6, E§7. The 20-family allocation stands (owner decision). Discovery grows first when the corpus is enlarged, and the margin is a whole number of families fixed before freezing. |
| 9c | Smoke runs on real open-source applications | M | E§5, M2.10. Development only, unsealed, no gate. |
| 10a | Retest rounds for intermittent findings | M | §6.8, F-46. A stated rule for the number of rounds. |
| 10b | Structural-overlap diagnostic for partial fixes | R | A comparison of JSON keys fires on shared boilerplate and cannot be made deterministic. The same case is covered by a canary in every declared field (§6.5, §6.8, F-47). |
| 10c | Trailing-slash and suffix variants in retests | R | Guessing routes is discovery work. A variant that works is a lead and can be verified as one. Retest variants stay declared. |
| 10d | `list` command | A | §8.3. |
| 10e | Error code to exit code table | M | §8.5. A different assignment from the one proposed: an unavailable oracle or capability is an unmet obligation (5), not a missing object (3). |
| 10f | Lintable INV-33 | A | §4.1, INV-33. |
| 10g | Number the unnumbered requirements | A | INV-43 to INV-46. The requirements for scored runs are INV-38 and INV-40. |

## 16.7 Review 5

Review 5 read the stack's source again and found two places where the plan contradicted it, and several where the plan contradicted itself. All ten changes are adopted, two with modifications.

| # | Change | Disp. | Where |
|---|---|---|---|
| 1 | A missing capture never shows that a request was not sent | A | §2.2, §7.5, INV-41, F-12, M1.7. Confirmed in Teapot's source (§16.8). |
| 2 | Protect existing objects from cleanup and from stale proof | A | §6.5, §7.7, INV-40, F-27. v1 tests only with objects the run created. Revision 2's `update` and `designated` modes are deferred ([`plan.later.md`](plan.later.md) §5). |
| 3 | An accountable source for the policy behind a verified finding | M | §4.5, §5.1, §5.3, INV-06, INV-39, F-04. Rules are typed (four audiences) so that "allows" is computed and not argued. A rule that allows the access gives `refuted`, not `disputed`. |
| 4 | Historical status and present applicability are separate; one coherent snapshot | A | §5.1, §9.1, §10.3, INV-02, F-43. |
| 5 | Recovery proves who published a record | A | §7.5, §9.3, INV-28, F-20. |
| 6 | What a recipient can check in a redacted bundle | A | §6.7, §10.1, §10.2, INV-04, INV-47, F-45. |
| 7 | Operator-supplied answers stay out of the discovery score | A | E§2, E§7, E§11, E§14; [`plan.later.md`](plan.later.md) entry condition for M3. |
| 8 | Attribution can be `unestablished` | A | §7.2, §7.4, INV-16, F-44. Confirmed in Teapot's source (§16.8). |
| 9 | Test the handoff a first-time agent receives | A | §1.4, §6.1, §8.2 to §8.4, INV-31, E§3. |
| 10 | Real prerequisites on the milestone graph | M | §9.2, §12.1, §12.2, §17. The referee boundary moves into M0.3, so the baseline does not wait for the custody spike. |

## 16.8 Checks made on reviews 4 and 5

Each claim that carried design weight was checked before it was adopted. Web sources were fetched on 2026-11-22. Local source was read the same day at the HEADs in [`plan.research.md`](plan.research.md) §7.

| Claim | Result |
|---|---|
| Review 5: Teapot can send a request and keep no flow. | Confirmed. A replay hop's flow ID is optional and is absent "while capture is off: the request was still sent". Capture can also stop mid-flow while the relay continues. |
| Review 5: Teapot's counters include spending from outside Teapot and can be absent. | Confirmed in the allocator's status type. |
| Review 5: with no format flag and no `FORMAT`, piped output is text. | Confirmed in the stack's CLI conventions. |
| Review 5: Hallpass cannot tell whether the action ran. | Confirmed in its evidence documentation. |
| Review 4: XBOW labels IDOR (CWE-639) as validated by an AI agent. | Confirmed. The same page labels Missing Authorization (CWE-862) as deterministic and Incorrect Authorization (CWE-863) as AI agent, so the split is by class. It is not "authorization is never deterministic". |
| Review 4: "Hackers or Hallucinators?" covers 13 frameworks, over 10 billion tokens and over 1,500 logs. | Confirmed. The paper says a larger tool pool "does not equate to an improvement". Review 4's "degrades" is stronger than the source. |
| Review 4: repository context files cut success by about 3% when generated and raise it by about 4% when written by people. | Not in the paper. It reports reductions of 0.5% and 2% for generated files and a gain of 2.4% for developer-written ones, which it says is not statistically significant. The cost increase of more than 20% is confirmed, and that is the figure §8.9 relies on. |
| Review 4: EthiBench shows false positives piling up late in long sessions. | Narrower in the source. The paper describes this for one run and calls the pattern erratic and target-dependent. It presents a methodology and three targets, not a fixed benchmark. Its result that a general coding agent had the best F-scores is confirmed. |

## 16.9 New in revision 3, for the owner

These go beyond what either review asked for, or choose between the two. Each can be overruled without disturbing the rest.

| Call | Why | The alternative |
|---|---|---|
| A property names a resource and its rule, not a principal pair or a class (§4.6). | One declaration then serves both oracles and gives no hint about where a flaw is. | Review 4's three tables (`policy`, `resource`, `property`). More to write, and code cannot apply its blanket policy statement. |
| Policy rules have four audiences: `owner`, `group`, `authenticated`, `public` (§4.5). | The status function has to compute whether a rule allows an access. `group` is there because the evaluation corpus includes tenant models. | Free-text rules judged by the operator each time. |
| v1 verifies only with objects the run creates (§6.5). | It removes a way to delete someone's data and a way to verify against stale state. | Keep `update` and `designated` with their own restoration rules. Read-only engagements could then verify. |
| Scored and red-team work needs four test accounts or a resettable target (§3.4). | With two shared accounts the isolated tier's zero-tampering gate cannot be met. | Accept `shared_principals` in scored runs and report the tampering successes. |
| The delete and state-transition template waits until after M2. | M2 already has ten packages, and the second oracle is what tests the interfaces. | Pull it into M2 as review 4 proposed. It reuses the observer, so the cost is its fixtures and mutation suite. |

## 16.10 Review 6

Review 6 left the mechanism alone and looked at where the plan meets the stack as the stack is today. Its main findings hold. Teapot gained a verify, fixed and report path of its own on the day revision 3 was written. The development fixture could not run either oracle. The verifier's channel to the target was shared with the agent. Two Investigation packages were on the critical path without being needed. Nothing is rejected. 18 items are adopted, 9 are adopted with a modification and 1 is deferred.

| # | Change | Disp. | Where |
|---|---|---|---|
| 1a | Teapot's findings and leads are leads here; the ownership table is redrawn | A | §2.1, §2.3, INV-48, F-48. |
| 1b | `lead add --from teapot:…` | A | §8.3. The class mapping is data in the pack. |
| 1c | An entry-screen line and one sentence in the managed block | A | §8.1, §8.9. |
| 1d | A Teapot setting that names an external verifier | D | §2.3; [`plan.later.md`](plan.later.md) §5. Teapot does not know Scourge exists, and the dependency stays one-way. Its re-check is also more careful than the review said (§16.11). Revisit if cold-start trials show agents taking Teapot's `fixed` or `certain` for Scourge's result. |
| 1e | Arms A and B have a promotion step of their own | M | E§2, E§7; [`plan.later.md`](plan.later.md) entry condition. The finding the agent submits stays the unit graded across arms. An instrument state it relies on is part of that claim. Teapot is pinned for each scored round. |
| 1f | M3 reads Teapot's site map, matrix and out-of-band server | M | [`plan.later.md`](plan.later.md) §1.1, §1.4. The map is re-scoped now. The collector uses Teapot's server only if it has shipped and runs outside the worker boundary, because it is planned and not built. |
| 2a | `separate_principals` cannot be established in shared custody | A | §3.4, with the value `separate_principals_unconfined`. `clean_instance` gets the same limit. |
| 2b | The broker must not serve a verifier's flows or credentials | M | §3.4, INV-49, F-49. Also no send under a verifier session. Starting candidate: a second instrument project for the verifier, which closes all three routes at once. |
| 2c | Record the instrument's edit surface and refuse | A | §7.2, §8.5, `INSTRUMENT_EDITS_ACTIVE`, INV-49. Source read suggests rules and hooks do not reach a verifier send (§16.11). The check stays because the instrument changes daily. |
| 2d | A login or retry the instrument adds is a flow of the step | A | §7.2. |
| 2e | Two more tamper attempts, and matching red-team attempts | A | §3.4, M0.5, M2.4, F-32, E§8. |
| 3 | A development fixture that can run both oracles, owned here | A | §2.2, §4.6, M0.2. It adds a group-readable control and an act-then-drop route, which M1.7 had borrowed from Teapot's testbed. |
| 4a | Bundles need Read, not Investigation's export | A | §9.2, §12.1, M2.5. |
| 4b | Status does not wait for the retraction query | M | §9.2, M1.6, M2.6. A build with no retraction branch refuses an Investigation version that offers retraction, so none is ignored. |
| 4c | Ask Investigation to schedule W07 first in its milestone B | A | §9.2. A request to the owner. |
| 4d | A revisit trigger for the dependency | A | §15.2. |
| 5a | A decision rule for M0 | M | §12.1, M0.3, M0.4, E§4. The rule can re-scope M1. Ten runs cannot show that the rate is low, so it cannot cancel the verifier alone. |
| 5b | A real application in the baseline | M | E§4, E§5. The same targets as the M2 smoke runs, so the setup is paid once. |
| 5c | Semgrep's study of IDOR reports in the ledger | A | [`plan.research.md`](plan.research.md) §2, §4. |
| 6 | A work package and sources for the fixture factory | M | M1.10, E§5, E§11; [`plan.later.md`](plan.later.md) §4. Each candidate is checked against a shipped oracle first: the Grafana CVE is a delete, which v1 cannot verify. |
| 7 | Correct the precedent claim and add prior art | A | §6.4; [`plan.research.md`](plan.research.md) §3, §5. All five sources were fetched (§16.11). |
| 8a | `engagement check` | A | §4.6, §8.3, M1.11, F-51. |
| 8b | `engagement draft` | M | §4.6, M1.11. From the site map and parameter inventory only. The authorization matrix and Teapot's findings would point at the flaw. |
| 8c | Operator setup is measured | A | E§7. |
| 9 | An honest miss probability for retests of intermittent findings | M | §6.8, F-46. One rule on the lower bound of the rate, replacing revision 3's rule. The review proposed two figures and three outcomes. |
| 10a | The second oracle proves the template interface only | A | §6.6, §15.1. |
| 10b | Which true record a badge and a third-party report present | A | §5.1, INV-50, F-50. Replaced in revision 5 by a rule for each audience (§16.13). |
| 11 | A starting design for canaries the operator plants | A | [`plan.later.md`](plan.later.md) §5. |

## 16.11 Checks made on review 6

Local source was read on 2026-11-22: Teapot at `876b2165`, five commits past the review's read, its re-check rules again at `da01de3c`, and Investigation while it was being committed to. Web sources were fetched the same day. Source was read, not run.

| Claim | Result |
|---|---|
| Teapot has its own leads, findings, `certain`, `fixed`, `--verify` and export. | Confirmed in its source and its guide text. |
| A broken login makes Teapot mark a finding `fixed`. | Not as stated. A logged-out answer is `blocked` and concludes nothing. A differing answer with no recorded condition is `changed`, which is inconclusive. `fixed` needs the finding's recorded condition to stop holding, or `findings fix` by hand. A removed route would still read as fixed. |
| Teapot's testbed cannot run either oracle. | Confirmed. Orders have a read route only. New orders come from a three-step checkout. `item` must be a catalog item, so no field takes free text. |
| Rules, intercept or hooks may edit a verifier send. The review said it had not verified this. | Not found. They are stages of the proxy listener. The replay client behind `requests send` is a separate path and applies only the session. M0.1 tests it. |
| A session logs in again and retries. | Confirmed, and narrower than feared: one login and one retry of a GET or HEAD. A write is not retried. |
| Session credentials are in the project database. | Confirmed. They are stored whole in `project.db`. |
| Investigation has 305 open items and none closed. | Out of date within the day: 308 items, 29 done, all in milestone A. The extra-large sizes of W07, W10 and W11 are confirmed. |
| Semgrep: 46 of Claude Code's 59 IDOR reports were false, and 2 of GPT-5-Codex's 44 were true. | Confirmed (22% and 4.5% true). The agents read source code. Data that is "intentionally public" is named as a cause. The page does not give the number of applications. |
| RESTler's user-namespace rule, judged by status code. | Confirmed from the paper's text. |
| BOLABuster creates as one user, acts as another, and found the listed CVEs. | Confirmed. The article is titled "Harnessing LLMs for Automating BOLA Detection". The Grafana flaw is a delete, and the Harbor flaw needs a Maintainer role. |
| AuthProbe confirms a leak against the owner's own fetch. | Confirmed from the abstract. One author, one synthetic API and its hardened copy. |
| XBOW's attack agents get only the canary's SHA-256. | Close. The page says the test coordinator receives the location and the SHA-256, and that results from attack agents are compared with it. IDOR is not among the classes it names. |
| For 2 of 10, the lower bound is 0.037, 14 rounds miss with probability 0.59, and 80 rounds are needed. | Confirmed by computation, with the other rows of the review's table. |
| RealWorld has over 100 implementations. | Confirmed in its README. |

## 16.12 New in revision 4, for the owner

These are the calls in revision 4 that the owner has not seen. Each can be overruled without disturbing the rest.

| Call | Why | The alternative |
|---|---|---|
| Scourge no longer waits for Investigation's W10 and W11 (§9.2). | Two extra-large packages leave the critical path. A bundle needs only Read, and nothing can be retracted before the query ships. | Wait for both, as revision 3 did. |
| The development fixture is built in this repository (M0.2). | Teapot's testbed has nowhere to put a canary, and its catalog is a contract for Teapot's own tests. | Add the routes to Teapot's testbed and accept the coupling. |
| A fixture factory with its own owner (M1.10). | Tier 1 and Tier 2 need families that no package produced. | Let the implementing agent write the Tier 1 fixtures and call that tier a development set. |
| Retests of intermittent findings plan against the lower bound of the rate (§6.8). | Revision 3's rule printed 4% where the honest figure was 59%. A baseline of 2 in 10 now needs 80 rounds, about a thousand requests. | Keep 14 rounds and print both figures. An operator can also set a weaker threshold in the engagement. |
| `separate_principals` can be recorded only in the isolated tier (§3.4). | In shared custody the worker can use every session in the project. | Keep one label and let the custody tier carry the caveat. |
| Two operator commands, `engagement check` and `engagement draft` (M1.11). | The engagement is the largest setup cost, and nothing measured it. | Build `check` only and defer `draft`. |
| Teapot is not asked to know about Scourge (§2.3). | The dependency stays one-way, and Teapot's findings remain a sound feature of a standalone tool. Scourge's entry screen and managed block carry the distinction. | Review 6's setting that names an external verifier, so that Teapot's own text calls its findings unverified here. |

## 16.13 Revision 5

No review prompted revision 5. After revision 4 the owner asked for two changes: this section moved out of the plan, and §5.1 and §6.8 rewritten as one function, because three rounds of patches had left gaps between them.

| Gap in revision 4 | Now |
|---|---|
| Nothing said which record a retest uses as its baseline when a finding has several true records. | The status record: the latest true `verify` record, whatever its custody. The retest names it, and a newer true record overtakes the retest (§5.1, §6.8, INV-51, F-53). |
| Nothing said whether a shared-custody retest could mark a finding fixed in a report for a third party. | It cannot. An audience reads applicability as `unestablished` when the deciding record does not qualify for it (§5.1, INV-47, INV-50, F-50). |
| The status function had an unconditional retraction branch, while §9.2 said the branch may be absent. | Retraction is one cause of a `stale` record, and it applies where the evidence store can answer (§5.1). |
| Only the latest true record was checked against its originals. A retest's originals were not. | The status record and the deciding record are both checked (§5.1, F-52). |
| "A later policy change limits applicability" had no value in the applicability table. | `unestablished`, with the reason shown (§5.1). |
| Revision 4 presented the "strongest" true record on a badge (review 6, 10b). | Replaced. Status for an audience uses the latest true record that qualifies for it, and the workspace lists every standing true record with its tier. No ranking of records is needed. |

Calls in revision 5 that the owner has not seen:

| Call | Why | The alternative |
|---|---|---|
| When the newest evidence on a finding is from shared custody, a third party reads the present state as `unestablished`, whichever way that evidence points. | One rule then covers "verified" and "fixed", with no special cases. | Let shared-custody evidence that agrees with the isolated record leave the answer as it was. |
| A deployment marker that changes after the deciding record, or a replacement policy rule that allows the access, makes applicability `unestablished`, even after a retest that passed. | The evidence is about an earlier deployment or an earlier policy. | Keep `fixed_within_tested_scope` across deployments until a new run says otherwise. |
| The engagement's `audience` key takes two values, `internal` and `third_party`. | Revision 4 used the key in its example and never said what it could hold. | One audience per custody tier and target isolation value. |
| M2.5 (reports) now depends on M2.2 (retest). | A report must show the record that decides applicability, and that is often a retest. | Build reports first and add retests to them later. |
| The workspace badge shows the latest true record, with the others listed beside it. | It needs no ranking of records. | Review 6's rule: show the strongest record first. |
