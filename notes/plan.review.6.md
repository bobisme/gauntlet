# Gauntlet implementation plan review 6

**Reviewed:** `notes/plan.md` revision 3 (commit `9115059`) and its companions `plan.evaluation.md`, `plan.later.md` and `plan.research.md`. Line references point into those files at that commit.
**Date:** 2026-11-22.
**Method:** The four plan files were read in full, and the headings and dispositions of reviews 1 to 5 were read so that this review does not repeat them. Local stack source was read at these HEADs: Teapot `d10ec866`, Investigation `f9c3817` (bones), Hallpass `f6ebf2f`, Playpen `19380df`. Web sources were fetched on 2026-11-22 and are listed at the end. No tool was run except `git`, `bn list`/`bn show` and `pdftotext`.

## Executive summary

### What the plan does well

Revision 3 is a strong design. The core mechanism is sound, and it is better than most published systems in this area:

- **Measurement and policy are separate (D15).** The research below supports this more strongly than the plan knows. In Semgrep's 2025 study of LLM-reported IDORs, "intentionally public data" was one of the main causes of false positives, and 46 of Claude Code's 59 IDOR findings were false.
- **The verifier acquires everything it judges (D3), and status is computed (D4).** Most public tools in this area store a verdict and trust it. This plan does not.
- **Controls have a named purpose and a reason code (§6.3, §6.5).** Each published precedent this review found (RESTler, BOLABuster, AuthProbe) decides with a status code, an owner-reference comparison or a human review. None decides with a fresh canary in a run-created object, with an anonymous control, a different-object control and identity probes around it. That design is real progress.
- **The evaluation protocol is honest about small samples (E§11).** It states the confidence bounds that most papers leave out.
- **The disposition tables (§16) make five rounds of review auditable.**

### Areas that need change

The main problems are not in the mechanism. They are in how the plan meets the stack as the stack is today, and in what the plan assumes will exist when M0 starts.

1. **Teapot changed under the plan.** On 2026-11-22, after the plan's last read (`2f63fad7`), Teapot gained its own **leads**, **findings**, `leads promote`, `findings repro --verify` (which sets a finding to `fixed`), a `certain` confidence level, a scanner, a race engine, and SARIF and Markdown export. `teapot guide findings` is titled "Read, verify and report findings". The plan's entry screen tells every agent to read `teapot guide`. This gives agents a one-command path to a "verified", "fixed" and exported finding that bypasses Gauntlet. It also puts two different meanings of "finding" in one workspace. §2.1's ownership table is now wrong.
2. **In shared custody, "separate principals" cannot be established, and the isolated tier's exploration route can leak the verifier's credentials.** The verifier's sessions live in the same Teapot project the agent uses. The broker's proposed "read-only flow queries" would serve the verifier's own flows, with their cookies, to the worker. Teapot's documented rules, intercept and Lua hooks may also be able to edit the verifier's sends. The plan does not check for any of this.
3. **The development fixture cannot run either oracle as specified.** On the testbed, orders are created only through a three-step checkout macro. There is no PATCH or DELETE on orders, and no field that the owner can fill with free text, so there is nowhere to put a canary. M0.2 does not list these routes. Adding them to Teapot's testbed would also break the contract of Teapot's own catalogue, which says that `authz compare` "must find the one planted IDOR".
4. **The Investigation dependency is much larger than "a narrow slice".** Investigation has 305 open bones and none closed. Gauntlet's M1.6 needs W10 (milestone B) and M2.5 needs W11 (milestone C). Both are sized `xl`, and W11 brings in Investigation's report renderer, audience policy and retention. Neither is needed for what Gauntlet uses them for.
5. **The premise is assumed, not tested.** No M0 decision rule says what happens if the baseline shows that agents with Teapot rarely make false authorization claims. The scenario factory that Tier 1 and Tier 2 depend on also has no work package, no owner and no source of families.
6. **Smaller items:**
   - The plan calls a deterministic IDOR check "this project's bet". RESTler's user-namespace checker (2020, already cited as [R9]) and BOLABuster (2024) are direct precedents for testing with objects that the tester creates.
   - The retest round rule for intermittent findings gives a 5% miss probability only at the point estimate. At the 95% lower bound of the observed rate, the miss probability is 59%.
   - The second oracle does not prove the observer interface, although §6.6 says it does.
   - The burden on the operator, who must declare a property for every resource class, is not measured anywhere.

The changes below are in priority order. Each one leaves the owner decisions of §15.2 and the binding decisions D1 to D15 as they are.

## Proposed changes

### [High impact, low–medium effort] Change 1: Teapot's findings are leads in a Gauntlet workspace

**Current state.**

- §2.1 (`plan.md:145`) says Teapot owns "HTTP capture, sessions, replay, crawl, authz compare, and enforcement of the pass's ceilings". §2.1 (`plan.md:155`) gives Gauntlet "leads … findings … fix verification, security reports".
- §2.2 says Teapot was read at `2f63fad7`.
- The entry screen (`plan.md:737`) says "Explore: use teapot directly (teapot guide)".
- `plan.later.md` §1.1 and §1.4 plan a Gauntlet surface map and a Gauntlet out-of-band collector.

**What Teapot is at `d10ec866`.** Seventeen commits landed on 2026-11-22 after the plan's read:

| Teapot feature | Source | Collision with Gauntlet |
|---|---|---|
| A leads model: rule-generated, ranked by weight, rarity and whether the endpoint was tested; `leads promote` "turns one into a finding with your note". | `9d83bf60`; Teapot `notes/plan.md` §9.6 | Same noun. Promotion by agent assertion is the act Gauntlet exists to prevent. |
| Findings with `confidence` `tentative / firm / certain`. `Certain` means "Shown beyond doubt (a reproduction confirmed it)". | `crates/teapot-core/src/findings.rs:159–169` | Same noun, different meaning. "Certain" reads as verified. |
| `findings repro N --verify` sends the minimal request once. The finding state `fixed` is "a `--verify` that no longer reproduces". The guide says: "After a fix, send it once: reproduces, fixed, changed or blocked." | `findings.rs:180–182`; `crates/teapot-api/src/commands/guide.rs:841–870` | A broken login gives `fixed`. That is fixture F-16's trap, built into the instrument. |
| `findings export --as json\|sarif\|markdown`, redacted, with the approval header. The guide calls it "a redacted report for the people who approved the test". | `fa61f664`; `guide.rs` | A second report path, with no custody, policy source or control results. |
| A scanner, a fuzzer, `flows race` (which records `race.condition` findings), probes and a passive pack. | `fb150e3d`, `83cadbae`, `c72389b9`, `d10ec866` | Produces findings in classes Gauntlet has no oracle for. These are valuable as leads. |
| `sitemap show`, `params list`, `authz matrix` with surprising cells highlighted, and lead ranking by "tested yet". | Teapot README (M4); plan §9.3, §9.6 | Duplicates `gauntlet map` and much of coverage (`plan.later.md` §1.1–§1.3). |
| An out-of-band server, `teapot oob serve`, matched by a random label per job, check and flow (Teapot M7). | Teapot `notes/plan.md` §9.12 | Duplicates the M3 collector (`plan.later.md` §1.4). |

**Proposed change.**

1. **Redraw §2.1.** Teapot owns its scanner, its site map, its lead ranking and its findings as *claims by its checks*. Gauntlet owns verification and the verified-findings record. In a Gauntlet workspace, every Teapot finding and every Teapot lead is a Gauntlet **lead** with origin `teapot`.
2. **Add a new §2.3, "Teapot's findings in a Gauntlet workspace".** It has four rules:
   - Gauntlet reads a Teapot finding's ID, check, endpoint and evidence flow IDs as hints.
   - Gauntlet never reads `confidence`, `state` or `verify_state` as evidence (new INV-48).
   - A Teapot finding marked `fixed` changes no Gauntlet applicability.
   - Reports list leads that came from Teapot findings under "leads", with Teapot's confidence shown as the producer's claim.
3. **Add `lead add --from teapot:finding:N` and `--from teapot:lead:N`.** The command maps Teapot's check ID to a Gauntlet class where one exists (for example, an `authz compare` "same" cell maps to `web-authz/private-object-read`). It copies no response bodies.
4. **Add an entry-screen line.** It counts Teapot findings and leads that are not yet recorded, and gives the import argv. This line is the bridge that a cold agent would otherwise not find.
5. **Change the managed block.** One sentence tells the agent that Teapot's findings are leads here and that `teapot findings repro --verify` does not verify or close anything.
6. **File an upstream request in M0.7.** Teapot gets a project setting (for example `[findings] verifier = "gauntlet"`). With it set, `findings list/show/export` and the guide name the finding "unverified here", `--verify` reports `not_reproduced` and does not set `fixed`, and `leads promote` prints the Gauntlet import argv. The same owner maintains both tools, so this is a small coordinated change, not a negotiation.
7. **Evaluation (E§2).** Condition A now has a promotion step of its own: Teapot findings at `certain`, promoted leads and `fixed` states. Score these as A's promotions and fix claims under the common rubric. This makes the false-promotion comparison direct, where E§7 now needs a workaround. Pin Teapot's version per scored round, because A's instrument is changing quickly.
8. **Re-scope M3 (`plan.later.md`).** `gauntlet map` consumes Teapot's `sitemap`, `params`, `authz matrix` and leads, and adds only coverage cells derived from Gauntlet runs. The out-of-band observer uses `teapot oob serve` as its collector where that server runs outside the worker boundary. Gauntlet supplies the per-run token and the controls. This removes two M3 builds.

**Rationale.** The plan's whole promise is that "Nothing else can make one [a verified finding]" (`plan.md:15`). Today the instrument that the plan sends every agent to has its own verify, fixed and report commands, and its own guide teaches them first. INV-33 bans synonyms, but a homonym across two tools is worse: "finding" now means two different things in one workspace. The cold-agent trials would measure this collision, not the design.

**Benefits.**

- Closes a side door that is one command wide and that the plan's own entry screen points to.
- Turns Teapot's scanner, race engine and lead ranker into a discovery source at no build cost. This is the "discovery is the hard half" problem (`plan.later.md` §1).
- Removes `gauntlet map` and the collector from M3.
- Gives condition A a real promotion step to compare against.

**Trade-offs.**

- One more import path to test.
- Depends on a small Teapot change. Until it lands, the managed block and the entry screen carry the warning alone.

**Implementation notes.**

- M0.1 must re-inventory Teapot's surface. It is mid-milestone (its M5), and it will keep moving.
- The class mapping is data in the pack, not code.
- Keep `--from` a hint. The verifier still acquires everything (INV-03).

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -143,15 +143,15 @@
 | Tool | Owns | Gauntlet must not build |
 |---|---|---|
-| Teapot | HTTP capture, sessions, replay, crawl, authz compare, and enforcement of the pass's ceilings. | An HTTP client, proxy, cookie jar or request editor. |
+| Teapot | HTTP capture, sessions, replay, crawl, `authz compare` and `authz matrix`, site map and parameter inventory, its scanner, fuzzer and race engine, its own ranked leads and its findings (claims by its checks), its out-of-band server (planned), and enforcement of the pass's ceilings. | An HTTP client, proxy, cookie jar, request editor, scanner, site map, lead ranker, out-of-band server, or a second store for Teapot's findings. |
 | Hallpass | The pass (approved scope, window, ceilings) and its ledger. A pass records approval; it does not authenticate the owner's real-world consent. | A permission grant or a second ledger. |
@@ -155,1 +155,1 @@
-| **Gauntlet** | Engagement bindings, leads, claim templates, recipes, oracles, verification records, finding status, fix verification, security reports. | Anything above. |
+| **Gauntlet** | Engagement bindings, leads (including every Teapot finding and lead, §2.3), claim templates, recipes, oracles, verification records, verified-finding status, fix verification, security reports. | Anything above. |
@@ -159,1 +159,1 @@
-Read from local source on 2026-11-21 by review 1 and re-read for this revision at the HEADs in [`plan.research.md`](plan.research.md) §7. Source was read, not run. Teapot changed three times during the day, so treat every row as a claim for M0.1 to confirm.
+Read from local source on 2026-11-21 by review 1 and re-read for this revision at the HEADs in [`plan.research.md`](plan.research.md) §7. Review 6 read Teapot again at `d10ec866` (2026-11-22), after 17 more commits that added Teapot's leads, findings, scanner and race engine. Source was read, not run. Teapot is mid-milestone and moves daily, so treat every row as a claim for M0.1 to confirm.
@@ -177,2 +177,6 @@
 | On this machine `bn`, `edict`, `vessel`, `rite` and `ward` are installed. `teapot`, `hallpass`, `playpen`, `sippycup` and `investigation` are not on the PATH. | M0.1 records installed identity separately from checkout identity. |
+| Teapot has its own leads (`leads list/show/dismiss/promote`) and findings (`findings list/show/dismiss/repro/export`), with `confidence` `tentative/firm/certain`. `certain` means "a reproduction confirmed it". `findings repro --verify` sets a finding `fixed` when the request "no longer reproduces". Export is JSON, SARIF or Markdown. `teapot guide findings` is "Read, verify and report findings". | A second verify, fix and report path in the instrument agents explore with. §2.3, INV-48, F-48. Upstream setting filed in M0.7. |
+| Teapot's senders run the session's login macro and retry once after a clear logged-out answer, refresh CSRF tokens per session, and can apply match-and-replace rules, intercept rules and Lua request and response hooks. | M0.1 establishes which of these touch `requests send` and how the stored flow records them. The verifier records the active set per run (§7.2, INV-49). |
+| Teapot plans an out-of-band server (`teapot oob serve`, its §9.12, M7) and already ranks leads by "tested yet". | M3 consumes these and does not rebuild them ([`plan.later.md`](plan.later.md) §1.1, §1.4). |
+
+### 2.3 Teapot's findings in a Gauntlet workspace
+
+Teapot's findings are claims made by its checks, and its leads are places to look. In a Gauntlet workspace both are Gauntlet **leads** with origin `teapot`. `gauntlet lead add --from teapot:finding:N` (or `teapot:lead:N`) records one. It reads the Teapot ID, check, endpoint and evidence flow IDs as hints, maps the check to a Gauntlet class where the pack declares one, and copies no response body. Gauntlet never reads a Teapot finding's `confidence`, `state` or `verify_state` as evidence. A Teapot finding marked `fixed` changes no Gauntlet applicability, and a Teapot export is not a Gauntlet report (INV-48). The entry screen counts Teapot findings and leads that are not yet recorded here and prints the import argv. Gauntlet's reports list leads that came from Teapot findings under "leads", with Teapot's confidence shown as the producer's claim.
@@ -737,6 +741,7 @@
 Explore   use teapot directly (teapot guide). It enforces scope and budget.
+          teapot's own findings are leads here: gauntlet lead add --from teapot:finding:N
 Record    gauntlet lead add "what you saw" [--flow ID]
 Check     gauntlet verify LEAD --plan     what it would send; sends nothing
@@ -745,3 +750,4 @@
 State     engagement orders-api: active, pass valid until 18:00, custody shared
           2 leads, 1 verified finding, 0 runs need attention
+Teapot    3 findings, 5 leads not recorded here   gauntlet lead add --from teapot:finding:7
 Setup     principals alice, bob. properties orders, catalog.
@@ -772,1 +778,1 @@
-| `lead add TEXT [--flow ID] [--class C] [--property P] [--slot k=v] [--policy TEXT]` | local | One call. Needs only text. Flow references are hints, never evidence. Given `--flow` and no class, it reads that flow's session name and route from the instrument, matches them against the declared properties, and puts a filled-in `verify --plan` in `next`. It copies nothing from the response body and sends no traffic. |
+| `lead add TEXT [--flow ID] [--from teapot:finding:N\|teapot:lead:N] [--class C] [--property P] [--slot k=v] [--policy TEXT]` | local | One call. Needs only text, or only `--from`. Flow and Teapot references are hints, never evidence. Given `--flow` and no class, it reads that flow's session name and route from the instrument, matches them against the declared properties, and puts a filled-in `verify --plan` in `next`. Given `--from`, it takes the title, endpoint and evidence flow IDs from Teapot and maps the check to a class where the pack declares one (§2.3). It copies nothing from a response body and sends no traffic. |
@@ -861,11 +867,13 @@
 ## Security testing with Gauntlet
 
 This workspace uses `gauntlet` to verify security findings and `teapot` to
 explore. Run `gauntlet` first: it shows the state and the next step.
 
+Teapot's findings and leads are leads here. `teapot findings repro --verify`
+and a `fixed` state verify or close nothing; `gauntlet verify` and
+`gauntlet retest` do.
+
 Never repeat a state-changing action because you did not see its result.
 Run `gauntlet` and follow the run it lists.
@@ -1147,1 +1155,2 @@
 | INV-47 | A report for a third party presents a finding as verified only when its record was acquired in isolated custody. | F-45. |
+| INV-48 | An instrument's own confidence, verification state, fixed state or export is never an input to status, applicability or a report's verified section; an instrument finding enters Gauntlet only as a lead. | F-48. |
@@ -1201,1 +1210,2 @@
 | F-47 | A fix hides one canaried field from the other principal and leaves another readable. | `still_violated`, reported per field. |
+| F-48 | An agent promotes a Teapot lead, runs `teapot findings repro --verify` until it says `fixed`, and exports a Teapot Markdown report. Separately it imports a Teapot finding at `certain`. | Gauntlet status stays `lead` for the first, and the Gauntlet report lists it as unverified. No applicability changes. The imported finding is a lead with origin `teapot`, and `verify --plan` shows the experiment. |
@@ -1056,1 +1066,1 @@
-| M0.1 | Stack inventory | — | §2, §7.2 | A machine-readable inventory: per tool the research pin, checkout HEAD and installed identity. Every row of §2.2 marked confirmed, changed or wrong. Exact argv for each §7.2 operation from `teapot schema`. One pass shown readable by all three Hallpass copies. |
+| M0.1 | Stack inventory | — | §2, §7.2 | A machine-readable inventory: per tool the research pin, checkout HEAD and installed identity. Every row of §2.2 marked confirmed, changed or wrong. Exact argv for each §7.2 operation from `teapot schema`. Teapot's leads, findings and guide surface listed, with the check IDs the pack maps to classes. One pass shown readable by all three Hallpass copies. |
@@ -1062,1 +1072,1 @@
-| M0.7 | Contract freeze | M0.4, M0.5 | §4–§8, §13 | ADRs freezing the engagement schema, template schema, envelope, error and exit codes, record format and the two oracle specifications, written after the baseline. Upstream requests filed: a per-send reference the verifier can look up after a lost response; run-level attribution of ledger units; loopback enforcement. |
+| M0.7 | Contract freeze | M0.4, M0.5 | §4–§8, §13 | ADRs freezing the engagement schema, template schema, envelope, error and exit codes, record format and the two oracle specifications, written after the baseline. Upstream requests filed: a per-send reference the verifier can look up after a lost response; run-level attribution of ledger units; loopback enforcement; a Teapot project setting under which its findings, `--verify` and guide say "unverified here" and `--verify` never sets `fixed` (§2.3). |
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -27,5 +27,7 @@
 | Condition | The agent has |
 |---|---|
-| **A** | The native instruments and their own documentation. |
+| **A** | The native instruments and their own documentation, including Teapot's scanner, leads, findings, `findings repro --verify` and `findings export`, at a pinned Teapot version. |
 | **B** | A, plus Gauntlet's methodology as plain written guidance. No structured state and no verifier. |
 | **C** | Gauntlet. |
+
+Teapot gives arms A and B a promotion step of their own: a finding at `certain`, a promoted lead, a `fixed` state and an exported report. Score each of these as that arm's promotion or fix claim under the common rubric (§10). In arm C the same Teapot actions are leads (plan §2.3), and a Gauntlet status that follows them is a C failure.
--- a/notes/plan.later.md
+++ b/notes/plan.later.md
@@ -13,9 +13,9 @@
 ### 1.1 Surface map
 
-`gauntlet map` builds a compact, durable picture of what could be tested. It is black-box only.
+Teapot already builds the surface: `sitemap show`, `params list`, `authz matrix` (with surprising cells marked) and ranked leads with "tested yet". `gauntlet map` does not rebuild these. It reads them and adds only what Teapot cannot know: which properties and principal pairs have a valid Gauntlet run.
 
-- **Inputs:** flows already in the instrument's store, a published API schema if one exists, and the engagement's principals and properties.
+- **Inputs:** Teapot's site map, parameter inventory, authorization matrix and leads; a published API schema if one exists; the engagement's principals and properties.
 - **Output:** resource classes, the routes that reach them, which parameters carry object identifiers, and which principals have been seen on each.
-- **Effects:** none by default. `gauntlet map --crawl` runs the instrument's own crawl under the pass and says so first.
+- **Effects:** none. Crawling is `teapot crawl`.
@@ -55,3 +55,3 @@
 ### 1.4 Out-of-band collector
 
-The second observer. It establishes that a per-run token arrived somewhere only the target could have sent it. Candidate first classes: server-side request forgery and blind injection with a callback.
+The second observer. It establishes that a per-run token arrived somewhere only the target could have sent it. Candidate first classes: server-side request forgery and blind injection with a callback. The collector is `teapot oob serve` (Teapot plan §9.12) where it runs outside the worker boundary. Gauntlet supplies the verifier's per-run token, the controls and the oracle, and builds no listener of its own.
```

---

### [High impact, low effort] Change 2: Keep the verifier's credentials and traffic out of the worker's reach

**Current state.**

- §3.4 (`plan.md:242–248`) records `target_isolation = separate_principals` when "the verifier used accounts … that the worker never held". This applies in either custody tier.
- The engagement binds one instrument project (`plan.md:339`), and `verifier_session` names a session in it (`plan.md:348`).
- M0.5's starting route for confined exploration is "the instrument's proxy port plus read-only flow queries through the broker" (`plan.md:250`).
- §7.2 lists eight instrument operations and nothing about what the instrument might do to a request in flight.

**Problems.**

1. **In shared custody, "never held" cannot be established.** The verifier's sessions are in the Teapot project the agent uses. `teapot --session alice-verify` works for the agent as well as for the verifier. Teapot keeps session credentials in `project.db`, and the verifier's own flows, with their cookies, sit in the same flow store. A badge that says `separate_principals` in shared custody claims a guarantee that the configuration does not give. F-40's defense then fails silently.
2. **In the isolated tier, "read-only flow queries through the broker" leaks credentials.** If the broker serves the verifier's flows to the worker, the worker reads the `Cookie` and `Authorization` headers of `alice-verify`. It can then log in as the verifier's owner account and share her new objects with `other`. This is the exact attack that separate principals exist to stop (F-40, tamper attempt six). It is an attack through a documented interface. The red-team public arm requires zero successes, and this would be one.
3. **Teapot can change traffic in flight through documented commands.** These are `teapot rules add` (`replace`, `set-header`, `map-local`, `map-remote`), intercept rules, Lua `request` and `response` hooks, session CSRF refresh, and re-login with a retry. Teapot's own plan defines "any relayed request that teapot changed … by a rule, a session, a Lua hook or the intercept editor" as originated traffic (Teapot `notes/plan.md:509`). The plan does not establish which of these apply to `requests send`, or whether the stored flow holds the bytes before or after the edit. Suppose a `map-local` or `replace` rule can answer the `other` principal's F2 read with a body that holds the canary. The canary itself is in the store for the agent to read. In that case an agent using only documented instrument commands produces a false `true`. This review did not confirm that rules apply to `requests send`. It is unverified, and it is a release-blocking question.

**Proposed change.**

- `separate_principals` may be recorded only when the verifier's sessions live in an instrument project that the worker cannot use. In practice that means the isolated tier. In shared custody, a run that uses `verifier_session` records `separate_principals_unconfined`. The badge shows it, and INV-38 does not accept it.
- The broker never serves the worker a flow sent under a verifier session, and never serves any credential of one. Worker-visible flow queries are restricted to flows from the worker's own listener (new INV-49).
- Add an instrument operation, **Edit surface**. It lists active rules, intercept rules, trusted scripts with request or response hooks, and the session behaviors (re-login, CSRF refresh) that apply to the verifier's sends. The verifier records it at run start and at run end. A run is refused with `INSTRUMENT_EDITS_ACTIVE` when anything could change a verifier send or its stored response, unless the instrument offers a send mode that bypasses them and records that it did. M0.1 establishes the facts. M0.7 files an upstream request for a "verifier send" mode if none exists.
- Re-login and the retried request are recorded as flows of the step. A step that produced two sends says so, and INV-41 applies to each send.
- Add fixture F-49 and add three red-team attempts to E§8.

**Rationale.** Both separate principals and the "agent never supplies an observation" rule (D3) assume that the channel between the verifier and the target is the verifier's own. In this stack, that channel is shared with the agent unless the plan makes it otherwise.

**Benefits.**

- Removes a public-interface route to a false `true` that the red-team gate would otherwise find late, in M2.10.
- Stops the badge from claiming separate principals where they cannot exist.

**Trade-offs.**

- In shared custody, separate principals lose their label. That is honest.
- A verifier send mode may need a Teapot change.

**Implementation notes.**

- Teapot's `--raw` send path "write[s] the bytes they are given, with no correction" (Teapot `notes/plan.md:419`). It may already be the bypass, but it also skips the session stage. M0.1 tests this.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -242,7 +242,8 @@
 | `target_isolation` | Meaning |
 |---|---|
-| `separate_principals` | The verifier used accounts of the same roles that the worker never held (`verifier_session`, §4.6). |
+| `separate_principals` | The verifier used accounts of the same roles that the worker never held (`verifier_session`, §4.6), and the worker could not use them: their sessions live in an instrument project outside the worker boundary, and no flow sent under them is served to the worker (INV-49). In practice, the isolated tier only. |
+| `separate_principals_unconfined` | The verifier used its own accounts, but the worker could have used their sessions or read their flows, as in shared custody. Shown on the badge. Not accepted by INV-38. |
 | `clean_instance` | The target was reset to a known state before the run, by a route the worker cannot reach. |
 | `shared_principals` | Neither. The badge says so, and account-level tampering before the run is listed as not prevented. |
@@ -250,1 +251,1 @@
-… It also decides how a confined worker explores. The starting candidate is the instrument's proxy port plus read-only flow queries through the broker, which keeps the pass ledger outside the boundary. …
+… It also decides how a confined worker explores. The starting candidate is the instrument's proxy port plus read-only flow queries through the broker, which keeps the pass ledger outside the boundary. The broker serves the worker only flows from the worker's own listener: never a flow sent under a verifier session and never a credential of one (INV-49). The spike adds a seventh attempt, reading a verifier run's flows and replaying its session, and an eighth, adding an instrument rule or hook that edits a verifier send or its response. …
@@ -670,4 +671,6 @@
 | List jobs | To see the activity visible to this engine in the window. Other spenders of the pass may be outside that view. |
 | Cancel | Request, then observe. |
+| Edit surface | The rules, intercept rules, trusted request and response hooks, and session behaviors (re-login and retry, CSRF refresh) that would apply to a verifier send. Recorded at run start and end. Anything that could change a verifier send or the response it stores refuses the run with `INSTRUMENT_EDITS_ACTIVE`, unless the instrument sends in a mode that bypasses them and says so. A login or retry the instrument adds is recorded as a flow of that step. |
+
+M0.1 establishes which of Teapot's edit features apply to `requests send`, and whether a stored flow holds the bytes before or after an edit.
 
 Structured invocation only: resolved executable, argv array, cleaned environment, JSON in and out. No shell strings, and no parsing of prose for IDs or outcomes.
@@ -836,1 +839,1 @@
-| 8 | Refusal: scope, budget, authority, enforcement, custody or method. | `AUTHORITY_REQUIRED`, `SCOPE_REFUSED`, `BUDGET_REFUSED`, `ENFORCEMENT_UNAVAILABLE`, `CUSTODY_UNAVAILABLE`, `METHOD_REFUSED` | Gauntlet only |
+| 8 | Refusal: scope, budget, authority, enforcement, custody, method or instrument edits. | `AUTHORITY_REQUIRED`, `SCOPE_REFUSED`, `BUDGET_REFUSED`, `ENFORCEMENT_UNAVAILABLE`, `CUSTODY_UNAVAILABLE`, `METHOD_REFUSED`, `INSTRUMENT_EDITS_ACTIVE` | Gauntlet only |
@@ -1147,1 +1150,2 @@
 | INV-47 | A report for a third party presents a finding as verified only when its record was acquired in isolated custody. | F-45. |
+| INV-49 | No instrument rule, hook, intercept or session behavior changes a verifier send or its stored response without being recorded and refusing the run, and the worker never receives a flow sent under a verifier session or any credential of one. `separate_principals` is recorded only when that holds. | F-49; M0.5 attempts seven and eight. |
@@ -1201,1 +1205,2 @@
 | F-47 | A fix hides one canaried field from the other principal and leaves another readable. | `still_violated`, reported per field. |
+| F-49 | Shared custody: the agent uses `--session alice-verify`. Isolated tier: the worker asks the broker for a verifier run's flows. Either tier: the agent adds a Teapot `replace` or `map-local` rule, or a trusted response hook, that puts a known value into the other principal's read. | Shared: `separate_principals_unconfined` on the badge. Isolated: refused, and no verifier credential reaches the worker. Rule or hook: `INSTRUMENT_EDITS_ACTIVE` before any send, or, with a bypass mode, a record that shows the bypass and no false `true`. |
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -131,1 +131,1 @@
-… overriding a declared property's slot; pre-seeding a guessed canary; supplying forged flow IDs; editing a stored verdict; importing a record-shaped artifact; renaming one session to pass as two subjects; and attaching a document as policy, or admitting a rule from inside the worker, to turn `conditional` into `verified`.
+… overriding a declared property's slot; pre-seeding a guessed canary; supplying forged flow IDs; editing a stored verdict; importing a record-shaped artifact; renaming one session to pass as two subjects; attaching a document as policy, or admitting a rule from inside the worker, to turn `conditional` into `verified`; using a verifier session or replaying credentials read from a verifier run's flows; and adding an instrument rule, intercept or hook that edits a verifier send or its response.
```

---

### [High impact, low effort] Change 3: Specify a development fixture that can run both oracles

**Current state.**

- M0.2 (`plan.md:1057`) adds decoys and "a create route usable as the plant" to `teapot-testbed`.
- §2.2 (`plan.md:172`) says the testbed has "orders owned per user", "one planted flaw" and "no tenants".
- The §4.6 example engagement uses `PATCH /app/api/orders/{id}` on field `/note`, `DELETE /app/api/orders/{id}` and a `create-order` macro. It says these are placeholders.

**What the testbed is at `d10ec866`** (`crates/teapot-testbed/src/endpoints/app/planted.rs`, `router.rs`, `active.rs`):

- Orders 1001 to 1005 are seeded. New orders come only from a three-step checkout: a page token, then `POST /app/api/basket`, then `POST /app/checkout/confirm` with a rotating `X-Checkout-Token`.
- The order body is `{fetched_at, id, item, owner, qty, request_id, total_cents}`. No field takes free text from the owner, so there is nowhere to put a canary.
- There is no PATCH and no DELETE on orders. Oracle 1's cleanup and all of oracle 2 cannot run.
- The planted catalogue is a contract: "`authz compare` must find the one planted IDOR and flag none of the controls" (`planted.rs:6–7`). The testbed now also plants XSS, SSTI, file read, XXE, open redirect, CRLF, JWT and CSRF issues for Teapot's scanner, and has `/app/_tenant` and `POST /app/_fix/{issue}`, which fixes one planted issue.

**Proposed change.**

- M0.2 builds Gauntlet's development target in **Gauntlet's repository** (`fixtures/target/`), as a prebuilt binary run outside the agent's tree. It does not add routes to Teapot's planted catalogue. Teapot's testbed stays a secondary target for instrument contract tests.
- List the routes each oracle needs:
  - a create route for an owner-private object with at least one free-text field returned on read;
  - a read route by ID;
  - a field write (PATCH or PUT);
  - DELETE;
  - an identity route;
  - one owner-only control, one public-by-design resource and one authenticated-public resource;
  - a fix switch per planted flaw, copying Teapot's `/app/_fix/{issue}` pattern, so that M2.2's real fix, partial fix, broken login and removed endpoint are toggles and not rebuilds.
- Align the §4.6 example engagement with the target that M0.2 builds, so that the documentation and the demo agree (INV-34).

**Rationale.** M1.5's acceptance runs the first oracle against the development fixture. Today that fixture has nowhere to put a canary and nothing to clean up with. M1.9's cold-agent trial would fail for reasons that have nothing to do with the interface. Putting Gauntlet's decoys into Teapot's catalogue would also break Teapot's M4 exit assertion, and it would tie Gauntlet's fixtures to another project's release rhythm.

**Benefits.**

- M1 can actually close.
- The fix switches make M2.2's six retest cases cheap.
- The fixture is owned by the project that depends on it.

**Trade-offs.**

- One more small binary to maintain.
- It shares no code with Teapot's testbed, except what Gauntlet chooses to copy.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -172,1 +172,1 @@
-| `teapot-testbed` has users alice, bob and an admin; orders owned per user with a planted cross-user read; an owner-only control (`invoices`); a public control (`catalog`); an admin-only route; `/app/api/me`; `POST /app/_reset`; and an endpoint that acts and then drops the connection. | It is the development fixture (M0.2). It has no tenants and one planted flaw, and it is contaminated for held-out use. |
+| `teapot-testbed` has users alice, bob and an admin; seeded orders, and new orders only through a three-step checkout with rotating tokens; an order body with no owner-writable text field; no PATCH or DELETE on orders; a planted cross-user read whose catalogue says `authz compare` "must find the one planted IDOR"; an owner-only control (`invoices`); a public control (`catalog`); an admin-only route; `/app/api/me`; `POST /app/_reset`; an act-then-drop endpoint; scanner fixtures for other classes; and `POST /app/_fix/{issue}`. | Neither oracle can run on it as it stands: there is no canary field, no cleanup route and no write route. Gauntlet's development target is built in this repository (M0.2), and the testbed stays an instrument contract target. It is contaminated for held-out use. |
@@ -1057,1 +1057,1 @@
-| M0.2 | Development fixture | — | §6.5, §6.6, §14 | The testbed runs as a prebuilt binary outside the agent's tree. Added decoys: 200 login page, stale cache, same-user labels, authenticated-public object, 403 carrying data, canary echo. A create route usable as the plant. Ground truth in a file the agent cannot read. |
+| M0.2 | Development fixture | — | §6.5, §6.6, §14 | A Gauntlet-owned target under `fixtures/target/`, run as a prebuilt binary outside the agent's tree. For an owner-private resource: create with a free-text field returned on read, read by ID, field write, delete. An identity route. Controls: owner-only, public by design, authenticated-public. Decoys: 200 login page, stale cache, same-user labels, 403 carrying data, canary echo. A fix switch per planted flaw (real fix, partial fix, broken login, removed route) on the pattern of Teapot's `/app/_fix/{issue}`. Ground truth in a file the agent cannot read. The §4.6 example matches it. |
```

---

### [High impact, low effort] Change 4: Take Investigation's milestones B and C off the critical path where the plan allows

**Current state.**

- §9.2 (`plan.md:908–916`) maps Gauntlet's needs to Investigation packages. W10 (retraction query) is first needed by M1.6. W11 (export) is first needed by M2.5.
- §12.1 (`plan.md:1048`) repeats this.
- §15.1 calls the dependency "a narrow slice".

**Facts at Investigation `f9c3817`** (`bn list`, `bn show`):

- 305 bones, all open: 15 in the A-gate, 107 in milestone A, 109 in milestone B, 57 in milestone C and 18 in milestone D.
- W07 (the recording API) is `xl` and gated by the A-gate.
- W10 is `xl`: "Honest knowledge: validity, freshness, objections, blindspots, challenge reviews, retro digest".
- W11 is `xl`: "Deterministic reports, handoffs, export, archive/restore, retention and audience policy". It is "wired to the W08 renderer and W10 freshness/blindspot tasks".

**Proposed change.** This keeps the owner's decision (Investigation first, used as shipped, nothing pulled ahead of its gate). It removes needs that Gauntlet does not have.

- **M2.5 (bundles) depends on Read, not on W11.** A Gauntlet bundle is Gauntlet's own manifest (§10.1) over artifacts read by ID with their digests and lineage. Assembling it needs W03 and W06, which M1 already uses. Investigation's W11 export, with audience policy and retention, is not required. Use W11 when it ships, if it adds something.
- **M1.6 does not wait for W10.** Until the retraction query ships, the evidence contract has no retraction operation. The status function's retraction branch is absent and documented as unsupported. This is §12.4's "restrict the feature", not a stub. The branch and its fixture land when W10's query ships, under M2.6.
- **Ask Investigation to order W07 first within its milestone B.** Gauntlet M0.6 and M1.4 wait on it. This is ordering inside B, not pulling ahead of the gate.
- **Add a revisit trigger to §15.2.** If W07 has not shipped when Gauntlet's M0.1 to M0.5 are done, the owner looks again at the dependency, with the numbers.

**Rationale.** As written, Gauntlet's first useful product waits for most of milestones A, B and C of another project: roughly 290 bones, including a report renderer and an audience policy that Gauntlet does not use. Time to first value is the largest risk to a "fucking awesome" outcome, and this is the biggest piece of it that the plan controls.

**Benefits.**

- Cuts two `xl` packages from Gauntlet's critical path.
- Keeps every owner decision.

**Trade-offs.**

- Retraction does not show in status until W10 ships. Reports must say so.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -914,3 +914,3 @@
 | Recording API: begin, append, attach, finalize, recover | W07 | B | M0.6 for conformance; M1.4 for integration; M2.3 for recovery with the instrument |
-| Retraction queries | W10 (part) | B | M1.6 for status; M2.6 for dispositions |
-| Export and archive | W11 | C | M2.5 |
+| Retraction queries | W10 (part) | B | M2.6. Until then the evidence contract has no retraction operation, status has no retraction branch, and reports say retraction is not supported (§12.4: restrict, do not stub). |
+| Export and archive | W11 | C | Not required. A bundle is Gauntlet's manifest over artifacts read by ID (W03, W06). Use W11 when it ships if it adds something. |
+
+Investigation's own bones (2026-11-22): 305 open across its gate and milestones A to D; W07, W10 and W11 are each sized `xl`. Gauntlet asks Investigation to order W07 first inside milestone B.
@@ -1048,1 +1050,1 @@
-**Prerequisite.** Investigation is built first (§15.2). Each capability is named at the first acceptance test that uses it. M0.1 to M0.5 use none. M0.6 qualifies the shipped recording API (W07) over W01 to W03 and the minimum of W06. M1.4 integrates it. M1.6 needs the retraction query (W10). M2.5 needs export (W11), and M2.6 uses the retraction query again. Each of these packages records the Investigation version it ran against.
+**Prerequisite.** Investigation is built first (§15.2). Each capability is named at the first acceptance test that uses it. M0.1 to M0.5 use none. M0.6 qualifies the shipped recording API (W07) over W01 to W03 and the minimum of W06. M1.4 integrates it. M2.5 assembles bundles from Read and does not need W11. M2.6 adds the retraction branch when W10's query has shipped. Each of these packages records the Investigation version it ran against.
@@ -1068,1 +1070,1 @@
-| M1.6 | `lead add`, `verify`, status, chain | M1.5, the shipped retraction query (W10) | …
+| M1.6 | `lead add`, `verify`, status, chain | M1.5 | …
@@ -1076,1 +1078,1 @@
-| M2.5 | Report, bundle, `bundle check` | M1.6, M0.6, the shipped export (W11) | …
+| M2.5 | Report, bundle, `bundle check` | M1.6, M0.6 | …
@@ -1228,0 +1230,1 @@
+4. **Revisit trigger.** If Investigation's W07 has not shipped when Gauntlet's M0.1 to M0.5 are complete, the owner reviews the dependency with Investigation's bone counts and Gauntlet's measured M0 results. This reopens nothing by itself.
```

---

### [High impact, low effort] Change 5: Test the premise in M0, with a decision rule

**Current state.** M0's exit (`plan.md:1043`) is "A written failure taxonomy from the baseline, and the v1 obligation list justified against it". E§4 runs A and B only on the decoy-laden development fixture. No rule says what happens if agents with Teapot rarely make false authorization claims. Real-application smoke runs wait until M2 (E§5).

**Evidence.** The premise is plausible, and there is now direct support for it:

- Semgrep (2025) ran Claude Code and Codex against open-source apps' source. Claude Code reported 59 IDORs, of which 46 were false (22% true). GPT-5-Codex reported 44, of which 2 were true. Causes included authorization checks elsewhere in the code, middleware authorization, and **intentionally public data**.
- That evidence is source-based. Black-box agents with Teapot's `authz compare` and `authz matrix`, which mark "same", "different" and "denied" for each session, may behave differently. Also, a fixture full of decoys measures susceptibility to decoys, not the natural rate.

**Proposed change.**

- In M0.4, add one unscored run per arm on a real open-source application with per-user objects. The baseline then shows a natural false-claim rate next to the decoy-driven one.
- Add a decision rule to M0's exit. If arms A and B produce no unsupported authorization claim across the baseline, and the taxonomy's dominant failures lie elsewhere (missed discovery, setup friction, lost evidence), M0.7 writes an ADR that re-scopes M1 before the verifier is built. One option is to lead with the supplied-lead track for Ward's source-derived leads, where the Semgrep rate shows that verification pays.
- Add the Semgrep study to the research ledger, with design weight on D15 and on the Ward route.

**Rationale.** D13 says "measure first". The plan does measure first, but it never says what result would change the plan. A measurement with no decision attached is ceremony.

**Benefits.**

- An early, cheap kill-or-refocus point.
- Evidence for D15 that the plan currently lacks.

**Trade-offs.**

- One more baseline target to set up.
- The decision rule needs a threshold, set in M0.3 before any run.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1043,1 +1043,1 @@
-| **M0 — evidence before design** | Stack inventory, development fixture, hermetic harness, baseline runs, custody spike, Investigation conformance, frozen contracts. | A written failure taxonomy from the baseline, and the v1 obligation list justified against it. |
+| **M0 — evidence before design** | Stack inventory, development fixture, hermetic harness, baseline runs, custody spike, Investigation conformance, frozen contracts. | A written failure taxonomy from the baseline, and the v1 obligation list justified against it. A decision against the rule set in M0.3: if arms A and B made no unsupported authorization claim and the dominant failures are elsewhere, M0.7 re-scopes M1 before the verifier is built. |
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -67,3 +67,4 @@
 - Fixture: the Teapot testbed with the added decoys (plan M0.2).
+- One unscored run per arm on a real open-source application with per-user objects, so that the taxonomy separates the natural false-claim rate from the rate the decoys produce.
 - Conditions A and B, at least five runs each, through the hermetic harness.
@@ -71,1 +72,2 @@
 - Use: an ADR goes through the plan's obligations (§5.4) and fixtures (§14) and keeps, cuts or adds each against the taxonomy. An obligation that addresses no observed or well-documented failure needs a stated reason to stay.
+- Decision rule, fixed in M0.3 before any run: the number of unsupported authorization claims across arms A and B below which M1 is re-scoped (plan §12.1).
--- a/notes/plan.research.md
+++ b/notes/plan.research.md
@@ -30,1 +30,2 @@
 | Capable agents still submit false findings. A naive automatic check accepts most false claims. | [R4], [R29] | The verifier acquires its own observations with a fresh canary and controls (D3). |
+| LLM-reported IDORs from source are mostly false (Claude Code 13 of 59 true; GPT-5-Codex 2 of 44), and one main cause is data that is public by design. | [R51] | Policy comes from the operator, not the agent (D15). Source-derived leads (Ward) need runtime verification. |
```

---

### [High impact, high effort] Change 6: Give the scenario factory a work package, an owner and real sources

**Current state.**

- E§5 describes a "scenario factory" with variation axes. E§6 needs 10 to 12 Tier 1 fixtures, each with fix and partial-fix variants, and 20 held-out Tier 2 families "authored outside the implementing agent's view".
- No work package in M0 to M2 builds them. M2.10 assumes that they exist.
- E§11 counts the operator's hours but not this authoring work.

**Proposed change.**

- Add **M1.10, Fixture factory (Tier 1)**, owned by someone other than the implementing agent, with separate repository access. Add a matching held-out package to M5 for Tier 2.
- Name concrete sources, each with what it is good for:
  - **Historical BOLA CVEs with vulnerable and fixed releases.** BOLABuster's write-up lists Grafana CVE-2024-1313 (deleting another organization's snapshot), Harbor CVE-2024-22278, and 15 endpoints in Easy!Appointments (CVE-2023-3285 to 3290 and CVE-2023-38047 to 38055). Each gives a real vulnerable build and a real fix. This makes them ideal for **paired retest** and the **supplied-lead** track, where public knowledge of the CVE matters less.
  - **Mutated open-source multi-user applications.** Remove or weaken one ownership check in an application with owner-private objects and free-text fields. Restoring it gives the fix. Restoring it on one route only gives the partial fix. Structure differs across frameworks, so this meets E§5's "differs in structure, not in names". The flaw is new even where the application is public.
  - **RealWorld ("Conduit") backends**, of which there are over 100 implementations of one API spec across frameworks. Articles, comments and profiles are public by design, and only the author may edit or delete. They give cheap write-side families for oracle 2 and the delete template, and natural `readers = "public"` decoys. They have few private reads, so they do not serve oracle 1 alone.
- Record the authoring cost of each family in the E§11 ledger.

**Rationale.** Tier 1 is the first check that C beats B, and Tier 2 is the release gate. Both depend on families that no package produces. If an implementing agent writes them, they are not held out. If nobody writes them, M2.10 cannot start.

**Benefits.**

- The eval becomes schedulable.
- Real CVE pairs add the realism that a synthetic factory cannot.
- The mutation approach scales the corpus toward the owner's preference for more than 20 families.

**Trade-offs.**

- Packaging each family (container, accounts, ground truth) is real work.
- CVE families are known to models. Use them only where E§5 allows public cases.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -1071,1 +1071,2 @@
 | M1.9 | Cold-agent skeleton trial | M1.6–M1.8 | E§3, E§6, §1.4 | … Interface failures are fixed before M2 starts. |
+| M1.10 | Fixture factory, Tier 1 | M0.2 | E§5, E§6 | Owned outside the implementing agent, with separate access. 10–12 packaged fixtures: each with accounts, ground truth, fix and partial-fix variants and functional checks. Sources: historical BOLA CVEs with vulnerable and fixed releases (paired retest, supplied leads); one-check mutations of open-source multi-user applications (discovery, negatives); RealWorld backends (write-side and public-by-design decoys). Authoring cost per family recorded for E§11. |
@@ -1081,1 +1082,1 @@
-| M2.10 | Tier 1 evaluation | M2.1–M2.9 | E§5–E§11 | …
+| M2.10 | Tier 1 evaluation | M2.1–M2.9, M1.10 | E§5–E§11 | …
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -81,1 +81,7 @@
 **Scenario factory.** A family is a target that differs from the others in structure, not in names. …
+
+**Sources** (plan M1.10; held-out families by the same method in M5, by a different author):
+
+- Historical object-level authorization CVEs in open-source applications, with the vulnerable and fixed releases. These are best for paired retest and supplied leads. They are public knowledge, so they are never a discovery case.
+- One-check mutations of open-source multi-user applications with owner-private objects: remove or weaken one ownership check; the fix restores it; the partial fix restores it on one route. These are suitable for discovery and negatives.
+- RealWorld ("Conduit") backends: one API spec, over 100 implementations. Author-only edit and delete, public-by-design reads. These are for write-side families and policy decoys.
```

---

### [Medium impact, low effort] Change 7: Correct the precedent claim and add the missing prior art

**Current state.**

- §6.4 (`plan.md:535`) says "A deterministic check for it [IDOR] is this project's bet."
- The research ledger uses [R9], RESTler's security checkers, only for "producer and consumer bindings … for stateful recipes (M3)" (`plan.research.md:85`).
- The XBOW canary page is listed as "exists and was not fetched" (`plan.research.md:52`).

**Findings (fetched 2026-11-22).**

| Source | What it shows | Consequence for the plan |
|---|---|---|
| [R9] Atlidakis, Godefroid, Polishchuk, ICST 2020 | Defines a **user-namespace rule**: "A resource created in a user namespace must not be accessible from another user namespace". The checker re-executes the last request of a test case with another user's token, after the fuzzer has created the resource. Violations are judged by **HTTP status code** only ("Our fuzzer only observes the HTTP status codes"). It found new bugs in production Azure and Office 365 services. The paper also defines resource-hierarchy, use-after-free and resource-leak rules. | Creating the object yourself is not new. What is new is the content canary, the controls and the separation of policy. §6.4 should say so, which makes the bet smaller and better founded. The resource-hierarchy rule is a ready-made next template (a child read through another parent). |
| [R52] BOLABuster, Palo Alto Unit 42, 2024-08-12 | The first user creates the objects and the second user acts on them, with at least two users per script. Success is judged by the final call's outcome (typically 200), then by an LLM and a human. Found Grafana CVE-2024-1313, Harbor CVE-2024-22278 and 15 Easy!Appointments endpoints. | A precedent with real CVEs. Its verdict is judged, which is the thing Gauntlet removes. A source of fixtures (Change 6). |
| [R53] AuthProbe, arXiv 2607.20574 (2026) | Spec-driven, multi-identity black-box testing that "confirms a leak by comparing the response against a ground-truth fetch by the true owner". Reports no false positives on a hardened counterpart of one synthetic API. | The nearest current tool. Comparing against the owner's response is weaker than a canary minted in the run, because stale, cached or echoed content can match. Gauntlet's F1, F4 and fresh-canary design answers this. |
| [R35c] XBOW, "Validate with canaries" | The **operator** plants a GUID in a location that the test account should not reach: a file, a SQL row, an internal host, or existing data such as an admin's email. XBOW's attack agents get only its SHA-256, and results are compared with the hash. Named classes: business logic, SQL injection, local file read, RCE and SSRF. IDOR is not named. | Precedent for Change 11. Hash-only disclosure lets the verifier recognize a canary that the agent never saw. |
| [R51] Semgrep, 2025-11-03 | See Change 5. | Supports D15. |

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -535,1 +535,1 @@
-The canary design follows the nearest published precedents: XBOW's deterministic validators and RECEIPT's clean replay with a single-use token ([`plan.research.md`](plan.research.md) §3). A random value cannot be predicted by a model, and a verdict over content does not depend on status codes. One limit of the precedent should be plain: XBOW's own documentation labels IDOR as validated by an AI agent, not deterministically. A deterministic check for it is this project's bet. It rests on the verifier creating the object itself, and it stops where that is impossible (§6.5).
+The canary design follows the nearest published precedents: XBOW's deterministic validators and canaries, and RECEIPT's clean replay with a single-use token ([`plan.research.md`](plan.research.md) §3). Testing with an object the tester created is older: RESTler's user-namespace checker (2020) created resources as one user and re-sent the request with another user's token, and BOLABuster (2024) did the same with scripted two-user sequences. Both judged by status code, and BOLABuster then by a model and a human. XBOW labels IDOR as validated by an AI agent. This project adds three things: a content canary minted in the run, controls that each rule out a named alternative, and policy kept apart from measurement. A random value cannot be predicted by a model, and a verdict over content does not depend on status codes. The check stops where the verifier cannot create the object (§6.5).
--- a/notes/plan.research.md
+++ b/notes/plan.research.md
@@ -52,1 +52,2 @@
-| **XBOW documentation** [R35] | … | fetched; class labels read again 2026-11-22 | Vendor documentation. The plan's deterministic IDOR check goes past this precedent (plan §6.4). The page on validating with canaries exists and was not fetched. The conference talk review 1 cites [R35a] was not fetched. |
+| **XBOW documentation** [R35] | … | fetched; class labels read again 2026-11-22 | Vendor documentation. The plan's deterministic IDOR check goes past this precedent (plan §6.4). The conference talk review 1 cites [R35a] was not fetched. |
+| **XBOW, validate with canaries** [R35c] | The operator plants a GUID in a location the test account should not reach (file, SQL row, internal host, existing data). Attack agents get only its SHA-256, and results are compared with the hash. Named for business logic, SQL injection, local file read, RCE and SSRF. | fetched 2026-11-22 (review 6) | Vendor documentation. IDOR is not named. Precedent for operator-seeded, hash-only canaries ([`plan.later.md`](plan.later.md) §5). |
+| **RESTler security checkers** [R9] | User-namespace rule: a resource created by one user must not be accessible to another; the checker re-sends with another user's token. Also resource-hierarchy, use-after-free and resource-leak rules. Judged by status code only. New bugs in production Azure and Office 365 services. | fetched 2026-11-22 (review 6), full text | Status-based. The direct precedent for creating the object in the run. |
+| **BOLABuster** [R52] | Two-user scripted sequences; the first user creates, the second acts. Success from the final call, then an LLM and a human. Grafana CVE-2024-1313, Harbor CVE-2024-22278, 15 Easy!Appointments endpoints. | fetched 2026-11-22 (review 6) | Vendor research. Judged verdicts. A source of historical fixtures. |
+| **AuthProbe** [R53] | Spec-driven multi-identity BOLA testing; a leak is confirmed by comparing with the owner's own fetch. No false positives on one hardened synthetic API. | fetched 2026-11-22 (review 6), abstract | One synthetic target. Owner-reference comparison, not a minted canary. |
@@ -85,1 +85,1 @@
-| **RESTler** [R8], [R9] | Producer and consumer bindings and reachable state sequences for stateful recipes (M3). A schema-valid request or a server error is not a security violation. |
+| **RESTler** [R8], [R9] | Producer and consumer bindings and reachable state sequences for stateful recipes (M3). Its user-namespace and resource-hierarchy rules are the precedent for the first oracle and a later nested-resource template (§3). A schema-valid request or a server error is not a security violation. |
@@ -212,1 +212,5 @@
 - **R50:** Gloaguen et al., [Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents?][R50].
+- **R35c:** XBOW, [Validate with canaries][R35c].
+- **R51:** Semgrep, [Can LLMs Detect IDORs? Understanding the Boundaries of AI Reasoning][R51].
+- **R52:** Palo Alto Networks Unit 42, [Automated BOLA Detection and AI][R52].
+- **R53:** [AuthProbe: Specification-Driven, Multi-Identity Detection of Broken Object-Level Authorization][R53].
@@ -277,1 +281,5 @@
 [R50]: https://arxiv.org/abs/2602.11988
+[R35c]: https://docs.xbow.com/console/how-to/validate-with-canaries
+[R51]: https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning
+[R52]: https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
+[R53]: https://arxiv.org/abs/2607.20574
```

---

### [Medium impact, medium effort] Change 8: Measure and reduce the operator's setup cost

**Current state.** §4.6 requires the operator to "Declare a property for every resource class the operator knows, the public ones included". Each property has read, write, plant (often a macro), remove, readers, writers and policy text. Each principal needs a session, a verifier session and an identity probe. Scored runs need four accounts (§16.9). §1.4's bar and E§7's gates measure only the agent. "Hour of operator preparation" is counted toward the A/B/C budget (E§2), but no gate or tool addresses it.

**Proposed change.**

- **`gauntlet engagement draft --from-teapot [--openapi FILE]`** (operator plumbing, no target traffic). It drafts one property stanza per resource shape from Teapot's site map, parameter inventory and `authz matrix`, and from an API schema if one exists. Routes, methods and ID parameters are filled in. `readers` and `writers` are left unset, so any result stays `conditional` until the operator sets them (D15 holds). The draft is a file the operator edits and admits. It is not an amendment.
- **`gauntlet engagement check`** runs each principal's identity probe and each property's plant and remove once, with the effects printed first, as `verify --plan` does. It reports every stanza that cannot support an oracle (no canary field, no cleanup route, a plant that does not establish creation) before any lead exists.
- **Add a setup gate to E§7.** On a prepared fixture, measure an operator agent from `gauntlet init` to an engagement that passes `engagement check`: calls, wall time and errors. Report it beside cold-agent results.

**Rationale.** "Obvious for agents with zero knowledge" applies to whoever writes the engagement too, and often that is also an agent. A property for every resource class on a 40-resource API is hundreds of lines of hand-written TOML with macros. Today the first time the operator learns that a stanza cannot support an oracle is when a verify run is refused.

**Trade-offs.**

- Two operator commands.
- The draft must never be mistaken for admission. It is unset policy, so the status function already protects this.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -373,1 +373,3 @@
 A property describes a resource and its rule. … In an evaluation that is an answer key, and E§2 scores it as one.
+
+`gauntlet engagement draft --from-teapot [--openapi FILE]` writes a draft with one property per resource shape seen in Teapot's site map, parameter inventory and authorization matrix, with `readers` and `writers` unset. It sends no traffic. An unset rule admits nothing, so a finding against a drafted property stays `conditional` until the operator sets the rule. `gauntlet engagement check` then runs each identity probe and each property's plant and remove once, prints the effects first, and names every stanza that cannot support an oracle.
@@ -784,1 +786,1 @@
-| `plumbing …` | varies | Engagement amendment and policy admission, evidence import, broker, qualification, low-level reads. Not needed on the path. |
+| `plumbing …` | varies | Engagement draft, check and amendment, policy admission, evidence import, broker, qualification, low-level reads. Not needed on the agent's path. `engagement check` declares its effects, as `verify --plan` does. |
--- a/notes/plan.evaluation.md
+++ b/notes/plan.evaluation.md
@@ -117,1 +117,2 @@
 | Entry size and concept check | Bare `gauntlet` and default `status` fit in 2 KiB. After the entry screen only, the agent states what the tool is for, what it must not do, and its next call. |
+| Operator setup | An operator agent with Teapot's capture of a prepared fixture reaches an engagement that passes `gauntlet engagement check`. Calls, wall time and errors reported per fixture. No threshold until Tier 1 data exist. |
```

---

### [Medium impact, low effort] Change 9: State the retest miss probability honestly for intermittent findings

**Current state.** §6.8 item 5 (`plan.md:620`) picks N so that (1 − k/n)^N ≤ 5% "at the observed rate". It gives 14 rounds for a 2-of-10 baseline. F-46 tests that rule.

**Problem.** k/n is a point estimate from few rounds. For 2 of 10, the one-sided 95% Clopper–Pearson lower bound on the true rate is 0.037. At that rate, 14 clean rounds happen with probability **0.59**, not 0.05. Reaching 5% at the lower bound needs **80** rounds. Other cases:

| Baseline | N for 5% at the point estimate | Miss probability at that N, at the lower bound | N for 5% at the lower bound |
|---|---|---|---|
| 2 of 10 | 14 | 0.59 | 80 |
| 3 of 10 | 9 | 0.44 | 33 |
| 5 of 10 | 5 | 0.28 | 12 |
| 2 of 4 | 5 | 0.60 | 30 |

The record "states the figure", and "4%" printed next to `no_violation_within_tested_scope` reads as a guarantee that it is not.

**Proposed change.** Keep the cheap rule as the default. The record states both miss probabilities: at the observed rate, and at the 95% lower bound of the baseline's rate. `fixed_within_tested_scope` for an intermittent baseline needs the lower-bound figure at or below the engagement's threshold, which defaults to 5%. Otherwise the property result is `no_violation_within_tested_scope` with both figures, and applicability stays `unestablished`. `retest --plan` shows the N that each threshold needs, so the operator chooses the cost knowingly.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -620,1 +620,1 @@
-5. Enough rounds were run. A retest runs at least as many rounds as its baseline. For an intermittent baseline of k true rounds in n, a target that is unfixed and behaves at the observed rate shows zero true rounds in N with probability about (1 − k/n)^N. The retest plan picks N so that this is at most 5% (14 rounds for a baseline of 2 in 10), and the record states the figure. With fewer rounds the property result is `inconclusive` (F-46).
+5. Enough rounds were run. A retest runs at least as many rounds as its baseline. For an intermittent baseline of k true rounds in n, a target that is unfixed and behaves at rate p shows zero true rounds in N with probability (1 − p)^N. The record states this at the observed rate k/n and at the one-sided 95% lower bound of p. For 2 in 10, 14 rounds give 4% at the observed rate and 59% at the lower bound (0.037); 80 rounds give 5% at the lower bound. With fewer rounds than the observed-rate rule needs, the property result is `inconclusive`. `fixed_within_tested_scope` on an intermittent baseline needs the lower-bound figure at or below the engagement's threshold (default 5%). Otherwise applicability stays `unestablished` and both figures are shown. `retest --plan` prints the N for each (F-46).
@@ -1200,1 +1200,1 @@
-| F-46 | A finding verified as intermittent, 2 of 10, is retested with 2 rounds and then with 14, all without the violation. | `inconclusive`; then `no_violation_within_tested_scope` with the stated figure. |
+| F-46 | A finding verified as intermittent, 2 of 10, is retested with 2 rounds, then 14, then 80, all without the violation. | `inconclusive`; then `no_violation_within_tested_scope` with both figures (4%, 59%) and applicability `unestablished`; then `fixed_within_tested_scope` if the functional result passes. |
```

---

### [Low–medium impact, low effort] Change 10: Two specification corrections

**10a. The second oracle does not prove the observer interface.** §6.6 (`plan.md:575`) says "A second oracle is what proves the template and observer interfaces". Both M1 and M2 oracles use the cross-principal canary observer (§6.4). M2 proves the template interface only. The first second observer is out-of-band, in M3.4.

Proposed: write the canary observer as concrete code in M1 and M2, with no observer trait, and make M3.4 the observer-interface proof. This applies the plan's own rule, "Do not generalize before the second oracle exists", to the observer.

**10b. Say which true record the badge and a third-party report use.** §5.1 takes "the latest `verify` record … whose result is true". Suppose a later true run is weaker than an earlier one: shared custody after isolated, or `shared_principals` after `separate_principals`. Then the badge weakens, and INV-47 removes the finding from a third-party report even though a qualifying isolated record exists.

Proposed: status keeps "latest", which is historical and simple. Each presentation (badge, a report for an audience) selects the strongest true record that qualifies for it and shows the latest beside it when they differ.

**Git-Diff.**

```diff
--- a/notes/plan.md
+++ b/notes/plan.md
@@ -406,1 +406,3 @@
 A record's result is `true` when its profile's round rule (§5.3) is met: every round for the controlled profile, at least two of the declared rounds for the intermittent one. The integrity check comes first so that no disposition can hide a broken chain.
+
+A badge, or a report for a given audience, presents the strongest true record that qualifies for it: isolated over shared custody, then `separate_principals` or `clean_instance` over the rest. When that record is not r, both are shown. INV-47 is checked against the record presented.
@@ -575,1 +577,1 @@
-Ships in M2. A second oracle is what proves the template and observer interfaces before anything is generalized.
+Ships in M2. A second oracle on the same observer proves the template interface. It does not prove the observer interface: the canary observer stays concrete code through M2, and the out-of-band observer (M3.4) is the first test of an observer abstraction.
```

---

### [Medium impact, low effort] Change 11: Give the deferred "objects the run did not create" mode a design: operator-seeded, hash-only canaries

**Current state.** `plan.later.md` §5 defers "Verification on objects the run did not create" because "reading an operator-named value has no freshness control". §1.2 says that "a read-only engagement produces leads and no verified findings". Owner call #3 in §16.9 accepts this for v1.

**Proposed design for the trigger** (not for v1). It follows XBOW's canary pattern [R35c]:

- At engagement start, the operator writes a fresh canary into an object owned by a **verifier-only** account. That account is outside the worker boundary, so tampering through the account is closed. The canary can also go into an admin-only object, which opens vertical privilege checks with no create route.
- Gauntlet records only the canary's SHA-256 and a commitment time. The worker never sees the value.
- The verifier matches by hashing each 32-hex-character token in a decoded body, so the canary is recognized without being disclosed.
- Freshness is bounded by the commitment time, not by the run. The record says so, and the badge reads `operator-seeded`. Cleanup deletes nothing, because the run created nothing (INV-40 holds).

**Rationale.** Read-only production engagements are common. This design reuses the canary observer and keeps D3 (the verifier still acquires the observation), and it is a known industrial pattern. Recording it now keeps the deferred item from being reinvented later with weaker controls.

**Git-Diff.**

```diff
--- a/notes/plan.later.md
+++ b/notes/plan.later.md
@@ -198,1 +198,1 @@
-| Verification on objects the run did not create | Writing into an existing object needs restoration, and reading an operator-named value has no freshness control. Deleting either on cleanup would destroy data. | A read-only engagement with real demand. Each mode ships with its own freshness, ownership, restoration and disclosure fixtures. |
+| Verification on objects the run did not create | Writing into an existing object needs restoration, and reading an operator-named value has no freshness control. Deleting either on cleanup would destroy data. | A read-only engagement with real demand. Starting design, after XBOW's canaries ([`plan.research.md`](plan.research.md) [R35c]): the operator seeds a fresh canary in an object of a verifier-only account (or an admin-only object for vertical checks) and gives Gauntlet only its SHA-256 and a commitment time; the verifier matches by hashing 32-hex tokens in decoded bodies; freshness is bounded by the commitment time and shown as `operator-seeded`; cleanup deletes nothing. Each mode ships with its own freshness, ownership, restoration and disclosure fixtures. |
```

---

## Summary priority matrix

| # | Change | Impact | Effort | Touches |
|---|---|---|---|---|
| 1 | Teapot's findings are leads; redraw ownership; M3 consumes Teapot | High | Low–medium | §2.1–§2.3, §8.1, §8.3, §8.9, INV-48, F-48, M0.1, M0.7, E§2, later §1 |
| 2 | Verifier credentials and instrument edits | High | Low | §3.4, §7.2, §8.5, INV-49, F-49, E§8 |
| 3 | A fixture that can run both oracles | High | Low | §2.2, M0.2, §4.6 |
| 4 | Investigation's milestones B and C off the critical path | High | Low | §9.2, §12.1, M1.6, M2.5, §15.2 |
| 5 | Premise test and M0 decision rule | High | Low | §12.1, E§4, research §2 |
| 6 | Fixture factory work package and sources | High | High | M1.10, M2.10, E§5 |
| 7 | Precedent correction and prior art | Medium | Low | §6.4, research §3, §5, §9 |
| 8 | Operator setup: draft, check, gate | Medium | Medium | §4.6, §8.3, E§7 |
| 9 | Honest retest miss probability | Medium | Low | §6.8, F-46 |
| 10 | Observer interface claim; record selection | Low–medium | Low | §5.1, §6.6 |
| 11 | Operator-seeded, hash-only canaries (design for a deferred item) | Medium | Low | later §5 |

Apply 1 to 5 before M0.1 starts. They change what M0.1, M0.2 and M0.5 must establish. Changes 6 and 8 can be adopted at M0.7. Changes 9 to 11 are edits to the specification text.

## What this review did not verify

- Whether Teapot's match-and-replace rules, intercept or Lua hooks actually apply to `requests send`, and whether stored flows hold bytes before or after an edit. The replay path visibly applies the session stage (`crates/teapot-engine/src/replay/mod.rs:715–720`). The rest was not traced. Change 2 makes this an M0.1 question.
- AuthProbe's full text. Only the abstract was read.
- The current count of RealWorld implementations on CodebaseShow. The figure "over 100" is from the project's README.
- Whether any candidate open-source application for one-check mutations has the routes oracle 1 needs. M1.10 must confirm per application.

## Sources consulted (2026-11-22)

- Atlidakis, Godefroid, Polishchuk. [Checking Security Properties of Cloud Service REST APIs](https://patricegodefroid.github.io/public_psfiles/icst2020.pdf), ICST 2020. Full text read via `pdftotext`.
- Palo Alto Networks Unit 42. [Automated BOLA Detection and AI](https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/), 2024-08-12.
- [AuthProbe: Specification-Driven, Multi-Identity Detection of Broken Object-Level Authorization in Recruitment API](https://arxiv.org/abs/2607.20574). Abstract only.
- Semgrep. [Can LLMs Detect IDORs? Understanding the Boundaries of AI Reasoning](https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning), 2025-11-03.
- XBOW. [Vulnerability classification](https://docs.xbow.com/console/reference/vulnerability-classification) (labels re-confirmed: CWE-639 and CWE-863 "AI agent", CWE-862 "Deterministic") and [Validate with canaries](https://docs.xbow.com/console/how-to/validate-with-canaries).
- [gothinkster/realworld](https://github.com/gothinkster/realworld) README.
- Searched and not used: [Barabanov et al., arXiv 2201.10833](https://arxiv.org/pdf/2201.10833) (spec-derived IDOR attack groups, 2022); [Invicti on BOLA detection](https://www.invicti.com/blog/web-security/how-to-detect-bola-api-vulnerability); [Escape's agentic pentesting benchmark](https://escape.tech/blog/benchmarking-agentic-ai-pentesting-tools/).
