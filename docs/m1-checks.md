# M1 checks and qualification

Run `just check` on each change. A fresh checkout needs the project's Rust and
C toolchains, Just, Bash, Python, the Bones CLI (`bn`) and the locked Cargo
dependencies. The frozen M1 tracker check reads the Bones projection through
that CLI. The fast suite uses local disposable files and sockets. The Linux
read guard uses seccomp.

`just test` runs all workspace targets and doctests, the evidence fixture
self-test and the shell-workflow witness.

| Check | Witness |
| --- | --- |
| Status and applicability histories | `generated_status_histories` in `scourge-core`, plus the retained-original, policy, version and snapshot tests |
| Request keys, storage and chain publication | `scourge-core` store and request tests, `publication_boundary`, and `f20_two_concurrent_reconciliations_leave_one_record_head_and_receipt` |
| Read-only surface | `read_process` guards bound `show`, `list` and `doctor` and unbound entry, `status` and `help` against network, subprocess and watched-file access on Linux. `lead_process` uses a Unix socket sink and an instrument sentinel for intake and planning. `entry_process` checks bound status, capability use, selection and generated `next` argv. |
| Generated examples | `generated_help_examples_run_against_passive_local_rows` runs passive help examples and rejects unfamiliar argv. `documentation_process` checks the README walkthrough and managed guide. `oracle-guide-example-check` executes the guide shell workflow against exact argv and reply fixtures, including the read-only plan and full-depth view. |
| Oracle properties and guide | `scourge-verify` integration targets `properties`, `contract`, `por_checks`, `scope` and the saved-observation tests. The core POR mutation suite requires every frozen check to have a killing witness. |
| Parser corpora | `scourge-parser-fuzz` tests replay the corpus, target routing and mutation witnesses. Run the same subset with `just parser-corpus-check`. The bounded coverage-guided runs use `just fuzz-parsers TARGET SECONDS` and have their own [session records](fuzzing.md). |
| Frozen contracts | `just check` adds `schema-check`, `cross-lane-check` including the Teapot argv captures, `oracle-spec-check`, `investigation-conformance-check`, and `m1-recut-check` including the full 55 KEEP, 0 CUT, 0 SPLIT projection. |

## Native runners

Run on Linux with local TCP loopback, Unix sockets, cached locked Cargo
dependencies, Bash and `jq` in `/usr/bin:/bin`. Use a short `TMPDIR` such as
`/tmp` for instrument socket paths.

```sh
just m1-qualification-check /path/to/oracle-teapot /path/to/request-reference-teapot /path/to/investigation
```

Before starting a lane, the runner copies each opened executable into a
private temporary directory and verifies the copied bytes against the
committed SHA-256. Every native command uses the admitted copies. The first
Teapot uses the M0.1 inventory checkout source and the
[historical contract manifest](../fixtures/contracts/manifest.json).
The second uses the [request-reference manifest](../fixtures/contracts/request-reference-manifest.json).
Investigation uses the [M0.6 conformance record](../fixtures/contracts/evidence/investigation-conformance.json).
The [historical inventory](inventory.json) records an installed Teapot digest
for the original snapshot. The reproducible contract build from its source
checkout is the binary used by native qualification.

| Lane | Runner and witness |
| --- | --- |
| Historical Teapot | `just instrument-contract-check ORACLE_TEAPOT INVESTIGATION` runs `scripts/teapot-contracts.py` in check mode for inventory, schemas and captured operations, and the historical native `teapot_invocation` cases for adapter argv, accounting and the verifier gate. |
| Investigation | The same instrument command uses `fixtures/contracts/evidence/check-live.py` to run the frozen M0.6 cases with the public-interface adapter. It then runs the evidence bridge commands for acquisition, publication and the CLI read projection. The producer child is reached by its crash test. |
| Packaged fixture | `just fixture-check` builds and launches the local fixture and checks its public engagement. |
| Live first oracle | `just oracle-fixture-check ORACLE_TEAPOT INVESTIGATION` runs the 25 development cases. The aggregate also selects the historical Teapot round-transport test. |
| Reference preflight and recovery | The aggregate selects the `teapot_invocation` pinned live preflight case with request-reference Teapot and Investigation. `just recovery-fixture-check REFERENCE_TEAPOT INVESTIGATION` runs the lost-response fixture and its companion unknown/refusal unit witness. |
| Native examples | `just demo-check ORACLE_TEAPOT INVESTIGATION` executes the generated argv, guide and README against the owned local demo, plus the serial orphan-helper regression. |
| Native Codex boundary | `just native-codex-boundary-check OUTPUT` qualifies the two-socket rootless worker with offline process stubs, an exact effective environment, and bounded relay evidence. `just installed-codex-compatibility-check OUTPUT` separately runs the pinned installed Codex 0.172 binary through the auth-free provider and a deterministic client `exec_command` round trip behind the exact static supervisor, proves `shell_snapshot` is disabled, exercises both fixed loopback-to-Unix routes, and emits the supervised production collector argv (`--rm --unsetenv-all --interactive`). It also fails closed on dead routes, broken stdin, ignored TERM, external signals, and missing crash receipts; a real direct-child TERM probe and bounded test of the production timeout helper require truthful SIGKILL accounting. Both use `--network=none` and fake upstreams; neither contacts a provider. |

An unavailable prerequisite stops qualification with a nonzero status and a
reason. Each Rust test command must report the expected test IDs and a single
complete passing summary with zero ignored tests. Each other command must
end with its exact completion marker and emit it once. The Investigation
public-interface wrapper emits its marker after all 12 frozen cases pass
with zero skips. Each lane reports its result and a failed lane fails the
aggregate. Requalify a change to any executable pin with the aggregate
before accepting the replacement.
Keep the runner output with the change evidence and identify the Scourge
revision and instrument bytes.
The ordinary fast lane reports native and milestone checks as excluded. Rust
lists its ignored tests and executes subprocess-only helpers through their
parent tests.

## Retained proof obligations

These routes follow the [M0 KEEP disposition](adr/baseline-taxonomy-decision.md#proof-obligations)
and the [functional gates](../notes/plan.evaluation.md#13-automated-functional-gates).

| Obligation | M1 witness | Later gate |
| --- | --- | --- |
| Claim | Template and scope tests, `lead_process`, `oracle-fixture-check` F-38 and F-39 | Second oracle in M2.1 |
| Target | `teapot_invocation` engine mismatch and `oracle-fixture-check` bound round | Isolated target qualification in M2.4 |
| Capability | `por_checks`, `oracle-fixture-check` F-01 and F-07 | Isolated target qualification in M2.4 |
| Policy | `engagement_policy` and `status_policy_admission_and_version_are_computed_without_a_new_run` for F-04, and `oracle-fixture-check` F-02 | Broker admission controls in M2.4 |
| Setup | Template tests, `lead_process`, `oracle-fixture-check` F-38 and F-39 | Operator draft workflow in M1.11 |
| Observation | Record and saved-observation tests, `evidence-bridge-check`, `oracle-fixture-check` F-09 to F-11 | Bundle checks in M2.5 |
| Causality | `por_checks`, `properties`, and the POR mutant witnesses | Second-oracle controls in M2.1 |
| Oracle | Registry and `contract` tests, status properties and F-21 | Second oracle in M2.1 |
| Reproduction | `mixed_rounds_are_retained_as_intermittent_not_a_false_verdict` and the live repeatability cases | Intermittent profile and retest in M2.1 and M2.2 |
| Freshness | `generated_status_histories`, `coordination_commit_during_evidence_read_is_observed_or_historical` | Fix applicability and report snapshots in M2.2 and M2.5 |
| Disclosure | Round cleanup, status properties, and native accounting and recovery | Engagement closure, enforced custody and complete accounting in M2.3, M2.4 and M2.7 |

## Retained invariants

| Plan IDs | Shipped evidence | Remaining gate |
| --- | --- | --- |
| INV-01, INV-02, INV-06, INV-28, INV-29 | CLI/catalog, store schema, chain and status properties. F-20 to F-22 below. | M2.10 red-team public path |
| INV-03, INV-07, INV-08, INV-09, INV-20, INV-36, INV-37 | Template, POR and mutation tests, plus `oracle-fixture-check` | M2.1 second-oracle cases |
| INV-04, INV-05, INV-35, INV-42, INV-47, INV-50 | Retained-original integrity, badge and audience projection tests exercise the shipped record/read path | M2.5 report snapshots and bundle checks, with M2.6 objection commands |
| INV-10, INV-11, INV-51 | Policy and status properties cover the admitted-policy and snapshot primitives | M2.2 retest and M2.6 disposition commands |
| INV-12, INV-13, INV-14, INV-18, INV-25, INV-41 | Request-key/store boundary, lease, concurrency and recovery regressions, plus `recovery-fixture-check` | M2.3 complete native crash matrix and M2.7 live shared-pass serialization |
| INV-15, INV-21, INV-30, INV-31, INV-32, INV-33, INV-34, INV-43, INV-46 | Entry, read, response, workspace and lead process suites, CLI catalog lint and `demo-check` | M1.9 cold-worker argv, M2.4 setup and verification of M2 read commands as they ship |
| INV-16, INV-17, INV-49 | Scripted and pinned Teapot invocation, accounting, edit and preflight tests | M2.4 isolated broker and M2.7 live enforced authority |
| INV-19, INV-40 | Round execution and record cleanup tests, and `recovery-fixture-check` | M2.3 live cleanup, pre-existing object and engagement closure |
| INV-22, INV-23, INV-24 | Passive CLI redaction, untrusted input and synthetic refusal checks | M2.5 seeded-secret outward surfaces and M2.8 adversarial-input/refusal qualification |
| INV-26 | Process-kill regression in store and recovery suites | M2.9 storage-fault and power-loss profile |
| INV-27 | `evidence-bridge-check` and the Investigation contract | M2.5 bundle evidence handling |
| INV-38 | M0 `tamper-matrix-check` reads the recorded custody result | M2.4 isolated custody and M2.10 scored harness preflight |
| INV-39 | Operator policy/template tests | M2.4 broker refuses worker admissions |
| INV-44 | Canonical JSON parser, contract tests and corpus replay | |
| INV-45 | Schema and authority unit tests | M2.7 live changed, expired and revoked pass |
| INV-48 | Teapot finding import and local projection in `lead_process` | M2.5 report treatment |

## Retained fixtures

| Plan IDs | Shipped evidence | Remaining gate |
| --- | --- | --- |
| F-01, F-02, F-03, F-04, F-05, F-06, F-07, F-08, F-09, F-10, F-11, F-14, F-36, F-37, F-38, F-39, F-42 | `oracle-fixture-check` and the fast oracle, template and lead-process tests | M1.9 cold decoys, supplied-lead F-37 and class-scope checks |
| F-12 | Request tests, sent-without-flow and typed-refusal unit witness, `recovery-fixture-check` | M2.3 full native crash matrix |
| F-13, F-44 | Teapot accounting and preserved native reply tests | M2.3 failure effects and M2.7 real-backend accounting and outside spender |
| F-15, F-16, F-17, F-18, F-19, F-46, F-47, F-52, F-53 | Fast status and per-field oracle tests cover the primitives | M2.2 live fix checks, retest integrity and supersession |
| F-20, F-21, F-22 | F-20 publication intent and concurrent reconciliation tests plus status properties | |
| F-23, F-24, F-43, F-45, F-50 | Retained-original integrity and snapshot/status properties | M2.2 fix applicability, M2.5 report and offline bundle checks, M2.6 objections |
| F-25 | Same-basis admitted policy tests | M2.6 refutation trio |
| F-26 | Pinned native verifier gate and scripted refusals | M2.7 real-backend enforcement |
| F-27 | Round ownership/cleanup unit tests and lost-response fixture | M2.3 live cleanup and prior-object preservation cases |
| F-28 | `read_process` Linux guard, workspace binding and process fixtures | |
| F-29, F-30, F-31 | Passive workspace, inert data and response tests | M2.6 objection retention and M2.8 hostile configuration and model-refusal scoring |
| F-32, F-40, F-49 | `tamper-matrix-check` for M0 observations, plus the native edit-surface and preflight checks | M2.4 broker and eight attempts against qualified isolated custody |
| F-33, F-34, F-35 | Evaluation harness self-test via `just eval-check` | M2.10 scored trials and referee adjudication |
| F-41 | Frozen state-change contract in `oracle-spec-check` | M2.1 live second-oracle qualification |
| F-48 | Teapot intake regression in `lead_process` | M2.5 report treatment |
| F-51 | Engagement and property schema and policy tests | M1.11 operator check/draft workflow |

M1.9 owns the cold-agent trials and M0-ADD-01, M0-ADD-02 and M0-ADD-04. Its generated
transport and typed failure have fast process witnesses (M0-ADD-01). Its
interrupted nested capture and invalid-trial adjudication remain M1.9 and
M2.10 gates (M0-ADD-02). The shipped object-read class boundary has fast scope and
guide checks and native decoys (M0-ADD-03). The development oracle fixture
exercises the owner-primed cache case. The scripted cold-trial route with a
supplied lead and separately counted discovery remain in M1.9 (M0-ADD-04).
M1.10 Tier 1 fixture authoring and M1.11 operator draft qualification are
independent of the M1 exit gate.
