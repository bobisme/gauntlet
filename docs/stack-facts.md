# Stack fact checks (M0.1.2)

Rows are in plan order; verdicts are scoped to the cited snapshots and observations. No external systems were contacted. Source line references
are to Git objects, not the changing working trees. Read, for example,
`git -C /home/bob/src/teapot show 6238d5a:vendor/hallpass/src/ledger.rs | nl -ba`.

Pins from `inventory.json`: T = Teapot `6238d5a78a6514466d54ad16dd5737f43c1d4961`;
H = Hallpass `44f749ac158e8378705bab80d855ed0a1f634a54`; P = Playpen
`32677f2dde4449d578f9a5bf3417f442c252c7a4`; S = Sippycup
`26e6391da9362615987c355ba48cffbacaf2fec3`; E = Edict
`3f882a4d70bb948e059a2458c2d5047072e1cbf0`; B = Bones
`86de2f863a238399b96d3c1392a4705bd433e3aa`; I = Investigation
`a7a5cb144945248f6652cc46fc6bf1a5ef7d4257`. Checkout HEADs have
moved since the inventory; these are deliberately the inventory pins. The
local binaries report Teapot 0.1.0, Hallpass 0.2.0, Playpen 0.1.0 via
`mise exec -- <name> --version`, but their commit identities are unknown.
Thus runtime observations below are not attributed to these source pins.

| §2.2 row | Verdict | Evidence |
|---|---|---|
| Teapot, no teacup | Confirmed | T `crates/teapot/Cargo.toml:2,10` names the workbench and executable. `command -v teacup` returns no path; the statement concerns this local stack. |
| Investigation tracker | Changed | I `notes/plan.md:1926,1929-1930,1941-1945` places W07, W10, W11 and the gate. I `.bones/events/2026-11.events` has 314 creates, six deletes and no state-transition events; W07 (bn-1y1), W10 (bn-3kh), W11 (bn-65s) have size XL. The previously observed 29 done was a live working-tree observation recorded in `notes/plan.research.md §7`, not reproduced by this committed snapshot. Affects §2.2 and §9.2 readiness. |
| Block spending and sequence | **Wrong** | T `crates/teapot-engine/src/allocator/mod.rs:3-8,41-49` describes block spends and no refunds; `vendor/hallpass/src/ledger.rs:80-91` lacks caller ref, but **lines 96-110 define `SpendOutcome.seq: Option<u64>`**. `crates/teapot-engine/src/allocator/spender.rs:18-38` returns that type; `allocator/mod.rs:486-509` constructs the request without caller reference and credits the block using spent and total, discarding the returned sequence. The plan claim that no API type carries a ledger sequence is wrong. This does not prove Teapot exposes or associates the sequence with each request. `units_left` and `within_ceiling`: T `crates/teapot-api/src/commands/authz_compare.rs:255-259`. Affects §2.2 and §7.4. |
| Send without flow, aggregate counter | Confirmed, source | T `crates/teapot-api/src/commands/flows_replay.rs:161`; `crates/teapot-engine/src/pipeline/capture.rs:18-22`; `crates/teapot-engine/src/allocator/mod.rs:356-368`. |
| Three Hallpass copies | Confirmed, source | H checkout pin above; P `Cargo.toml:19` pins `05d657aaa214c42db2c4807e965e29080b76c43b`; T `Cargo.toml:40-42` vendors Hallpass. Compatibility is a separate test. |
| Playpen egress | Confirmed, source | P `docs/spec.md:183-191,745-748` covers loopback, ceilings and name restrictions; `docs/DESIGN.md:350-358` explains the limit. |
| Teapot enforcement and fixture | Confirmed, source | T `crates/teapot-api/src/commands/pass.rs:226-234,376-383`; `crates/teapot-testbed/src/main.rs:1-3,81-88`. |
| Same-account custody | Confirmed, source | H `docs/INTEGRATING.md:584-587` excludes protection from the operator account; P `docs/DESIGN.md:500-505,526-530` excludes file confinement and identifies same-user access; Vessel at `f0ccd685a9bd084289d42a1eda8c7e44223f037a` `README.md:3,50,242` is a same-user PTY and socket runtime. None supplies the required custody boundary. |
| Identity check | Confirmed, source | T `crates/teapot-api/src/commands/sessions_check.rs:1-18,57-59` defines the three states; `commands/mod.rs:207-219` registers the session commands without a who-am-I. `mise exec -- teapot sessions --help` lists capture, check, create, list, remove, resume, set, show and use; binary commit unknown. |
| Testbed | Confirmed, source | T `crates/teapot-testbed/src/endpoints/app/planted.rs:1-26,36-90,143-144,149-215,738-752` specifies the contract, fixed order fields, read-only order route, checkout, item validation, controls and act/drop; `router.rs:28-32,360,434` registers groups and reset; `auth.rs:30` gives /me and `active.rs:47-48,78-79` gives scanner fixtures and fix switch. |
| Receipt | Confirmed, source | H `docs/EVIDENCE.md:7-22` describes caller reference, found/absent/ambiguous. T `vendor/hallpass/src/ledger.rs:80-91` has no reference in the vendored request type, and `crates/teapot-engine/src/allocator/mod.rs:486-492` constructs it without one. |
| Sippycup | Confirmed, source | S `lib/sippycup/approval.py:1-15`, `lib/sippycup/call_ledger.py:1-25`, `config/commands.tsv:5,26`, `lib/sippycup_oracle/cli.py:414` show approval, reserve/release, go, offline assert and three outcomes. `git grep -n -i hallpass 26e6391 -- lib config` returns no integration matches. |
| Edict evals | Confirmed, source | E `evals/README.md:1-27,40-55,65-71,131-133,137-163` documents scoring, terse prompt, real Claude session, scripted self-test, live hooks and the safety gate. |
| CLI conventions | **Changed** | B `.agents/edict/design/cli-conventions.md:30-36,51-60,96-104` calls for a hidden alias, FORMAT, pipe text and advice. `mise exec -- teapot sessions --help` prints `--json` in Global options. T `crates/teapot/src/globals.rs:98-106` and `crates/teapot/tests/cli/snapshots/cli__front_end__root_help.snap:60` show the visible alias at the source pin too. Binary commit is unknown. I `notes/plan.md:1091-1099` specifies the listed exit codes. Affects §8.4. |
| PATH | Confirmed, runtime | Unmodified `command -v bn edict vessel rite ward teapot hallpass playpen sippycup investigation` printed the first five paths only. Project `mise exec` supplies the first three instruments; PATH changes with the environment. |
| Findings and leads | Confirmed, source | T `crates/teapot-core/src/findings.rs:159-167`, `crates/teapot-api/src/commands/findings_repro.rs:24-40,100-101`, `commands/mod.rs:246-261`, `commands/findings_export.rs:3`, `commands/guide.rs:857`; `mise exec -- teapot guide findings` prints “Read, verify and report findings” and the four repro outcomes. |
| Proxy stages, send and sessions | Confirmed, source | T `crates/teapot-engine/src/pipeline/installed.rs:4-6,27-34`, `replay/mod.rs:1-6,59-68`, `commands/requests.rs:525-541`, `sessions/mod.rs:1-13,218-225`, `teapot-store/sql/v6_m4.sql:18,74-103`. An opt-in job retry of unknown-outcome GET/HEAD exists at `sessions/mod.rs:218-266`; this does not itself establish that ordinary `requests send` opts in. Runtime isolation tests remain a separate M0.1 contract task. |
| Sitemap, params, matrix, OOB | Confirmed, source | T `crates/teapot-api/src/commands/sitemap.rs:91`, `params.rs:79`, `authz_matrix.rs:91`; `notes/plan.md:206,648` plans OOB under M7. |

The source-only checks are scoped to the named commits. A documented API or
plan does not establish actual network behavior; dependent contract tests still
need to run. Runtime executable identities and source pins remain separate; no runtime behavior is attributed to a source commit without provenance.
