# Rust dependency contract

M0 freezes exact direct crate versions in the root `Cargo.toml`. Workspace
members inherit those versions and select only the features they use. The
lockfile still freezes the transitive graph; `scripts/check-dependency-pins.py`
prevents a member from bypassing the workspace contract.
Cargo's `unused_workspace_dependencies` lint is temporarily allowed because ten
product pins intentionally precede their M1 crates; the pin validator owns that
exact external set and fails on additions, removals or non-exact versions.
Future local path dependencies are accepted only when they point to declared
workspace members, and members must inherit both local and external dependencies
through the workspace table.

| Job | Choice | Why this pin |
| --- | --- | --- |
| CLI | `clap 4.6.8` | Derive-based command definitions and machine-readable argument handling; the same release is used by pinned Teapot and Hallpass. |
| Serialization | `serde 1.0.229`, `serde_json 1.0.154` | Matches pinned Teapot and Hallpass. Wire compatibility with Investigation is its versioned JSON contract, not a shared Rust type. |
| Stored HTTP bodies | `base64 0.22.1` | The same pinned release as the Investigation excerpt decoder: stored Teapot body windows are decoded from padded base64 without turning retained bytes into text. |
| JSON Schema | `schemars 1.2.3` | Matches pinned Teapot and Investigation and keeps schemas generated from the serializable types. |
| Coordination store | `rusqlite 0.43.0` | Matches pinned Teapot and Investigation. `bundled` fixes the SQLite implementation; `backup` and `cache` cover consistent backup and prepared statements. WAL, foreign-key and durability settings remain application obligations. |
| SHA-256 | `sha2 0.11.1` | The plan requires SHA-256 for immutable bytes; this matches pinned Teapot and Hallpass. Investigation's older implementation remains behind JSON. |
| Binary evidence | `base64 0.22.1` | Decodes the pinned Investigation CLI's padded RFC 4648 excerpts without changing retained bytes. |
| Process I/O | `tokio 1.54.1` | The fixture already uses it; Scourge adapters can add `process`, `io-util` and `time` features and use Tokio's cancellation APIs without inventing a subprocess framework. |
| Durable local filesystem | `rustix 1.1.6` | Exact Linux file/process operations for later fsync and process-boundary work; matches the sibling tools' selected release. |
| IDs | `uuid 1.29.3` | Existing fixture v4 IDs and later time-ordered run IDs can share one maintained crate; each member enables only `v4` or `v7` as needed. |
| Time and TOML | `time 0.3.55`, `toml 1.2.1` | Match pinned Teapot and Hallpass for approval windows and operator-authored configuration. |
| Declaration validation | `regex 1.12.3`, `serde_path_to_error 0.1.20`, `toml_parser 1.1.6` | Enforce the frozen prose restrictions and locate malformed stanzas without including input values in diagnostics. The TOML diagnostics reuse the grammar parser already selected by `toml`. |
| Errors and events | `thiserror 2.0.21`, `tracing 0.1.44`, `tracing-subscriber 0.3.23` | Typed library errors plus local structured JSON events, matching Teapot's approach and requiring no telemetry service. |
| Temporary files | `tempfile 3.27.0` | Provides private subprocess staging and supports isolated filesystem tests. |
| Fixture HTTP | `axum 0.8.9`, `tower 0.5.3`, `http-body-util 0.1.5`, `futures-util 0.3.34`, `flate2 1.1.11` | Exact versions resolved by the development fixture, including stream errors and compressed response modes. |

The sibling-source comparison uses the frozen Scourge pins: Teapot
`6238d5a78a6514466d54ad16dd5737f43c1d4961`, Hallpass
`44f749ac158e8378705bab80d855ed0a1f634a54`, and Investigation
`a7a5cb144945248f6652cc46fc6bf1a5ef7d4257`. The M0.6 conformance run
pins the shipped Investigation 0.1.0 source at
`6a0c5ed843d0f4870910d3a926298890290c916e`. The fixture uses the
versioned JSON CLI with no checkout-relative Rust dependency. The
[evidence contract ADR](adr/evidence-contract.md) records the tested API,
conformance result and requalification triggers.

## Supply-chain check

`just audit` runs the mise-pinned cargo-deny 0.20.2 in offline/locked mode for
RustSec, the license allow-list and source policy. This is deliberately a
separate operator gate: `just check` remains reproducible without an advisory
database. The M0 check used cargo-deny's locally cached RustSec database and did
not claim it was freshly fetched. A release check must refresh that database
under an explicitly network-enabled workflow.

On 2026-11-23, an isolated temporary manifest resolved all selected future
dependencies to a 112-package lock using Cargo `--offline`. Cargo-deny passed
advisories, licenses and sources using its cached RustSec commit
`55e1c3dfbd834237a05bbbf7b50ba3b5be27b662` (2026-11-21). That database
snapshot was not refreshed by the check and is not release qualification; the
result is an M0 compatibility/license check, not a current release audit.

The allow-list is MIT, Apache-2.0 (including the LLVM exception), BSD-3-Clause,
Unicode-3.0 and Zlib. Private unpublished workspace packages are ignored;
registry and Git sources fail closed outside crates.io, and no Git source is
allowed.
