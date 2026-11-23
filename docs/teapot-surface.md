# Teapot leads, findings and check surface

This is the source-backed M0.1.4 surface map. The complete machine-readable
record, including every check ID and its class or explicit unmapped reason, is
[`packs/teapot-surface.json`](../packs/teapot-surface.json). Validate it with
`python3 scripts/check-teapot-surface.py`; the script reads the pinned Git
object locally and does not use the working checkout HEAD or `.stack-target`.

## Pin and evidence

The map is for Teapot commit
`6238d5a78a6514466d54ad16dd5737f43c1d4961`, the full commit recorded in
`docs/inventory.json` and `fixtures/contracts/manifest.json`. Its tree is
`a5f74f8849165f9a0aac26881b2f7d95ac7f8b50`. The pack records SHA-256 for each
of the 25 source files used and an aggregate source digest
`a337ecfb2633aab76cd7faae6cdf07b813c298c3595e95ca7ab9b8c6312aff28`.
The local checkout may be dirty or at another HEAD; all source reads use
`git show <pin>:<path>`.

The command registry is `crates/teapot-api/src/commands/mod.rs:246-261`.
The leads API and fields are in `crates/teapot-api/src/commands/leads.rs:74-163`
(list) and `:224-315` (show); findings are in
`crates/teapot-api/src/commands/findings.rs:85-125,160-215,297-414`.
The stored finding model and fingerprint inputs are in
`crates/teapot-core/src/findings.rs:453-539`. `guide findings` is defined at
`crates/teapot-api/src/commands/guide.rs:855-908` and frozen in
`crates/teapot/tests/cli/snapshots/cli__snapshots__guide-findings.snap:5-38`.
The `authz.idor` behavior and evidence rules are documented at
`crates/teapot-engine/src/checks/authz.rs:1-79,109-110,525-570`; the registry
confirms it is the built-in active check at
`crates/teapot-engine/src/checks/mod.rs:66-71`.

## Commands

- `teapot leads list`, `teapot leads show <id>`, `teapot leads dismiss <id>`,
  and `teapot leads promote <id>`.
- `teapot findings list`, `teapot findings show <id|fingerprint>`,
  `teapot findings dismiss <id>`, `teapot findings fix <id>`,
  `teapot findings reopen <id>`, `teapot findings repro <id|fingerprint>`,
  and `teapot findings export`.

The JSON pack records the command flags and their roles: lead filters, state,
reason/scope and note; finding filters and pagination; reproduction output,
verify and session options; export format, filters, evidence bodies and
redaction. `leads list` ranks hints; a promoted lead becomes a tentative,
info-severity finding with source `lead` and its original flows.

## Finding fields and guide

The stored finding carries check ID, severity, confidence, source, endpoint
(shape key, scheme, host, port, method and path template), optional point,
title, description, remediation, check detail, optional group key and session,
and evidence rows (optional flow ID, role and redacted note). Its fingerprint
is derived from check ID, endpoint shape and optional point ID. The CLI's
`findings show` adds lifecycle data: state, seen/timestamps, jobs, dismissal
reason/time, person note, reproduction state/flow/note/verification, evidence
flow metadata and truncation indicators. These field groups and evidence
roles are enumerated in the JSON pack.

`teapot guide findings` teaches the operator to find evidence flows; list
findings grouped with severity counts; inspect one; dismiss with a reason;
fail a run on open high-or-worse findings; print and verify a reproduction
once; mark fixed after reviewing the change; reopen when closure was wrong;
and export redacted Markdown or SARIF.

## Class mapping

The pin contains **48 distinct check IDs**. Only `authz.idor` maps, to
`web-authz/private-object-read`: the built-in scan compares the recorded
owner's response with each other named session and anonymous access, requires
an authorization control to hold, and suppresses findings when anonymous
access establishes the endpoint is public. This is an observed cross-principal
read comparison; it is not inferred from the ID's name.

No check maps to `web-authz/forbidden-state-change`. In particular, the
passive CSRF check detects a missing form token but does not send a forged
action or observe a state transition. The remaining unmapped checks test
response/header/cookie/transport policy, reflected injection, exposed paths,
metadata, token shape or secret disclosure; they do not provide Scourge's
required protected-object/principal controls or a verified unauthorized
write. Every ID has its own explicit reason in the pack.
