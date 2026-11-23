# Engagement schema

**Status** · M0.7.1 freeze for the versioned engagement declaration. The
operational verifier input contract remains open. This ADR replaces the earlier
M0.7.1 offline review subset; every constraint that subset encoded is retained
by the contract and by `just schema-check`.

## Problem

The engagement file is the largest setup cost and the thing every lead is
resolved against. Its shape in plan §4.6 is a proposal until the baseline and
the fixture have exercised it. [Plan §4.6](../../notes/plan.md#46-the-engagement-file)

§4.6 also writes request lines, response pointers, a plant macro name and a pass
path into the file. Those are dispatch inputs. A declaration that carries them
can be read as an executable instruction, and a reader cannot tell a reference
from a request. The schema therefore keeps every operational field inert.

## Decision

[`schemas/engagement.v1.schema.json`](../../schemas/engagement.v1.schema.json)
(`scourge.engagement.v1`) is the contract, and
[`fixtures/target/schema-examples/engagement.toml`](../../fixtures/target/schema-examples/engagement.toml)
is the development fixture's declaration. It covers engagement metadata, both
principals with an identity probe and an optional verifier session, and all
twelve fixture properties.

Every operational field is a registered reference with a typed namespace. The
file names no request, method, route, host, address, credential, payload or
command.

| Field | Registered reference |
| --- | --- |
| `engagement.pass` | `pass.*` |
| `engagement.instrument.project` | `project.*` |
| `engagement.target_version` | `version.*` |
| `principal.session`, `principal.verifier_session` | `session.*`, unique in the file |
| `principal.groups` | `group.*` |
| `principal.identity_probe.operation` | `operation.*` |
| `principal.identity_probe.subject` | `selector.*` |
| `property.resource` | `resource.*` |
| `property.read`, `property.remove` | `operation.*` |
| `property.write` | `operation.*` plus `selector.*` writable fields |
| `property.plant` | `operation.*` plus a `selector.*` ID source and `selector.*` canary fields |

`readers` and `writers` keep the four plan audiences `owner`, `group`,
`authenticated` and `public`. `writers` requires a `write` operation; a
declared write with no `writers` rule admits nothing, which is the §4.6 draft
state. `required_custody`, `required_enforcement`, `allow_effects`,
`max_verify_runs`, `retest_miss_threshold` and `audience` carry the limits of
plan §§4.6, 5.1, 7.8 and 6.8.

`engagement.target_version` is required for every schema-valid engagement.
Every admitted engagement-source policy rule names a `target_version` that the
local check must match against this declaration, so an engagement that declared
no version could never admit one of its own rules. Requiring the version for the
whole engagement keeps the cross-contract obligation at its source rather than
leaving a schema-valid but unadmittable shape.

## Guarantees and limits

Parsing is strict. UTF-8 is decoded with duplicate keys rejected before
validation, including nested keys and keys that become equal after decoding
escapes. Unknown versions, tables and fields are invalid. Explicit `null`,
non-finite numbers, booleans in integer fields, fractional integers and
malformed UTC timestamps are invalid. Every identifier is checked by its own
namespace and spelling, and prose is single-line, bounded and free of control
characters.

Shape conveys no authority. A declared property is not an admitted rule, which
is why the policy rule is a separate contract. Concrete registry IDs, their
request shapes, methods and the §6.2 safe-method rule for a lead-supplied read
belong to the trusted operation registry and the verifier; this file carries no
grammar for them. Pass contents, digest pinning and revocation belong to
Hallpass integration (§7.1, INV-45). The identity probe names a registered
operation, not a response shape, so its subject selector resolves in the
registry too.

## Evidence and revisit trigger

`just schema-check` validates the example against the schema, compares its
principals, property names and `readers`/`writers`/`policy` values against
[`fixtures/target/example/engagement.toml`](../../fixtures/target/example/engagement.toml),
and exercises missing fields, including an omitted `target_version`, invalid
references, reused session labels, executable-shaped content and unknown
versions. The recipe runs inside `just check`.

Reopen this contract when the operational verifier input contract freezes, when
the fixture gains or loses a resource route, or if M1.11's `engagement draft`
needs a field this file cannot express.
