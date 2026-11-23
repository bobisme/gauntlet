# Custody topology and target isolation

**Status** · Selected for implementation in M0.5. The local spike used
pinned tools and an unenforced fixture.

## Problem

The custody label says whether the worker could alter what the verifier saw
or recorded. Keeping the verifier's files private still leaves the target's
state in play. A worker who shares the verifier's owner account can change
that account's sharing settings before the verifier creates a fresh object.
The instrument also holds sessions and flows and can change traffic.
[Plan §3.4](../../notes/plan.md#34-custody-tiers)

## Decision

Use a confined worker and two Teapot projects for isolated custody. The
tested worker is a read-only rootless container with no network and no
capabilities. It uses its exploration accounts through a Unix socket
mounted read-only. A referee-owned relay forwards that socket to the
exploration project's proxy. The broker may expose read-only queries over
the worker's own flows only. M0.5 exercised proxy exploration and left the
broker for M2.4. [Candidate topology](../candidate-topology.md)

The verifier uses named sessions and direct `requests send` in the second
project, outside the worker boundary. That project holds verifier sessions
and original flows, which can contain credentials. The fixture issued
private verifier passwords kept in the referee's private package. The
worker has no instrument control socket or verifier flow access, and the
pass ledger and fixture administration stay outside its boundary. Both
projects used the same physical pass in the spike. Proxy traffic succeeded
with zero project requests handed and zero drawn, which leaves the
exploration request ceiling and pass-wide request count unestablished.
[Candidate topology and accounting](../candidate-topology.md)

The verifier must record the edit surface at run start and end, refuse a
run with `INSTRUMENT_EDITS_ACTIVE` if a rule, intercept or hook could alter
it, and account for any login or retry as a flow of the step. The tested
edits left direct sends intact at the pinned Teapot version. The ordinary
session experiment saw one login after expiration, then one retry for GET.
The POST was sent once. That evidence covers the exercised commands and
configurations. [Plan §7.2](../../notes/plan.md#72-the-instrument-contract)
[Teapot channel observations](../teapot-channel-contracts.md)

## Target isolation

| Configuration | Record `target_isolation` | What supports the label |
|---|---|---|
| Isolated custody, private equivalent-role accounts (`isolated_separate`) | `separate_principals` | The worker has never held and cannot use the verifier accounts, credentials, sessions or flows. |
| Isolated custody, a target reset to known state before the run through a worker-inaccessible route | `clean_instance` | Requires a separately qualified reset and boundary. M0.5 did not qualify this configuration. |
| Shared custody, distinct accounts (`shared_unconfined`) | `separate_principals_unconfined` | The accounts differ, and the same-user worker can access the verifier project. |
| Shared accounts (`isolated_shared` or shared custody with the same accounts) | `shared_principals` | The worker can change account-level state before the run. |

Scored evaluations and the red-team track require isolated custody with
`separate_principals` or `clean_instance`. Cross-account target state,
such as a tenant-wide sharing default, remains a limit even with separate
principals. [Plan §3.4](../../notes/plan.md#34-custody-tiers)

## Evidence and limits

The M0.5.3 outcome table records eight refusals with isolated custody and
separate principals, seven refusals with isolated custody and shared
principals, and eight successes with shared custody. Three cases used
stand-ins for future Scourge components. The result covers the eight fixed
attempts, one host and the recorded pins. The host and other same-user host
processes remain trusted. [M0.5.3 outcome table](../tamper-matrix.md#attempt-by-configuration)
[Machine-readable observation](../../fixtures/contracts/tamper-matrix-observed.json)

Retain the exploration traffic hold during runs with isolated custody and
shared principals. The hold blocked the measured sharing-state change
during a run. Earlier sharing changes persisted, and an unconfined worker
can bypass the relay. The isolated separate-principal configuration refused
the same attempt with or without the hold.
[M0.5.3 hold experiment](../tamper-matrix.md#attempt-06-the-hold-experiment)

Record the local fixture as `unenforced`. The non-loopback topology failed
to deliver an approved request, and nested enforcement in the offline
topology failed to start. Playpen `bn-vcn` tracks the upstream blocker and
reproduction. Refuse a run when the engagement's required custody or egress
enforcement is unavailable. [Enforcement spike](../enforced-local-topology.md)

## Revisit trigger

Repeat the affected qualification when the worker mounts, relay, broker,
target account or reset semantics, or pinned host and instrument stack
change. Revisit the enforcement label when a pinned topology delivers an
approved request and demonstrates denial outside the pass under enforcement.
