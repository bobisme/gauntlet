# Native Codex worker boundary

`lib/native_codex_boundary.py` and `lib/responses_relay.py` are the reusable,
credential-free worker seam for the M1.9 native Codex cells. They do not run a
trial on their own. The harness remains the sole owner of preparation, launch,
capture, teardown, and `trial_capture` settlement.

The worker has no provider credential. Codex uses the custom provider
`scourge_responses_relay` at `http://127.0.0.1:18080/v1`, with
`wire_api = "responses"` and `requires_openai_auth = false`. Do not use
`codex-launch.py` for this lane. The existing
`baseline/worker/forward.js` always exposes worker loopback port 18080 and
forwards it to `/gateway/model.sock`. A real target-evaluation cell additionally
sets the prepared numeric `M0_PROXY_PORT` and provides `/gateway/proxy.sock`;
the model-only offline qualification deliberately omits both.

The host relay receives provider authentication only on inherited descriptor
3. It does not read an auth argument, environment variable, or file. Its
upstream is compiled to `https://api.openai.com:443/v1/responses`; worker Host,
Authorization, API-key, cookie, project, organization, and all other header
values are discarded. The relay sends a fixed Host, identity content encoding,
and its descriptor-owned Authorization header. It makes one TLS attempt per
accepted request, follows no redirect, and performs no retry.

Each worker request must be an unambiguous HTTP/1.1 `POST /v1/responses` with a
single Content-Length and a strict JSON object. The model, streaming mode,
non-storage mode, top-level field set, output-token ceiling, request-body
ceiling, response-body ceiling, request count, and cumulative byte budget are
host policy. Transfer encoding, upgrades, alternate routes, alternate models,
unknown body fields, duplicate request digests, and post-budget requests are
refused before upstream dispatch. A compressed upstream response is refused;
the relay never removes Content-Encoding and forwards compressed bytes as
identity.

Inbound count and cumulative body-byte admission happen before any record or
body artifact is retained. The first refusal poisons the relay and closes the
listener after its bounded response, so queued, serial, concurrent, malformed,
post-finalized, and post-budget floods cannot grow evidence or in-memory record
lists. Rejected bodies are charged but never stored or digested. A
credential-bearing body is charged at the full request ceiling so aggregate
accounting does not disclose its exact length. The receipt and accepted-body
artifacts have separate explicit caps; their exact current byte counts and file
count appear in `accounting`.

An explicit positive `max_output_tokens` must fit within the host ceiling. The
pinned Codex 0.172 client omits that field, so omission causes the relay to
inject the exact host ceiling into the provider copy. It does not permit an
unbounded provider default. The exact worker body and its digest remain the raw
request witness; the separately digested provider body records the injection.
Codex 0.172 also sends a fixed seven-field `client_metadata` object. The relay
accepts only that exact bounded string shape and strips it from the provider
copy so installation, window, thread, and turn identifiers do not leave the
host. Its 36-byte UUID `prompt_cache_key` is validated, then replaced with a
random relay scope plus the accepted-attempt sequence. Worker-controlled cache
identity therefore never reaches the provider or crosses attempts.

The required top-level shape is the exact installed 0.172 witness:
`client_metadata`, `include`, `input`, `model`, `parallel_tool_calls`,
`prompt_cache_key`, `reasoning`, `store`, `stream`, `text`, `tool_choice`, and
`tools`. Only `max_output_tokens` and the chain-bound `previous_response_id`
may additionally occur. `reasoning` must be exactly `{"effort":"high"}`,
`text` exactly `{"verbosity":"low"}`, parallel tool calls true, tool choice
`auto`, and include exactly the encrypted-reasoning value. Legacy `metadata`,
`instructions`, retention, safety-identifier, service-tier, and truncation
fields are refused.

Nested request policy admits the exact eight observed client tools using only
bounded `function` and `custom` definitions. Hosted tools (`web_search`,
`file_search`, `computer`, `code_interpreter`, `image_generation`, and MCP
variants), unknown future tool types, and hosted `tool_choice` values are
refused before dispatch. `include` may contain only the exact
`reasoning.encrypted_content` value. The first
accepted request may not carry `previous_response_id`; a later request that
does carry it must name the immediately prior completed response recorded by
this relay instance. A later request without that ID is accepted only when it
echoes the exact prior client tool-call item and supplies exactly its matching
tool output. An independent follow-up is refused before provider dispatch.

## Preparation and launch

Create separate, private host directories for the prepared workspace, runtime,
gateway, relay evidence, referee data, and grading data. The gateway directory
must contain exactly `model.sock`, or exactly `model.sock` plus `proxy.sock`
when a proxy port is supplied. Every socket has mode `0600`; mount the gateway
directory read-only into the worker. The builder rejects every other entry or
socket/port mismatch.

Use `build_podman_argv` after verifying rootless local Podman and the exact
cached image ID. It fixes these controls:

- absolute pinned Podman and OCI-runtime paths, emitted as
  `/usr/bin/podman --remote=false --runtime=/usr/bin/crun run`;
- `--unsetenv-all`, `--pull=never`, `--network=none`, and
  `--http-proxy=false`;
- a fixed `--hostname=scourge-worker` and explicit
  `HOSTNAME=scourge-worker`, preventing the runtime-generated container ID from
  becoming worker environment;
- explicit booleans for `--rm` and `--interactive`: collector production uses
  both, while inspection qualifications omit both so the stopped container can
  be inspected and removed explicitly;
- read-only root, all capabilities dropped, no-new-privileges, a PID ceiling,
  and the rootless keep-id user namespace;
- exactly two writable bind mounts, `/workspace` and `/runtime`;
- the exact one- or two-socket gateway and explicitly staged binaries/adapters
  read-only;
- a complete allowlisted environment rooted below `/runtime`, with no auth,
  credential, proxy URL, token, or secret variable; the optional numeric
  `M0_PROXY_PORT` is admitted only with the exact `proxy.sock` topology.

Production uses the exact cached `debian:bookworm-slim` image ID
`43f84a0b210f98845ef003912981774c95efe439eaa4b1cb62cf803fd46fc82a`.
It mounts the exact Codex binary and a reproducibly built, static-musl
`native-codex-supervisor` read-only. The supervisor is the entrypoint; its
fixed arguments pin its own digest, the Codex digest, and the complete Codex
argv. It binds only `127.0.0.1:18080` to `/gateway/model.sock` and, when the
canonical proxy port is present, that distinct loopback port to
`/gateway/proxy.sock`. No arbitrary destination or hosted tool route exists.
The checked build compiles identical source from two different isolated roots
using the same repository-relative source argument and requires byte-identical
outputs, so the pin does not depend on the maw checkout's absolute path.

`--interactive` appears before the image and the supervised Codex command ends
with `-`, allowing the collector to deliver one nonempty UTF-8 prompt of at
most 256 KiB. The supervisor verifies the exact effective environment, both
executable digests, gateway socket ownership/mode, and the fixed route set
before spawning Codex. It allows at most 32 concurrent bridges per route, imposes a 900
second run ceiling, records route-specific sessions/refusals/byte counts, and
fails the run on any route failure or incomplete prompt write. After the direct
Codex child exits it requires the whole Codex process group to disappear,
waits five seconds after TERM, escalates to KILL, reaps group children, and
records whether escalation occurred either while waiting for the direct Codex
child or while quiescing its remaining process group. Route inactivity and process-group
quiescence are both required for `teardown.complete`. A five-second bounded
writer result wait prevents an inherited stdin reader from deadlocking the
supervisor. External interruption is recorded separately from timeout and can
never settle. The outer container-removal receipt remains authoritative for a
child that deliberately escapes the Codex process group.

Moving, duplicating, or placing an attach/runtime option after the image
invalidates the launch manifest. No Python wrapper or independent forwarder is
part of the production process tree: collector lineage is exactly supervisor,
Codex, then client tool commands.

The rootless Podman boundary is authoritative, so Codex runs with its inner
`--sandbox danger-full-access` and approval policy `never`; this avoids relying
on an unqualified nested sandbox. Both modes pass `--ignore-rules`, which
disables execpolicy rule files, while `project_doc_max_bytes` remains the
separate executable/managed project-document control. Both `code_mode` and
`code_mode_host` are explicitly disabled. Stable feature `shell_snapshot` is
also explicitly disabled: its default-on Unix initialization child is not a
Scourge tool item and would violate the collector's direct-child accounting.
The worker does not mount a code-mode host helper. Its local shell path is the
stable client `exec_command` tool declared by the bundled `gpt-5.5` model.

Pass every referee, fixture-source, ground-truth, administration, hidden-canary,
grading, checkout, and host project root as a protected root. The builder
refuses any mount that contains, equals, or sits below one. Stage exact worker
binaries outside those roots; never mount the checkout merely to obtain a
binary.

The host opens the credential source and passes only its descriptor to the
relay. Descriptor plumbing is runner-owned; the credential bytes must never
appear in a command string or shell variable exported to a child. A relay
invocation has this shape:

```text
python3 -I lib/responses_relay.py \
  --socket HOST_GATEWAY/model.sock --evidence PRIVATE_EVIDENCE \
  --model PINNED_MODEL --mode executable 3<&PROVIDER_AUTH_FD
```

Managed mode additionally supplies a host-owned file containing the exact
single generated Scourge block. `--forbid-context LABEL=TEXT` entries name
project-path and host-guide fragments that must not occur in the first accepted
request. Do not include sensitive bytes in those values.

## Context and accounting evidence

The relay stores every accepted raw request body byte for byte under
`requests/`, plus its length and SHA-256 in `relay.json`. Rejected requests
retain only bounded fixed-shape metadata and no body artifact or digest. It never stores
worker header values or provider authentication. If provider authentication
occurs in a request or response body, the body is not retained or forwarded
and the relay becomes invalid. Its body length, digest, and path are also
redacted, so a low-entropy credential cannot survive as a brute-forceable
receipt artifact. Unexpected targets are represented only by the constant
`unexpected`; worker header values and unknown header names are never retained.
The evidence root, request directory, receipt, and request bodies are opened
through retained directory descriptors. Every operation revalidates device and
inode, owner-only directory modes, regular owner-only artifact modes, link
count, and the exact known entry set. `O_NOFOLLOW` and dirfd-relative atomic
replacement prevent a root, subdirectory, receipt, request-body, or symlink
swap from redirecting or suppressing evidence.

Context evidence is bound to the first request that would actually be sent
upstream. A rejected route, model, framing, or body cannot prime it; any request
before the first acceptable request causes refusal. The strict JSON body is
then inspected as the actual Codex context witness:

- executable mode requires zero Scourge managed-start and managed-end markers;
- managed mode requires exactly one start, one end, and one byte-intact expected
  managed block after JSON decoding;
- every labelled forbidden host-context fragment must be absent.

The forbidden-context scan covers JSON keys and values and fails closed across
split strings; it is not limited to the conventional instructions field.

Each accepted response needs one final `response.completed` event with status
`completed`. The terminal receipt retains response ID, usage, byte count, and
digest. Accepted requests, physical upstream attempts, and terminal receipts
must reconcile exactly. Provider failures, incomplete streams, duplicate
requests, rejected requests, or missing terminal accounting make the relay
unsettled.

## Required probes before settlement

After the worker and its process group stop, supply all of these to
`settle_boundary`:

- provider-canary absence in the captured worker environment, worker `/proc`
  cmdline/environ bytes, worker-visible files, and all retained artifacts, with
  scanned byte counts and empty match/issue arrays;
- an exact effective-environment receipt comparing `/proc/self/environ` and
  Podman inspect against the 13 fixed safe names and values (plus optional
  `M0_PROXY_PORT`), including the pinned hostname and no credential-like,
  missing, inherited-image, duplicate, or mismatched name;
- separate attempted-and-refused read and write receipts, including errno and
  the fixed worker path, for fixture source, ground truth, administration
  secret, hidden canaries, and grading state;
- a typed attempt receipt for `192.0.2.1:443` showing the direct connection
  failed under `--network=none`, including errno and error;
- successful, cleaned workspace/runtime write receipts and refused rootfs,
  binary, and gateway write receipts, bound to an exact Podman-inspected mount
  destination list and the container ID;
- a container-ID-bound exact gateway receipt: `model.sock` alone admits no
  proxy receipt, while the two-socket form requires a successful worker
  loopback-to-`proxy.sock` exchange at the same launch-bound
  `M0_PROXY_PORT`;
- a container-ID-bound isolation receipt preserving both the exact launch flag
  manifest and Podman's inspected runtime state; Podman may expand
  `--cap-drop=all` to concrete names and report keep-id as a private namespace,
  so the worker also proves an all-zero effective capability set and
  `NoNewPrivs: 1` from its own `/proc/self/status`;
- typed stopped-process receipts for Codex and the forwarder, plus the same
  container ID, an explicit removal attempt, and
  `podman container exists ID` exit 1.

The probe object must identify schema `scourge.native-codex-probes`, version 1.
Plain booleans are not accepted: an omitted attempt, substituted path, mount
list from another container, or removal check for another ID invalidates the
boundary.

The final receipt uses the same consumer-facing final fields as
`scourge.trial-capture`: `status`, `settled`, `valid`, `score`, and `reasons`.
Every mismatch is `status: "unsettled"`, `settled: false`, `valid: false`, and
`score: null`. A valid boundary receipt still has `score: null`; only the
separate frozen referee may score retained evidence.

Run the offline adversarial suite with:

```sh
python3 -B evals/scripts/test-native-codex-boundary.py
```

It uses a fake Codex subprocess and fake upstream connection. It makes no model
call, reads no real credential, and requires no network. It covers header
stripping, exact raw request retention, context priming, managed-block counts,
host-context leakage, alternate methods/routes/models, ambiguous framing,
oversize bodies, duplicate retries, credential echo, encoded responses, byte
and terminal reconciliation, hosted/unknown tool refusal, safe include values,
host-injected token caps, cache-key replacement, exact reasoning/text and body
fields, response-ID and tool-call chain binding, dirfd evidence replacement,
rejected-request flood/restart hard caps, inherited-image environment refusal,
production stdin/auto-remove/runtime argv placement, Podman argv, canary scans,
and null-score failure receipts. The unit suite does
not execute Podman or the installed Codex binary; the two host qualifications
below provide those witnesses.

Run installed-Codex compatibility separately:

```sh
just installed-codex-compatibility-check \
  /tmp/scourge-installed-codex-compatibility.json
```

This pins `codex-cli 0.172.0` and its binary SHA-256, reads its bundled model
catalog and feature list offline, and requires `gpt-5.5` to remain an
API-supported `unified_exec` model without a code-mode-only tool mode. It runs
both executable and managed argv in separate rootless Podman containers with
`--network=none`, one model socket, an auth-free custom provider, and no
code-mode helper. A fake Responses upstream first calls the real declared
`exec_command` client tool. Codex writes a marker in the prepared workspace and
returns the same marker and call ID in its second request; the fake terminal
then lets Codex exit successfully. The receipt requires all eight observed
client tool definitions, the safe include value, exact metadata stripping,
host cache-key replacement, host token-cap injection, an exact tool-call chain,
two reconciled requests, zero managed blocks in executable mode, exactly one
intact block in managed mode, the exact effective environment, exact mounts,
and container removal. It also proves `shell_snapshot` is supported but
disabled, observes no direct Codex child before the first model request, and
observes the expected direct client-tool child afterward. Each mode emits a
collector-parity production argv using absolute Podman/crun, `--rm`,
`--unsetenv-all`, `--interactive`, the digest-pinned static supervisor
entrypoint, the exact mounted Codex child, and final stdin `-`. The qualifier
exercises both loopback routes and adversarially checks dead model/proxy
upstreams, broken and inherited stdin, a TERM-ignoring group descendant, a
TERM-ignoring direct Codex child that must report signal 9 and KILL escalation,
an external TERM with an escaped child, and SIGKILL receipt absence. The same
production `wait_child_with_limits` helper is compiled as a Rust test and runs
the timeout branch with a 40 ms timeout and grace. This source-faithful bounded
test proves timeout and escalation accounting without spending the production
900-second ceiling; the exact 900-second wall-clock duration is not executed.
No provider
credential, live model, target, or network is used. The checked-in
[`qualification/installed-codex-compatibility.json`](qualification/installed-codex-compatibility.json)
is source-bound evidence for that compatibility lane.

Run the separate offline host qualification with the cached image:

```sh
just native-codex-boundary-check /tmp/scourge-native-codex-boundary.json
```

That lane uses rootless Podman with `--network=none`, the real two-socket
Unix/loopback topology, read-only bind mounts, a credential read through an
inherited descriptor, a fake Codex process, a fake target proxy, and a fake
in-process Responses upstream. It removes the container and reconciles the
proxy exchange, model request, and terminal before settlement.
It uses a fake Codex process and does not contact a provider. The checked-in
[`qualification/native-codex-boundary.json`](qualification/native-codex-boundary.json)
receipt records its exact source hashes, sanitized empty worker logs, and these
limits. Re-run the lane whenever any hashed source changes; a historical
receipt is evidence for its recorded sources, not a substitute for a cold
Scourge trial or current integration acceptance.
