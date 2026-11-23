# Local fixture enforcement spike

**The fixture remains `unenforced`.** Neither candidate established an
approved Teapot request reaching the fixture under enforcement. The blocker is
tracked as Playpen `bn-vcn`; #playpen request anchor
`01M830B41K2ZHBJH7N8JJQHXJB`.

On Linux 7.2.8-arch1-2 with user namespaces enabled, Playpen's host doctor
reported egress available. The disposable fixture bound the existing host
address `172.16.0.35` and a random port. A direct login returned 200. A pass
allowed exactly that address and port. Teapot started with `--enforce`,
reported `engine.enforced=true` and `enforcement.on=true`; its approved login
failed `connect-failed` / connection refused. An attempted GET to the adjacent,
unlisted port was refused with `port-not-listed` by Teapot's pass gate. That
is evidence of the application gate, not an independent packet-filter denial.
The verified ledger contains a ten-unit block reservation; this is not evidence
of ten delivered requests. The engine was stopped cleanly. See the full
[capture](../fixtures/contracts/enforced-nonloopback.jsonl).

For the second candidate, a Playpen `--no-network` sandbox ran both the
loopback fixture and the Teapot client; direct login returned 200. Teapot's
enforced engine did not start: its nested Playpen doctor failed to make mounts
private or start pasta with EPERM. The outer sandbox report records `network:
none`, startup and exit, but has no pass; it is not pass enforcement and the
zero drops do not establish a denial test. The [capture](../fixtures/contracts/enforced-offline.jsonl)
and [outer report](../fixtures/contracts/enforced-offline-report.json) retain
the fresh empty ledger and host-specific details. At pinned Teapot source
`crates/teapot-api/src/commands/pass.rs:226-234`, loopback destinations are
also declared non-enforceable. Playpen's pinned `docs/spec.md:183-191` explains
that sandbox loopback is private and always allowed. Its `src/pasta.rs:10-30`
disables host loopback mapping and forwarding; the precise cause of the
non-loopback refusal was not established. Other kernels, privileges, network
layouts and Playpen versions may differ.

The Teapot binary was built offline from `6238d5a78a6514466d54ad16dd5737f43c1d4961`
(SHA-256 `6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458`);
Hallpass from `44f749ac158e8378705bab80d855ed0a1f634a54` (SHA-256
`cc945c9eaa0054e903dde53cee8e4c8d7c74f6fca5de465306fa185a519fe422`);
Playpen from `32677f2dde4449d578f9a5bf3417f442c252c7a4` (SHA-256
`4bf7ade4fa677e15319b825d2bdd2c79ee247586adda1abd40f3b9880654548b`).
Build provenance is documented in [Teapot contracts](teapot-contracts.md) and
[three copies](hallpass-three-copies.md); the fixture binary digest is in each
capture. Digests identify observed bytes, not reproducible build guarantees.

Build the fixture with `cargo build --offline --locked -p scourge-fixture`.
Then supply absolute paths to the pinned builds and an existing local IPv4
address. The script starts and stops only its own fixture and engine, creates a
temporary project, pass and ledger, and emits JSONL including the pass and
verified ledger. Review its output: its exit status alone does not establish
success. Use a disposable isolated machine or network when exposing the fixture
on a non-loopback interface; its development credentials are public.

```sh
python3 scripts/enforced-topology.py --teapot "$TEAPOT" --hallpass "$HALLPASS" \
  --playpen "$PLAYPEN" --fixture "$PWD/target/debug/scourge-fixture" --address "$LOCAL_IPV4"
"$PLAYPEN" run --no-network --report /tmp/scourge-offline-report.json -- \
  python3 "$PWD/scripts/enforced-topology.py" --teapot "$TEAPOT" --hallpass "$HALLPASS" \
  --playpen "$PLAYPEN" --fixture "$PWD/target/debug/scourge-fixture" --address 127.0.0.1
```

Neither observation establishes general containment, custody, or release
readiness. Playpen filters packets and time, while Teapot accounts for requests;
Playpen does not enforce application name restrictions or spend the ceiling.
