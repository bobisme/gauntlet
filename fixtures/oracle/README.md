# Runnable first-oracle qualification

This package owns the host qualification for the first web oracle. It starts
the real development target on loopback, invokes the exact pinned Teapot
adapter and qualified Investigation evidence backend, and drives the public
`prepare -> execute_live -> evaluate_and_store` path. It never sends traffic to
an external target.

Run it through `just oracle-fixture-check TEAPOT INVESTIGATION`. Both paths are
required. A missing binary, a digest mismatch, a missing fixture case, or a
case-count mismatch fails the command; cases are never skipped.

The target's `_oracle-mode` endpoint is referee-only choreography protected by
the fixture administration secret. It changes deterministic fixture behavior,
not the verifier recipe. The verifier continues to mint canaries and acquire
all flows from its frozen operation registry.

## Offline mutation qualification

Run `just oracle-mutation-check` to replay the POR-01 through POR-12 witnesses
and print the `scourge.oracle-mutation.v1` JSON matrix. The ordinary Rust test
suite runs the same gate. The test build disables one numbered check at a
time and requires a failure in at least one case associated with that check
in the frozen oracle contract. The matrix names each failing case and its
specific saved-input witness. These replays and scope checks are deterministic
and send no requests.

F-05 supplies a test-only HTTP status alongside the saved input. Its 403
response contains the current canary and must still yield an exposure. The
POR-11 replay checks how the oracle classifies a recorded removal when the
plant never established ownership. The core acquisition tests separately
verify that a lost plant response sends no DELETE. Run the loopback fixture
qualification above for live acquisition coverage.
