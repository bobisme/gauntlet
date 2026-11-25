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
