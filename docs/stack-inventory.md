# Stack inventory

`inventory.json` is a snapshot of this machine, not a lockfile. It records the
revision 1 and revision 2 pins from the research ledger separately from current
checkout HEADs. `installed` describes the executable selected for this project:
the local build directory takes precedence over PATH. Its version is the exact
captured stdout, stderr and exit code of `--version`; SHA-256 hashes the resolved
executable bytes. Paths have an explicit kind and base: `relative` paths use
`project_root`, while `absolute` paths have a null base. The local target path
is relative to the project root, so it remains meaningful after integration;
the snapshot describes the observed bytes and does not install them. Rebuild in
the destination project before running those paths. A checkout HEAD does not prove where an executable came from,
so executable commit is `unknown` unless independently established. Missing
checkouts and executables are recorded as unknown and null respectively.

From the project root, build the three instruments into the ignored local target
and regenerate the snapshot:

```sh
scripts/build-stack.sh
python3 scripts/stack-inventory.py --output docs/inventory.json
mise exec -- teapot --version
mise exec -- hallpass --version
mise exec -- playpen --version
just check
```

The build uses `~/src/{teapot,hallpass,playpen}` and their lockfiles without
changing their working trees. Set `SCOURGE_SOURCE_ROOT` for another source
parent; pass the same path as `--source-root` to the inventory script. Mise
adds the local debug binaries to PATH when activated or through `mise exec`.
Alternatively prepend `$PWD/.stack-target/debug` to PATH. Rebuild and regenerate
when checking a different checkout or binary; do not treat this snapshot as a
claim about another machine or a later run.

The [Teapot instrument contract](teapot-contracts.md) records a separate
source-pinned rebuild and runtime captures; it explains why those bytes must
not be confused with this snapshot's historical installed executable.
