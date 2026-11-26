# Cold-trial preparation boundary

The M1 skeleton uses the product's owned `demo` setup to prepare a real
development fixture, qualified Teapot project, canonical engagement manifest,
pass and Scourge binding. It does not construct grader-shaped substitutes.

The evaluator creates two new empty directories under separate trusted roots:
the worker workspace and a mode-0700 referee directory. It then runs the exact
pinned binaries without a model or provider credential:

```sh
scourge --format json demo WORKSPACE \
  --teapot /absolute/pinned/teapot \
  --investigation /absolute/qualified/investigation \
  --managed-guide false \
  --referee-root REFEREE_ROOT
```

Use `--managed-guide true` for the managed cell. The executable cell never
creates `AGENTS.md`; the managed cell installs the ordinary owned Scourge block.
Supplying `--referee-root` also suppresses the tutorial lead suggestion, and a
fresh prepared workspace has no leads.

The referee root must already exist, be canonical, owned by the current user,
mode 0700, and disjoint from the workspace and Scourge state roots. A new
attempt requires an empty root. A restart may reopen only that workspace's
bound pending or settled transaction. The command holds a no-follow directory
descriptor, binds its device and inode into `transaction.json`, and performs
all protected file I/O relative to that descriptor. Artifacts are installed
through private temporary files, file `fsync`, a no-replace same-directory
rename, and directory `fsync`; an interrupted temporary file is retained as
invalid evidence rather than adopted. Every artifact is a single-link
owner-only regular file at mode 0600. The worker is never given the root.

Preparation retains:

- a unique fresh-process reset receipt and exact loopback target receipt;
- exact engagement source, pass bytes, canonical revision-1 manifest and empty
  manifest history;
- immutable response-body originals for all seven native Teapot
  `/app/api/me` flows, including Alice, Bob, anonymous, verifier sessions and
  two independent same-subject session pairs;
- only cookie and subject digests in the protected session map, never cookie
  values;
- exact Teapot and Investigation binary digests;
- native request-ceiling snapshots before and after preparation from a fresh
  private Teapot project and unique pass digest; the delta is only a
  fixture-specific completeness lower bound, while per-run debit attribution
  remains explicitly `unestablished`;
- a recursive digest/mode inventory of the worker-visible workspace; and
- a final settlement that binds every protected file.

The same-subject control is native target state, not a relabel: `alice` and
`alice_same` have different cookie digests and the same subject digest, as do
their verifier counterparts. The other cells use distinct Alice and Bob
subjects. The normal `scourge demo` command remains the tutorial path and still
installs the guide and returns the example lead command.

Stop every prepared runtime with the exact `demo.stop_argv` returned by the
start response. A pending transaction is written before target setup. A crash
retains that marker and every durable partial artifact. Restart can settle a
complete preparation against its matching active workspace, and can revalidate
an already settled workspace. Restart strictly decodes and cross-validates the
transaction, reset, target, preparation, session, accounting, workspace and
settlement receipts, every referenced digest, every identity original, the
exact declaration/manifest/pass binding, and both binary pins before allowing
settlement. A durable `workspace.json` without `settlement.json` is an explicit
pre-settlement state that a matching restart can validate and finish. An
incomplete or corrupt transaction is reported as unsettled; it is never
silently reused as a fresh attempt. A preparation or settlement failure must
not be graded.
