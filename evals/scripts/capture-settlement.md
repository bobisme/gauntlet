# Trial capture and settlement

`lib/trial_capture.py` qualifies the M0-ADD-02 capture contract on Linux. It
measures the evidence filesystem and retains the output of a stopped worker.
The harness owns launch, process teardown, and the safety and boundary checks.
The referee owns scoring.

## Before launch

Provide an existing, absolute, canonical run root with mode `0700`, owned by
the effective user. Use a dedicated directory outside the checkout, protected
home directories, and live tool stores. Pass any additional protected paths
with repeatable `--exclude-root` flags.

Supply positive `--min-bytes` and `--min-inodes` for the expected workload and
retained copy. The preflight receipt records effective-user capacity from
`fstatvfs`, the configured minima, and a probe that writes, flushes, syncs,
and removes a file and syncs its parent. The capacity is a measurement at
preflight time. Future writers can consume it.

```sh
python3 -B evals/scripts/lib/trial_capture.py pending \
  --run-root "$run_root" --checkout "$checkout" --trial-id "$trial_id" \
  --min-bytes "$capture_bytes" --min-inodes "$capture_inodes"
```

Use the same flags without `--trial-id` on the `preflight` subcommand when
only a measurement is needed. A successful `pending` publishes
`$run_root/$trial_id/capture.json` in a new directory before launch. Both
commands emit JSON and return `2` on refusal. A capacity refusal leaves no
trial directory. The pending receipt binds `--terminal-event`, which defaults
to `turn.completed`.

## After teardown

Keep the worker's source directory and the receipt directory disjoint. Pass
the three input paths relative to the source directory. Supply
`--worker-stopped`, `--safety-ok`, and `--boundary-ok` only after each
corresponding check succeeds. An absent `--exit-code` records a missing
command receipt. Pass `--interrupted` when the command or trial was interrupted.

```sh
python3 -B evals/scripts/lib/trial_capture.py settle \
  --run-root "$run_root" --trial-id "$trial_id" --source-root "$stopped_worker_dir" \
  --events logs/events.jsonl --stderr logs/worker.stderr --artifacts outputs \
  --exit-code "$worker_exit" --worker-stopped --safety-ok --boundary-ok
```

The capture writes the byte-exact streams under `retained/raw/` as
`transcript.jsonl` and `worker.stderr`. It copies nested output below
`retained/artifacts/`, including empty directories. Descriptor-relative
traversal refuses symlinks, hardlinks, special files, mount crossings, and
path substitutions. Source metadata is rechecked after the copy. The
retained files are reopened and hashed independently, then compared with
the hashes computed from the source bytes during copying.

The receipt identifies schema `scourge.trial-capture`, version `1`. Inventory
rows contain `path`, `type`, `bytes`, and `sha256`. Paths are relative to
`retained/` and sorted lexically. A directory row has zero bytes and a null
digest. Both inventories have digests over the compact ASCII JSON arrays
with sorted object keys and no trailing newline. `complete` indicates
successful enumeration and matching paths, and `verified` requires matching
types, sizes, and digests. Collection issues identify affected paths, with
safe siblings and the original source preserved.

A settled capture has one newline-terminated terminal event at the end of
the nonempty event lines. The event summary records the byte length, digest,
and event count of the valid prefix, along with any usage reported there.
Raw JSONL retains malformed or torn bytes for inspection. Interruption, a
missing command or terminal receipt, failure of a safety or boundary check,
and an incomplete or mismatched inventory each leave `valid` and `settled`
false. The command returns `2` and publishes the final receipt when possible.
Every capture receipt has `score: null`. A consumer should verify the
retained digest when it later reads the evidence for scoring.

Run the synthetic acceptance with
`python3 -B evals/scripts/test-capture-settlement.py`.
