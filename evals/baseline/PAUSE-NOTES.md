# M0.4.2 pause notes (2026-11-23)

**Status:** historical pause record. After separate lead approval, positions
6–10 were executed once each at `/home/bob/m0e` and all six remaining valid
sessions completed. The final counts are in [`RESULT.md`](RESULT.md).

**HEAD at the pause:** `ca1df64` plus the uncommitted collection changes in this
directory. Positions 6–10 were not run at that point.

## State

| Position | Arm | Status | Valid for the decision rule |
| --- | --- | --- | --- |
| 1 | A | `agent_error` (exit 126, truncated transcript) | no |
| 2 | B | `agent_error` (exit 126, truncated transcript) | no |
| 3 | A | `completed`, `agent_settled: true` | yes |
| 4 | B | `agent_error` (exit 126, truncated transcript) | no |
| 5 | B | `infrastructure_failure` (`OSError: [Errno 122] Disk quota exceeded`) | no |

The ledger has five immutable rows. Its SHA-256 at the pause is
`adf473f8b51f4b1804e8edb2db44e6d123e6aa0138bc0e6f39e86b80883a1442`.
No row was rewritten or retried.

**Preregistered result so far: inconclusive.** The rule needs ten valid
sessions; one completed cleanly. No branch of the decision rule applies.

## Collection repair (P1)

The first evidence copy carried only top-level workspace files. Nested
agent-created files remained in the retained run roots. They are now preserved
under `evidence/<position>/workspace-supplement/` by
`supplement_evidence.py`, with `SUPPLEMENT.json` (per-file SHA-256 and byte
count) and a top-level `workspace-supplement.json`. The original `run.json`,
run rows and `SHA256SUMS.json` files were not edited. The supplement excludes
the Teapot instrument store, which remains in the retained run root.

`copy_evidence` is fixed prospectively: future runs recursively retain every
regular, singly-linked workspace file, hash it in `SHA256SUMS.json`, and skip
symlinks and hardlinks without reading them. `report_files` uses the same safe
enumeration and guarded read. A hardlink check is repeated on the opened
descriptor before any read. `supplement_evidence.py` and `verify` use the same no-follow,
no-escape joins. `test_evidence_paths.py` exercises nested retention and an
escaping symlink. Existing evidence bytes were not rewritten.

## Verification change (P2)

`run_baseline.py verify` now:

- compares every `run.json` byte-for-byte at the JSON value level with its
  ledger row (exact equality, not a subset);
- recomputes every entry in each `SHA256SUMS.json` (metadata keys
  `*.sha256` and `*.bytes` are values, not files);
- decompresses the transcript and checks it against the ledger digest;
- checks the supplementary manifest when present;
- checks for live worker containers, relays, Teapot engines and fixtures that
  reference the retained run roots;
- partitions immutable run rows from typed append-only amendments, validates
  each amendment's exact source-line hash and identity, and requires exactly
  one inline or amended score disposition per assigned run;
- reports valid completed sessions and marks the decision inconclusive when
  there are fewer than the scheduled ten.

The strengthened verifier was applied prospectively. It does not rewrite the
earlier records.

### Append-only score disposition

Position 5 reached `EDQUOT` before the runner created its normal mechanical
`pending_adjudication` score placeholder. The original position-5 row remains
byte-identical. A typed `score_amendment` was appended to `ledger.jsonl`, bound
to that row's exact LF-terminated SHA-256 and position/arm/label. It records
`not_adjudicable_infrastructure_failure`, infers no claim score or unsupported
claim count, and leaves M0.4.4 (`bn-93a`) as the adjudication owner. The
verifier reports 10/10 score coverage: nine inline dispositions and one valid
amendment. Future infrastructure failures receive the same honest disposition
inline before their run row is appended.

## Diagnosis

### EDQUOT (position 5)

`/tmp` is a 63 GiB tmpfs with `usrquota`, 51 GiB used and 13 GiB free at the
pause. Swap was 31 GiB/31 GiB full. The user cgroup recorded 53 OOM kills. Run
roots, project stores and raw transcripts were written under
`/tmp/scourge-evals`, so the runner itself hit `EDQUOT` while writing evidence.

### Abrupt exits (positions 1, 2, 4)

Each container exited **126**, wrote a truncated final JSONL record, produced
no stderr, and appears in the user journal as `container died` with no error
line. Position 4's last completed tool result was a permission-denied
`./phase1c.sh` with tool exit 126. A controlled reproduction outside the scored
path showed that Pi survives tool exits 126 and 127 and reaches `agent_settled`,
so the tool exit alone is **not** a sufficient explanation. The common
environmental factor is the near-full `/tmp` tmpfs and sustained memory
pressure. The root cause of the container exit code is **not established**;
this note does not claim one.

### Unscored qualification

`qualification-2` ran the same runner, boundary, model, fixture, Teapot project,
relays and cleanup with run roots on ext4 (`/home/bob/m0e`). It completed with
`agent_settled: true`, four bash calls, `QUALIFICATION-OK 401`, and a successful
container/relay/proxy/fixture teardown. It is explicitly unscored, is not in the
ledger and is not in the decision-rule denominator. `qualification-1` was an
aborted attempt whose base path exceeded the 107-byte Unix-socket limit; it is
retained as a failed qualification, not a session.

A short-base check now refuses a run root whose Teapot control-socket path
would exceed 107 bytes. `--base /home/bob/m0e` is the documented short ext4
location for any future run.

## Resume record (executed)

After lead approval at `7adb6cc`, positions 6–10 were run once each, in
schedule order, with `--base /home/bob/m0e`, the existing ledger and the pinned
Teapot binary. Each was checked for a retained ledger/evidence row, successful
cleanup and no worker/container/relay/proxy/fixture leak before the next. All
five completed with `agent_settled: true` and successful cleanup. No retry,
replacement or substitute trial was added. The final ledger, verifier and
per-position costs are in [`RESULT.md`](RESULT.md).

The host-filesystem change is a collection-environment change, not a change to
the frozen condition materials, model, prompt, boundary or scoring. It is
reported beside the final result.
