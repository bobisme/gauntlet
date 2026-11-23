# Evidence contract fixtures

**Passing the in-memory fixture double proves nothing about Investigation.**
These are the Scourge M0.6.1 cases. M0.6.2 runs them through a named release of
Investigation's shipped public recording interface.

Run the fixture self-check with Python 3.11 or newer.

~~~sh
python3 -B fixtures/contracts/evidence/run.py --self-test
~~~

Pass an adapter file as the single implementation slot. Use repeated `--case`
arguments to run individual cases. The runner lists case names in `--help`.

~~~sh
python3 -B fixtures/contracts/evidence/run.py --adapter /path/to/investigation_adapter.py
~~~

## Adapter contract

Export `open_driver(scratch)` from the adapter file. The runner supplies a fresh
temporary workspace per case. Reopening that directory must preserve the
backend's accepted state. The lineage case also opens an independent workspace
to get a well-formed artifact ID absent from the main workspace. The runner
calls `close` during cleanup, including after interruption and case failures.
Import the protocol, result types and `Rejected` exception from
[driver.py](driver.py). The fixture uses only the Python standard library.

- Use caller-supplied keys as stable retry identities. Return the original
  backend IDs and receipts for exact retries. A changed operation under the same
  key returns `conflict`. After a partial or complete seal, a new attachment
  returns `closed` and an exact retry returns its prior receipt.
- Normalize the accepted position to one-based attachment positions with cursor
  zero before the first item. Return attachment receipts in position order.
  Expose the backend's accepted position and `open`, `partial` or `complete` seal
  state. Finalize using the declared inventory of attachment keys and expected
  last position. A complete seal with a stale cursor or mismatched inventory
  returns `conflict`. A partial seal reports missing positions. These are the
  attachment lifecycle checks from
  Investigation §11.3 at the recorded pin, limited to the capture operations
  used by Scourge §9.2.
- Return the full artifact ID, full SHA-256 digest, original capture ID where
  applicable and source lineage from the backend in the order supplied when
  recording. Each lineage entry carries the source ID and digest with the
  versioned transform. Reject lineage with an absent source as `missing` and a
  different source digest as `digest_mismatch`.
  For a byte range, return the selected bytes with the same full-artifact
  metadata. Negative, reversed, empty and out-of-bounds ranges return
  `invalid_range`.
- Keep raw reads byte-exact. The `structured_as` read parses the entire artifact as
  the named kind and returns its exact bytes after validation. A structured read
  or record that rejects a JSON document returns `invalid_json`. Treat errors from
  an unavailable operation as case failures.
- On `interrupt`, terminate the writer without a graceful capture shutdown.
  The runner loads a fresh adapter module and checks that its factory returns a
  different driver instance for the same workspace. The new driver discovers
  acknowledged items and seal state through the backend. In the crash recovery
  case, `recover` is the first operation after reopening.

The runner keeps the same Python process across sessions. The adapter supplies
and verifies the actual writer interruption. Any interpreter-global state in
imported dependencies survives module reloading, so the adapter must recover
through the backend's public interface. The self-test models acknowledged
state with one in-memory store per workspace shared by fresh driver instances.

The dependency decision selects Investigation's versioned JSON protocol when a
public recording crate is unavailable. Keep the adapter on the shipped public
interface. Populate fixture results from observed responses and reads. The
runner independently computes expected digests and compares bytes, lineage and
lifecycle results. [Scourge dependency contract](../../../docs/dependencies.md)

## JSON rules

The fixtures follow Investigation §10.1 at the Investigation pin in the
dependency contract. SHA-256 covers the exact retained bytes. Distinct JSON
spellings of the same value retain their own bytes and digests. Structured
parsing requires UTF-8, rejects duplicate keys at every level, and rejects
non-finite numbers and unsafe integers. Measured decimals and large integers
can be represented as strings. The raw capture path also retains arbitrary
bytes, including input that a subsequent structured read rejects.

Each test names its plan or invariant reference in its first line of output.
[Scourge plan §9.2](../../../notes/plan.md#92-evidence-store)
