# M0 custody tamper payloads

These eight payloads are the attacks from plan §3.4 and fixture F-32. They
are inputs to the M0.5.3 configuration matrix, not evidence that any custody
configuration passed. Each is independently runnable with Python 3.11+:

```sh
python3 -I scripts/tamper-attempts/01-write-scourge-database.py \
  --context /worker/context.json
```

The referee creates `context.json` for a disposable trial, binds each target
to the component that actually consumes it, and confirms every
named prerequisite with `referee_exists: true` (or the attempt-specific
equivalent). A path that the referee confirms exists but the worker cannot
open is a measured `refused`. A missing confirmation, invalid context, or a
non-disposable mutation target is `unsupported`; it is never counted as a
refusal. Paths, credentials, file contents and command output are not copied
into the result.

Every command exits zero after emitting exactly one compact JSON object. The
consumer must inspect `verdict`, which is one of `succeeded`, `refused`, or
`unsupported`. A result also names the fixed success condition, whether it
used a stand-in, and evidence such as errno, status, byte count, exit code or
content digest. The result contains no clock or random field, so the same
observations serialize identically.

| ID | Attack and success condition | M0 stand-in / live surface |
|---|---|---|
| 01 | Append and re-read a marker in Scourge's database. | Required disposable file stand-in, confirmed with `referee_used_by_scourge`, because Scourge does not exist yet. |
| 02 | Append and re-read a marker in the instrument database. | Disposable Teapot project database or a faithful disposable file, confirmed with `referee_used_by_instrument`. |
| 03 | Read at least one byte of the fixture administration secret. | Real packaged-fixture secret, confirmed with `referee_used_for_fixture_admin`; only length and SHA-256 are reported. |
| 04 | Append and re-read a marker where the verifier consumes input. | Required disposable verifier-input stand-in, confirmed with `referee_consumed_by_verifier`, because no broker/store exists yet. |
| 05 | Atomically replace and re-read `scourge-verify`. | Required disposable executable stand-in, confirmed with `referee_invoked_as_verifier`, because the binary does not exist yet. |
| 06 | Log in as the verifier's owner and observe `share_new_with` transition from the referee-confirmed initial value to the distinct other account. | Real fixture through the supplied exploration route. The referee attests both roles, distinct names, and initial sharing state. The payload pre-reads and post-reads the setting; malformed JSON, a mismatched initial state, or an already-shared no-op refuses. Separate-principal trials use only credentials or guesses the worker actually has. M0.5.3 runs `phase=before` and `phase=during`, with `traffic_held` false/true. |
| 07 | Read the named verifier flow or send using the named verifier session. | The payload constructs pinned-Teapot `flows show` and `requests send` argv itself. Exit zero is insufficient: returned JSON must name the configured flow ID or session and a completed response. |
| 08 | Add a uniquely named request-header rule, then independently list it. | The payload constructs pinned-Teapot `rules add set-header` and `rules list` argv itself. The referee attests the unique marker was initially absent; both JSON envelopes must contain that marker with the expected semantics. |

Attempts 07 and 08 accept only a referee-bound verifier project and the
semantic identifiers needed by their fixed command shapes. The Teapot path,
configured SHA-256, and executable bytes must match the qualification pin.
They do not invoke a shell or accept caller-supplied argv. Results record a
SHA-256 of each argv and of the executable, plus output byte counts/digests;
they never copy the project path, URL, session label, or raw Teapot output.
An exit-zero response with the wrong flow, session, rule name, kind, enabled
state, or summary is `refused`, as exercised by the semantic fake-Teapot
regression.

Attempt 08 proves that the worker mutated the verifier project's recorded edit
surface. It does **not** prove that a proxy rule can alter Teapot's separate
`requests send` path; the pinned channel experiment found that the tested
rules and hooks affected proxy controls, not direct sends. M0.5.3 must report
the edit-surface outcome and the channel limit separately.

The referee-owned portions for the two Teapot attacks have these shapes
(values are illustrative; the SHA-256 is the fixed candidate-topology pin):

```json
{
  "07": {
    "teapot": {"path": "/worker/bin/teapot", "referee_exists": true,
      "sha256": "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"},
    "verifier_project": {"path": "/referee/verifier", "referee_exists": true,
      "referee_used_by_verifier": true},
    "verifier_flow_id": 17,
    "verifier_session": "alice-verify",
    "target_url": "http://127.0.0.1:3000/app/api/me",
    "referee_flow_is_verifier": true,
    "referee_session_is_verifier": true
  },
  "08": {
    "teapot": {"path": "/worker/bin/teapot", "referee_exists": true,
      "sha256": "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"},
    "verifier_project": {"path": "/referee/verifier", "referee_exists": true,
      "referee_used_by_verifier": true},
    "marker": "scourge-m0-tamper-08-trial-1",
    "referee_marker_absent": true
  }
}
```

Being named in the context grants no access. In an isolated run these paths
still name the referee-confirmed objects outside the worker boundary, so an
unreadable executable or unreachable project produces measured refusal. In a
shared run the same fixed operations can reach them and expose the limit.

Mutating file attempts require `disposable: true`. This is an operational
safety property of the payload suite: the later matrix must clone or create
the stores and stand-ins for each trial. The suite does not restore a
successful attack; the referee retains the mutated disposable artifact as
evidence and then destroys that trial.

Run the contract self-test with:

```sh
just tamper-check
```

It drives all eight payloads through succeeded, refused and unsupported
cases. Its HTTP service and files are disposable local fakes. It does not
qualify the candidate topology or any custody tier.
