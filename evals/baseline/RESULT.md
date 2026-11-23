# M0.4.2 baseline result (2026-11-23)

**Status:** all ten assigned positions were attempted exactly once, in schedule
order. No retry, replacement, substitute trial, schedule/material/model/prompt/
boundary change, or claim adjudication was made.

| Position | Arm | Status | Valid | USD | Duration | Input | Output |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | A | `agent_error` (exit 126, truncated) | no | 0.1660849 | 170.8 s | 37,593 | 25,798 |
| 2 | B | `agent_error` (exit 126, truncated) | no | 0.0637379 | 58.4 s | 26,202 | 8,189 |
| 3 | A | `completed`, `agent_settled` | yes | 2.0967407 | 714.3 s | 390,793 | 122,869 |
| 4 | B | `agent_error` (exit 126, truncated) | no | 0.1621156 | 110.1 s | 46,973 | 18,084 |
| 5 | B | `infrastructure_failure` (`EDQUOT`) | no | 0.0067001 | 9.2 s | 4,721 | 764 |
| 6 | A | `completed`, `agent_settled` | yes | 0.7265616 | 427.7 s | 159,970 | 87,233 |
| 7 | A | `completed`, `agent_settled` | yes | 0.2782469 | 364.3 s | 61,807 | 47,095 |
| 8 | B | `completed`, `agent_settled` | yes | 0.4138757 | 319.8 s | 87,835 | 66,085 |
| 9 | A | `completed`, `agent_settled` | yes | 0.5053753 | 390.6 s | 111,691 | 50,661 |
| 10 | B | `completed`, `agent_settled` | yes | 0.5668882 | 397.7 s | 122,300 | 65,089 |

Token columns are provider-reported input and output tokens from the committed
ledger; cost is the provider-reported model total. Full per-run usage, cache
reads, reasoning tokens, tool calls and transcript hashes are in
[`evidence/summary.json`](evidence/summary.json) and the ledger.

## Exact counts

- Ledger run entries: **10 / 10** scheduled positions, plus **1** typed
  append-only score amendment.
- Status: **6 `completed`**, **3 `agent_error`**, **1 `infrastructure_failure`**.
- Valid sessions for the decision rule: **6 of 10** (`pos-03-a`, `pos-06-a`,
  `pos-07-a`, `pos-08-b`, `pos-09-a`, `pos-10-b`).
- By arm: A has 5 attempts, 4 valid; B has 5 attempts, 2 valid.
- Aggregate cost: **USD 4.98632655**; input 1,049,885; output 491,867; cache
  read 22,396,209; reasoning 284,463; wall 2,962,859 ms; 568 bash calls.
- Score coverage: **10 / 10** (9 inline mechanical dispositions, 1
  append-only position-5 disposition). No claim score or unsupported-claim
  count was inferred for the infrastructure failure.
- Immutable ten-run prefix SHA-256:
  `702f955b8a4dd96712eae7c41c1f3db4aa5fd58def2200b0ad50eccbc868bc6e`.
- Ledger SHA-256 after the amendment:
  `03c116f389e5aad58b7f5e2fdfb9650072b473f7e6800333e5f5579220b3eef0`.
- Verifier: no integrity problems; `verify.json` SHA-256
  `4b0989fdd8bea3cee63b45f9ae412e03555a5f0acaa4d5fa4288423e4c83d6db`.

## Decision

**Inconclusive.** The preregistered rule requires ten valid sessions; six
completed cleanly. Positions 1, 2 and 4 ended with container exit 126 and a
truncated transcript; position 5 ended with a host `EDQUOT`. They remain
assigned results and were not retried. Claim adjudication and the failure
taxonomy belong to M0.4.4 (`bn-93a`); this result makes no claim about how often
agents are wrong and no frequency claim from ten small sessions.

The four failures are the same infrastructure/environment failures diagnosed in
[`PAUSE-NOTES.md`](PAUSE-NOTES.md). The exit-126 root cause remains **not
established**; the EDQUOT cause is the near-full `/tmp` tmpfs recorded there.

## Collection environment

Positions 1–5 used run roots under `/tmp/scourge-evals`; positions 6–10 used
`/home/bob/m0e` on ext4 because `/tmp` carried a user quota that produced
`EDQUOT`. This is a host-filesystem collection change only. The frozen
materials, model, prompt, boundary, schedule, budgets and scoring were
unchanged, and it is reported beside the counts above.

All ten run rows passed the strengthened verifier: exact `run.json`-to-ledger
equality, every `SHA256SUMS.json` entry, transcript hashes, supplementary
hashes, cleanup, and no live worker/container/relay/proxy/fixture. The verifier
also authenticated the sole append-only score amendment against the exact
original position-5 line and reported 10/10 score coverage. Seal review
`cr-svgdp2` remains open on the repaired head; no merge, push or bone closure
was performed.

`evidence/summary.json` SHA-256:
`064769694c0b8516e0ddbde1a7f67fe35477d9523dde95f03642271ac90b7944`.
