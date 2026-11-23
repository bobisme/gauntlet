# M0.7.4 instrument requests

Scourge [bn-2r5](bone://scourge/bn-2r5) filed two requests in Teapot’s local
Bones tracker. The [M0.1 inventory](stack-inventory.md) pinned Teapot at `6238d5a7`.

| Capability | Outcome and evidence | Scourge gate |
|---|---|---|
| Per-send reference | Filed [Teapot bn-1gah](bone://teapot/bn-1gah). The [pinned send contract](teapot-contracts.md) returns a nullable flow ID in the reply. The caller has no reference it can look up after losing that reply, and a request digest cannot distinguish identical sends. See [bn-1b4](bone://scourge/bn-1b4), the [send schema](../fixtures/contracts/schema-requests-send.json), and an [observed reply](../fixtures/contracts/send.json). | [M1.3.2](bone://scourge/bn-3s5) receipt correlation and [M1.7](bone://scourge/bn-1j8) lost-response reconciliation. The lookup must be read-only. Without dispatch evidence tied to the submission, Scourge records uncertainty and leaves the original send alone. [§7.2](../notes/plan.md#72-the-instrument-contract), [§7.5](../notes/plan.md#75-run-lifecycle-and-recovery). |
| Run-level accounting | Filed [Teapot bn-6e58](bone://teapot/bn-6e58). [bn-1iw](bone://scourge/bn-1iw) found that Teapot discards the returned ledger sequence. [bn-2cv](bone://scourge/bn-2cv) observed two loopback requests and two ten-unit ledger draws from one pass. Hallpass at `44f749ac` already accepts a caller reference in `SpendChargesRequest` and offers receipt lookup. Teapot owns the allocator and its mapping of reserved units to individual runs. [Stack facts](stack-facts.md), [two-project experiment](two-projects-pass.md), [captured accounting](../fixtures/contracts/two-projects-observed.jsonl). | An engagement requiring exact per-run accounting stays refused until the instrument can substantiate the attribution. A ledger receipt for a block identifies that reservation. A block shared across runs also needs evidence of which run consumed each unit. [§7.4](../notes/plan.md#74-accounting-evidence), INV-16, M2.7. |
| Bypass mode | No request filed. In [bn-3vk](bone://scourge/bn-3vk), the response replacement rule and Lua request and response hooks affected their proxy controls. None changed `requests send`. The send also completed with the intercept rule active and zero paused requests. The intercept case had no positive proxy control. [Channel contract](teapot-channel-contracts.md), [captured output](../fixtures/contracts/channel-observed.txt). | INV-49 still requires reading the edit surface at run start and end and refusing when an edit could affect a verifier send. The pinned result covers the tested edits. Session relogin and eligible retries still count as separate sends for the relevant step. [§7.2](../notes/plan.md#72-the-instrument-contract). |

Rite threads for the filings can be read with `rite history --thread` and the
corresponding anchor:

- Teapot `bn-1gah` · `01M82ZHY1X840YF4ZAH8YEWGTB`
- Teapot `bn-6e58` · `01M82ZHY4S8GNFXMKT1G12KZX0`
