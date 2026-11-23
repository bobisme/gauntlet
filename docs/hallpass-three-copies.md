# One pass across three Hallpass copies

On 2026-11-23 UTC, the offline contract in `scripts/check-hallpass-copies.py` accepted the same synthetic pass in Hallpass, Playpen and Teapot. The captured JSON is [`hallpass-three-copies.evidence.json`](../fixtures/contracts/hallpass-three-copies.evidence.json); it includes the binary hashes and the digest returned by each consumer. The pass expires in 2030, so a later run must use a newly reviewed fixture rather than treat expiry as an incompatibility.

The pass is synthetic, authorizes no real engagement, and was created by `hallpass init` then filled with the checked-in fixture bytes. Hallpass `check` validates it. Playpen `plan` goes through its real `pass::load`, validates the current window, translates the selected destinations and returns the pass digest and effective grant. Teapot `pass attach` and `pass show` use the vendored loader and report a bound, currently valid pass and its digest; `pass check` allows the literal target. The test compares all three returned digests with SHA-256 of the exact file, and checks the consumer results, not just TOML parsing.

This is a read and policy-preview contract, not a live enforcement or network test. Playpen plan does not launch a workload or install a firewall; its coverage reports the `requests` ceiling must be enforced externally. Teapot show/check ran offline, with no engine or Playpen running. This proves neither enforcement startup nor end-to-end spending, and the documentation address is not contacted.

## Provenance

The historical [`inventory.json`](inventory.json) recorded Hallpass HEAD `44f749ac158e8378705bab80d855ed0a1f634a54` and Playpen HEAD `32677f2dde4449d578f9a5bf3417f442c252c7a4`. Teapot used the inventory checkout revision `6238d5a78a6514466d54ad16dd5737f43c1d4961`, tree `a5f74f8849165f9a0aac26881b2f7d95ac7f8b50`. Its `vendor/hallpass` tree is `f81fda56ea746fe9a12ab7fe29be3f0d4b696fb3`; `vendor/README.md` attributes it to Hallpass `df90119121e13205e2a3b69426b4221ae9ef043c` with an added Cargo workspace stanza. Playpen Cargo.toml and Cargo.lock pin Hallpass `05d657aaa214c42db2c4807e965e29080b76c43b` (tree `3f247f65edd122a759c1938b55076c530f61b9b6`). Hallpass and Playpen trees are respectively `e1b62d17b12875500c6c24e8c2b61da6cc56dee8` and `50d324c72b41ebb55c4a0ee2fe011f146b46f1b8`.

The binaries were built offline from `git archive` snapshots, Cargo `--locked`, rustc `1.100.0 (0ef1bc386 2026-11-09)` and cargo `1.100.0 (3acc79c0c 2026-11-05)`. Build outputs were copied immediately to private paths before running the harness. The mutable `.stack-target` was a compilation cache, not an identity pin: Hallpass and Playpen source files were touched to force their package rebuild, and Teapot and its vendored Hallpass compiled from the archived source. The recorded executable hashes identify the binaries actually exercised. Builds on another host need not reproduce those executable hashes.

## Repeat

Prepare the three source archives at the commits above and build offline into a private `CARGO_TARGET_DIR`, using `cargo build --offline --locked --manifest-path <archive>/Cargo.toml --bin hallpass`, the same for Playpen with `--bin playpen`, and for Teapot `-p teapot --bin teapot`. These require the dependencies and Playpen Git pin already cached; no network access is needed. Then run:

```sh
python3 scripts/check-hallpass-copies.py --hallpass /absolute/path/hallpass --playpen /absolute/path/playpen --teapot /absolute/path/teapot
```

The script uses a temporary HOME, XDG directories, project and mode-0600 pass and removes them on exit. It prints machine-readable results and hashes; it fails on CLI errors, unexpected policy results or unequal digests. It does not verify source provenance for supplied binaries: retain build provenance separately and compare their hashes with the captured evidence when reproducing that run.
