# All Rust tests. The external fixture acceptance is `just fixture-check`.
test:
    cargo test --workspace --all-targets --locked
    cargo test --workspace --doc --locked
    python3 -B fixtures/contracts/evidence/run.py --self-test

# Build and run the local fixture in a new directory outside the agent tree.
[positional-arguments]
fixture package_dir agent_tree port="3000":
    python3 fixtures/target/package.py --package-dir "$1" --agent-tree "$2" --port "$3"

# Build and check the external fixture and public engagement over loopback.
fixture-check:
    python3 -B fixtures/target/check-package.py

# Exercise the dry harness and live-hook preflight without a model.
eval-check:
    evals/scripts/selftest.sh

# Exercise all eight M0 custody attacks against disposable success, refusal,
# and missing-precondition contexts. This does not qualify a custody tier.
tamper-check:
    python3 -B scripts/test-tamper-attempts.py

# Verify frozen M0 A/B materials and their only assigned difference.
baseline-check:
    python3 -B evals/m0-baseline/check-materials.py
    python3 -B evals/m0-baseline/test_project_inventory.py
    python3 -B evals/baseline/check_failure_taxonomy.py
    python3 -B evals/baseline/test_failure_taxonomy.py

# Check the frozen surface, verifier, evidence and native argv contracts.
cross-lane-check:
    python3 -B scripts/test-cross-lane-contracts.py

# Run the local M0.5.3 custody matrix. Needs rootless Podman, the cached worker
# image and Teapot/Hallpass binaries matching the committed pins; no network.
[positional-arguments]
tamper-matrix teapot hallpass:
    python3 -B scripts/tamper-matrix.py --teapot "$teapot" --hallpass "$hallpass"

# Validate the committed tamper-matrix observation and its deterministic logic.
tamper-matrix-check:
    python3 -B scripts/test-tamper-matrix.py

# Static gate for the M0.4.3 real-application smoke: frozen inputs, target pin,
# assignment parity, and the consistency of every committed session record. No
# network, no container, no model.
realapp-check:
    python3 -B evals/realapp/check_materials.py
    python3 -B evals/realapp/test_run_smoke.py

# Validate the frozen v1 oracle contracts and mutation-check inventory.
oracle-spec-check:
    python3 -B scripts/check-oracle-specifications.py
    python3 -B scripts/test-oracle-specifications.py

# Check the M0 evidence decision, frozen-contract routes and complete M1 keep set.
m1-recut-check:
    python3 -B scripts/check-m1-recut.py
    python3 -B scripts/test-m1-recut.py

# Validate the versioned engagement, policy rule and claim template contracts.
schema-check:
    python3 -B scripts/check-schema-contracts.py

# Static dependency contract. This does not need an advisory database.
deps-check:
    python3 scripts/check-dependency-pins.py

# Explicit local supply-chain gate. `--offline` deliberately uses the
# operator's cached RustSec database; docs/dependencies.md records the pin.
audit:
    cargo deny --offline --locked check advisories licenses sources

# Required pre-commit checks, including stack-inventory validation.
check:
    bash -n scripts/build-stack.sh
    bash -n evals/scripts/run.sh
    bash -n evals/scripts/lib/common.sh
    bash -n evals/scripts/lib/codex-agent.sh
    bash -n evals/scripts/selftest.sh
    bash -n evals/scripts/test-scripted.sh
    python3 -c "import ast, pathlib; ast.parse(pathlib.Path('scripts/stack-inventory.py').read_text())"
    python3 -B scripts/test-candidate-topology.py
    python3 -B scripts/check-baseline-adr.py
    python3 -B scripts/test-baseline-adr.py
    just cross-lane-check
    just oracle-spec-check
    just m1-recut-check
    just schema-check
    just tamper-check
    just tamper-matrix-check
    python3 -c "import ast, pathlib; [ast.parse(p.read_text()) for root in ('fixtures/target', 'evals/scripts', 'evals/baseline', 'evals/realapp') for p in pathlib.Path(root).rglob('*.py')]"
    python3 -B evals/baseline/test_evidence_paths.py
    python3 -B evals/baseline/test_ledger_amendments.py
    python3 -B evals/baseline/check_failure_taxonomy.py
    bash -n evals/baseline/worker/entry.sh
    bash -n evals/baseline/worker/bin/bash
    bash -n evals/baseline/worker/bin/teapot
    bash -n evals/baseline/worker/bin/curl
    bash -n evals/baseline/worker/bin/jq
    python3 -B evals/m0-baseline/check-materials.py
    python3 -B evals/m0-baseline/test_project_inventory.py
    python3 -B evals/realapp/check_materials.py
    python3 -B evals/realapp/test_run_smoke.py
    python3 -c "import json, pathlib; d=json.loads(pathlib.Path('docs/inventory.json').read_text()); assert d['schema_version'] == 2 and len(d['tools']) == 10; assert len({x['tool'] for x in d['tools']}) == 10"
    python3 -c "import pathlib; assert '.maw/workspaces' not in pathlib.Path('docs/inventory.json').read_text()"
    python3 -c "import json, pathlib; d=json.loads(pathlib.Path('docs/inventory.json').read_text()); rows={x['tool']: x for x in d['tools']}; assert all(rows[t]['installed']['resolved_path']['base'] == 'project_root' and rows[t]['installed']['resolved_path']['kind'] == 'relative' for t in ('teapot', 'hallpass', 'playpen'))"
    just deps-check
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    just test
