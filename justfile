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
    python3 -c "import ast, pathlib; ast.parse(pathlib.Path('scripts/stack-inventory.py').read_text())"
    python3 -c "import ast, pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('fixtures/target').rglob('*.py')]"
    python3 -c "import json, pathlib; d=json.loads(pathlib.Path('docs/inventory.json').read_text()); assert d['schema_version'] == 2 and len(d['tools']) == 10; assert len({x['tool'] for x in d['tools']}) == 10"
    python3 -c "import pathlib; assert '.maw/workspaces' not in pathlib.Path('docs/inventory.json').read_text()"
    python3 -c "import json, pathlib; d=json.loads(pathlib.Path('docs/inventory.json').read_text()); rows={x['tool']: x for x in d['tools']}; assert all(rows[t]['installed']['resolved_path']['base'] == 'project_root' and rows[t]['installed']['resolved_path']['kind'] == 'relative' for t in ('teapot', 'hallpass', 'playpen'))"
    just deps-check
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    just test
