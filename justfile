# Validate the checked-in inventory and helper scripts.
check:
    bash -n scripts/build-stack.sh
    python3 -c "import ast, pathlib; ast.parse(pathlib.Path('scripts/stack-inventory.py').read_text())"
    python3 -c "import json, pathlib; d=json.loads(pathlib.Path('docs/inventory.json').read_text()); assert d['schema_version'] == 2 and len(d['tools']) == 10; assert len({x['tool'] for x in d['tools']}) == 10"
    python3 -c "import pathlib; assert '.maw/workspaces' not in pathlib.Path('docs/inventory.json').read_text()"
    python3 -c "import json, pathlib; d=json.loads(pathlib.Path('docs/inventory.json').read_text()); rows={x['tool']: x for x in d['tools']}; assert all(rows[t]['installed']['resolved_path']['base'] == 'project_root' and rows[t]['installed']['resolved_path']['kind'] == 'relative' for t in ('teapot', 'hallpass', 'playpen'))"
