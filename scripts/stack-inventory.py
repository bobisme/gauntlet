#!/usr/bin/env python3
"""Record local stack identity without inferring executable provenance from a checkout."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

# Research ledger §7: revision 1 and revision 2 source reads respectively.
TOOLS = {
    "teapot": ("teapot", "c90ab5bb", "38d88c50a2"),
    "hallpass": ("hallpass", "0474bb03", "261e74d57d"),
    "playpen": ("playpen", "17ed1c74", "206190c78d"),
    "sippycup": ("sippycup", "26e6391d", "26e6391da9"),
    "edict": ("edict", "3f882a4d", "3f882a4d70"),
    "bones": ("bn", "86de2f86", "86de2f863a"),
    "vessel": ("vessel", "f0ccd685", "f0ccd685a9"),
    "ward": ("ward", None, "9c6bd71c33"),
    "rite": ("rite", None, None),
    "investigation": ("investigation", "plan revision 3", "12c90ab"),
}


def command(argv, cwd=None):
    try:
        result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=15, check=False)
        return {"exit_code": result.returncode, "stdout": result.stdout.rstrip("\n"), "stderr": result.stderr.rstrip("\n")}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"exit_code": None, "stdout": "", "stderr": str(exc)}


def describe_path(path, root):
    path = Path(path)
    try:
        relative = path.relative_to(root)
    except ValueError:
        return {"path": str(path), "kind": "absolute", "base": None}
    return {"path": str(relative), "kind": "relative", "base": "project_root"}


def inventory(src, path, root):
    items = []
    for name, (binary, rev1, rev2) in TOOLS.items():
        checkout = src / name
        head = command(["git", "rev-parse", "HEAD"], checkout) if checkout.is_dir() else None
        status = command(["git", "status", "--porcelain"], checkout) if head and head["exit_code"] == 0 else None
        executable = shutil.which(binary, path=path)
        identity = None
        if executable:
            resolved = Path(executable).resolve()
            try:
                digest = hashlib.file_digest(resolved.open("rb"), "sha256").hexdigest()
            except OSError as exc:
                digest = None
                digest_error = str(exc)
            else:
                digest_error = None
            identity = {"executable_path": describe_path(Path(executable), root),
                        "resolved_path": describe_path(resolved, root), "version": command([executable, "--version"]),
                        "sha256": digest, "digest_error": digest_error, "commit": "unknown"}
        items.append({"tool": name, "research_pin": {"revision_1": rev1, "revision_2": rev2},
                      "checkout": {"path": str(checkout), "head": head["stdout"] if head and head["exit_code"] == 0 else "unknown",
                                   "dirty": bool(status["stdout"]) if status and status["exit_code"] == 0 else None},
                      "installed": identity})
    return {"schema_version": 2, "generated_at": datetime.now(timezone.utc).isoformat(), "research_source": "notes/plan.research.md section 7", "tools": items, "advice": []}


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Example: python3 scripts/stack-inventory.py --output docs/inventory.json")
    parser.add_argument("--source-root", type=Path, default=Path.home() / "src", help="directory containing tool checkouts (default: ~/src)")
    parser.add_argument("--output", type=Path, default=Path("docs/inventory.json"), help="output JSON path (default: docs/inventory.json)")
    args = parser.parse_args()
    # Prefer project-local builds even without mise activation.
    root = Path(__file__).resolve().parent.parent
    path = str(root / ".stack-target" / "debug") + os.pathsep + os.environ.get("PATH", "")
    data = inventory(args.source_root.expanduser().resolve(), path, root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
