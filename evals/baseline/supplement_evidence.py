#!/usr/bin/env python3
"""Preserve workspace files that an earlier evidence copy did not carry.

The first runner's `copy_evidence` copied only top-level workspace files, so
nested agent-created files were left behind in retained run roots. This script
copies every remaining regular file from each run root's workspace (excluding
the Teapot instrument store) into a new `workspace-supplement/` directory
beside the original evidence. It never edits `run.json`, `ledger.jsonl`,
`SHA256SUMS.json` or any original evidence file.

It uses the same no-follow, no-escape walker as the runner: symlinks are
skipped and recorded, not followed, and no destination may leave the evidence
root. The supplementary tree is hashed separately.
"""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evidence_paths as ep  # noqa: E402


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    ledger_path = args.ledger.resolve()
    if ledger_path.is_symlink() or not ledger_path.is_file():
        raise SystemExit(f"ledger is missing or a symlink: {ledger_path}")
    rows = [
        json.loads(line)
        for line in ep.read_regular_nofollow(ledger_path).decode("utf-8").splitlines()
        if line.strip()
    ]
    report = {"schema_version": 1, "collection_change": "workspace-supplement-v1", "runs": []}
    for row in rows:
        try:
            label = ep.safe_label(row["trial_label"])
        except ep.PathSafetyError as error:
            raise SystemExit(f"unsafe trial label: {error}") from error
        run_root = Path(row["run_root"])
        source = run_root / "workspace"
        if source.is_symlink():
            raise SystemExit(f"workspace is a symlink; refusing to read: {source}")
        target = ep.safe_join(ep.safe_join(evidence, label), "workspace-supplement")
        if target.is_symlink():
            raise SystemExit(f"supplement target is a symlink: {target}")
        if target.exists():
            raise SystemExit(f"refusing to overwrite existing supplement: {target}")
        entry = {
            "trial_label": label,
            "schedule_position": row["schedule_position"],
            "assigned_arm": row["assigned_arm"],
            "run_root": str(run_root),
            "source_workspace_present": source.is_dir(),
            "files": {},
            "skipped": [],
            "total_bytes": 0,
        }
        if source.is_dir():
            try:
                result = ep.copy_workspace_tree(source, target)
            except ep.PathSafetyError as error:
                raise SystemExit(f"{label}: unsafe workspace copy: {error}") from error
            entry["files"] = result["files"]
            entry["skipped"] = result["skipped"]
            entry["total_bytes"] = result["total_bytes"]
        else:
            target.mkdir(parents=True, exist_ok=True)
            entry["skipped"] = [{"path": ".", "reason": "workspace-missing"}]
        manifest = target / "SUPPLEMENT.json"
        if manifest.is_symlink():
            raise SystemExit(f"supplement manifest is a symlink: {manifest}")
        write_json(manifest, entry)
        report["runs"].append(entry)
    output = ep.safe_join(evidence, "workspace-supplement.json")
    if output.is_symlink():
        raise SystemExit(f"supplement report is a symlink: {output}")
    write_json(output, report)
    print(json.dumps({"runs": len(report["runs"]), "report": str(output)}, sort_keys=True))


if __name__ == "__main__":
    main()
