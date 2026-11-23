#!/usr/bin/env python3
"""Capture reproducible fresh-project evidence for the M0 inventory projector.

This is qualification of the prelaunch inventory contract only. It starts no
assessment agent and sends no traffic to the target. The output directory must
not exist so an earlier evidence set is never silently overwritten.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

M0 = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(M0))

import project_inventory  # noqa: E402


PINNED_TEAPOT_SHA256 = "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"
APPROVAL_SOURCE = ROOT / "fixtures/target/example/passes/staging.toml"
INVENTORY_COMMANDS = {
    "version": ("version",),
    "projects_list": ("projects", "list"),
    "projects_show": ("projects", "show"),
    "proxy_status": ("proxy", "status"),
    "pass_show": ("pass", "show"),
    "scope_list": ("scope", "list"),
    "hosts_list": ("hosts", "list"),
    "flows_list": ("flows", "list"),
    "findings_list": ("findings", "list"),
    "leads_list": ("leads", "list"),
    "sessions_list": ("sessions", "list"),
    "rules_list": ("rules", "list"),
    "intercept_status": ("intercept", "status"),
    "intercept_rules_list": ("intercept", "rules", "list"),
    "intercept_queue_list": ("intercept", "queue", "list"),
    "scripts_list": ("scripts", "list"),
    "scripts_approvals": ("scripts", "approvals"),
    "config_list": ("config", "list"),
    "macros_list": ("macros", "list"),
    "jobs_list": ("jobs", "list"),
    "sitemap_show": ("sitemap", "show"),
    "authz_matrix": ("authz", "matrix"),
    "checks_list": ("checks", "list"),
    "commands_list": ("commands", "list"),
}
SCHEMA_COMMANDS = dict(INVENTORY_COMMANDS)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class Recorder:
    def __init__(self, teapot, env):
        self.teapot = teapot
        self.env = env
        self.rows = []

    def run(self, label, argv):
        completed = subprocess.run(
            [str(part) for part in argv],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            check=False,
        )
        self.rows.append(
            {
                "label": label,
                "argv": [str(part) for part in argv],
                "exit": completed.returncode,
                "stdout_sha256": sha256_bytes(completed.stdout.encode()),
                "stderr": completed.stderr,
            }
        )
        if completed.returncode:
            raise RuntimeError(f"{label} failed ({completed.returncode}): {completed.stderr}")
        return completed.stdout

    def teapot_json(self, label, project, words):
        stdout = self.run(label, [self.teapot, "--project", project, "--json", *words])
        return json.loads(stdout)


def clean_environment(run_root):
    paths = {
        "HOME": run_root / "home",
        "XDG_CONFIG_HOME": run_root / "config",
        "XDG_STATE_HOME": run_root / "state",
        "XDG_DATA_HOME": run_root / "data",
    }
    initial = {name: not path.exists() for name, path in paths.items()}
    for path in paths.values():
        path.mkdir(mode=0o700)
    empty = {name: list(path.iterdir()) == [] for name, path in paths.items()}
    env = {
        "HOME": str(paths["HOME"]),
        "XDG_CONFIG_HOME": str(paths["XDG_CONFIG_HOME"]),
        "XDG_STATE_HOME": str(paths["XDG_STATE_HOME"]),
        "XDG_DATA_HOME": str(paths["XDG_DATA_HOME"]),
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    return env, paths, initial, empty


def cleanup_run(recorder, project, run_root, start_attempted, output, label):
    cleanup = {
        "success": False,
        "proxy_stop_attempted": start_attempted,
        "proxy_stopped": not start_attempted,
        "proxy_status_verified": not start_attempted,
        "run_root_removal_attempted": False,
        "run_root_removed": False,
        "errors": [],
    }
    if start_attempted:
        try:
            stopped = recorder.teapot_json("cleanup: proxy stop", project, ("proxy", "stop"))
            if stopped.get("proxy", {}).get("stopped") is not True:
                raise RuntimeError("proxy stop did not confirm stopped=true")
        except Exception as error:
            recorder.rows.append({"label": "cleanup failure", "error": str(error)})
            cleanup["errors"].append(f"proxy stop: {error}")
        try:
            status = recorder.teapot_json("cleanup: proxy status", project, ("proxy", "status"))
            running = status.get("proxy", {}).get("running")
            if running is not False:
                raise RuntimeError(f"proxy status did not confirm running=false: {running!r}")
            cleanup["proxy_stopped"] = True
            cleanup["proxy_status_verified"] = True
        except Exception as error:
            recorder.rows.append({"label": "cleanup verification failure", "error": str(error)})
            cleanup["errors"].append(f"proxy status: {error}")
    write_json(output / label / "commands.json", recorder.rows)
    if cleanup["proxy_status_verified"]:
        cleanup["run_root_removal_attempted"] = True
        try:
            shutil.rmtree(run_root)
            cleanup["run_root_removed"] = not run_root.exists()
            if not cleanup["run_root_removed"]:
                cleanup["errors"].append("run root still exists after removal")
        except Exception as error:
            cleanup["errors"].append(f"run root removal: {error}")
    cleanup["success"] = cleanup["proxy_stopped"] and cleanup["proxy_status_verified"] and cleanup["run_root_removed"] and not cleanup["errors"]
    write_json(output / label / "cleanup.json", cleanup)
    if not cleanup["success"]:
        raise RuntimeError(f"{label} cleanup failed: {cleanup['errors']}")


def capture_run(label, teapot, output):
    run_root = Path(tempfile.mkdtemp(prefix=f"scourge-m0-{label}-"))
    run_root_initially_empty = list(run_root.iterdir()) == []
    project = run_root / "project"
    approval_dir = run_root / "approval"
    approval = approval_dir / "staging.toml"
    env, env_paths, env_absent, env_empty = clean_environment(run_root)
    recorder = Recorder(teapot, env)
    project_preexisting = project.exists()
    approval_dir_preexisting = approval_dir.exists()
    approval_preexisting = approval.exists()
    start_attempted = False
    try:
        recorder.teapot_json("setup: projects init", project, ("projects", "init"))
        approval_dir.mkdir(mode=0o700)
        shutil.copyfile(APPROVAL_SOURCE, approval)
        approval.chmod(0o600)
        recorder.teapot_json("setup: pass attach", project, ("pass", "attach", str(approval)))
        recorder.teapot_json("setup: scope add", project, ("scope", "add", "127.0.0.1"))
        start_attempted = True
        recorder.teapot_json(
            "setup: proxy start",
            project,
            ("proxy", "start", "--listen", "127.0.0.1:0", "--detach", "--pass", str(approval), "--no-enforce"),
        )

        raw = {
            name: recorder.teapot_json(f"capture: {' '.join(words)}", project, words)
            for name, words in INVENTORY_COMMANDS.items()
        }
        projection, digest = project_inventory.project_inventory(raw, output / "schemas")
        raw_path = output / label / "raw-inventory.json"
        projected_path = output / label / "projected.json"
        creation_path = output / label / "creation-evidence.json"
        write_json(raw_path, raw)
        write_json(
            projected_path,
            {"schema_version": project_inventory.SCHEMA_VERSION, "sha256": digest, "projection": projection},
        )
        project_files = sorted(
            str(path.relative_to(project)) for path in project.rglob("*") if path.is_file()
        )
        creation = {
            "schema_version": 1,
            "run": label,
            "run_root": str(run_root),
            "project": str(project),
            "approval": str(approval),
            "before_setup": {
                "run_root_initially_empty": run_root_initially_empty,
                "project_absent": not project_preexisting,
                "approval_directory_absent": not approval_dir_preexisting,
                "approval_absent": not approval_preexisting,
                "environment_directories_absent": env_absent,
            },
            "fresh_environment_directories_empty": env_empty,
            "environment": {name: str(path) for name, path in env_paths.items()},
            "after_setup": {
                "project_exists": project.exists(),
                "project_id": raw["projects_list"]["projects"][0]["id"],
                "project_files": project_files,
                "approval_mode": oct(approval.stat().st_mode & 0o777),
                "approval_sha256": sha256_file(approval),
            },
            "raw_inventory_sha256": sha256_file(raw_path),
            "projected_sha256": sha256_file(projected_path),
            "semantic_projection_sha256": digest,
        }
        write_json(creation_path, creation)
        return {
            "label": label,
            "run_root": str(run_root),
            "project": str(project),
            "approval": str(approval),
            "project_id": creation["after_setup"]["project_id"],
            "raw_inventory": str(raw_path.relative_to(output)),
            "raw_inventory_sha256": sha256_file(raw_path),
            "projected": str(projected_path.relative_to(output)),
            "projected_sha256": sha256_file(projected_path),
            "creation_evidence": str(creation_path.relative_to(output)),
            "creation_evidence_sha256": sha256_file(creation_path),
            "semantic_projection_sha256": digest,
            "eligible": projection["prelaunch"]["eligible"],
        }
    finally:
        cleanup_run(recorder, project, run_root, start_attempted, output, label)


def capture_schemas(teapot, output):
    schema_dir = output / "schemas"
    schema_dir.mkdir(parents=True)
    env = {"HOME": str(output / "schema-home"), "NO_COLOR": "1", "TERM": "dumb"}
    rows = []
    files = {}
    for name, words in SCHEMA_COMMANDS.items():
        completed = subprocess.run(
            [str(teapot), "--json", "schema", *words],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
        rows.append(
            {
                "command": " ".join(words),
                "argv": [str(teapot), "--json", "schema", *words],
                "exit": completed.returncode,
                "stderr": completed.stderr,
            }
        )
        if completed.returncode:
            raise RuntimeError(f"schema {' '.join(words)} failed: {completed.stderr}")
        path = schema_dir / f"{name.replace('_', '-')}.json"
        write_json(path, json.loads(completed.stdout))
        files[str(path.relative_to(output))] = sha256_file(path)
    write_json(output / "schema-commands.json", rows)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--teapot", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    teapot = args.teapot.resolve()
    output = args.output_dir.resolve()
    if output.exists():
        parser.error(f"output directory already exists: {output}")
    if sha256_file(teapot) != PINNED_TEAPOT_SHA256:
        parser.error("Teapot binary does not match the locked SHA-256")
    version = subprocess.run(
        [str(teapot), "--version"], capture_output=True, text=True, timeout=10, check=True
    ).stdout.strip()
    if version != "teapot 0.1.0":
        parser.error(f"unexpected Teapot version: {version}")
    output.mkdir(parents=True)
    schema_files = capture_schemas(teapot, output)
    runs = [capture_run(label, teapot, output) for label in ("run-a", "run-b")]
    command_files = {}
    command_files["schema-commands.json"] = sha256_file(output / "schema-commands.json")
    for label in ("run-a", "run-b"):
        for name in ("commands.json", "cleanup.json"):
            path = output / label / name
            command_files[str(path.relative_to(output))] = sha256_file(path)
    equal = runs[0]["semantic_projection_sha256"] == runs[1]["semantic_projection_sha256"]
    unique = len({row["run_root"] for row in runs}) == len(runs) and len(
        {row["project_id"] for row in runs}
    ) == len(runs)
    manifest = {
        "schema_version": 1,
        "purpose": "real fresh-project twin qualification; no assessment agent or target traffic",
        "capture_script": "evals/m0-baseline/qualification/capture_fresh_pair.py",
        "capture_script_sha256": sha256_file(Path(__file__)),
        "teapot": {
            "path": str(teapot),
            "version_stdout": version,
            "sha256": sha256_file(teapot),
        },
        "approval_source": str(APPROVAL_SOURCE.relative_to(ROOT)),
        "approval_source_sha256": sha256_file(APPROVAL_SOURCE),
        "inventory_commands": [" ".join(words) for words in INVENTORY_COMMANDS.values()],
        "schema_files": schema_files,
        "supporting_files": command_files,
        "runs": runs,
        "attestation": {
            "fresh_roots_and_project_ids_unique": unique,
            "raw_inventory_hashes_distinct": runs[0]["raw_inventory_sha256"]
            != runs[1]["raw_inventory_sha256"],
            "semantic_projections_equal": equal,
            "semantic_projection_sha256": runs[0]["semantic_projection_sha256"] if equal else None,
            "both_prelaunch_eligible": all(row["eligible"] for row in runs),
            "all_cleanup_succeeded": all(
                json.loads((output / row["label"] / "cleanup.json").read_text())["success"]
                for row in runs
            ),
            "assessment_agents_started": 0,
            "target_requests_sent": 0,
        },
    }
    write_json(output / "manifest.json", manifest)
    if not all(
        manifest["attestation"][key]
        for key in (
            "fresh_roots_and_project_ids_unique",
            "raw_inventory_hashes_distinct",
            "semantic_projections_equal",
            "both_prelaunch_eligible",
            "all_cleanup_succeeded",
        )
    ):
        raise SystemExit("fresh-project qualification failed; inspect manifest.json")
    print(json.dumps(manifest["attestation"], sort_keys=True))


if __name__ == "__main__":
    main()
