#!/usr/bin/env python3
"""Fail when the M0 dependency contract drifts or a member bypasses it."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "axum": "=0.8.9",
    "clap": "=4.6.8",
    "flate2": "=1.1.11",
    "futures-util": "=0.3.34",
    "http-body-util": "=0.1.5",
    "regex": "=1.12.3",
    "rusqlite": "=0.43.0",
    "rustix": "=1.1.6",
    "schemars": "=1.2.3",
    "serde": "=1.0.229",
    "serde_json": "=1.0.154",
    "serde_path_to_error": "=0.1.20",
    "sha2": "=0.11.1",
    "tempfile": "=3.27.0",
    "thiserror": "=2.0.21",
    "time": "=0.3.55",
    "tokio": "=1.54.1",
    "toml": "=1.2.1",
    "toml_parser": "=1.1.6",
    "tower": "=0.5.3",
    "tracing": "=0.1.44",
    "tracing-subscriber": "=0.3.23",
    "uuid": "=1.29.3",
}

DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}


def fail(message: str) -> None:
    raise SystemExit(f"dependency pins: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def version(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        item = value.get("version")
        return item if isinstance(item, str) else None
    return None


root = tomllib.loads((ROOT / "Cargo.toml").read_text())
actual = root["workspace"]["dependencies"]
local_workspace_dependencies = {
    name: value
    for name, value in actual.items()
    if isinstance(value, dict) and "path" in value
}
external_workspace_dependencies = {
    name: value for name, value in actual.items() if name not in local_workspace_dependencies
}
require(
    set(external_workspace_dependencies) == set(PINS),
    "external workspace dependency set drifted: "
    f"actual={sorted(external_workspace_dependencies)!r}; expected={sorted(PINS)!r}",
)
for name, expected in PINS.items():
    require(
        version(external_workspace_dependencies[name]) == expected,
        f"{name} must be pinned to {expected}, found {external_workspace_dependencies[name]!r}",
    )


def dependency_tables(manifest: dict, manifest_path: Path):
    for section in sorted(DEPENDENCY_TABLES):
        table = manifest.get(section, {})
        require(isinstance(table, dict), f"{manifest_path}: [{section}] must be a table")
        yield section, table
    targets = manifest.get("target", {})
    require(isinstance(targets, dict), f"{manifest_path}: [target] must be a table")
    for target, target_table in targets.items():
        require(isinstance(target_table, dict), f"{manifest_path}: target {target!r} must be a table")
        for section in sorted(DEPENDENCY_TABLES):
            table = target_table.get(section, {})
            require(
                isinstance(table, dict),
                f"{manifest_path}: [target.{target!r}.{section}] must be a table",
            )
            yield f"target.{target!r}.{section}", table


member_patterns = root["workspace"].get("members", [])
require(isinstance(member_patterns, list), "workspace members must be a list")
member_manifests = set()
for pattern in member_patterns:
    require(isinstance(pattern, str), f"workspace member pattern must be text, found {pattern!r}")
    matches = list(ROOT.glob(pattern))
    require(bool(matches), f"workspace member pattern matched nothing: {pattern!r}")
    for match in matches:
        manifest_path = match / "Cargo.toml" if match.is_dir() else match
        require(manifest_path.is_file(), f"workspace member has no Cargo.toml: {match}")
        member_manifests.add(manifest_path.resolve())

for name, value in local_workspace_dependencies.items():
    path = value.get("path")
    require(isinstance(path, str), f"local workspace dependency {name} has no text path")
    require("git" not in value and "registry" not in value, f"local workspace dependency {name} mixes sources")
    manifest_path = (ROOT / path / "Cargo.toml").resolve()
    require(
        manifest_path in member_manifests,
        f"local workspace dependency {name} must point to a declared member, found {path!r}",
    )

direct_count = 0
for manifest_path in sorted(member_manifests):
    manifest = tomllib.loads(manifest_path.read_text())
    relative = manifest_path.relative_to(ROOT)
    for section, table in dependency_tables(manifest, relative):
        for name, value in table.items():
            direct_count += 1
            require(
                isinstance(value, dict) and value.get("workspace") is True,
                f"{relative}: {section}.{name} bypasses workspace inheritance: {value!r}",
            )
            require(
                "version" not in value and "path" not in value and "git" not in value,
                f"{relative}: {section}.{name} combines workspace inheritance with a direct source",
            )

print(
    f"dependency pins: {len(PINS)} exact external workspace entries and "
    f"{len(local_workspace_dependencies)} local member entries; "
    f"{len(member_manifests)} members inherit all {direct_count} direct dependencies"
)
