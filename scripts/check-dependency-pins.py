#!/usr/bin/env python3
"""Fail when the M0 dependency contract drifts or a member bypasses it."""

from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "axum": "=0.8.9",
    "base64": "=0.22.1",
    "clap": "=4.6.8",
    "flate2": "=1.1.11",
    "futures-util": "=0.3.34",
    "http-body-util": "=0.1.5",
    "libfuzzer-sys": "=0.4.13",
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

# The nightly toolchain the optional coverage-guided run uses. The stable
# toolchain builds and tests everything else, so the fuzz pin has to be exact
# and documented in one place.
FUZZ_TOOLCHAIN = "nightly-2026-08-21"


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

# Optional parser fuzzing is a pinned dependency like any other: the crate is a
# cargo-fuzz package, every target file is declared, every target gated on the
# `fuzzing` feature that pulls libFuzzer in, every target has a seed corpus, and
# the run pins one documented nightly toolchain.
fuzz_manifest_path = ROOT / "fuzz" / "Cargo.toml"
require(fuzz_manifest_path.is_file(), "fuzz harness manifest is missing")
fuzz_manifest = tomllib.loads(fuzz_manifest_path.read_text())
require(
    fuzz_manifest.get("package", {}).get("metadata", {}).get("cargo-fuzz") is True,
    "fuzz crate must declare [package.metadata] cargo-fuzz = true",
)
require(
    fuzz_manifest.get("features", {}).get("fuzzing") == ["dep:libfuzzer-sys"],
    "the fuzzing feature must be the only place libFuzzer is enabled",
)
bins = fuzz_manifest.get("bin", [])
require(isinstance(bins, list) and bins, "fuzz crate declares no targets")
for entry in bins:
    require(
        isinstance(entry, dict) and entry.get("required-features") == ["fuzzing"],
        f"fuzz target {entry!r} must require the fuzzing feature",
    )
targets = sorted(path.stem for path in (ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
require(
    targets == sorted(entry.get("name") for entry in bins),
    f"fuzz targets drifted from their declarations: {targets!r}",
)
for target in targets:
    seeds = sorted((ROOT / "fuzz" / "corpus" / target).glob("*"))
    require(bool(seeds), f"fuzz target {target} has no seed corpus")
    require(
        all(seed.is_file() for seed in seeds),
        f"fuzz target {target} corpus contains a non-file entry",
    )

justfile = (ROOT / "justfile").read_text()
toolchains = set(re.findall(r"\+nightly-\d{4}-\d{2}-\d{2}", justfile))
require(
    toolchains == {f"+{FUZZ_TOOLCHAIN}"},
    f"justfile must pin exactly +{FUZZ_TOOLCHAIN} for fuzzing, found {sorted(toolchains)!r}",
)
require(
    FUZZ_TOOLCHAIN in (ROOT / "docs" / "dependencies.md").read_text(),
    f"docs/dependencies.md must record the fuzz toolchain {FUZZ_TOOLCHAIN}",
)

# cargo-fuzz is the driver that constructs the instrumented build, so its
# version is pinned like any other dependency: the checker holds the only copy,
# the run recipe must gate on that checker before it compiles or launches a
# target, and the docs record the same version.
CARGO_FUZZ = "cargo-fuzz 0.13.1"
checker = (ROOT / "scripts" / "check-fuzz-toolchain.py").read_text()
require(
    f'PINNED = "{CARGO_FUZZ}"' in checker,
    f"scripts/check-fuzz-toolchain.py must pin {CARGO_FUZZ!r}",
)
require(
    "scripts/check-fuzz-toolchain.py" in justfile,
    "the justfile must gate a fuzz run on scripts/check-fuzz-toolchain.py",
)
check_at = justfile.index("scripts/check-fuzz-toolchain.py")
run_at = justfile.index("fuzz run")
require(
    check_at < run_at,
    "the cargo-fuzz driver check must run before `cargo ... fuzz run`",
)
require(
    CARGO_FUZZ in (ROOT / "docs" / "dependencies.md").read_text(),
    f"docs/dependencies.md must record the cargo-fuzz pin {CARGO_FUZZ}",
)

# The harness inspects captured action replies through scourge-core's own
# decoders, which are compiled only for the inspection feature. A harness that
# dropped the feature would silently stop covering the live action parsers, so
# the wiring is pinned too.
core_manifest = tomllib.loads((ROOT / "crates" / "scourge-core" / "Cargo.toml").read_text())
require(
    "hostile-input" in core_manifest.get("features", {}),
    "scourge-core must declare the hostile-input inspection feature",
)
require(
    fuzz_manifest.get("dependencies", {}).get("scourge-core", {}).get("features")
    == ["hostile-input"],
    "the fuzz crate must enable scourge-core/hostile-input inspection",
)

print(
    f"dependency pins: {len(targets)} fuzz targets on {FUZZ_TOOLCHAIN}, "
    f"each with a seed corpus and the fuzzing feature gate, driven by {CARGO_FUZZ}"
)
