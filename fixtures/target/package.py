#!/usr/bin/env python3
"""Build and launch the development fixture from a referee-owned directory."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile


FIXTURE = Path(__file__).resolve().parent
CHECKOUT = FIXTURE.parents[1]
BINARY = "scourge-fixture"
GROUND_TRUTH = "ground-truth.json"
ADMIN_SECRET = "admin-secret"


def overlaps(left, right):
    return left.is_relative_to(right) or right.is_relative_to(left)


def has_private_alias(agent_tree, package_dir):
    for directory, dirs, files in os.walk(agent_tree, followlinks=False):
        for name in dirs + files:
            entry = Path(directory) / name
            if entry.is_symlink():
                target = entry.resolve()
                if overlaps(target, CHECKOUT) or overlaps(target, package_dir):
                    return True
    return False


def build_package(package_dir):
    package_dir.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix=".build-", dir=package_dir) as build_dir:
            subprocess.run(
                [
                    "cargo", "build", "--locked", "--release", "--package", BINARY,
                    "--bin", BINARY, "--target-dir", build_dir,
                    "--config", 'profile.release.strip="symbols"',
                ],
                cwd=CHECKOUT,
                check=True,
            )
            binary = package_dir / BINARY
            shutil.copyfile(Path(build_dir) / "release" / BINARY, binary)
            binary.chmod(0o700)

        ground_truth = package_dir / GROUND_TRUTH
        shutil.copyfile(FIXTURE / "referee" / GROUND_TRUTH, ground_truth)
        ground_truth.chmod(0o600)
        admin_secret = package_dir / ADMIN_SECRET
        admin_secret.write_text(secrets.token_hex(32) + "\n", encoding="ascii")
        admin_secret.chmod(0o600)
    except (OSError, subprocess.CalledProcessError, KeyboardInterrupt):
        for name in (BINARY, GROUND_TRUTH, ADMIN_SECRET):
            (package_dir / name).unlink(missing_ok=True)
        package_dir.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", required=True, type=Path,
                        help="new directory under an existing referee-controlled parent")
    parser.add_argument("--agent-tree", required=True, type=Path,
                        help="existing directory made available to the assessed agent")
    parser.add_argument("--port", type=int, default=3000,
                        help="loopback TCP port (default: 3000; 0: allocate a port)")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")

    agent_tree = args.agent_tree.resolve()
    package_dir = args.package_dir.resolve()
    if not agent_tree.is_dir():
        parser.error("--agent-tree must be an existing directory")
    if overlaps(package_dir, agent_tree) or overlaps(CHECKOUT, agent_tree):
        parser.error("the checkout and package directory must be outside the agent tree")
    if overlaps(package_dir, CHECKOUT):
        parser.error("the package directory must be outside the source checkout")
    if args.package_dir.is_symlink() or package_dir.exists():
        parser.error("--package-dir must name a new directory")
    if not package_dir.parent.is_dir():
        parser.error("the package directory's parent must exist")
    if has_private_alias(agent_tree, package_dir):
        parser.error("the agent tree links to the checkout or package directory")

    os.umask(0o077)
    os.environ.pop("SCOURGE_FIXTURE_ADMIN_SECRET", None)
    try:
        build_package(package_dir)
        os.chdir(package_dir)
        os.execv(package_dir / BINARY, [BINARY, "--listen", f"127.0.0.1:{args.port}",
                                       "--admin-secret-file", ADMIN_SECRET])
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: fixture package: {error}\n")
    except KeyboardInterrupt:
        parser.exit(130)


if __name__ == "__main__":
    main()
