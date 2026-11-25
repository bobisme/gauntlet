#!/usr/bin/env python3
"""Refuse a fuzz launch unless the recorded cargo-fuzz driver is installed.

`cargo-fuzz` constructs the instrumented build, owns the libFuzzer flags and
supplies the mutator, so a different driver silently changes what a recorded
run means. The recorded pin is `cargo-fuzz 0.13.1` (docs/dependencies.md and
docs/fuzzing.md). This check runs before the target is compiled or launched, and
only ever asks the driver for its version.
"""

from __future__ import annotations

import subprocess
import sys


PINNED = "cargo-fuzz 0.13.1"
PROBE_TIMEOUT_SECONDS = 120
INSTALL = "cargo install cargo-fuzz --version 0.13.1 --locked"


class ToolchainPinError(Exception):
    """The fuzz driver on PATH is not the recorded one."""


def read_version(cargo: str = "cargo") -> str:
    """Ask the driver for its exact version line, without launching a target."""
    try:
        completed = subprocess.run(
            [cargo, "fuzz", "--version"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        raise ToolchainPinError(
            f"{cargo} is not installed or not on PATH; install the recorded driver "
            f"with: {INSTALL}"
        ) from None
    except OSError as error:
        raise ToolchainPinError(f"cannot run `{cargo} fuzz --version`: {error}") from None
    except subprocess.TimeoutExpired:
        raise ToolchainPinError(
            f"`{cargo} fuzz --version` did not answer within {PROBE_TIMEOUT_SECONDS}s"
        ) from None
    output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    if completed.returncode != 0:
        raise ToolchainPinError(
            f"`{cargo} fuzz --version` exited {completed.returncode}: {first_line(output)}"
        )
    return output


def require_pinned(version: str) -> str:
    """Fail unless `version` is exactly the recorded driver."""
    if version != PINNED:
        raise ToolchainPinError(
            f"refusing to run: expected {PINNED!r}, found {version!r}. "
            f"Install the recorded driver with: {INSTALL}"
        )
    return version


def first_line(text: str) -> str:
    return text.splitlines()[0] if text else "(no output)"


def main(argv: list[str]) -> int:
    cargo = "cargo"
    args = list(argv[1:])
    while args:
        match args[0]:
            case "--cargo":
                if len(args) < 2:
                    print("usage: check-fuzz-toolchain.py [--cargo PATH]", file=sys.stderr)
                    return 2
                cargo = args[1]
                args = args[2:]
            case unknown:
                print(
                    f"usage: check-fuzz-toolchain.py [--cargo PATH]; unknown argument {unknown!r}",
                    file=sys.stderr,
                )
                return 2
    try:
        print(require_pinned(read_version(cargo)))
    except ToolchainPinError as error:
        print(f"cargo-fuzz pin: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
