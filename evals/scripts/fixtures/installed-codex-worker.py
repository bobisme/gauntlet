#!/usr/bin/env python3
"""Run the pinned Codex binary behind the offline qualification forwarder."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


FORWARDER = "/opt/adapter/native-responses-forwarder.py"
READY = Path("/runtime/forwarder.ready")
ARTIFACTS = Path("/runtime/artifacts")
PROMPT = (
    b"Use exec_command to write exactly 'offline Codex tool roundtrip' followed by a newline "
    b"to /workspace/installed-codex-tool-roundtrip.txt, then confirm completion.\n"
)


def main(argv: list[str]) -> int:
    if not argv or argv[0] != "/opt/scourge-bin/codex":
        raise SystemExit("expected the exact mounted Codex command")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    forwarder = subprocess.Popen([sys.executable, "-I", FORWARDER])
    completed = None
    try:
        deadline = time.monotonic() + 5
        while not READY.is_file():
            if forwarder.poll() is not None:
                raise RuntimeError("forwarder exited before readiness")
            if time.monotonic() >= deadline:
                raise RuntimeError("forwarder readiness timeout")
            time.sleep(0.02)
        completed = subprocess.run(
            argv,
            input=PROMPT,
            capture_output=True,
            check=False,
            timeout=45,
        )
        (ARTIFACTS / "codex.stdout").write_bytes(completed.stdout)
        (ARTIFACTS / "codex.stderr").write_bytes(completed.stderr)
    finally:
        forwarder.terminate()
        try:
            forwarder_exit = forwarder.wait(timeout=3)
        except subprocess.TimeoutExpired:
            forwarder.kill()
            forwarder_exit = forwarder.wait(timeout=3)

    assert completed is not None
    final_path = Path(argv[argv.index("--output-last-message") + 1])
    final_data = final_path.read_bytes() if final_path.is_file() else b""
    receipt = {
        "schema": "scourge.installed-codex-worker",
        "schema_version": 1,
        "codex": {
            "attempted": True,
            "exit_code": completed.returncode,
            "stdout_bytes": len(completed.stdout),
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_bytes": len(completed.stderr),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        },
        "forwarder": {
            "attempted": True,
            "stopped": forwarder.poll() is not None,
            "exit_code": forwarder_exit if forwarder_exit >= 0 else 128 - forwarder_exit,
        },
        "final_message": {
            "present": final_path.is_file(),
            "bytes": len(final_data),
            "sha256": hashlib.sha256(final_data).hexdigest(),
        },
    }
    (ARTIFACTS / "installed-codex-worker.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
