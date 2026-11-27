#!/usr/bin/env python3
"""Real offline rootless-Podman qualification for the skeleton collector."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import skeleton_process_monitor as monitor  # noqa: E402


IMAGE = "docker.io/library/python:3.12-alpine"
IMAGE_ID = "28eb0cb65acb65b970e85c0dc57d10067868fae8dd00d072413df273132123ac"
CC_PATH = "/usr/bin/gcc"
CC_SHA256 = "8aac907d6fbf40394b424b5fa4a2ad1aa291dac7d3a0315c5b415c1f5ace1287"
PYTHON_PATH = "/usr/local/bin/python3"
PYTHON_RESOLVED_PATH = "/usr/local/bin/python3.12"
SHELL_PATH = "/bin/sh"
SHELL_RESOLVED_PATH = "/bin/busybox"
PROBE_PATH = "/opt/scourge-bin/scourge"
TEAPOT_PATH = "/runtime/bound-tools/teapot"
INVESTIGATION_PATH = "/runtime/bound-tools/investigation"
CANARY = "MONITOR-CREDENTIAL-CANARY-DO-NOT-RETAIN"
WORKER_ENVIRONMENT = {
    "CODEX_HOME": "/runtime/codex-home",
    "HOME": "/runtime/home",
    "HOSTNAME": "scourge-worker",
    "LANG": "C.UTF-8",
    "NO_COLOR": "1",
    "PATH": "/opt/scourge-bin:/usr/bin:/bin",
    "TERM": "dumb",
    "TMPDIR": "/runtime/tmp",
    "XDG_CACHE_HOME": "/runtime/cache",
    "XDG_CONFIG_HOME": "/runtime/config",
    "XDG_DATA_HOME": "/runtime/data",
    "XDG_RUNTIME_DIR": "/runtime/run",
    "XDG_STATE_HOME": "/runtime/state",
}

PROBE_SOURCE = r'''#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(const char *path, int fd_lane, int investigation) {
    int output[2];
    if (pipe(output) != 0) return 70;
    int executable = -1;
    if (fd_lane) {
        executable = open(path, O_RDONLY);
        if (executable < 0) return 71;
    }
    pid_t pid = fork();
    if (pid < 0) return 72;
    if (pid == 0) {
        close(output[0]);
        if (dup2(output[1], STDOUT_FILENO) < 0) _exit(73);
        close(output[1]);
        char proc[64];
        const char *program = path;
        if (fd_lane) {
            snprintf(proc, sizeof(proc), "/proc/self/fd/%d", executable);
            program = proc;
        }
        if (investigation) {
            char *args[] = {(char *)program, "--format", "json", "--actor", "agent:scourge",
                "--workspace", "/workspace", "capture", "begin", "--input", "-", NULL};
            execv(program, args);
        } else {
            char *args[] = {(char *)path, "--json", "rules", "list", NULL};
            execv(program, args);
        }
        _exit(74);
    }
    close(output[1]);
    char buffer[1024];
    while (read(output[0], buffer, sizeof(buffer)) > 0) {}
    close(output[0]);
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 75;
    return puts("child-ok") < 0 ? 76 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    if (strcmp(argv[1], "fail") == 0) return 7;
    if (strcmp(argv[1], "teapot") == 0) return child("/runtime/bound-tools/teapot", 0, 0);
    if (strcmp(argv[1], "teapot-fd") == 0) return child("/runtime/bound-tools/teapot", 1, 0);
    if (strcmp(argv[1], "investigation-fd") == 0) return child("/runtime/bound-tools/investigation", 1, 1);
    if (strcmp(argv[1], "upper") == 0) {
        int value;
        while ((value = getchar()) != EOF) putchar(toupper((unsigned char)value));
        return ferror(stdin) || ferror(stdout) ? 74 : 0;
    }
    if (printf("%s\n", argv[1]) < 0) return 74;
    return 0;
}
'''

FAKE_CODEX = r'''import json, subprocess, sys
sys.stdin.buffer.read()
commands = [
    "/opt/scourge-bin/scourge direct",
    "/bin/sh -c '/opt/scourge-bin/scourge shell'",
    "/opt/scourge-bin/scourge piped | /opt/scourge-bin/scourge upper",
    "/opt/scourge-bin/scourge transformed | /opt/scourge-bin/scourge upper",
    "/opt/scourge-bin/scourge redirected > /workspace/redirected.txt",
    "/opt/scourge-bin/scourge fail",
    "/opt/scourge-bin/scourge short-lived",
    "/opt/scourge-bin/scourge teapot",
    "/opt/scourge-bin/scourge teapot-fd",
    "/opt/scourge-bin/scourge investigation-fd",
]
print(json.dumps({"type":"thread.started","thread_id":"qualification-session"}, separators=(",", ":")), flush=True)
for number, command in enumerate(commands, 1):
    result = subprocess.run(command, shell=True, capture_output=True, text=True, cwd="/workspace")
    item = {
        "id": f"command-{number}", "type": "command_execution", "command": command,
        "aggregated_output": result.stdout + result.stderr, "exit_code": result.returncode,
        "status": "completed" if result.returncode == 0 else "failed",
    }
    print(json.dumps({"type":"item.completed","item":item}, separators=(",", ":")), flush=True)
'''


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as reader:
        for block in iter(lambda: reader.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, **kwargs)


def image_pins() -> tuple[str, str]:
    inspected = run(
        ["/usr/bin/podman", "--remote=false", "image", "inspect", "--format", "{{.Id}}", IMAGE],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if inspected != IMAGE_ID:
        raise RuntimeError(f"cached image pin mismatch: {inspected}")
    output = run(
        [
            "/usr/bin/podman", "--remote=false", "run", "--rm", "--pull=never",
            "--network=none", "--read-only", "--http-proxy=false", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--entrypoint", "/bin/sh", IMAGE,
            "-c", f"sha256sum {PYTHON_PATH} /bin/busybox",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.splitlines()
    values = [line.split()[0] for line in output]
    if len(values) != 2 or not all(len(value) == 64 for value in values):
        raise RuntimeError("could not pin image executables")
    return values[0], values[1]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        raise RuntimeError("qualification must use rootless Podman")
    rootless = run(
        ["/usr/bin/podman", "--remote=false", "info", "--format", "{{.Host.Security.Rootless}}"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if rootless != "true":
        raise RuntimeError("rootless Podman is required")
    python_digest, shell_digest = image_pins()
    compiler = shutil.which("cc")
    if (compiler is None or os.path.realpath(compiler) != CC_PATH
            or sha256(Path(CC_PATH)) != CC_SHA256):
        raise RuntimeError("offline qualification requires the pinned host C compiler")
    compiler = CC_PATH

    with tempfile.TemporaryDirectory(prefix="scourge-process-monitor-") as directory:
        root = Path(directory).resolve()
        os.chmod(root, 0o700)
        control = root / "control"
        evidence = root / "evidence"
        retained = evidence / "qualification-attempt" / "retained" / "artifacts"
        workspace = root / "workspace"
        for path in (
            control, evidence, evidence / "qualification-attempt",
            evidence / "qualification-attempt" / "retained", retained, workspace,
        ):
            path.mkdir(mode=0o700)
        source = root / "probe.c"
        source.write_text(PROBE_SOURCE, encoding="ascii")
        probe = root / "probe"
        run([compiler, "-static", "-O2", "-fno-ident", "-o", str(probe), str(source)], timeout=60)
        os.chmod(probe, 0o500)
        bound_tools = root / "bound-tools"
        bound_tools.mkdir(mode=0o700)
        for name in ("teapot", "investigation"):
            bound = bound_tools / name
            shutil.copyfile(probe, bound)
            os.chmod(bound, 0o500)
        fake = root / "fake-codex.py"
        fake.write_text(FAKE_CODEX, encoding="ascii")
        os.chmod(fake, 0o400)
        probe_digest = sha256(probe)
        worker_environment = monitor.worker_environment_rows(WORKER_ENVIRONMENT)
        name = "scourge-process-monitor-qualification"
        cidfile = control / "worker.cid"
        command = [
            "/usr/bin/podman", "--remote=false", "--runtime=/usr/bin/crun", "run", "--rm",
            "--unsetenv-all", "--interactive", "--pull=never", "--network=none",
            "--read-only", "--http-proxy=false", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--userns=keep-id",
            "--hostname=scourge-worker", "--name", name, "--cidfile", str(cidfile),
            "--mount", f"type=bind,src={probe},dst={PROBE_PATH},ro=true",
            "--mount", f"type=bind,src={bound_tools},dst=/runtime/bound-tools,ro=true",
            "--mount", f"type=bind,src={fake},dst=/opt/collector/fake-codex.py,ro=true",
            "--mount", f"type=bind,src={workspace},dst=/workspace",
        ]
        for environment_name, environment_value in worker_environment:
            command.extend(("--env", f"{environment_name}={environment_value}"))
        command.extend((
            "--entrypoint", PYTHON_PATH, IMAGE_ID, "-I", "-B", "/opt/collector/fake-codex.py",
            "--disable", "code_mode", "--disable", "code_mode_host",
            "--disable", "shell_snapshot", "-",
        ))
        pins = (
            monitor.ExecutablePin(PYTHON_PATH, python_digest, "image"),
            monitor.ExecutablePin(PYTHON_RESOLVED_PATH, python_digest, "image"),
            monitor.ExecutablePin(SHELL_PATH, shell_digest, "image"),
            monitor.ExecutablePin(SHELL_RESOLVED_PATH, shell_digest, "image"),
            monitor.ExecutablePin(PROBE_PATH, probe_digest, "read-only-mount"),
            monitor.ExecutablePin(TEAPOT_PATH, probe_digest, "read-only-mount"),
            monitor.ExecutablePin(INVESTIGATION_PATH, probe_digest, "read-only-mount"),
        )
        config = monitor.MonitorConfig(
            "/usr/bin/strace", "/usr/bin/podman", "/usr/bin/crun",
            PYTHON_PATH, PROBE_PATH, pins, monitor.podman_argv_digest(command),
            worker_environment=worker_environment,
            teapot_path=TEAPOT_PATH, teapot_sha256=probe_digest,
            investigation_path=INVESTIGATION_PATH, investigation_sha256=probe_digest,
            qualification_child_pins=True,
        )
        frozen = monitor.freeze_monitor(config)
        key = monitor.create_monitor_key(control)
        prior = os.environ.get("SCOURGE_MONITOR_CREDENTIAL_CANARY")
        os.environ["SCOURGE_MONITOR_CREDENTIAL_CANARY"] = CANARY
        try:
            result = monitor.run_monitored(
                command,
                prompt=b"offline qualification prompt\n",
                config=config,
                attempt_id="qualification-attempt",
                assignment_sha256="a" * 64,
                key_path=key,
                private_control_root=control,
                evidence_root=evidence,
                retained_path="qualification-attempt/retained/artifacts",
                forbidden_canaries=(CANARY.encode(),),
                timeout_seconds=120,
            )
        finally:
            if prior is None:
                os.environ.pop("SCOURGE_MONITOR_CREDENTIAL_CANARY", None)
            else:
                os.environ["SCOURGE_MONITOR_CREDENTIAL_CANARY"] = prior
        exists = subprocess.run(
            ["/usr/bin/podman", "--remote=false", "container", "exists", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        ).returncode
        if exists != 1:
            raise RuntimeError("qualification container was not removed")
        envelope = result.envelope
        trace = envelope["trace"]
        if not monitor.verify_envelope(envelope, monitor.read_monitor_key(key)):
            raise RuntimeError("trace envelope failed authentication")
        if (len(trace["commands"]) != 10 or len(result.call_stdout) != 12
                or len(result.teapot_stdout) != 2 or len(result.investigation_stdout) != 1):
            raise RuntimeError("qualification did not account for every scenario")
        outputs = [path.read_bytes() for path in result.call_stdout]
        expected = [
            b"direct\n", b"shell\n", b"piped\n", b"PIPED\n",
            b"transformed\n", b"TRANSFORMED\n", b"redirected\n", b"", b"short-lived\n",
            b"child-ok\n", b"child-ok\n", b"child-ok\n",
        ]
        if outputs != expected or (workspace / "redirected.txt").read_bytes() != b"redirected\n":
            raise RuntimeError(f"collector stdout reconstruction differs: {outputs!r}")
        if [row["exit_code"] for row in trace["commands"]] != [0, 0, 0, 0, 0, 7, 0, 0, 0, 0]:
            raise RuntimeError("child and native exits differ")
        if ([path.read_bytes() for path in result.teapot_stdout] != [b"--json\n", b"--json\n"]
                or [path.read_bytes() for path in result.investigation_stdout] != [b"--format\n"]):
            raise RuntimeError("approved child stdout was not retained exactly")
        scanned = [result.raw_path, result.stderr_path, result.envelope_path, result.events_path,
                   result.exec_snapshots_path, *result.call_stdout,
                   *result.teapot_stdout, *result.investigation_stdout]
        if any(CANARY.encode() in path.read_bytes() for path in scanned):
            raise RuntimeError("host credential canary leaked into monitor evidence")
        receipt = {
            "schema": "scourge.skeleton-process-monitor-qualification.v1",
            "qualified": True,
            "offline": True,
            "rootless": True,
            "image": {"reference": IMAGE, "id": IMAGE_ID},
            "tools": {
                "strace_sha256": monitor.STRACE_SHA256,
                "podman_sha256": monitor.PODMAN_SHA256,
                "crun_sha256": monitor.CRUN_SHA256,
                "cc_path": CC_PATH,
                "cc_sha256": CC_SHA256,
            },
            "monitor": frozen,
            "probe": {"source_sha256": hashlib.sha256(PROBE_SOURCE.encode()).hexdigest(),
                      "binary_sha256": probe_digest},
            "assertions": {
                "scenarios": ["direct", "shell", "pipe", "transformed", "redirected", "failed",
                              "short-lived", "teapot", "teapot-fd", "investigation-fd"],
                "command_count": len(trace["commands"]),
                "call_count": len(result.call_stdout),
                "teapot_child_count": len(result.teapot_stdout),
                "investigation_child_count": len(result.investigation_stdout),
                "production_teapot_sha256": monitor.REQUEST_REFERENCE_TEAPOT_SHA256,
                "production_investigation_sha256": monitor.INVESTIGATION_SHA256,
                "codex_stdout_exact": trace["raw_sha256"] == hashlib.sha256(result.raw_path.read_bytes()).hexdigest(),
                "trace_authenticated": True,
                "lost_events": trace["lost_events"],
                "credential_canary_absent": True,
                "container_removed": True,
                "exec_stop_snapshot_count": trace["exec_stop_snapshot_count"],
                "network": "none",
            },
            "evidence_sha256": {
                "host_trace": sha256(result.envelope_path),
                "events": sha256(result.events_path),
                "raw_jsonl": sha256(result.raw_path),
            },
        }
        rendered = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
        if args.output:
            if (not args.output.is_absolute()
                    or args.output.parent.resolve(strict=True) != args.output.parent):
                raise RuntimeError("qualification output requires a canonical absolute parent")
            fd = os.open(
                args.output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                data = rendered.encode("ascii")
                if os.write(fd, data) != len(data):
                    raise RuntimeError("short qualification receipt write")
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
