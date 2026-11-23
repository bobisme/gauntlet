#!/usr/bin/env python3
"""Qualify the packaged fixture through a networkless rootless worker."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

PODMAN = ["podman", "--remote=false"]

WORKER = r'''
import http.client, json, os, socket, sys
attempts = []
for label, path in zip(("ground_truth", "fixture_source", "admin_secret"), sys.argv[1:]):
    try:
        with open(path, "rb") as f: f.read(1)
    except OSError as e:
        attempts.append({"name": label, "path": path, "refused": True, "error": e.strerror})
    else:
        attempts.append({"name": label, "path": path, "refused": False})
class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect("/gateway/fixture.sock")
c = Connection("fixture")
c.request("GET", "/")
response = c.getresponse()
print(json.dumps({"reads": attempts, "http_status": str(response.status),
                  "tool": "python3 http.client"}))
'''


async def main(url, paths):
    parent = os.getppid()
    for key in ("CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINER_SSHKEY", "DOCKER_HOST"):
        os.environ.pop(key, None)
    if len(paths) != 3:
        raise ValueError("expected exactly three protected paths")
    rootless = subprocess.run([*PODMAN, "info", "--format", "{{.Host.Security.Rootless}}"],
                              check=True, capture_output=True, text=True, timeout=30)
    if rootless.stdout.strip() != "true":
        raise RuntimeError("rootless Podman is required")
    image = subprocess.run([*PODMAN, "image", "inspect", "--format", "{{.Id}}",
                            "docker.io/library/python:3.12-alpine"],
                           check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    if len(image) != 64 or any(c not in "0123456789abcdef" for c in image):
        raise ValueError("invalid local image identity")
    version = subprocess.run([*PODMAN, "--version"], check=True, capture_output=True,
                             text=True, timeout=30).stdout.strip()
    target = urlsplit(url)
    if target.scheme != "http" or target.hostname != "127.0.0.1" or not target.port:
        raise ValueError("expected the harness loopback fixture URL")
    if not all(Path(p).is_file() and os.access(p, os.R_OK) for p in paths):
        raise ValueError("all three protected files must exist and be readable by the referee")

    async def relay(reader, writer):
        try:
            remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", target.port)
            async def copy(source, destination):
                try:
                    while chunk := await source.read(65536):
                        destination.write(chunk)
                        await destination.drain()
                finally:
                    destination.close()
            await asyncio.gather(copy(reader, remote_writer), copy(remote_reader, writer))
        except (OSError, ConnectionError):
            writer.close()

    with tempfile.TemporaryDirectory(prefix="scourge-boundary-") as directory:
        gateway = Path(directory) / "gateway"
        gateway.mkdir()
        name = "scourge-boundary-" + secrets.token_hex(16)
        server = await asyncio.start_unix_server(relay, path=str(gateway / "fixture.sock"))
        os.chmod(gateway / "fixture.sock", 0o600)
        command = [*PODMAN, "run", "--rm", "--pull=never", "--network=none", "--read-only",
                   "--name", name, "--http-proxy=false",
                   "--cap-drop=all", "--security-opt=no-new-privileges", "--pids-limit=64",
                   "--mount", f"type=bind,src={gateway},dst=/gateway,ro=true",
                   "--entrypoint", "python3", image,
                   "-I", "-c", WORKER, *paths]
        process = None
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        async def watch_parent():
            while os.getppid() == parent:
                await asyncio.sleep(0.2)
            task.cancel()
        watcher = asyncio.create_task(watch_parent())
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, task.cancel)
        try:
            process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                            stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 60)
        finally:
            watcher.cancel()
            if process is not None and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            subprocess.run([*PODMAN, "rm", "--force", "--ignore", name], check=True, timeout=30,
                           stdout=subprocess.DEVNULL)
            probe = subprocess.run([*PODMAN, "container", "exists", name], timeout=30)
            if probe.returncode != 1:
                raise RuntimeError(f"cannot verify worker container removal: {name}")
            server.close()
            await server.wait_closed()
        if process.returncode:
            raise RuntimeError(f"worker failed: {stderr.decode(errors='replace')}")
        result = json.loads(stdout)
        result.update({"podman_version": version, "rootless": True, "image_id": image,
                       "network": "none", "gateway_mount": "read-only", "container_removed": True,
                       "podman_remote": False, "http_proxy_injection": False})
        if len(result["reads"]) != 3 or not all(item["refused"] for item in result["reads"]) or result["http_status"] != "404":
            raise RuntimeError(f"qualification failed: {result}")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2:]))
