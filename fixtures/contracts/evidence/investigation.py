"""Fixture adapter for the published Investigation JSON CLI."""

import base64
import hashlib
import json
import multiprocessing
import os
import signal
import subprocess
from pathlib import Path

from driver import Artifact, Attachment, Capture, Lineage, Read, Rejected


ACTOR = "agent:scourge-evidence"
PROTOCOL = "inv.capture.v1"
METADATA = "scourge.fixture"
INVESTIGATION_VERSION = "investigation 0.1.0"


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value):
    algorithm, digest = value.split(":", 1)
    if algorithm != "sha256":
        raise RuntimeError(f"Expected SHA-256, got {algorithm}")
    return digest


def _writer(channel, parent_channel, binary, scratch):
    """One producer process issues CLI calls for the lifetime of a fixture session."""
    parent_channel.close()
    with channel:
        while True:
            try:
                request = channel.recv()
            except EOFError:
                return
            if request is None:
                return
            argv, payload = request
            try:
                reply = subprocess.run(
                    [binary, "--format", "json", *argv],
                    input=payload,
                    capture_output=True,
                    cwd=scratch,
                    env={"PATH": os.defpath},
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                channel.send((None, b"", str(error)))
                continue
            channel.send((reply.returncode, reply.stdout, reply.stderr))


class InvestigationError(RuntimeError):
    def __init__(self, argv, response):
        self.code = response["error"]["code"]
        self.path = response["error"].get("path", "")
        self.message = response["error"]["message"]
        super().__init__(f"{' '.join(argv)}: {self.code} at {self.path}: {self.message}")


class Investigation:
    def __init__(self, binary, scratch):
        self.workspace = scratch / "investigation"
        self.inputs = scratch / "producer"
        self.inputs.mkdir(exist_ok=True)
        self.case_id = None
        context = multiprocessing.get_context("fork")
        self.channel, writer_channel = context.Pipe()
        self.writer = context.Process(
            target=_writer, args=(writer_channel, self.channel, binary, scratch)
        )
        self.writer.start()
        writer_channel.close()
        try:
            if not self.workspace.exists():
                self._call("init", str(self.workspace), "--no-vault", "--import-root", str(self.inputs))
        except BaseException:
            self.close()
            raise

    def _call(self, *argv, payload=None):
        if not self.writer.is_alive():
            raise RuntimeError("Investigation producer session has exited")
        command = argv if argv[0] == "init" else ("--workspace", str(self.workspace), *argv)
        stdin = b"" if payload is None else json.dumps(payload, allow_nan=False).encode()
        self.channel.send((command, stdin))
        if not self.channel.poll(35):
            raise RuntimeError(f"Investigation producer timed out running {' '.join(argv)}")
        status, stdout, stderr = self.channel.recv()
        try:
            reply = json.loads(stdout)
        except ValueError as error:
            raise RuntimeError(f"Investigation returned no JSON ({status}) for {argv}: {stderr!r}") from error
        if status:
            raise InvestigationError(argv, reply)
        if reply.get("ok") is False:
            raise RuntimeError(f"Investigation exited successfully with a rejection for {argv}: {reply}")
        return reply

    def _capture(self, operation, request):
        try:
            return self._call("capture", operation, "--input", "-", payload=request)
        except InvestigationError as error:
            if (operation, error.code, error.path) == ("attach", "REVISION_CONFLICT", "/handle"):
                raise Rejected("closed") from error
            if error.code in {"IDEMPOTENCY_KEY_REUSED", "REVISION_CONFLICT"}:
                raise Rejected("conflict") from error
            raise

    def open(self, key):
        receipt = self._capture("begin", {
            "key": f"capture/{key}/begin",
            "actor": ACTOR,
            "producer": {"name": "scourge-evidence", "version": "0.1.0"},
            "external_run_id": key,
            "intent": {"label": "Scourge contract fixture"},
            "case": {"kind": "new_record_case", "title": "Scourge contract fixture"},
            "protocol": PROTOCOL,
        })
        if receipt["protocol"] != PROTOCOL:
            raise RuntimeError(f"Unexpected capture protocol {receipt['protocol']}")
        self.case_id = receipt["case_id"]
        return receipt["handle"]

    @staticmethod
    def _attachment(response, handle):
        item = response["receipt"]
        if response["availability"] != "staged" or item["handle"] != handle:
            raise RuntimeError(f"Unexpected attachment receipt: {response}")
        if item["result"] not in {"accepted", "already_accepted"}:
            raise RuntimeError(f"Unexpected item result: {item}")
        return Attachment(
            item["position"], item["key"], _hex(response["digest"]),
            _hex(item["request_digest"]), item["accepted_at"],
        )

    def attach(self, capture_id, key, data, *, position):
        digest = _digest(data)
        name = f"capture-{_digest(f'{capture_id}/{key}'.encode())}"
        (self.inputs / name).write_bytes(data)
        receipt = self._capture("attach", {
            "handle": capture_id,
            "position": position,
            "key": key,
            "role": "original-output",
            "source": {"kind": "file", "path": name},
            "expected_digest": f"sha256:{digest}",
            "expected_size_bytes": len(data),
        })
        if receipt["size_bytes"] != len(data):
            raise RuntimeError(f"Unexpected attached size: {receipt}")
        return self._attachment(receipt, capture_id)

    def finalize(self, capture_id, request):
        receipt = self._capture("finalize", {
            "handle": capture_id,
            "key": f"{capture_id}/finalize",
            "expected_last_position": request.expected_position,
            "completion": "complete" if request.complete else "partial",
            "strict_artifact_inventory": request.complete,
            "execution": {"state": "unknown"},
            "declared_artifacts": list(request.item_keys),
            "metadata": {METADATA: {"handle": capture_id}},
        })
        captured, recovered = self._recover(capture_id)
        finalized = recovered["finalized"]
        if (
            receipt["commit"]["transaction_id"] != finalized["commit"]["transaction_id"]
            or receipt["manifest_digest"] != finalized["manifest_digest"]
        ):
            raise RuntimeError("Finalization and recovery disagree on the committed seal")
        return captured

    def _recover(self, capture_id):
        response = self._call("capture", "recover", "--handle", capture_id)
        handle, = response["handles"]
        if handle["handle"] != capture_id:
            raise RuntimeError(f"Recovered a different capture: {handle}")
        self.case_id = handle["case_id"]
        attachments = tuple(self._attachment(item, capture_id) for item in handle["artifacts"])
        position = handle.get("last_position") or 0
        if handle["seal"] == "open":
            return Capture(handle["handle"], attachments, position, "open"), handle
        if handle["seal"] != "finalized":
            raise RuntimeError(f"Unexpected recovery seal: {handle['seal']}")
        receipt = handle["finalized"]
        run = self._show(handle["run_id"])
        if run["capture"]["handle"] != capture_id:
            raise RuntimeError("Committed Run belongs to a different capture handle")
        finalization = run["capture_finalization"]
        if finalization["manifest"]["digest"] != receipt["manifest_digest"]:
            raise RuntimeError("Committed Run and recovery disagree on the manifest digest")
        inventory = [
            item for item in finalization["artifacts"] if item["retention"]["state"] == "retained"
        ]
        observed = [
            (item["position"], item["key"], _hex(item["retention"]["digest"])) for item in inventory
        ]
        if observed != [(item.position, item.key, item.sha256) for item in attachments]:
            raise RuntimeError("Committed Run and recovery disagree on the attachment inventory")
        artifacts = tuple(
            Artifact(
                item["retention"]["artifact_ref"]["id"],
                _hex(item["retention"]["digest"]),
                run["capture"]["handle"],
            )
            for item in inventory
        )
        seal = {"finalized": "complete", "finalized_partial": "partial"}[receipt["finalization"]]
        return Capture(
            capture_id, attachments, position, seal, tuple(receipt.get("missing_positions", [])),
            artifacts,
        ), handle

    def recover(self, capture_id):
        return self._recover(capture_id)[0]

    def _show(self, record_id):
        try:
            return self._call("show", record_id, "--depth", "full")["record"]["body"]
        except InvestigationError as error:
            if (error.code, error.path) == ("UNKNOWN_REFERENCE", "/id"):
                raise Rejected("missing") from error
            raise

    def _artifact(self, artifact_id, body):
        lineage = tuple(
            Lineage(
                link["input"]["id"],
                _hex(link["input_digest"]),
                f"{link['transformation']}/{link['version']}",
            )
            for link in body["transforms"]
        )
        handle = None
        if body["role"] == "original":
            source = self._show(body["source"]["id"])
            handle = source["metadata"][METADATA]["handle"]
        return Artifact(artifact_id, _hex(body["digest"]), handle, lineage)

    def _select(self, artifact_id, digest, selector):
        response = self._call("evidence", "read", artifact_id, "--selector-file", "-", payload={
            "schema_version": "inv.selector.v1",
            "artifact_digest": digest,
            "selector": selector,
        })
        if response["artifact"]["id"] != artifact_id:
            raise RuntimeError("Evidence read returned a different Artifact ID")
        return response["excerpt"]

    def read(self, artifact_id, *, part=None, structured_as=None):
        body = self._show(artifact_id)
        digest = body["digest"]
        if structured_as is not None:
            try:
                checked = self._select(artifact_id, digest, {
                    "type": "json_pointer", "pointer": "", "parser": "serde_json-strict-v1",
                })
            except InvestigationError as error:
                if (error.code, error.path, error.message) == (
                    "INVALID_INPUT", "/basis/selector", "invalid or over-limit strict JSON",
                ):
                    raise Rejected("invalid_json") from error
                raise
            if checked["availability"] != "json_value":
                raise RuntimeError("Strict JSON selector returned no JSON value")
        selector = {"type": "whole"} if part is None else {
            "type": "byte_range", "start": part.start, "end": part.end,
        }
        try:
            excerpt = self._select(artifact_id, digest, selector)
        except InvestigationError as error:
            if part is not None and error.code == "INVALID_INPUT" and (
                error.path.startswith("/selector") or error.path == "/basis/selector"
            ):
                raise Rejected("invalid_range") from error
            raise
        if excerpt["availability"] == "text":
            data = excerpt["text"].encode("utf-8")
        elif excerpt["availability"] == "binary":
            data = base64.b64decode(excerpt["bytes_base64"], validate=True)
        else:
            raise RuntimeError(f"Investigation returned {excerpt['availability']} without exact bytes")
        return Read(self._artifact(artifact_id, body), data)

    def record(self, key, kind, data, *, lineage):
        if self.case_id is None:
            case, = self._call("check")["heads"]
            self.case_id = case["case_id"]
        name = f"record-{_digest(key.encode())}"
        (self.inputs / name).write_bytes(data)
        transform, version = lineage[0].transform.rsplit("/", 1)
        if any(link.transform != lineage[0].transform for link in lineage):
            raise ValueError("Investigation ingest needs one transform identity per record")
        media_type = "text/plain" if kind == "redaction" else "application/json"
        request = {
                "schema_version": "inv.ingest.v1",
                "actor": ACTOR,
                "command_id": f"record/{key}",
                "case_id": self.case_id,
                "source": {"title": kind, "format": media_type},
                "paths": [name],
                "derived_from": {
                    "transformation": transform,
                    "version": version,
                    # The fixture refers to freshly created immutable revision 1 records.
                    "inputs": [
                        {
                            "artifact_ref": {"id": link.artifact_id, "revision": 1},
                            "digest": f"sha256:{link.sha256}",
                        }
                        for link in lineage
                    ],
                },
            }
        if media_type == "application/json":
            request["validate_as"] = "strict_json"
        try:
            receipt = self._call("ingest", "--input", "-", payload=request)
        except InvestigationError as error:
            if error.code == "IDEMPOTENCY_KEY_REUSED":
                raise Rejected("conflict") from error
            if error.code == "INVALID_INPUT" and error.path.startswith("/validate_as"):
                raise Rejected("invalid_json") from error
            if error.code == "INVALID_INPUT" and error.path.startswith("/derived_from/inputs/"):
                if error.path.endswith("/artifact_ref"):
                    raise Rejected("missing") from error
                if error.path.endswith("/digest"):
                    raise Rejected("digest_mismatch") from error
            raise
        item, = receipt["items"]
        if item["outcome"] != "derived":
            raise RuntimeError(f"Expected a derivative receipt: {item}")
        artifact_id = item["artifact_id"]
        return self._artifact(artifact_id, self._show(artifact_id))

    def interrupt(self):
        if not self.writer.is_alive():
            raise RuntimeError("Investigation producer exited before interruption")
        self.writer.kill()
        self.writer.join(timeout=5)
        if self.writer.exitcode != -signal.SIGKILL:
            raise RuntimeError("Investigation producer did not terminate with SIGKILL")
        self.channel.close()

    def close(self):
        if self.writer.is_alive():
            self.channel.send(None)
            self.writer.join(timeout=5)
            if self.writer.is_alive():
                self.interrupt()
        self.channel.close()


def open_driver(scratch: Path):
    location = os.environ.get("SCOURGE_INVESTIGATION_BIN")
    if not location:
        raise RuntimeError("Set SCOURGE_INVESTIGATION_BIN to the pinned Investigation executable")
    binary = Path(location).resolve(strict=True)
    version = subprocess.check_output([binary, "--version"], text=True, timeout=10).strip()
    if version != INVESTIGATION_VERSION:
        raise RuntimeError(f"Expected {INVESTIGATION_VERSION}, got {version}")
    return Investigation(binary, scratch)
