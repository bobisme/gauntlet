"""Deterministic in-memory double for fixture self-tests."""

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from driver import (
    Artifact,
    Attachment,
    ByteRange,
    Capture,
    Finalization,
    JsonKind,
    Lineage,
    Read,
    RecordKind,
    Rejected,
)


_MAX_SAFE_INTEGER = (1 << 53) - 1


def _object_without_duplicates(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("duplicate key")
        values[key] = value
    return values


def _safe_int(token: str) -> int:
    number = int(token)
    if abs(number) > _MAX_SAFE_INTEGER:
        raise ValueError("unsafe integer")
    return number


def _safe_float(token: str) -> float:
    number = float(token)
    if not math.isfinite(number) or (number.is_integer() and abs(number) > _MAX_SAFE_INTEGER):
        raise ValueError("unsafe number")
    return number


def _validate_json(data: bytes) -> None:
    try:
        json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_int=_safe_int,
            parse_float=_safe_float,
            parse_constant=_safe_float,
        )
    except ValueError as error:
        raise Rejected("invalid_json") from error


@dataclass
class _CaptureState:
    items: dict[str, Attachment] = field(default_factory=dict)
    payloads: dict[str, bytes] = field(default_factory=dict)
    artifacts: tuple[Artifact, ...] = ()
    finalization: Finalization | None = None


@dataclass
class _Store:
    captures: dict[str, _CaptureState] = field(default_factory=dict)
    artifacts: dict[str, Read] = field(default_factory=dict)
    records: dict[str, tuple[RecordKind, Read]] = field(default_factory=dict)


class _Reference:
    def __init__(self, store: _Store):
        self.store = store
        self.active = True

    def open(self, key: str) -> str:
        capture_id = f"capture/{key}"
        self._check_active()
        self.store.captures.setdefault(capture_id, _CaptureState())
        return capture_id

    def attach(self, capture_id: str, key: str, data: bytes, *, position: int) -> Attachment:
        state = self._capture(capture_id)
        if old := state.items.get(key):
            if old.position != position or state.payloads[key] != data:
                raise Rejected("conflict")
            return old
        if state.finalization is not None:
            raise Rejected("closed")
        if position != len(state.items) + 1:
            raise Rejected("conflict")
        digest = hashlib.sha256(data).hexdigest()
        request_digest = hashlib.sha256(f"{key}:{position}:{digest}".encode()).hexdigest()
        receipt = Attachment(position, key, digest, request_digest, f"accepted:{position}")
        state.items[key] = receipt
        state.payloads[key] = data
        return receipt

    def finalize(self, capture_id: str, request: Finalization) -> Capture:
        state = self._capture(capture_id)
        if state.finalization is not None:
            if state.finalization != request:
                raise Rejected("conflict")
            return self._snapshot(capture_id, state)
        accepted = len(state.items)
        if (
            request.expected_position != len(request.item_keys)
            or tuple(state.items) != request.item_keys[:accepted]
            or (request.complete and request.expected_position != accepted)
        ):
            raise Rejected("conflict")
        artifacts = []
        for item in state.items.values():
            artifact = Artifact(f"{capture_id}/item/{item.position}", item.sha256, capture_id)
            self.store.artifacts[artifact.id] = Read(artifact, state.payloads[item.key])
            artifacts.append(artifact)
        state.artifacts = tuple(artifacts)
        state.finalization = request
        return self._snapshot(capture_id, state)

    def read(
        self,
        artifact_id: str,
        *,
        part: ByteRange | None = None,
        structured_as: JsonKind | None = None,
    ) -> Read:
        self._check_active()
        stored = self.store.artifacts.get(artifact_id)
        if stored is None:
            raise Rejected("missing")
        if structured_as is not None:
            _validate_json(stored.data)
        if part is None:
            return stored
        if not 0 <= part.start < part.end <= len(stored.data):
            raise Rejected("invalid_range")
        return Read(stored.artifact, stored.data[part.start:part.end])

    def record(
        self, key: str, kind: RecordKind, data: bytes, *, lineage: tuple[Lineage, ...]
    ) -> Artifact:
        self._check_active()
        if key in self.store.records:
            old_kind, old = self.store.records[key]
            if (kind, data, lineage) != (old_kind, old.data, old.artifact.lineage):
                raise Rejected("conflict")
            return old.artifact
        if kind != "redaction":
            _validate_json(data)
        for link in lineage:
            if self.read(link.artifact_id).artifact.sha256 != link.sha256:
                raise Rejected("digest_mismatch")
        artifact = Artifact(f"record/{key}", hashlib.sha256(data).hexdigest(), lineage=lineage)
        stored = Read(artifact, data)
        self.store.records[key] = kind, stored
        self.store.artifacts[artifact.id] = stored
        return artifact

    def interrupt(self) -> None:
        self.active = False

    def recover(self, capture_id: str) -> Capture:
        return self._snapshot(capture_id, self._capture(capture_id))

    def close(self) -> None:
        self.interrupt()

    def _check_active(self) -> None:
        if not self.active:
            raise RuntimeError("driver session interrupted")

    def _capture(self, capture_id: str) -> _CaptureState:
        self._check_active()
        state = self.store.captures.get(capture_id)
        if state is None:
            raise Rejected("missing")
        return state

    @staticmethod
    def _snapshot(capture_id: str, state: _CaptureState) -> Capture:
        attachments = tuple(state.items.values())
        accepted = len(attachments)
        if state.finalization is None:
            return Capture(capture_id, attachments, accepted, "open")
        seal = "complete" if state.finalization.complete else "partial"
        missing = tuple(range(accepted + 1, state.finalization.expected_position + 1))
        return Capture(capture_id, attachments, accepted, seal, missing, state.artifacts)


def make_factory():
    stores: dict[Path, _Store] = {}

    def open_driver(scratch: Path) -> _Reference:
        return _Reference(stores.setdefault(scratch, _Store()))

    return open_driver
