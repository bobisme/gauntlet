"""Fixture vocabulary for the Scourge evidence contract."""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Protocol

JsonKind = Literal["manifest", "experiment", "verification"]
RecordKind = Literal["manifest", "experiment", "verification", "redaction"]
Rejection = Literal[
    "conflict", "closed", "missing", "invalid_range", "invalid_json", "digest_mismatch"
]
SealState = Literal["open", "complete", "partial"]


class Rejected(Exception):
    """A rejected operation, normalized by the adapter from the observed result."""

    def __init__(self, reason: Rejection):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Lineage:
    artifact_id: str
    sha256: str
    transform: str  # Includes the transform version.


@dataclass(frozen=True)
class Artifact:
    id: str
    sha256: str  # Lowercase hex of the exact full artifact bytes.
    capture_id: str | None = None
    lineage: tuple[Lineage, ...] = ()


@dataclass(frozen=True)
class Read:
    artifact: Artifact
    data: bytes  # Exact bytes of the whole artifact or selected part.


@dataclass(frozen=True)
class ByteRange:
    start: int
    end: int  # Zero-based, exclusive.


@dataclass(frozen=True)
class Attachment:
    position: int
    artifact: Artifact


@dataclass(frozen=True)
class Finalization:
    expected_position: int
    item_keys: tuple[str, ...]  # Declared attachment keys in position order.
    complete: bool


@dataclass(frozen=True)
class Capture:
    id: str
    attachments: tuple[Attachment, ...]
    accepted_position: int
    seal: SealState
    missing_positions: tuple[int, ...] = ()


class Driver(Protocol):
    """One adapter supplies these operations, using isolated state for each case."""

    def open(self, key: str) -> str: ...

    def attach(self, capture_id: str, key: str, data: bytes, *, position: int) -> Attachment: ...

    def finalize(self, capture_id: str, request: Finalization) -> Capture: ...

    def read(
        self,
        artifact_id: str,
        *,
        part: ByteRange | None = None,
        structured_as: JsonKind | None = None,
    ) -> Read: ...

    def record(
        self, key: str, kind: RecordKind, data: bytes, *, lineage: tuple[Lineage, ...]
    ) -> Artifact: ...

    def interrupt(self) -> None:
        """Terminate the writer without sealing or gracefully closing the capture."""
        ...

    def recover(self, capture_id: str) -> Capture:
        """Discover the accepted state from the underlying store."""
        ...

    def close(self) -> None:
        """Release case resources, including after an interrupted or failed case."""
        ...


DriverFactory = Callable[[Path], Driver]
